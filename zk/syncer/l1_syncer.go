package syncer

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gateway-fm/cdk-erigon-lib/common"
	"github.com/grail-rollup/btcman"
	"github.com/iden3/go-iden3-crypto/keccak256"
	ethereum "github.com/ledgerwatch/erigon"
	"github.com/ledgerwatch/log/v3"

	"encoding/binary"

	ethTypes "github.com/ledgerwatch/erigon/core/types"
	"github.com/ledgerwatch/erigon/rpc"
	"github.com/ledgerwatch/erigon/zk/contracts"
)

var (
	batchWorkers = 2
)

var errorShortResponseLT32 = fmt.Errorf("response too short to contain hash data")
var errorShortResponseLT96 = fmt.Errorf("response too short to contain last batch number data")

const (
	rollupSequencedBatchesSignature = "0x25280169" // hardcoded abi signature
	globalExitRootManager           = "0xd02103ca"
	rollupManager                   = "0x49b7b802"
	admin                           = "0xf851a440"
	trustedSequencer                = "0xcfa8ed47"
	sequencedBatchesMapSignature    = "0xb4d63f58"
)

type IEtherman interface {
	HeaderByNumber(ctx context.Context, blockNumber *big.Int) (*ethTypes.Header, error)
	BlockByNumber(ctx context.Context, blockNumber *big.Int) (*ethTypes.Block, error)
	FilterLogs(ctx context.Context, query ethereum.FilterQuery) ([]ethTypes.Log, error)
	CallContract(ctx context.Context, msg ethereum.CallMsg, blockNumber *big.Int) ([]byte, error)
	TransactionByHash(ctx context.Context, hash common.Hash) (ethTypes.Transaction, bool, error)
	TransactionReceipt(ctx context.Context, txHash common.Hash) (*ethTypes.Receipt, error)
	StorageAt(ctx context.Context, account common.Address, key common.Hash, blockNumber *big.Int) ([]byte, error)
}

type fetchJob struct {
	From uint64
	To   uint64
}

type jobResult struct {
	Size  uint64
	Error error
	Logs  []ethTypes.Log
}

type L1Syncer struct {
	ctx                 context.Context
	etherMans           []IEtherman
	ethermanIndex       uint8
	ethermanMtx         *sync.Mutex
	btcMan              btcman.Clienter
	l1ContractAddresses []common.Address
	topics              [][]common.Hash
	blockRange          uint64
	queryDelay          uint64

	latestL1Block uint64

	// atomic
	isSyncStarted         atomic.Bool
	isDownloading         atomic.Bool
	lastCheckedL1Block    atomic.Uint64
	lastCheckedBtcL1Block atomic.Int32
	wgRunLoopDone         sync.WaitGroup
	flagStop              atomic.Bool

	// Channels
	logsChan         chan []ethTypes.Log
	logsChanProgress chan string
	btcTxChan        chan BtcLog

	highestBlockType string // finalized, latest, safe
}

func NewL1Syncer(ctx context.Context, etherMans []IEtherman, btcMan btcman.Clienter, l1ContractAddresses []common.Address, topics [][]common.Hash, blockRange, queryDelay uint64, highestBlockType string) *L1Syncer {
	return &L1Syncer{
		ctx:                 ctx,
		etherMans:           etherMans,
		ethermanIndex:       0,
		ethermanMtx:         &sync.Mutex{},
		btcMan:              btcMan,
		l1ContractAddresses: l1ContractAddresses,
		topics:              topics,
		blockRange:          blockRange,
		queryDelay:          queryDelay,
		logsChan:            make(chan []ethTypes.Log),
		logsChanProgress:    make(chan string),
		btcTxChan:           make(chan BtcLog),
		highestBlockType:    highestBlockType,
	}
}

func (s *L1Syncer) getNextEtherman() IEtherman {
	s.ethermanMtx.Lock()
	defer s.ethermanMtx.Unlock()

	if s.ethermanIndex >= uint8(len(s.etherMans)) {
		s.ethermanIndex = 0
	}

	etherman := s.etherMans[s.ethermanIndex]
	s.ethermanIndex++

	return etherman
}

func (s *L1Syncer) IsSyncStarted() bool {
	return s.isSyncStarted.Load()
}

func (s *L1Syncer) IsDownloading() bool {
	return s.isDownloading.Load()
}

func (s *L1Syncer) GetLastCheckedL1Block() uint64 {
	return s.lastCheckedL1Block.Load()
}

func (s *L1Syncer) GetLastCheckedBtcL1Block() int32 {
	return s.lastCheckedBtcL1Block.Load()
}

func (s *L1Syncer) StopQueryBlocks() {
	s.flagStop.Store(true)
}

func (s *L1Syncer) ConsumeQueryBlocks() {
	for {
		select {
		case <-s.logsChan:
		case <-s.logsChanProgress:
		default:
			if !s.isSyncStarted.Load() {
				return
			}
			time.Sleep(time.Second)
		}
	}
}

func (s *L1Syncer) WaitQueryBlocksToFinish() {
	s.wgRunLoopDone.Wait()
}

// Channels
func (s *L1Syncer) GetLogsChan() chan []ethTypes.Log {
	return s.logsChan
}

func (s *L1Syncer) GetProgressMessageChan() chan string {
	return s.logsChanProgress
}

func (s *L1Syncer) GetBtcTxChan() chan BtcLog {
	return s.btcTxChan
}

func (s *L1Syncer) RunQueryBlocks(lastCheckedBlock uint64, lastCheckedBtcBlock int32) {
	//if already started, don't start another thread
	if s.isSyncStarted.Load() {
		return
	}

	s.isSyncStarted.Store(true)

	// set it to true to catch the first cycle run case where the check can pass before the latest block is checked
	s.isDownloading.Store(true)
	s.lastCheckedL1Block.Store(lastCheckedBlock)
	s.lastCheckedBtcL1Block.Store(lastCheckedBtcBlock)

	s.wgRunLoopDone.Add(1)
	s.flagStop.Store(false)

	//start a thread to cheack for new l1 block in interval
	go func() {
		defer s.isSyncStarted.Store(false)
		defer s.wgRunLoopDone.Done()

		log.Info("Starting L1 syncer thread")
		defer log.Info("Stopping L1 syncer thread")

		for {
			if s.flagStop.Load() {
				return
			}

			latestL1Block, err := s.getLatestL1Block()
			if err != nil {
				log.Error("Error getting latest L1 block", "err", err)
			} else {
				if latestL1Block > s.lastCheckedL1Block.Load() {
					s.isDownloading.Store(true)
					if err := s.queryBlocks(); err != nil {
						log.Error("Error querying blocks", "err", err)
					} else {
						s.lastCheckedL1Block.Store(latestL1Block)
					}
				}
			}

			// BTC START
			// latestBtcL1Block, err := s.getLatestBtcL1Block()
			// lastCheckedBtcBlock = s.lastCheckedBtcL1Block.Load()
			// if err != nil {
			// 	log.Error("Error getting latest BTC L1 block", "err", err)
			// } else {
			// 	log.Info("Got latest BTC block", "new", latestBtcL1Block, "old", lastCheckedBtcBlock)
			// 	if latestBtcL1Block > lastCheckedBtcBlock && lastCheckedBtcBlock >= 0 { // TODO remove >=0 check when the other stages are implemented
			// 		s.isDownloading.Store(true)
			// 		txs, err := s.btcMan.GetHistory()
			// 		if err != nil {
			// 			log.Error("Error getting history", "err", err)
			// 		}
			// 		log.Info("BTC history", "len", len(txs), "latestBtcL1Block", latestBtcL1Block)

			// 		for _, tx := range txs {
			// 			// TODO: txs are sorted so we can find the new ones with binary search instead of going through all of them
			// 			// TODO: we can use fulcrum to filter by height when calling the indexer
			// 			if tx.Height > lastCheckedBtcBlock {
			// 				inscription, err := s.btcMan.DecodeInscription(tx.TxHash)
			// 				if err != nil {
			// 					log.Error("Error decoding tx", "err", err)
			// 				} else {
			// 					btcLog := BtcLog{
			// 						TxHash:          tx.TxHash,
			// 						InscriptionData: inscription,
			// 						BlockNumber:     tx.Height,
			// 						// Get it from `blockchain.transaction.get` or `blockchain.block.header`
			// 						BlockHash: "",
			// 					}
			// 					s.btcTxChan <- btcLog
			// 				}
			// 			}
			// 		}

			// 		// TODO: error handle?
			// 		s.lastCheckedBtcL1Block.Store(latestBtcL1Block)
			// 	}
			// }
			// BTC END

			s.isDownloading.Store(false)
			time.Sleep(time.Duration(s.queryDelay) * time.Millisecond)
		}
	}()
}

func (s *L1Syncer) GetHeader(number uint64) (*ethTypes.Header, error) {
	em := s.getNextEtherman()
	return em.HeaderByNumber(context.Background(), new(big.Int).SetUint64(number))
}

func (s *L1Syncer) GetBlock(number uint64) (*ethTypes.Block, error) {
	em := s.getNextEtherman()
	return em.BlockByNumber(context.Background(), new(big.Int).SetUint64(number))
}

func (s *L1Syncer) GetTransaction(hash common.Hash) (ethTypes.Transaction, bool, error) {
	em := s.getNextEtherman()
	return em.TransactionByHash(context.Background(), hash)
}

func (s *L1Syncer) GetPreElderberryAccInputHash(ctx context.Context, addr *common.Address, batchNum uint64) (common.Hash, error) {
	h, err := s.callSequencedBatchesMap(ctx, addr, batchNum)
	if err != nil {
		return common.Hash{}, err
	}

	return h, nil
}

// returns accInputHash only if the batch matches the last batch in sequence
// on Etrrof the rollup contract was changed so data is taken differently
func (s *L1Syncer) GetElderberryAccInputHash(ctx context.Context, addr *common.Address, rollupId, batchNum uint64) (common.Hash, error) {
	h, _, err := s.callGetRollupSequencedBatches(ctx, addr, rollupId, batchNum)
	if err != nil {
		return common.Hash{}, err
	}

	return h, nil
}

func (s *L1Syncer) GetL1BlockTimeStampByTxHash(ctx context.Context, txHash common.Hash) (uint64, error) {
	em := s.getNextEtherman()
	r, err := em.TransactionReceipt(ctx, txHash)
	if err != nil {
		return 0, err
	}

	header, err := em.HeaderByNumber(context.Background(), r.BlockNumber)
	if err != nil {
		return 0, err
	}

	return header.Time, nil
}

func (s *L1Syncer) L1QueryHeaders(logs []ethTypes.Log) (map[uint64]*ethTypes.Header, error) {
	logsSize := len(logs)

	// queue up all the logs
	logQueue := make(chan *ethTypes.Log, logsSize)
	defer close(logQueue)
	for i := 0; i < logsSize; i++ {
		logQueue <- &logs[i]
	}

	var wg sync.WaitGroup
	wg.Add(logsSize)

	headersQueue := make(chan *ethTypes.Header, logsSize)

	process := func(em IEtherman) {
		ctx := context.Background()
		for {
			l, ok := <-logQueue
			if !ok {
				break
			}
			header, err := em.HeaderByNumber(ctx, new(big.Int).SetUint64(l.BlockNumber))
			if err != nil {
				log.Error("Error getting block", "err", err)
				// assume a transient error and try again
				time.Sleep(1 * time.Second)
				logQueue <- l
				continue
			}
			headersQueue <- header
			wg.Done()
		}
	}

	// launch the workers - some endpoints might be faster than others so will consume more of the queue
	// but, we really don't care about that.  We want the data as fast as possible
	mans := s.etherMans
	for i := 0; i < len(mans); i++ {
		go process(mans[i])
	}

	wg.Wait()
	close(headersQueue)

	headersMap := map[uint64]*ethTypes.Header{}
	for header := range headersQueue {
		headersMap[header.Number.Uint64()] = header
	}

	return headersMap, nil
}

func (s *L1Syncer) getLatestL1Block() (uint64, error) {
	em := s.getNextEtherman()

	var blockNumber *big.Int

	switch s.highestBlockType {
	case "finalized":
		blockNumber = big.NewInt(rpc.FinalizedBlockNumber.Int64())
	case "safe":
		blockNumber = big.NewInt(rpc.SafeBlockNumber.Int64())
	case "latest":
		blockNumber = nil
	}

	latestBlock, err := em.BlockByNumber(context.Background(), blockNumber)
	if err != nil {
		return 0, err
	}

	latest := latestBlock.NumberU64()
	s.latestL1Block = latest

	return latest, nil
}

func (s *L1Syncer) getLatestBtcL1Block() (int32, error) {
	return s.btcMan.GetBlockchainHeight()
}

func (s *L1Syncer) queryBlocks() error {
	// Fixed receiving duplicate log events.
	// lastCheckedL1Block means that it has already been checked in the previous cycle.
	// It should not be checked again in the new cycle, so +1 is added here.
	startBlock := s.lastCheckedL1Block.Load() + 1
	log.Debug("GetHighestSequence", "startBlock", startBlock)

	startBlockBTC := s.lastCheckedBtcL1Block.Load() + 1
	log.Debug("GetHighestSequenceBTC", "startBlock", startBlockBTC)
	latestBtcL1Block, err := s.btcMan.GetBlockchainHeight()
	if err != nil {
		return err
	}

	// define the blocks we're going to fetch up front
	fetches := make([]fetchJob, 0)
	low := startBlock
	for {
		high := low + s.blockRange
		if high > s.latestL1Block {
			// at the end of our search
			high = s.latestL1Block
		}

		fetches = append(fetches, fetchJob{
			From: low,
			To:   high,
		})

		if high == s.latestL1Block {
			break
		}
		low += s.blockRange + 1
	}

	fetchesBTC := make([]fetchJob, 0)
	lowBTC := startBlockBTC
	for {
		high := uint64(lowBTC) + s.blockRange
		if high > uint64(latestBtcL1Block) {
			// at the end of our search
			high = uint64(latestBtcL1Block)
		}

		fetchesBTC = append(fetchesBTC, fetchJob{
			From: uint64(lowBTC),
			To:   high,
		})

		if high == uint64(latestBtcL1Block) {
			break
		}
		lowBTC = int32(uint64(lowBTC) + s.blockRange + 1)
	}

	wg := sync.WaitGroup{}
	stop := make(chan bool)
	stopBTC := make(chan bool)

	jobs := make(chan fetchJob, len(fetches))
	jobsBTC := make(chan fetchJob, len(fetchesBTC))

	results := make(chan jobResult, len(fetches)+len(fetchesBTC))
	defer close(results)

	wg.Add(batchWorkers * 2)
	for i := 0; i < batchWorkers; i++ {
		go s.getSequencedLogs(jobs, results, stop, &wg)
		go s.getSequencedLogsBTC(jobsBTC, results, stopBTC, &wg)
	}

	for _, fetch := range fetches {
		jobs <- fetch
	}
	close(jobs)

	for _, fetch := range fetchesBTC {
		jobsBTC <- fetch
	}
	close(jobsBTC)

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	// var err error
	var progress uint64 = 0

	aimingFor := s.latestL1Block - startBlock
	complete := 0
loop:
	for {
		select {
		case <-s.ctx.Done():
			break loop
		case res := <-results:
			if s.flagStop.Load() {
				break loop
			}

			complete++
			if res.Error != nil {
				err = res.Error
				break loop
			}
			progress += res.Size
			if len(res.Logs) > 0 {
				s.logsChan <- res.Logs
			}

			if complete == len(fetches) {
				// we've got all the results we need
				break loop
			}
		case <-ticker.C:
			if aimingFor == 0 {
				continue
			}
			s.logsChanProgress <- fmt.Sprintf("L1 Blocks processed progress (amounts): %d/%d (%d%%)", progress, aimingFor, (progress*100)/aimingFor)
		}
	}

	close(stop)
	wg.Wait()

	return err
}

func (s *L1Syncer) getSequencedLogs(jobs <-chan fetchJob, results chan jobResult, stop chan bool, wg *sync.WaitGroup) {
	defer wg.Done()

	for {
		select {
		case <-stop:
			return
		case j, ok := <-jobs:
			if !ok {
				return
			}
			query := ethereum.FilterQuery{
				FromBlock: new(big.Int).SetUint64(j.From),
				ToBlock:   new(big.Int).SetUint64(j.To),
				Addresses: s.l1ContractAddresses,
				Topics:    s.topics,
			}

			var logs []ethTypes.Log
			var err error
			retry := 0
			for {
				em := s.getNextEtherman()
				logs, err = em.FilterLogs(context.Background(), query)
				if err != nil {
					log.Debug("getSequencedLogs retry error", "err", err)
					retry++
					if retry > 5 {
						results <- jobResult{
							Error: err,
							Logs:  nil,
						}
						return
					}
					time.Sleep(time.Duration(retry*2) * time.Second)
					continue
				}
				break
			}
			filteredLogs := []ethTypes.Log{}
			for _, l := range logs {
				if l.Topics[0] != contracts.SequencedBatchTopicEtrog && l.Topics[0] != contracts.VerificationTopicEtrog {
					filteredLogs = append(filteredLogs, l)
				}
			}
			results <- jobResult{
				Size:  j.To - j.From,
				Error: nil,
				Logs:  filteredLogs,
			}
		}
	}
}

func populateInscriptionMap(inscriptionData string, rootsByBatch map[int]common.Hash, l1InfoRootByBatch map[int]common.Hash) error {
	if inscriptionData == "" {
		return errors.New("inscription data is empty")
	}

	if len(inscriptionData) == 1681 { // 840 bytes + starting 0
		inscription := inscriptionData[1:]
		stateRoot := common.HexToHash(inscription[64:128])

		batchNum := new(big.Int).SetBytes(common.FromHex(inscription[1664:])).Uint64()

		rootsByBatch[int(batchNum)] = stateRoot
	} else {
		inscription := inscriptionData[1:]
		// fmt.Println(inscription)
		batchNum := new(big.Int).SetBytes(common.FromHex(inscription[64:80])).Uint64()
		l1InfoRoot := common.HexToHash(inscription[16:64])
		l1InfoRootByBatch[int(batchNum)] = l1InfoRoot
	}
	return nil
}

func (s *L1Syncer) getInscriptions(stateRootByBatch map[int]common.Hash, l1InfoRootByBatch map[int]common.Hash) error {

	tnxs, err := s.btcMan.GetHistory()
	if err != nil {
		return err
	}

	for _, tnx := range tnxs {
		decoded, err := s.btcMan.DecodeInscription(tnx.TxHash)
		if err != nil {
			// fmt.Println("No inscription: ", err)
			continue
		}
		err = populateInscriptionMap(decoded, stateRootByBatch, l1InfoRootByBatch)
		if err != nil {
			continue
		}
	}

	return nil
}
func (s *L1Syncer) getSequencedLogsBTC(jobs <-chan fetchJob, results chan jobResult, stop chan bool, wg *sync.WaitGroup) {
	defer wg.Done()
	/* what we need to do here :
	- construct the two topic logs and pass the to the logs channel
	- skip this two two topics in the original getSequencedLogs: this is done
	- update parsing logic for this two events
	*/
	for {
		select {
		case <-stop:
			return
		case j, ok := <-jobs:
			if !ok {
				return
			}
			// from := j.From
			// Get inscriptions and prepare logs ONLY FROM THE UNCHECKED BLOCKS
			stateRootByBatch := make(map[int]common.Hash)
			l1InfoRootByBatch := make(map[int]common.Hash)
			err := s.getInscriptions(stateRootByBatch, l1InfoRootByBatch)
			if err != nil {
				// fmt.Println("Error getting inscriptions: ", err)
				continue
			}

			logs := []ethTypes.Log{}
			for batchNum, stateRoot := range stateRootByBatch {
				batchNumHash := common.BigToHash(new(big.Int).SetInt64(int64(batchNum)))
				verificationTopicLog := ethTypes.Log{
					Topics: []common.Hash{
						contracts.VerificationTopicEtrog,
						batchNumHash,
					},
					Data: []byte(stateRoot.Hex()),
				}
				logs = append(logs, verificationTopicLog)
			}

			for _, l1InfoRoot := range l1InfoRootByBatch {
				rollupID := common.BigToHash(new(big.Int).SetInt64(int64(420)))
				sequencedBatchTopicLog := ethTypes.Log{
					Topics: []common.Hash{
						contracts.SequencedBatchTopicEtrog,
						rollupID,
					},
					Data: []byte(l1InfoRoot.Hex()),
				}
				logs = append(logs, sequencedBatchTopicLog)
			}

			results <- jobResult{
				Size:  j.To - j.From,
				Error: nil,
				Logs:  logs,
			}
		}
	}
}

// calls the old rollup contract to get the accInputHash for a certain batch
// returns the accInputHash and lastBatchNumber
func (s *L1Syncer) callSequencedBatchesMap(ctx context.Context, addr *common.Address, batchNum uint64) (accInputHash common.Hash, err error) {
	mapKeyHex := fmt.Sprintf("%064x%064x", batchNum, 114 /* _legacySequencedBatches slot*/)
	mapKey := keccak256.Hash(common.FromHex(mapKeyHex))
	mkh := common.BytesToHash(mapKey)

	em := s.getNextEtherman()

	resp, err := em.StorageAt(ctx, *addr, mkh, nil)
	if err != nil {
		return
	}

	if err != nil {
		return
	}

	if len(resp) < 32 {
		return
	}
	accInputHash = common.BytesToHash(resp[:32])

	return
}

// calls the rollup contract to get the accInputHash for a certain batch
// returns the accInputHash and lastBatchNumber
func (s *L1Syncer) callGetRollupSequencedBatches(ctx context.Context, addr *common.Address, rollupId, batchNum uint64) (common.Hash, uint64, error) {
	rollupID := fmt.Sprintf("%064x", rollupId)
	batchNumber := fmt.Sprintf("%064x", batchNum)

	em := s.getNextEtherman()
	resp, err := em.CallContract(ctx, ethereum.CallMsg{
		To:   addr,
		Data: common.FromHex(rollupSequencedBatchesSignature + rollupID + batchNumber),
	}, nil)

	if err != nil {
		return common.Hash{}, 0, err
	}

	if len(resp) < 32 {
		return common.Hash{}, 0, errorShortResponseLT32
	}
	h := common.BytesToHash(resp[:32])

	if len(resp) < 96 {
		return common.Hash{}, 0, errorShortResponseLT96
	}
	lastBatchNumber := binary.BigEndian.Uint64(resp[88:96])

	return h, lastBatchNumber, nil
}

func (s *L1Syncer) CallAdmin(ctx context.Context, addr *common.Address) (common.Address, error) {
	return s.callGetAddress(ctx, addr, admin)
}

func (s *L1Syncer) CallRollupManager(ctx context.Context, addr *common.Address) (common.Address, error) {
	return s.callGetAddress(ctx, addr, rollupManager)
}

func (s *L1Syncer) CallGlobalExitRootManager(ctx context.Context, addr *common.Address) (common.Address, error) {
	return s.callGetAddress(ctx, addr, globalExitRootManager)
}

func (s *L1Syncer) CallTrustedSequencer(ctx context.Context, addr *common.Address) (common.Address, error) {
	return s.callGetAddress(ctx, addr, trustedSequencer)
}

func (s *L1Syncer) callGetAddress(ctx context.Context, addr *common.Address, data string) (common.Address, error) {
	em := s.getNextEtherman()
	resp, err := em.CallContract(ctx, ethereum.CallMsg{
		To:   addr,
		Data: common.FromHex(data),
	}, nil)

	if err != nil {
		return common.Address{}, err
	}

	if len(resp) < 20 {
		return common.Address{}, errorShortResponseLT32
	}

	return common.BytesToAddress(resp[len(resp)-20:]), nil
}

func (s *L1Syncer) CheckL1BlockFinalized(blockNo uint64) (finalized bool, finalizedBn uint64, err error) {
	em := s.getNextEtherman()
	block, err := em.BlockByNumber(s.ctx, big.NewInt(rpc.FinalizedBlockNumber.Int64()))
	if err != nil {
		return false, 0, err
	}

	return block.NumberU64() >= blockNo, block.NumberU64(), nil
}
