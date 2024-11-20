package syncer

import (
	"context"
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
	"golang.org/x/crypto/sha3"

	"encoding/binary"
	"encoding/hex"

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

	highestBlockType string // finalized, latest, safe

	hasSentInitLogs        atomic.Bool
	stateRootByBlockNumber map[uint64]common.Hash
	lastLocalExitRoot      atomic.Value
}

func NewL1Syncer(ctx context.Context, etherMans []IEtherman, btcMan btcman.Clienter, l1ContractAddresses []common.Address, topics [][]common.Hash, blockRange, queryDelay uint64, highestBlockType string) *L1Syncer {
	return &L1Syncer{
		ctx:                    ctx,
		etherMans:              etherMans,
		ethermanIndex:          0,
		ethermanMtx:            &sync.Mutex{},
		btcMan:                 btcMan,
		l1ContractAddresses:    l1ContractAddresses,
		topics:                 topics,
		blockRange:             blockRange,
		queryDelay:             queryDelay,
		logsChan:               make(chan []ethTypes.Log),
		logsChanProgress:       make(chan string),
		highestBlockType:       highestBlockType,
		stateRootByBlockNumber: make(map[uint64]common.Hash),
		lastLocalExitRoot:      atomic.Value{},
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

func (s *L1Syncer) RunQueryBlocks(lastCheckedBlock uint64, syncFromBtc bool) {
	//if already started, don't start another thread
	if s.isSyncStarted.Load() {
		return
	}

	s.isSyncStarted.Store(true)

	// set it to true to catch the first cycle run case where the check can pass before the latest block is checked
	s.isDownloading.Store(true)
	s.lastCheckedL1Block.Store(lastCheckedBlock)

	s.wgRunLoopDone.Add(1)
	s.flagStop.Store(false)

	//start a thread to cheack for new l1 block in interval
	go func() {
		defer s.isSyncStarted.Store(false)
		defer s.wgRunLoopDone.Done()

		log.Info("Starting L1 syncer thread", "lastChecked", lastCheckedBlock, "syncFromBtc", syncFromBtc)
		defer log.Info("Stopping L1 syncer thread")

		for {
			if s.flagStop.Load() {
				return
			}

			var latestL1Block uint64
			var err error
			if syncFromBtc {
				latestL1Block, err = s.getLatestBtcL1Block()
			} else {
				latestL1Block, err = s.getLatestL1Block()
			}
			log.Info("Latest block", "block", latestL1Block, "syncFromBtc", syncFromBtc)
			if err != nil {
				log.Error("Error getting latest L1 block", "err", err)
			} else {
				log.Info("Checking for update", "latestL1Block", latestL1Block, "lastCheckedL1Block", s.lastCheckedL1Block.Load())
				if latestL1Block > s.lastCheckedL1Block.Load() {
					s.isDownloading.Store(true)
					if err := s.queryBlocks(syncFromBtc); err != nil {
						log.Error("Error querying blocks", "err", err)
					} else {
						s.lastCheckedL1Block.Store(latestL1Block)
					}
				}
			}

			s.isDownloading.Store(false)
			time.Sleep(time.Duration(s.queryDelay) * time.Millisecond)
		}
	}()
}

func (s *L1Syncer) GetHeader(number uint64, syncFromBtc bool) (*ethTypes.Header, error) {
	if syncFromBtc {
		return s.getBtcHeader(number)
	}
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

func (s *L1Syncer) L1QueryHeaders(logs []ethTypes.Log, syncFromBtc bool) (map[uint64]*ethTypes.Header, error) {
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

			var header *ethTypes.Header
			var err error
			if syncFromBtc {
				header, err = s.getBtcHeader(l.BlockNumber)
			} else {
				header, err = em.HeaderByNumber(ctx, new(big.Int).SetUint64(l.BlockNumber))
			}

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

func (s *L1Syncer) getBtcHeader(number uint64) (*ethTypes.Header, error) {
	btcHeader, err := s.btcMan.GetBlockHeader(number)
	if err != nil {
		return nil, err
	}

	// TODO: can we pass the btcHash directly?
	hash := btcHeader.BlockHash()
	btcHash := common.CastToHash(hash[:])
	header := ethTypes.Header{
		ParentHash: common.Hash(btcHeader.PrevBlock),
		Number:     new(big.Int).SetUint64(number),
		Time:       uint64(btcHeader.Timestamp.Unix()),
		BtcHash:    &btcHash,
		Root:       s.stateRootByBlockNumber[number],
	}
	return &header, nil
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

func (s *L1Syncer) getLatestBtcL1Block() (uint64, error) {
	latest, err := s.btcMan.GetBlockchainHeight()
	if err != nil {
		return 0, err
	}

	return uint64(latest), err
}

func (s *L1Syncer) queryBlocks(syncFromBtc bool) error {
	// Fixed receiving duplicate log events.
	// lastCheckedL1Block means that it has already been checked in the previous cycle.
	// It should not be checked again in the new cycle, so +1 is added here.
	startBlock := s.lastCheckedL1Block.Load() + 1
	log.Debug("GetHighestSequence", "startBlock", startBlock)

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

	wg := sync.WaitGroup{}
	stop := make(chan bool)
	stopBTC := make(chan bool)

	jobs := make(chan fetchJob, len(fetches))

	results := make(chan jobResult, len(fetches))
	defer close(results)

	wg.Add(batchWorkers)
	for i := 0; i < batchWorkers; i++ {
		go s.getSequencedLogs(jobs, results, stop, &wg)
	}

	if syncFromBtc {
		wg.Add(1)
		go s.getSequencedLogsBTC(int32(startBlock), stopBTC, &wg)
	}

	for _, fetch := range fetches {
		jobs <- fetch
	}
	close(jobs)

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	var err error
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
	close(stopBTC)
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
			if !s.hasSentInitLogs.Load() {
				addNewRollupLog := s.generateAddNewRollupTopicLog()
				filteredLogs = append(filteredLogs, addNewRollupLog)

				createNewRollupLog := s.generateCreateNewRollupTopicLog()
				filteredLogs = append(filteredLogs, createNewRollupLog)

				initialSequenceBatchesLog := s.generateInitialSequenceBatchesTopicLog()
				filteredLogs = append(filteredLogs, initialSequenceBatchesLog)

				s.hasSentInitLogs.Store(true)
			}
			for _, l := range logs {
				topicType := l.Topics[0]
				if topicType != contracts.SequencedBatchTopicEtrog &&
					topicType != contracts.VerificationTopicEtrog &&
					topicType != contracts.VerificationValidiumTopicEtrog &&
					topicType != contracts.UpdateRollupTopic &&
					topicType != contracts.AddNewRollupTypeTopic &&
					topicType != contracts.CreateNewRollupTopic &&
					topicType != contracts.UpdateL1InfoTreeTopic &&
					topicType != contracts.InitialSequenceBatchesTopic {

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

func (s *L1Syncer) getInscriptions(startBlock int32) (logs []ethTypes.Log, error error) {

	tnxs, err := s.btcMan.GetHistory(int(startBlock), false)
	if err != nil {
		return nil, err
	}

	for _, tnx := range tnxs {
		decoded, err := s.btcMan.DecodeInscription(tnx.TxHash)
		if err != nil || len(decoded) == 0 {
			continue
		}

		if len(decoded) == 1889 { // 944 bytes + starting 0
			// Verify message
			// [0:16] firstBatchNum
			// [16:32] finalBatchNum
			// [32:96] newLocalExitRoot
			// [96:160] oldStateRoot
			// [160:224] newStateRoot
			// [224:288] oldAccumulatedInputHash
			// [288:352] newAccumulatedInputHash
			// [352:] proof
			inscription := decoded[1:]

			firstBatchNum := new(big.Int).SetBytes(common.FromHex(inscription[0:16])).Uint64()
			// firstBatchNumHash := common.BigToHash(new(big.Int).SetInt64(int64(firstBatchNum)))

			finalBatchNum := new(big.Int).SetBytes(common.FromHex(inscription[16:32])).Uint64()
			finalBatchNumHash := common.BigToHash(new(big.Int).SetInt64(int64(finalBatchNum)))

			newLocalExitRoot := common.HexToHash(inscription[32:96])
			oldStateRoot := common.HexToHash(inscription[96:160])
			newStateRoot := common.HexToHash(inscription[160:224])
			oldAccumulatedInputHash := common.HexToHash(inscription[224:288])
			newAccumulatedInputHash := common.HexToHash(inscription[288:352])
			proof := inscription[352:]

			log.Info("Got verify inscription",
				"firstBatchNum", firstBatchNum,
				"finalBatchNum", finalBatchNum,
				"newLocalExitRoot", newLocalExitRoot,
				"oldStateRoot", oldStateRoot,
				"newStateRoot", newStateRoot,
				"oldAccumulatedInputHash", oldAccumulatedInputHash,
				"newAccumulatedInputHash", newAccumulatedInputHash,
				"proof", proof)

			s.stateRootByBlockNumber[uint64(tnx.Height)] = newStateRoot
			// TODO: verify proof here using the verifier

			rollupID := common.BigToHash(new(big.Int).SetInt64(int64(1))) // TODO: change; Default value in kurtosis
			verificationTopicLog := ethTypes.Log{
				Topics: []common.Hash{
					contracts.VerificationTopicEtrog,
					rollupID,
				},
				Data:        append(finalBatchNumHash.Bytes(), newStateRoot.Bytes()...),
				BlockNumber: uint64(tnx.Height),
				TxHash:      common.HexToHash(tnx.TxHash),
			}

			lastExitRoot := s.lastLocalExitRoot.Load()
			if lastExitRoot == nil || lastExitRoot.(common.Hash) != newLocalExitRoot {
				s.lastLocalExitRoot.Store(newLocalExitRoot)
				l1UpdateInfoTreeLog := ethTypes.Log{
					Topics: []common.Hash{
						contracts.UpdateL1InfoTreeTopic,
						common.HexToHash("0x00"),
						calculateRollupExitRoot(newLocalExitRoot),
					},
					BlockNumber: 1,
					TxHash:      common.HexToHash("0x01"),
				}
				logs = append(logs, verificationTopicLog, l1UpdateInfoTreeLog)
			} else {
				logs = append(logs, verificationTopicLog)
			}

		} else {
			// Sequence message
			// [0:64] l1ExitRoot
			// [64:80] lastBatchNum
			inscription := decoded[1:]
			batchNum := new(big.Int).SetBytes(common.FromHex(inscription[64:80])).Uint64()
			l1InfoRoot := common.HexToHash(inscription[0:64])
			batchNumHash := common.BigToHash(new(big.Int).SetInt64(int64(batchNum)))
			sequencedBatchTopicLog := ethTypes.Log{
				Topics: []common.Hash{
					contracts.SequencedBatchTopicEtrog,
					batchNumHash,
				},
				Data:        l1InfoRoot.Bytes(),
				BlockNumber: uint64(tnx.Height),
				TxHash:      common.HexToHash(tnx.TxHash),
			}
			logs = append(logs, sequencedBatchTopicLog)
			log.Info("Got sequence inscription", "batch num", batchNum, "l1InfoRoot", l1InfoRoot)
		}
	}

	return logs, nil
}

func (s *L1Syncer) getSequencedLogsBTC(startBlock int32, stop chan bool, wg *sync.WaitGroup) {
	/* what we need to do here :
	- construct the two topic logs and pass the to the logs channel
	- skip this two two topics in the original getSequencedLogs: this is done
	- update parsing logic for this two events
	*/
	defer wg.Done()
	for {
		select {
		case <-stop:
			return
		default:
			logs, err := s.getInscriptions(startBlock)
			if err != nil {
				log.Error("Error getting inscriptions", "error", err)
			}
			if err == nil {
				s.logsChan <- logs
			}
		}
	}

}

func (s *L1Syncer) generateAddNewRollupTopicLog() ethTypes.Log {
	// TODO: move to config
	rollUpID := common.BigToHash(big.NewInt(1))
	consensusAddress := common.HexToHash("0x01")
	verifierAddress := common.HexToHash("0x01")
	forkID := common.HexToHash("0x0c")
	rollupCompatibilityID := common.HexToHash("0x00")
	genesisBytes := common.HexToHash("0xd619a27d32e3050f2265a3f58dd74c8998572812da4874aa052f0886d0dfaf47")
	descriptionSlot := common.HexToHash("0xc0")
	descriptionLength := common.HexToHash("0x0f")
	description := common.HexToHash("0x6b7572746f7369732d6465766e65740000000000000000000000000000000000")

	data := []byte{}
	data = append(data, consensusAddress.Bytes()...)
	data = append(data, verifierAddress.Bytes()...)
	data = append(data, forkID.Bytes()...)
	data = append(data, rollupCompatibilityID.Bytes()...)
	data = append(data, genesisBytes.Bytes()...)
	data = append(data, descriptionSlot.Bytes()...)
	data = append(data, descriptionLength.Bytes()...)
	data = append(data, description.Bytes()...)

	addNewRollupLog := ethTypes.Log{
		Topics: []common.Hash{
			contracts.AddNewRollupTypeTopic,
			rollUpID,
		},
		Data:        data,
		BlockNumber: 1,
		TxHash:      common.HexToHash("0xdd992e42874d7046147f526a94806d08df5e794b8f3545b481bf95f93f8478d5"),
	}
	log.Info("Sent add new rollup topic log", "log", addNewRollupLog.Topics[0], "data", hex.EncodeToString(addNewRollupLog.Data))
	return addNewRollupLog
}

func (s *L1Syncer) generateCreateNewRollupTopicLog() ethTypes.Log {
	// TODO: move to config
	rollUpID := common.BigToHash(big.NewInt(1))
	rollupAddress := common.HexToHash("0x01")
	chainID := common.HexToHash("0x2775")
	gasTokenAddress := common.HexToHash("0x0000000000000000000000000000000000000000")

	data := []byte{}
	data = append(data, rollUpID.Bytes()...)
	data = append(data, rollupAddress.Bytes()...)
	data = append(data, chainID.Bytes()...)
	data = append(data, gasTokenAddress.Bytes()...)

	createNewRollupLog := ethTypes.Log{
		Topics: []common.Hash{
			contracts.CreateNewRollupTopic,
			rollUpID,
		},
		Data:        data,
		BlockNumber: 1,
		TxHash:      common.HexToHash("0x01"),
	}
	log.Info("Sent create new rollup topic log", "log", createNewRollupLog.Topics[0], "data", hex.EncodeToString(createNewRollupLog.Data))
	return createNewRollupLog
}

func (s *L1Syncer) generateInitialSequenceBatchesTopicLog() ethTypes.Log {
	// TODO: move to config
	zeroHash := common.HexToHash("0x00")

	data := []byte{}
	initialGER := []common.Hash{common.HexToHash("0x60"), common.HexToHash("0xad3228b676f7d3cd4284a5443f17f1962b36e491b30a40b2405849e597ba5fb5")}
	for _, hash := range initialGER {
		data = append(data, hash.Bytes()...)
	}

	dataHashes := []common.Hash{
		common.HexToHash("0x0000000000000000000000005b06837a43bdc3dd9f114558daf4b26ed49842ed"),
		common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000148"),
		common.HexToHash("0xf9010380808401c9c38094d71f8f956ad979cc2988381b8a743a2fe280537d80"),
		common.HexToHash("0xb8e4f811bff70000000000000000000000000000000000000000000000000000"),
		common.HexToHash("0x0000000000010000000000000000000000000000000000000000000000000000"),
		zeroHash,
		common.HexToHash("0x000000000000000000000000000000000000a40d5f56745a118d0906a34e69ae"),
		common.HexToHash("0xc8c0db1cb8fa0000000000000000000000000000000000000000000000000000"),
		zeroHash,
		common.HexToHash("0x0000000000c00000000000000000000000000000000000000000000000000000"),
		zeroHash,
		common.HexToHash("0x0005ca1ab1e00000000000000000000000000000000000000000000000000000"),
		common.HexToHash("0x00005ca1ab1e1bff000000000000000000000000000000000000000000000000"),
	}

	for _, hash := range dataHashes {
		data = append(data, hash.Bytes()...)
	}

	initialSequenceBatchesLog := ethTypes.Log{
		Topics: []common.Hash{
			contracts.InitialSequenceBatchesTopic,
		},
		Data:        data,
		BlockNumber: 1,
		TxHash:      common.HexToHash("0x01"),
	}
	log.Info("Sent initial sequence batches topic log", "log", initialSequenceBatchesLog.Topics[0], "data", hex.EncodeToString(initialSequenceBatchesLog.Data))
	return initialSequenceBatchesLog
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

func calculateRollupExitRoot(currentRoot common.Hash) common.Hash {
	currentZeroHashHeight := [32]byte{}
	remainingLevels := 32

	for i := 0; i < remainingLevels; i++ {
		hasher := sha3.NewLegacyKeccak256()
		hasher.Write(currentRoot[:])
		hasher.Write(currentZeroHashHeight[:])
		copy(currentRoot[:], hasher.Sum(nil))

		hasher.Reset()
		hasher.Write(currentZeroHashHeight[:])
		hasher.Write(currentZeroHashHeight[:])
		copy(currentZeroHashHeight[:], hasher.Sum(nil))
	}

	return common.BytesToHash(currentRoot[:])
}
