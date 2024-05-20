package stages

import (
	"context"
	"fmt"
	"time"

	"github.com/gateway-fm/cdk-erigon-lib/kv"
	"github.com/ledgerwatch/erigon/eth/ethconfig"
	"github.com/ledgerwatch/erigon/eth/stagedsync"
	"github.com/ledgerwatch/erigon/eth/stagedsync/stages"
	"github.com/ledgerwatch/erigon/zk/hermez_db"
	"github.com/ledgerwatch/erigon/zk/l1_data"
	"github.com/ledgerwatch/erigon/zk/syncer"
	zktx "github.com/ledgerwatch/erigon/zk/tx"
	"github.com/ledgerwatch/log/v3"
	"github.com/ledgerwatch/erigon/core/types"
)

type SequencerL1BlockSyncCfg struct {
	db     kv.RwDB
	zkCfg  *ethconfig.Zk
	syncer *syncer.L1Syncer
}

func StageSequencerL1BlockSyncCfg(db kv.RwDB, zkCfg *ethconfig.Zk, syncer *syncer.L1Syncer) SequencerL1BlockSyncCfg {
	return SequencerL1BlockSyncCfg{
		db:     db,
		zkCfg:  zkCfg,
		syncer: syncer,
	}
}

// SpawnSequencerL1BlockSyncStage is a special mode of operation where a flag is passed to force the sequencer
// to rebuild the batches as they were sent to the L1 in the first place. Typically, this will be used after
// the unwind tool has rolled the DB back so that the network can be recovered if a bug is found
func SpawnSequencerL1BlockSyncStage(
	s *stagedsync.StageState,
	u stagedsync.Unwinder,
	ctx context.Context,
	tx kv.RwTx,
	cfg SequencerL1BlockSyncCfg,
	firstCycle bool,
	quiet bool,
) error {
	logPrefix := s.LogPrefix()
	log.Info(fmt.Sprintf("[%s] Starting L1 block sync stage", logPrefix))
	defer log.Info(fmt.Sprintf("[%s] Finished L1 block sync stage", logPrefix))

	if cfg.zkCfg.L1SyncStartBlock == 0 {
		log.Info(fmt.Sprintf("[%s] Skipping L1 block sync stage", logPrefix))
		return nil
	}

	var err error
	freshTx := false
	if tx == nil {
		freshTx = true
		tx, err = cfg.db.BeginRw(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback()
	}

	hermezDb := hermez_db.NewHermezDb(tx)

	// perform a quick check to see if we have fully recovered from the l1 and exit the node
	highestBatch, err := stages.GetStageProgress(tx, stages.HighestSeenBatchNumber)
	if err != nil {
		return err
	}
	highestKnownBatch, err := hermezDb.GetLastL1BatchData()
	if err != nil {
		return err
	}

	// check if the highest batch from the L1 is higher than the config value if it is set
	if cfg.zkCfg.L1SyncStopBatch > 0 && highestKnownBatch > cfg.zkCfg.L1SyncStopBatch {
		log.Info("Stopping L1 sync stage based on configured stop batch", "config", cfg.zkCfg.L1SyncStopBatch, "highest-known", highestKnownBatch)
		time.Sleep(5 * time.Second)
	}

	// check if execution has caught up to the tip of the chain
	if highestBatch > 0 && highestKnownBatch == highestBatch {
		log.Info("L1 block sync recovery has completed!", "batch", highestBatch)
		time.Sleep(5 * time.Second)
	}

	l1BlockHeight, err := stages.GetStageProgress(tx, stages.L1BlockSync)
	if err != nil {
		return err
	}
	if l1BlockHeight == 0 {
		l1BlockHeight = cfg.zkCfg.L1SyncStartBlock
	}

	if !cfg.syncer.IsSyncStarted() {
		cfg.syncer.Run(l1BlockHeight)
	}

	logChan := cfg.syncer.GetLogsChan()
	progressChan := cfg.syncer.GetProgressMessageChan()
	totalBlocks := 0
	if highestKnownBatch == 0 {
		// if we don't have any batches, we need to start from the beginning, and we know batch 1 won't be
		// in the contract data, so we can start at block 1 for reporting purposes as this will always be added
		// in the first batch
		totalBlocks = 1
	}

	logTicker := time.NewTicker(10 * time.Second)
	defer logTicker.Stop()
	var latestBatch uint64

LOOP:
	for {
		select {
		case logs := <-logChan:
			for _, l := range logs {
				// for some reason some endpoints seem to not have certain transactions available to
				// them even they are perfectly valid and other RPC nodes return them fine.  So, leaning
				// on the internals of the syncer which will round-robin through available RPC nodes, we
				// can attempt a few times to get the transaction before giving up and returning an error
				var transaction types.Transaction
				attempts := 0
				for {
					transaction, _, err = cfg.syncer.GetTransaction(l.TxHash)
					if err == nil {
						break
					} else {
						log.Warn("Error getting transaction, attempting again", "hash", l.TxHash.String(), "err", err)
						attempts++
						if attempts > 50 {
							return err
						}
						time.Sleep(500 * time.Millisecond)
					}
				}

				lastBatchSequenced := l.Topics[1].Big().Uint64()
				latestBatch = lastBatchSequenced

				batches, coinbase, err := l1_data.DecodeL1BatchData(transaction.GetData())
				if err != nil {
					return err
				}

				// here we find the first batch number that was sequenced by working backwards
				// from the latest batch in the original event
				initBatch := lastBatchSequenced - uint64(len(batches)-1)

				log.Debug(fmt.Sprintf("[%s] Processing L1 sequence transaction", logPrefix),
					"hash", transaction.Hash().String(),
					"initBatch", initBatch,
					"batches", len(batches),
				)

				// iterate over the batches in reverse order to ensure that the batches are written in the correct order
				// this is important because the batches are written in reverse order
				for idx, batch := range batches {
					b := initBatch + uint64(idx)
					data := append(coinbase.Bytes(), batch...)
					if err := hermezDb.WriteL1BatchData(b, data); err != nil {
						return err
					}

					decoded, err := zktx.DecodeBatchL2Blocks(batch, cfg.zkCfg.SequencerInitialForkId)
					if err != nil {
						return err
					}
					totalBlocks += len(decoded)
					log.Debug(fmt.Sprintf("[%s] Wrote L1 batch", logPrefix), "batch", b, "blocks", len(decoded), "totalBlocks", totalBlocks)

					// check if we need to stop here based on config
					if cfg.zkCfg.L1SyncStopBatch > 0 && b == cfg.zkCfg.L1SyncStopBatch {
						log.Info("Stopping L1 sync based on stop block config")
						break LOOP
					}
				}

			}
		case msg := <-progressChan:
			log.Info(fmt.Sprintf("[%s] %s", logPrefix, msg))
		case <-logTicker.C:
			log.Info(fmt.Sprintf("[%s] Syncing L1 blocks", logPrefix), "latest-batch", latestBatch)
		default:
			if !cfg.syncer.IsDownloading() {
				break LOOP
			}
		}
	}

	lastCheckedBlock := cfg.syncer.GetLastCheckedL1Block()
	if lastCheckedBlock > l1BlockHeight {
		log.Info(fmt.Sprintf("[%s] Saving L1 block sync progress", logPrefix), "lastChecked", lastCheckedBlock)
		if err := stages.SaveStageProgress(tx, stages.L1BlockSync, lastCheckedBlock); err != nil {
			return err
		}
	}

	if freshTx {
		if err := tx.Commit(); err != nil {
			return err
		}
	}

	return nil
}

func UnwindSequencerL1BlockSyncStage(u *stagedsync.UnwindState, tx kv.RwTx, cfg SequencerL1BlockSyncCfg, ctx context.Context) (err error) {
	return nil
}

func PruneSequencerL1BlockSyncStage(s *stagedsync.PruneState, tx kv.RwTx, cfg SequencerL1BlockSyncCfg, ctx context.Context) error {
	return nil
}
