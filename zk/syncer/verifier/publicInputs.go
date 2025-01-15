package verifier

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
)

const rFieldNumericStr = "21888242871839275222246405745257275088548364400416034343698204186575808495617"

// publicInputs partially replicates PolygonRollupManager.sol
type publicInputs struct {
	rollupChainID    uint64
	rollupForkID     uint64
	initNumBatch     uint64
	finalNewBatch    uint64
	newLocalExitRoot string
	oldStateRoot     string
	newStateRoot     string
	oldAccInputHash  string
	newAccInputHash  string
	beneficiary      string
}

type PublicInputer interface {
	generatePubInput() (*big.Int, error)
}

func NewPublicInput(beneficiary string, rollupChainID uint64, rollupForkID uint64, initNumBatch uint64, finalNewBatch uint64, newLocalExitRoot string, oldStateRoot string, newStateRoot string, oldAccInputHash string, newAccInputHash string) PublicInputer {
	return &publicInputs{beneficiary: beneficiary, rollupChainID: rollupChainID, rollupForkID: rollupForkID, initNumBatch: initNumBatch, finalNewBatch: finalNewBatch, newLocalExitRoot: newLocalExitRoot, oldStateRoot: oldStateRoot, newStateRoot: newStateRoot, oldAccInputHash: oldAccInputHash, newAccInputHash: newAccInputHash}
}

func decodeHexString(s string) ([]byte, error) {
	if len(s) > 2 && (s[:2] == "0x" || s[:2] == "0X") {
		return hex.DecodeString(s[2:])
	}
	return nil, fmt.Errorf("string should start with '0x'")
}

func abiEncodePacked(args ...interface{}) ([]byte, error) {
	var buffer bytes.Buffer

	for _, arg := range args {
		switch v := arg.(type) {
		case []byte:
			buffer.Write(v)
		case string:
			bytes, err := decodeHexString(v)
			if err != nil {
				return nil, err
			}
			buffer.Write(bytes)
		case uint64:
			var bytes [8]byte
			binary.BigEndian.PutUint64(bytes[:], v)
			buffer.Write(bytes[:])
		default:
			return nil, fmt.Errorf("unsupported arg type: %T", arg)
		}
	}

	return buffer.Bytes(), nil
}

func (pi *publicInputs) generatePubInput() (*big.Int, error) {
	msgSender, err := decodeHexString(pi.beneficiary)
	if err != nil {
		return nil, fmt.Errorf("error converting address: %v", err)
	}

	inputData, err := abiEncodePacked(
		msgSender,
		pi.oldStateRoot,
		pi.oldAccInputHash,
		pi.initNumBatch,
		pi.rollupChainID,
		pi.rollupForkID,
		pi.newStateRoot,
		pi.newAccInputHash,
		pi.newLocalExitRoot,
		pi.finalNewBatch,
	)
	if err != nil {
		return nil, fmt.Errorf("error encoding data: %v", err)
	}

	hash := sha256.Sum256(inputData)
	hashInt := new(big.Int).SetBytes(hash[:])

	rField := new(big.Int)
	rField.SetString(rFieldNumericStr, 10)
	pubs := new(big.Int).Mod(hashInt, rField)

	return pubs, nil
}
