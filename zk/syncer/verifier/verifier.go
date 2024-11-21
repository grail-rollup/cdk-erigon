package verifier

import (
	"math/big"
	"os"
	"os/exec"

	"github.com/ledgerwatch/log/v3"
)

const (
	VERIFIER_KEY_PATH    = "/usr/local/bin/verifier-key-fork12.json"
	VERIFIER_BIN_PATH    = "/usr/local/bin/verifier"
	VERIFIER_MODULE_NAME = "verifier"
)

type Verifier struct {
}

type Verifierer interface {
	Verify(publicInputs PublicInputer) bool
}

func NewVerifier() Verifierer {
	return &Verifier{}
}

func (v *Verifier) Verify(publicInputs PublicInputer) bool {

	pubs, err := publicInputs.generatePubInput()
	if err != nil {
		log.Error(VERIFIER_MODULE_NAME, "Error generating public input: %v", err)
		return false
	}

	proof := publicInputs.getProof()

	if err := v.runVerify(proof, pubs); err != nil {
		log.Error(VERIFIER_MODULE_NAME, "Verifier execution failed: %v", err)
		return false
	}

	log.Info(VERIFIER_MODULE_NAME, "Verifier execution successful", nil)
	return true
}

func (v *Verifier) runVerify(proof string, pubs *big.Int) error {
	cmd := exec.Command(VERIFIER_BIN_PATH, "--proof-fmt", "hex-string", VERIFIER_KEY_PATH, proof, pubs.String())
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}
