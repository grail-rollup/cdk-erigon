package verifier

import (
	"math/big"
	"os"
	"os/exec"

	"github.com/ledgerwatch/log/v3"
)

const (
	verifierKeyPath    = "/usr/local/bin/verifier-key-fork12.json"
	verifierBinPath    = "/usr/local/bin/verifier"
	verifierModuleName = "verifier"
)

type Verifier struct {
}

type Verifierer interface {
	Verify(proof string, publicInputs PublicInputer) bool
}

func NewVerifier() Verifierer {
	return &Verifier{}
}

func (v *Verifier) Verify(proof string, publicInputs PublicInputer) bool {

	pubs, err := publicInputs.generatePubInput()
	if err != nil {
		log.Error(verifierModuleName, "Error generating public input: %v", err)
		return false
	}

	if err := v.runVerify(proof, pubs); err != nil {
		log.Error(verifierModuleName, "Verifier execution failed: %v", err)
		return false
	}

	log.Info(verifierModuleName, "Verifier execution successful", nil)
	return true
}

func (v *Verifier) runVerify(proof string, pubs *big.Int) error {
	cmd := exec.Command(verifierBinPath, "--proof-fmt", "hex-string", verifierKeyPath, proof, pubs.String())
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}
