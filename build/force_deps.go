package build

import (
	// This is here to force `go.mod` to pick up the github.com/btcsuite/btcd/chaincfg/chainhash dependency. It is a
	// workaround to fix https://github.com/TBD54566975/ssi-service/issues/483
	_ "github.com/btcsuite/btcd/chaincfg/chainhash"
)
