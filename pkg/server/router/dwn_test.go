package router

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/pkg/service/dwn"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

func TestDWNRouter(t *testing.T) {
	// remove the db file after the test
	t.Cleanup(func() {
		_ = os.Remove(storage.DBFile)
	})

	t.Run("Nil Service", func(tt *testing.T) {
		dwnRouter, err := NewDWNRouter(nil)
		assert.Error(tt, err)
		assert.Empty(tt, dwnRouter)
		assert.Contains(tt, err.Error(), "service cannot be nil")
	})

	t.Run("Bad Service", func(tt *testing.T) {
		dwnRouter, err := NewDWNRouter(&testService{})
		assert.Error(tt, err)
		assert.Empty(tt, dwnRouter)
		assert.Contains(tt, err.Error(), "could not create dwn router with service type: test")
	})

	t.Run("DWN Service Test", func(tt *testing.T) {
		bolt, err := storage.NewBoltDB()
		assert.NoError(tt, err)
		assert.NotEmpty(tt, bolt)

		serviceConfig := config.DWNServiceConfig{BaseServiceConfig: &config.BaseServiceConfig{Name: "dwn"}}
		keyStore := testKeyStoreService(t, bolt)
		dwnService, err := dwn.NewDWNService(serviceConfig, bolt, keyStore)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, dwnService)

		// check type and status
		assert.Equal(tt, framework.DWN, dwnService.Type())
		assert.Equal(tt, framework.StatusReady, dwnService.Status().Status)
	})

}
