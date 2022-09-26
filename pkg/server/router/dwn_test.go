package router

import (
	"github.com/stretchr/testify/assert"
	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/pkg/service/dwn"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/storage"
	"os"
	"testing"
)

func TestDWNRouter(t *testing.T) {
	// remove the db file after the test
	t.Cleanup(func() {
		_ = os.Remove(storage.DBFile)
	})

	t.Run("Nil Service", func(tt *testing.T) {
		manifestRouter, err := NewDWNRouter(nil)
		assert.Error(tt, err)
		assert.Empty(tt, manifestRouter)
		assert.Contains(tt, err.Error(), "service cannot be nil")
	})

	t.Run("Bad Service", func(tt *testing.T) {
		manifestRouter, err := NewDWNRouter(&testService{})
		assert.Error(tt, err)
		assert.Empty(tt, manifestRouter)
		assert.Contains(tt, err.Error(), "could not create dwn router with service type: test")
	})

	t.Run("DWN Service Test", func(tt *testing.T) {
		bolt, err := storage.NewBoltDB()
		assert.NoError(tt, err)
		assert.NotEmpty(tt, bolt)

		serviceConfig := config.DWNServiceConfig{BaseServiceConfig: &config.BaseServiceConfig{Name: "dwn"}}
		manifestService, err := dwn.NewDWNService(serviceConfig, bolt)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, manifestService)

		// check type and status
		assert.Equal(tt, framework.DWN, manifestService.Type())
		assert.Equal(tt, framework.StatusReady, manifestService.Status().Status)
	})

}
