package server

import (
	"context"
	"fmt"
	"github.com/tbd54566975/vc-service/pkg/server/framework"
	"github.com/tbd54566975/vc-service/pkg/services"
	"log"
	"net/http"
)

// ServiceGetter is a dependency of this readiness handler to know which services are available in the server
type ServiceGetter interface {
	GetServices() []services.Service
}

func NewReadinessService(getter ServiceGetter, log *log.Logger) ReadinessServiceHTTP {
	return ReadinessServiceHTTP{
		getter: getter,
		log:    log,
	}
}

type ReadinessServiceHTTP struct {
	getter ServiceGetter
	log    *log.Logger
}

type ReadinessResponse struct {
	Status          services.Status                   `json:"status"`
	ServiceStatuses map[services.Type]services.Status `json:"serviceStatuses"`
}

// Statuses runs a number of application specific checks to see if all the
// relied upon services are healthy. Should return a 500 if not ready.
func (r ReadinessServiceHTTP) Statuses(ctx context.Context, w http.ResponseWriter, _ *http.Request) error {
	svcs := r.getter.GetServices()
	numServices := len(svcs)
	readyServices := 0
	statuses := make(map[services.Type]services.Status)
	for _, s := range svcs {
		status := s.Status()
		statuses[s.Type()] = status
		if status.Status == services.StatusReady {
			readyServices++
		}
	}

	var status services.Status
	if readyServices < numServices {
		status = services.Status{
			Status:  services.StatusNotReady,
			Message: fmt.Sprintf("out of [%d] services, [%d] are ready", numServices, readyServices),
		}
	} else {
		status = services.Status{
			Status:  services.StatusReady,
			Message: "all services ready",
		}
	}
	response := ReadinessResponse{
		Status:          status,
		ServiceStatuses: statuses,
	}

	return framework.Respond(ctx, w, response, http.StatusOK)
}
