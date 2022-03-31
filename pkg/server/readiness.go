package server

import (
	"context"
	"fmt"
	"github.com/tbd54566975/vc-service/pkg/server/framework"
	"github.com/tbd54566975/vc-service/pkg/service"
	"log"
	"net/http"
)

// ServiceGetter is a dependency of this readiness handler to know which services are available in the server
type ServiceGetter interface {
	GetServices() []service.Service
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
	Status          service.Status                  `json:"status"`
	ServiceStatuses map[service.Type]service.Status `json:"serviceStatuses"`
}

// Statuses runs a number of application specific checks to see if all the
// relied upon services are healthy. Should return a 500 if not ready.
func (r ReadinessServiceHTTP) Statuses(ctx context.Context, w http.ResponseWriter, _ *http.Request) error {
	services := r.getter.GetServices()
	numServices := len(services)
	readyServices := 0
	statuses := make(map[service.Type]service.Status)
	for _, s := range services {
		status := s.Status()
		statuses[s.Type()] = status
		if status.Status == service.StatusReady {
			readyServices++
		}
	}

	var status service.Status
	if readyServices < numServices {
		status = service.Status{
			Status:  service.StatusNotReady,
			Message: fmt.Sprintf("out of [%d] services, [%d] are ready", numServices, readyServices),
		}
	} else {
		status = service.Status{
			Status:  service.StatusReady,
			Message: "all services ready",
		}
	}
	response := ReadinessResponse{
		Status:          status,
		ServiceStatuses: statuses,
	}

	return framework.Respond(ctx, w, response, http.StatusOK)
}
