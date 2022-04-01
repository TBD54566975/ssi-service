package server

import (
	"context"
	"fmt"
	"github.com/tbd54566975/vc-service/pkg/server/framework"
	"github.com/tbd54566975/vc-service/pkg/service"
	"log"
	"net/http"
)

func readinessService(getter serviceGetter, log *log.Logger) readinessServiceHTTP {
	return readinessServiceHTTP{
		getter: getter,
		log:    log,
	}
}

type readinessServiceHTTP struct {
	getter serviceGetter
	log    *log.Logger
}

type readinessResponse struct {
	Status          service.Status                  `json:"status"`
	ServiceStatuses map[service.Type]service.Status `json:"serviceStatuses"`
}

// ready runs a number of application specific checks to see if all the
// relied upon service are healthy. Should return a 500 if not ready.
func (r readinessServiceHTTP) ready(ctx context.Context, w http.ResponseWriter, _ *http.Request) error {
	services := r.getter.getServices()
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
			Message: fmt.Sprintf("out of [%d] service, [%d] are ready", numServices, readyServices),
		}
	} else {
		status = service.Status{
			Status:  service.StatusReady,
			Message: "all service ready",
		}
	}
	response := readinessResponse{
		Status:          status,
		ServiceStatuses: statuses,
	}

	return framework.Respond(ctx, w, response, http.StatusOK)
}

// serviceGetter is a dependency of this readiness handler to know which service are available in the server
type serviceGetter interface {
	getServices() []service.Service
}

type servicesToGet struct {
	services []service.Service
}

func (s servicesToGet) getServices() []service.Service {
	return s.services
}
