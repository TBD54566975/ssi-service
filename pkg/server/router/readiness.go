package router

import (
	"context"
	"fmt"
	"net/http"

	"github.com/tbd54566975/ssi-service/pkg/server/framework"
	svcframework "github.com/tbd54566975/ssi-service/pkg/service/framework"
)

func Readiness(services []svcframework.Service) framework.Handler {
	return readiness{
		getter: servicesToGet{services},
	}.ready
}

type readiness struct {
	getter serviceGetter
}

type GetReadinessResponse struct {
	Status          svcframework.Status                       `json:"status"`
	ServiceStatuses map[svcframework.Type]svcframework.Status `json:"serviceStatuses"`
}

// Readiness godoc
// @Summary      Readiness
// @Description  ready runs a number of application specific checks to see if all the
// @Description  relied upon service are healthy. Should return a 500 if not ready.
// @Tags         Readiness
// @Accept       json
// @Produce      json
// @Success      200  {string}  string  "OK"
// @Router       /readiness [get]
func (r readiness) ready(ctx context.Context, w http.ResponseWriter, _ *http.Request) error {
	services := r.getter.getServices()
	numServices := len(services)
	readyServices := 0
	statuses := make(map[svcframework.Type]svcframework.Status)
	for _, s := range services {
		status := s.Status()
		statuses[s.Type()] = status
		if status.Status == svcframework.StatusReady {
			readyServices++
		}
	}

	var status svcframework.Status
	if readyServices < numServices {
		status = svcframework.Status{
			Status:  svcframework.StatusNotReady,
			Message: fmt.Sprintf("out of [%d] service, [%d] are ready", numServices, readyServices),
		}
	} else {
		status = svcframework.Status{
			Status:  svcframework.StatusReady,
			Message: "all service ready",
		}
	}
	response := GetReadinessResponse{
		Status:          status,
		ServiceStatuses: statuses,
	}

	return framework.Respond(ctx, w, response, http.StatusOK)
}

// serviceGetter is a dependency of this readiness handler to know which service are available in the server
type serviceGetter interface {
	getServices() []svcframework.Service
}

type servicesToGet struct {
	services []svcframework.Service
}

func (s servicesToGet) getServices() []svcframework.Service {
	return s.services
}
