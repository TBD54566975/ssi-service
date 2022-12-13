package operation

import (
	"fmt"
	"strings"

	sdkutil "github.com/TBD54566975/ssi-sdk/util"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	opstorage "github.com/tbd54566975/ssi-service/pkg/service/operation/storage"
	"github.com/tbd54566975/ssi-service/pkg/service/operation/submission"
	"github.com/tbd54566975/ssi-service/pkg/service/presentation/model"
	prestorage "github.com/tbd54566975/ssi-service/pkg/service/presentation/storage"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

type Service struct {
	storage opstorage.Storage
}

func (s Service) Type() framework.Type {
	return framework.Operation
}

func (s Service) Status() framework.Status {
	ae := sdkutil.NewAppendError()
	if s.storage == nil {
		ae.AppendString("no storage configured")
	}
	if !ae.IsEmpty() {
		return framework.Status{
			Status:  framework.StatusNotReady,
			Message: fmt.Sprintf("operation service is not ready: %s", ae.Error().Error()),
		}
	}
	return framework.Status{Status: framework.StatusReady}
}

func (s Service) GetOperations(request GetOperationsRequest) (*GetOperationsResponse, error) {
	if err := request.Validate(); err != nil {
		return nil, errors.Wrap(err, "invalid request")
	}

	ops, err := s.storage.GetOperations(request.Parent, request.Filter)
	if err != nil {
		return nil, errors.Wrap(err, "fetching ops from storage")
	}

	resp := &GetOperationsResponse{
		Operations: make([]Operation, len(ops)),
	}
	for i, op := range ops {
		op := op
		newOp, err := serviceModel(op)
		if err != nil {
			logrus.WithError(err).WithField("operation_id", op.ID).Error("converting to storage operations to model")
			continue
		}
		resp.Operations[i] = newOp
	}
	return resp, nil
}

type ServiceModelFunc func(any) any

func serviceModel(op opstorage.StoredOperation) (Operation, error) {
	newOp := Operation{
		ID:   op.ID,
		Done: op.Done,
		Result: Result{
			Error: op.Error,
		},
	}

	if len(op.Response) > 0 {
		switch {
		case strings.HasPrefix(op.ID, submission.ParentResource):
			var s prestorage.StoredSubmission
			if err := json.Unmarshal(op.Response, &s); err != nil {
				return Operation{}, err
			}
			newOp.Result.Response = model.ServiceModel(&s)
		default:
			return newOp, errors.New("unknown response type")
		}
	}

	return newOp, nil
}

func (s Service) GetOperation(request GetOperationRequest) (Operation, error) {
	if err := request.Validate(); err != nil {
		return Operation{}, errors.Wrap(err, "invalid request")
	}

	storedOp, err := s.storage.GetOperation(request.ID)
	if err != nil {
		return Operation{}, errors.Wrap(err, "fetching from storage")
	}
	return serviceModel(storedOp)
}

func (s Service) CancelOperation(request CancelOperationRequest) (Operation, error) {
	if err := request.Validate(); err != nil {
		return Operation{}, errors.Wrap(err, "invalid request")
	}

	storedOp, err := s.storage.CancelOperation(request.ID)
	if err != nil {
		return Operation{}, errors.Wrap(err, "marking as done")
	}
	return serviceModel(storedOp)
}

func NewOperationService(s storage.ServiceStorage) (*Service, error) {
	opStorage, err := NewOperationStorage(s)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "creating operation storage")
	}
	service := &Service{storage: opStorage}
	if !service.Status().IsReady() {
		return nil, errors.New(service.Status().Message)
	}
	return service, nil
}
