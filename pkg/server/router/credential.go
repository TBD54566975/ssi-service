package router

import (
	"context"
	"fmt"
	"github.com/pkg/errors"
	"github.com/tbd54566975/ssi-service/pkg/service/credential"
	svcframework "github.com/tbd54566975/ssi-service/pkg/service/framework"
	"net/http"
)

type CredentialRouter struct {
	service *credential.Service
}

func NewCredentialRouter(s svcframework.Service) (*CredentialRouter, error) {
	if s == nil {
		return nil, errors.New("service cannot be nil")
	}
	credService, ok := s.(*credential.Service)
	if !ok {
		return nil, fmt.Errorf("could not create credential router with service type: %s", s.Type())
	}
	return &CredentialRouter{
		service: credService,
	}, nil
}

func (cr CredentialRouter) CreateCredential(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	return nil
}

func (cr CredentialRouter) GetCredential(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	return nil
}

func (cr CredentialRouter) GetCredentialByIssuer(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	return nil
}

func (cr CredentialRouter) GetCredentialBySubject(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	return nil
}

func (cr CredentialRouter) GetCredentialBySchema(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	return nil
}

func (cr CredentialRouter) DeleteCredential(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	return nil
}
