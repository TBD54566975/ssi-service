package authorizationserver

import (
	"context"
	"net/http"
)

func revokeEndpoint(ctx context.Context, rw http.ResponseWriter, req *http.Request) error {

	// This will accept the token revocation request and validate various parameters.
	err := oauth2.NewRevocationRequest(ctx, req)

	// All done, send the response.
	oauth2.WriteRevocationResponse(ctx, rw, err)
	return nil
}
