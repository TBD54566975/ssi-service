package authorizationserver

import (
	"context"
	"log"
	"net/http"
)

func introspectionEndpoint(ctx context.Context, rw http.ResponseWriter, req *http.Request) error {
	mySessionData := newSession("")
	ir, err := oauth2.NewIntrospectionRequest(ctx, req, mySessionData)
	if err != nil {
		log.Printf("Error occurred in NewIntrospectionRequest: %+v", err)
		oauth2.WriteIntrospectionError(ctx, rw, err)
		return nil
	}

	oauth2.WriteIntrospectionResponse(ctx, rw, ir)
	return nil
}
