package framework

import (
	"context"
	"net/http"

	"github.com/goccy/go-json"
	"github.com/pkg/errors"
)

// Respond convert a Go value to JSON and sends it to the client.
func Respond(ctx context.Context, w http.ResponseWriter, data any, statusCode int) error {
	// set the status code within the context's request state. Gracefully shutdown if
	// the request state doesn't exist in the context
	v, ok := ctx.Value(KeyRequestState).(*RequestState)
	if !ok {
		return NewShutdownError("Request state missing from context")
	}

	v.StatusCode = statusCode

	// if there's no payload to marshal, set the status code of the response and return
	if statusCode == http.StatusNoContent {
		w.WriteHeader(statusCode)
		return nil
	}

	// convert response payload to json
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	// send response payload to client
	_, err = w.Write(jsonData)
	return err
}

// TODO: add documentation
func RespondError(ctx context.Context, w http.ResponseWriter, err error) error {
	// if the cause of the error provided is a `SafeError`, construct an ErrorResponse
	// using the contents of SafeError and send it back to the client
	var webErr *SafeError
	if ok := errors.As(errors.Cause(err), &webErr); ok {
		er := ErrorResponse{
			Error:  webErr.Err.Error(),
			Fields: webErr.Fields,
		}

		if err := Respond(ctx, w, er, webErr.StatusCode); err != nil {
			return err
		}

		return nil
	}

	// if the error isn't a `SafeError`, it's not safe to send back the error
	// message as is because it may contain sensitive data. Send back a generic
	// 500.
	er := ErrorResponse{
		Error: http.StatusText(http.StatusInternalServerError),
	}

	if err := Respond(ctx, w, er, http.StatusInternalServerError); err != nil {
		return err
	}

	return nil
}
