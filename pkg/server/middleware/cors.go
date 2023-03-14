package middleware

import (
	"context"
	"net/http"

	"github.com/rs/cors"
	"github.com/sirupsen/logrus"
	"github.com/tbd54566975/ssi-service/pkg/server/framework"
)

func Cors() framework.Middleware {
	c := cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{
			http.MethodHead,
			http.MethodGet,
			http.MethodPost,
			http.MethodPut,
			http.MethodPatch,
			http.MethodDelete,
		},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: false,
		Debug:            true,
	})
	c.Log = logrus.StandardLogger()
	return func(handler framework.Handler) framework.Handler {
		return func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
			c.HandlerFunc(w, r)
			return handler(ctx, w, r)
		}
	}
}
