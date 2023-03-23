package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/ardanlabs/conf"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/pkg/authorizationserver"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.18.0"
)

func main() {
	logrus.Info("Starting up...")

	if err := run(); err != nil {
		logrus.Fatalf("main: error: %s", err.Error())
	}
}

func run() error {
	var cfg authorizationserver.AuthConfig
	if err := conf.Parse(os.Args[1:], "AUTHSERVER", &cfg); err != nil {
		panic(err)
	}

	if cfg.Server.LogLevel != "" {
		level, err := logrus.ParseLevel(cfg.Server.LogLevel)
		if err != nil {
			logrus.WithError(err).Errorf("could not parse log level<%s>, setting to info", cfg.Server.LogLevel)
			logrus.SetLevel(logrus.InfoLevel)
		} else {
			logrus.SetLevel(level)
		}
	}

	// create a channel of buffer size 1 to handle shutdown.
	// buffer's size is 1 in order to ignore any additional ctrl+c
	// spamming.
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	var err error
	srv := authorizationserver.NewServer(shutdown, &cfg)
	api := http.Server{
		Addr:         cfg.Server.APIHost,
		Handler:      srv,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	serverErrors := make(chan error, 1)

	// Create a new tracer provider with a batch span processor and the given exporter.
	tp, err := newTracerProvider(cfg)
	if err != nil {
		logrus.Errorf("failed to initialize tracer provider: %s", err)
	} else {
		otel.SetTracerProvider(tp)
	}

	go func() {
		logrus.Infof("main: server started and listening on -> %s", api.Addr)
		serverErrors <- api.ListenAndServe()
	}()

	select {
	case err = <-serverErrors:
		return errors.Wrap(err, "server error")
	case sig := <-shutdown:
		logrus.Infof("main: shutdown signal received -> %v", sig)

		ctx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
		defer cancel()

		// Handle shutdown properly so nothing leaks.
		if tp != nil {
			if err = tp.Shutdown(ctx); err != nil {
				logrus.Errorf("main: failed to shutdown tracer: %s", err)
			}
		}

		if err = api.Shutdown(ctx); err != nil {
			if err = api.Close(); err != nil {
				return err
			}
			return errors.Wrap(err, "main: failed to stop server gracefully")
		}
	}

	return nil
}

func newTracerProvider(cfg authorizationserver.AuthConfig) (*sdktrace.TracerProvider, error) {
	// Create the Jaeger exporter
	jagerHost := cfg.Server.JagerHost
	if jagerHost == "" {
		return nil, errors.New("no jager host provided")
	}
	exp, err := jaeger.New(jaeger.WithCollectorEndpoint(jaeger.WithEndpoint(jagerHost)))
	if err != nil {
		return nil, err
	}
	tp := sdktrace.NewTracerProvider(
		// Always be sure to batch in production.
		sdktrace.WithBatcher(exp),
		// Record information about this application in a Resource.
		sdktrace.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String(config.ServiceName),
			semconv.ServiceVersionKey.String(cfg.Version.SVN),
		)),
	)
	return tp, nil
}
