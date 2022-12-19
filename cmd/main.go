package main

import (
	"context"
	"expvar"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/TBD54566975/ssi-sdk/schema"
	"github.com/ardanlabs/conf"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"

	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/pkg/server"

	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.10.0"
)

const (
	LogPrefix = config.ServiceName + ": "
)

func init() {
	// Log as JSON instead of the default ASCII formatter.
	logrus.SetFormatter(&logrus.JSONFormatter{})

	// Output to stdout instead of the default stderr
	// Can be any io.Writer, see below for File example
	logrus.SetOutput(os.Stdout)
}

// @title          SSI Service API
// @version        0.1
// @description    https://github.com/TBD54566975/ssi-service
// @contact.name   TBD
// @contact.url    https://github.com/TBD54566975/ssi-service/issues
// @contact.email  tbd-developer@squareup.com
// @license.name   Apache 2.0
// @license.url    http://www.apache.org/licenses/LICENSE-2.0.html
// @host           localhost:8080
func main() {
	logrus.Info("Starting up...")

	if err := run(); err != nil {
		logrus.Fatalf("main: error: %s", err.Error())
	}
}

// startup and shutdown logic
func run() error {
	cfg, err := config.LoadConfig(os.Getenv("SSI_HOME"))
	if err != nil {
		logrus.Fatalf("could not instantiate config: %s", err.Error())
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
	// set log config from config file
	if cfg.Server.LogLocation != "" {
		logFilePath, err := createLogFile(cfg.Server.LogLocation)
		if err != nil {
			return err
		}
		file, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err == nil {
			logrus.SetOutput(file)
		} else {
			logrus.WithError(err).Error("Failed to log to file, using default stdout")
		}
		defer file.Close()
	}

	// set up schema caching based on config
	if cfg.Server.EnableSchemaCaching {
		localSchemas, err := schema.GetAllLocalSchemas()
		if err != nil {
			logrus.WithError(err).Error("could not load local schemas")
		} else {
			cl, err := schema.NewCachingLoader(localSchemas)
			if err != nil {
				logrus.WithError(err).Error("could not create caching loader")
			}
			cl.EnableHTTPCache()
		}
	}

	expvar.NewString("build").Set(cfg.Svn)

	logrus.Infof("main: Started : Service initializing : version %q", cfg.Svn)
	defer logrus.Info("main: Completed")

	out, err := conf.String(cfg)
	if err != nil {
		return errors.Wrap(err, "serializing config")
	}

	logrus.Infof("main: Config: \n%v\n", out)

	// create a channel of buffer size 1 to handle shutdown.
	// buffer's size is 1 in order to ignore any additional ctrl+c
	// spamming.
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	ssiServer, err := server.NewSSIServer(shutdown, *cfg)
	if err != nil {
		logrus.Fatalf("could not start http services: %s", err.Error())
	}
	api := http.Server{
		Addr:         cfg.Server.APIHost,
		Handler:      ssiServer,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	serverErrors := make(chan error, 1)

	// Create a new tracer provider with a batch span processor and the given exporter.
	tp, err := newTracerProvider(*cfg)
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
		if err = tp.Shutdown(ctx); err != nil {
			logrus.Errorf("main: failed to shutdown tracer: %s", err)
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

// newTracerProvider returns an OpenTelemetry TracerProvider configured to use
// the Jaeger exporter that will send spans to the provided url. The returned
// TracerProvider will also use a Resource configured with all the information
// about the application.
func newTracerProvider(cfg config.SSIServiceConfig) (*sdktrace.TracerProvider, error) {
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
			semconv.ServiceVersionKey.String(cfg.Svn),
		)),
	)
	return tp, nil
}

func createLogFile(location string) (string, error) {
	if _, err := os.Stat(location); os.IsNotExist(err) {
		if err = os.MkdirAll(location, 0766); err != nil {
			return "", err
		}
	}
	return location + "/" + config.ServiceName + "-" + time.Now().Format(time.RFC3339) + ".log", nil
}
