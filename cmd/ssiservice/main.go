package main

import (
	"context"
	"expvar"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/TBD54566975/ssi-sdk/schema"
	"github.com/ardanlabs/conf"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"

	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/doc"
	"github.com/tbd54566975/ssi-service/pkg/server"

	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.10.0"
)

// @title          SSI Service API
// @description    https://github.com/TBD54566975/ssi-service
// @contact.name   TBD
// @contact.url    https://github.com/TBD54566975/ssi-service/issues
// @contact.email  tbd-developer@squareup.com
// @license.name   Apache 2.0
// @license.url    http://www.apache.org/licenses/LICENSE-2.0.html
func main() {
	logrus.Info("Starting up...")

	if err := run(); err != nil {
		logrus.Fatalf("main: error: %s", err.Error())
	}
}

// startup and shutdown logic
func run() error {
	configPath := config.DefaultConfigPath
	envConfigPath, present := os.LookupEnv(config.ConfigPath.String())
	if present {
		logrus.Infof("loading config from env var path: %s", envConfigPath)
		configPath = envConfigPath
	}
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		logrus.Fatalf("could not instantiate config: %s", err.Error())
	}

	// set up some additional swagger config
	doc.SwaggerInfo.Version = cfg.SVN
	doc.SwaggerInfo.Description = cfg.Desc
	doc.SwaggerInfo.Host = cfg.Server.APIHost
	doc.SwaggerInfo.Schemes = []string{"http"}

	// set up logger
	if logFile := configureLogger(cfg.Server.LogLevel, cfg.Server.LogLocation); logFile != nil {
		defer func(logFile *os.File) {
			if err = logFile.Close(); err != nil {
				logrus.WithError(err).Error("failed to close log file")
			}
		}(logFile)
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

	expvar.NewString("build").Set(cfg.Version.SVN)

	logrus.Infof("main: Started : Service initializing : env [%s] : version %q", cfg.Server.Environment, cfg.Version.SVN)
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

	serverErrors := make(chan error, 1)

	// Create a new tracer provider with a batch span processor and the given exporter.
	tp, err := newTracerProvider(*cfg)
	if err != nil {
		logrus.Errorf("failed to initialize tracer provider: %s", err)
	} else {
		otel.SetTracerProvider(tp)
	}

	go func() {
		logrus.Infof("main: server started and listening on -> %s", ssiServer.Server.Addr)
		serverErrors <- ssiServer.ListenAndServe()
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

		if err = ssiServer.Shutdown(ctx); err != nil {
			if err = ssiServer.Close(); err != nil {
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
			semconv.ServiceVersionKey.String(cfg.Version.SVN),
		)),
	)
	return tp, nil
}

// configureLogger configures the logger to logs to the given location and returns a file pointer to a logs
// file that should be closed upon server shutdown
func configureLogger(level, location string) *os.File {
	if level != "" {
		logLevel, err := logrus.ParseLevel(level)
		if err != nil {
			logrus.WithError(err).Errorf("could not parse log level<%s>, setting to info", level)
			logrus.SetLevel(logrus.InfoLevel)
		} else {
			logrus.SetLevel(logLevel)
		}
	}

	logrus.SetFormatter(&logrus.JSONFormatter{
		DisableTimestamp: false,
		PrettyPrint:      true,
	})
	logrus.SetReportCaller(true)
	logLevel, err := logrus.ParseLevel(level)
	if err != nil {
		logrus.WithError(err).Errorf("could not parse logs level<%s>, setting to info", level)
		logrus.SetLevel(logrus.InfoLevel)
	} else {
		logrus.SetLevel(logLevel)
	}

	logrus.SetOutput(os.Stdout)

	// set logs config from config file
	now := time.Now()
	if location != "" {
		logFile := location + "/" + config.ServiceName + "-" + now.Format(time.DateOnly) + "-" + strconv.FormatInt(now.Unix(), 10) + ".log"
		file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			logrus.WithError(err).Warn("failed to create logs file, using default stdout")
		} else {
			logrus.SetOutput(file)
		}
		return file
	}
	return nil
}
