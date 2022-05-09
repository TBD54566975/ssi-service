package main

import (
	"context"
	"expvar"
	"github.com/ardanlabs/conf"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/pkg/server"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
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

func main() {
	logrus.Info("Starting up...")

	if err := run(); err != nil {
		logrus.Fatalf("main: error: %s", err.Error())
	}
}

// startup and shutdown logic
func run() error {
	cfg, err := config.LoadConfig(config.DefaultConfigPath)
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
		file, err := os.OpenFile(createLogFile(cfg.Server.LogLocation), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err == nil {
			logrus.SetOutput(file)
		} else {
			logrus.Info("Failed to log to file, using default stdout")
		}
		defer file.Close()
	}

	expvar.NewString("build").Set(cfg.Version.SVN)

	logrus.Infof("main: Started : Service initializing : version %q", cfg.Version.SVN)
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

	go func() {
		logrus.Infof("main: server started and listening on -> %s", api.Addr)

		serverErrors <- api.ListenAndServe()
	}()

	select {
	case err := <-serverErrors:
		return errors.Wrap(err, "server error")
	case sig := <-shutdown:
		logrus.Infof("main: shutdown signal received -> %v", sig)

		ctx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
		defer cancel()

		if err := api.Shutdown(ctx); err != nil {
			api.Close()
			return errors.Wrap(err, "failed to stop server gracefully")
		}
	}

	return nil
}

func createLogFile(location string) string {
	return location + "/" + config.ServiceName + "-" + time.Now().Format(time.RFC3339) + ".log"
}
