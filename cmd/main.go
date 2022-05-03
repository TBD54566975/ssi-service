package main

import (
	"context"
	"expvar"
	"github.com/ardanlabs/conf"
	"github.com/pkg/errors"
	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/pkg/server"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

const (
	LogPrefix = config.ServiceName + ": "
)

func main() {
	svcLog := log.New(os.Stdout, LogPrefix, log.LstdFlags|log.Lmicroseconds|log.Lshortfile)

	svcLog.Println("Starting up...")

	if err := run(svcLog); err != nil {
		svcLog.Fatalf("main: error: %s", err.Error())
	}
}

// startup and shutdown logic
func run(logger *log.Logger) error {
	cfg, err := config.LoadConfig(logger, config.DefaultConfigPath)
	if err != nil {
		logger.Fatalf("could not instantiate config: %s", err.Error())
	}

	expvar.NewString("build").Set(cfg.Version.SVN)

	logger.Printf("main: Started : Service initializing : version %q", cfg.Version.SVN)
	defer logger.Println("main: Completed")

	out, err := conf.String(&cfg)
	if err != nil {
		return errors.Wrap(err, "serializing config")
	}

	logger.Printf("main: Config: \n%v\n", out)

	// create a channel of buffer size 1 to handle shutdown.
	// buffer's size is 1 in order to ignore any additional ctrl+c
	// spamming.
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	ssiServer, err := server.NewSSIServer(shutdown, logger, *cfg)
	if err != nil {
		logger.Fatalf("could not start http services: %s", err.Error())
	}
	api := http.Server{
		Addr:         cfg.Server.APIHost,
		Handler:      ssiServer,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	serverErrors := make(chan error, 1)

	go func() {
		logger.Printf("main: server started and listening on -> %s", api.Addr)

		serverErrors <- api.ListenAndServe()
	}()

	select {
	case err := <-serverErrors:
		return errors.Wrap(err, "server error")
	case sig := <-shutdown:
		logger.Printf("main: shutdown signal received -> %v", sig)

		ctx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
		defer cancel()

		if err := api.Shutdown(ctx); err != nil {
			api.Close()
			return errors.Wrap(err, "failed to stop server gracefully")
		}
	}

	return nil
}
