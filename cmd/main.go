package main

import (
	"context"
	"expvar"
	"fmt"
	"github.com/ardanlabs/conf"
	"github.com/pkg/errors"
	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/pkg/server"
	"github.com/tbd54566975/ssi-service/pkg/service"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

const (
	ServiceName = "ssi-server"
	LogPrefix   = ServiceName + ": "
)

func main() {
	svcLog := log.New(os.Stdout, LogPrefix, log.LstdFlags|log.Lmicroseconds|log.Lshortfile)

	svcLog.Println("Starting up...")

	if err := run(svcLog); err != nil {
		svcLog.Fatalf("main: error: %s", err.Error())
	}
}

// startup and shutdown logic
func run(log *log.Logger) error {
	cfg := config.SSIServiceConfig{
		Version: conf.Version{
			SVN:  "2022.03.15",
			Desc: "The Self Sovereign Identity Service",
		},
		Server: config.ServerConfig{},
	}

	if err := conf.Parse(os.Args[1:], ServiceName, &cfg); err != nil {
		switch err {
		case conf.ErrHelpWanted:
			usage, err := conf.Usage(ServiceName, &cfg)
			if err != nil {
				return errors.Wrap(err, "parsing config")
			}
			fmt.Println(usage)

			return nil

		case conf.ErrVersionWanted:
			version, err := conf.VersionString(ServiceName, &cfg)
			if err != nil {
				return errors.Wrap(err, "generating cfg version")
			}

			fmt.Println(version)
			return nil
		}

		return errors.Wrap(err, "parsing config")
	}

	expvar.NewString("build").Set(cfg.Version.SVN)

	log.Printf("main: Started : Service initializing : version %q", cfg.Version.SVN)
	defer log.Println("main: Completed")

	out, err := conf.String(&cfg)
	if err != nil {
		return errors.Wrap(err, "serializing config")
	}

	log.Printf("main: Config: \n%v\n", out)

	// create a channel of buffer size 1 to handle shutdown.
	// buffer's size is 1 in order to ignore any additional ctrl+c
	// spamming.
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	serviceConfig := service.Config{Logger: log}
	ssiServer, err := server.NewSSIServer(shutdown, serviceConfig)
	if err != nil {
		log.Fatalf("could not start http services: %s", err.Error())
	}
	api := http.Server{
		Addr:         cfg.Server.APIHost,
		Handler:      ssiServer,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	serverErrors := make(chan error, 1)

	go func() {
		log.Printf("main: server started and listening on -> %s", api.Addr)

		serverErrors <- api.ListenAndServe()
	}()

	select {
	case err := <-serverErrors:
		return errors.Wrap(err, "server error")
	case sig := <-shutdown:
		log.Printf("main: shutdown signal received -> %v", sig)

		ctx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
		defer cancel()

		if err := api.Shutdown(ctx); err != nil {
			api.Close()
			return errors.Wrap(err, "failed to stop server gracefully")
		}
	}

	return nil
}
