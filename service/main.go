package main

import (
	"context"
	"expvar"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/tbd54566975/vc-service/service/handlers"

	"github.com/ardanlabs/conf"
	"github.com/pkg/errors"
)

// set this to the name of the service
const SVC_NAME = "VC-SERVICE"
const LOG_PREFIX = SVC_NAME + ": "

func main() {
	log := log.New(os.Stdout, LOG_PREFIX, log.LstdFlags|log.Lmicroseconds|log.Lshortfile)

	log.Println("Starting up")

	if err := run(log); err != nil {
		log.Println("main: error:", err)
		os.Exit(1)
	}
}

// startup and shutdown logic
func run(log *log.Logger) error {
	var cfg struct {
		conf.Version
		Web struct {
			APIHost         string        `conf:"default:0.0.0.0:3000"`
			DebugHost       string        `conf:"default:0.0.0.0:4000"`
			ReadTimeout     time.Duration `conf:"default:5s"`
			WriteTimeout    time.Duration `conf:"default:5s"`
			ShutdownTimeout time.Duration `conf:"default:5s"`
		}
	}

	cfg.Version.SVN = "2022.03.15"
	cfg.Version.Desc = "TODO: include service description"

	if err := conf.Parse(os.Args[1:], SVC_NAME, &cfg); err != nil {
		switch err {
		case conf.ErrHelpWanted:
			usage, err := conf.Usage(SVC_NAME, &cfg)
			if err != nil {
				return errors.Wrap(err, "parsing config")
			}
			fmt.Println(usage)

			return nil

		case conf.ErrVersionWanted:
			version, err := conf.VersionString(SVC_NAME, &cfg)
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

	api := http.Server{
		Addr:         cfg.Web.APIHost,
		Handler:      handlers.API(cfg.Version.SVN, shutdown, log),
		ReadTimeout:  cfg.Web.ReadTimeout,
		WriteTimeout: cfg.Web.WriteTimeout,
	}

	serverErrors := make(chan error, 1)

	go func() {
		log.Printf("main: API server started and listening on -> %s", api.Addr)

		serverErrors <- api.ListenAndServe()
	}()

	select {
	case err := <-serverErrors:
		return errors.Wrap(err, "server error")
	case sig := <-shutdown:
		log.Printf("main: Shutdown signal received -> %v", sig)

		ctx, cancel := context.WithTimeout(context.Background(), cfg.Web.ShutdownTimeout)
		defer cancel()

		if err := api.Shutdown(ctx); err != nil {
			api.Close()
			return errors.Wrap(err, "failed to stop server gracefully")
		}
	}

	return nil
}
