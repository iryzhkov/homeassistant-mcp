package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/iryzhkov/ha-mcp/internal/endpoint"
)

func main() {
	if os.Geteuid() == 0 {
		fmt.Fprintln(os.Stderr, "ha-mcp requires a non-root runtime UID")
		os.Exit(1)
	}
	path := flag.String("config", "", "Required JSON configuration file")
	flag.Parse()
	if *path == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: ha-mcp -config /etc/ha-mcp/config.json")
		os.Exit(2)
	}
	cfg, e := endpoint.LoadConfig(*path)
	if e != nil {
		fmt.Fprintln(os.Stderr, "configuration refused")
		os.Exit(1)
	}
	h, e := endpoint.New(cfg)
	if e != nil {
		fmt.Fprintln(os.Stderr, "startup refused")
		os.Exit(1)
	}
	srv := &http.Server{Addr: cfg.Listen, Handler: h, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10, ErrorLog: log.New(io.Discard, "", 0)}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(c)
	}()
	if e = srv.ListenAndServe(); e != nil && e != http.ErrServerClosed {
		fmt.Fprintln(os.Stderr, "server stopped")
		os.Exit(1)
	}
}
