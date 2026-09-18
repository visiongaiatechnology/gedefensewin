// STATUS: DIAMANT VGT SUPREME
package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/audit"
	"github.com/visiongaiatechnology/gedefense/windows/internal/evidence"
	"github.com/visiongaiatechnology/gedefense/windows/internal/hardening"
	"github.com/visiongaiatechnology/gedefense/windows/internal/integrity"
	"github.com/visiongaiatechnology/gedefense/windows/internal/mhx"
	"github.com/visiongaiatechnology/gedefense/windows/internal/monitor"
	"github.com/visiongaiatechnology/gedefense/windows/internal/security"
	webserver "github.com/visiongaiatechnology/gedefense/windows/internal/server"
	"github.com/visiongaiatechnology/gedefense/windows/internal/xdr"
)

type App struct {
	server    *http.Server
	monitor   *monitor.Monitor
	mhx       *mhx.Engine
	integrity *integrity.Engine
}

func New(root, version string) (*App, error) {
	programData := os.Getenv("ProgramData")
	if programData == "" || !filepath.IsAbs(programData) {
		return nil, errors.New("ProgramData is unavailable")
	}
	dataRoot := filepath.Join(programData, "VGT", "GeDefense")
	token, err := security.LoadOrCreateToken(filepath.Join(dataRoot, "dashboard.token"))
	if err != nil {
		return nil, fmt.Errorf("dashboard token: %w", err)
	}
	ledger, err := evidence.Open(filepath.Join(dataRoot, "evidence.jsonl"), filepath.Join(dataRoot, "evidence.key"))
	if err != nil {
		return nil, fmt.Errorf("evidence ledger: %w", err)
	}
	engine, err := hardening.New(filepath.Join(root, "engine", "Invoke-VgtHardening.ps1"), filepath.Join(dataRoot, "operations"), ledger)
	if err != nil {
		return nil, fmt.Errorf("hardening engine: %w", err)
	}
	auditEngine, err := audit.New(filepath.Join(root, "audit", "Invoke-VgtSecurityAudit.ps1"), filepath.Join(dataRoot, "operations"), ledger)
	if err != nil {
		return nil, fmt.Errorf("audit engine: %w", err)
	}
	xdrEngine, err := xdr.New(filepath.Join(root, "xdr", "Invoke-VgtXdrScan.ps1"), filepath.Join(dataRoot, "operations"), ledger)
	if err != nil {
		return nil, fmt.Errorf("XDR engine: %w", err)
	}
	mhxEngine, err := mhx.NewEngine(filepath.Join(dataRoot, "mhx"), filepath.Join(root, "xdr", "Set-VgtMhxProtection.ps1"), filepath.Join(root, "xdr", "Sync-VgtMhxFirewall.ps1"), filepath.Join(root, "xdr", "Set-VgtMhxApplicationAllow.ps1"), filepath.Join(root, "xdr", "Set-VgtMhxAppControl.ps1"), filepath.Join(dataRoot, "operations"), ledger)
	if err != nil {
		return nil, fmt.Errorf("MHX realtime engine: %w", err)
	}
	integrityEngine, err := integrity.New(filepath.Join(dataRoot, "integrity"), ledger)
	if err != nil {
		return nil, fmt.Errorf("integrity engine: %w", err)
	}
	handler := webserver.New(version, token, engine, auditEngine, xdrEngine, mhxEngine, integrityEngine, ledger)
	return &App{monitor: monitor.New(engine, ledger, 5*time.Minute), mhx: mhxEngine, integrity: integrityEngine, server: &http.Server{
		Addr:              "127.0.0.1:17831",
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      12 * time.Minute,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}}, nil
}

func (a *App) Run(stop <-chan struct{}) error {
	internalStop := make(chan struct{})
	var stopOnce sync.Once
	stopAll := func() { stopOnce.Do(func() { close(internalStop) }) }
	var workers sync.WaitGroup
	workers.Add(3)
	go func() { defer workers.Done(); a.monitor.Run(internalStop) }()
	go func() { defer workers.Done(); a.mhx.Run(internalStop) }()
	go func() { defer workers.Done(); a.integrity.Run(internalStop) }()

	serverErr := make(chan error, 1)
	go func() { serverErr <- a.server.ListenAndServe() }()

	var result error
	select {
	case err := <-serverErr:
		if !errors.Is(err, http.ErrServerClosed) {
			result = err
		}
		stopAll()
	case <-stop:
		stopAll()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		shutdownErr := a.server.Shutdown(ctx)
		cancel()
		if shutdownErr != nil {
			result = shutdownErr
		}
	}

	done := make(chan struct{})
	go func() { workers.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(12 * time.Second):
		if result == nil {
			result = errors.New("security worker shutdown timed out")
		}
	}
	return result
}
