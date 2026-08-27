// STATUS: DIAMANT VGT SUPREME
package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
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
	errCh := make(chan error, 1)
	go a.monitor.Run(stop)
	go a.mhx.Run(stop)
	go a.integrity.Run(stop)
	go func() { errCh <- a.server.ListenAndServe() }()
	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-stop:
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return a.server.Shutdown(ctx)
	}
}
