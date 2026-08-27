// STATUS: DIAMANT VGT SUPREME
package xdr

import (
	"context"
	"sync"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/evidence"
	"github.com/visiongaiatechnology/gedefense/windows/internal/scriptengine"
)

type Finding struct {
	ID          string `json:"Id"`
	Timestamp   string `json:"TimestampUtc"`
	Severity    string `json:"Severity"`
	Category    string `json:"Category"`
	Title       string `json:"Title"`
	Description string `json:"Description"`
	Entity      string `json:"Entity"`
	Evidence    string `json:"Evidence"`
}

type Result struct {
	TimestampUTC string    `json:"TimestampUtc"`
	Engine       string    `json:"Engine"`
	Scanned      int       `json:"Scanned"`
	Critical     int       `json:"Critical"`
	High         int       `json:"High"`
	Medium       int       `json:"Medium"`
	Low          int       `json:"Low"`
	Findings     []Finding `json:"Findings"`
}

type Engine struct {
	runner *scriptengine.Engine
	ledger *evidence.Ledger
	mu     sync.RWMutex
	last   Result
}

func New(script, operationRoot string, ledger *evidence.Ledger) (*Engine, error) {
	runner, err := scriptengine.New(script, operationRoot, 4*time.Minute)
	if err != nil {
		return nil, err
	}
	return &Engine{runner: runner, ledger: ledger, last: Result{Engine: "VGT MHX 5.0", Findings: []Finding{}}}, nil
}

func (e *Engine) Scan(ctx context.Context) (Result, error) {
	result, err := scriptengine.RunJSON[Result](e.runner, ctx, "xdr-scan")
	if err != nil {
		_ = e.ledger.Append("xdr.operation", "MHX scan", "failed")
		return Result{}, err
	}
	e.mu.Lock()
	e.last = result
	e.mu.Unlock()
	if err := e.ledger.Append("xdr.operation", "MHX scan", "verified"); err != nil {
		return Result{}, err
	}
	return result, nil
}

func (e *Engine) Last() Result {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.last
}
