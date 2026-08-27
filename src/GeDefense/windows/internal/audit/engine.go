// STATUS: DIAMANT VGT SUPREME
package audit

import (
	"context"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/evidence"
	"github.com/visiongaiatechnology/gedefense/windows/internal/scriptengine"
)

type Check struct {
	ID       string `json:"Id"`
	Category string `json:"Category"`
	Title    string `json:"Title"`
	Status   string `json:"Status"`
	Severity string `json:"Severity"`
	Expected string `json:"Expected"`
	Actual   string `json:"Actual"`
}

type Result struct {
	TimestampUTC string  `json:"TimestampUtc"`
	Framework    string  `json:"Framework"`
	Score        int     `json:"Score"`
	MaxScore     int     `json:"MaxScore"`
	Percent      float64 `json:"Percent"`
	Passed       int     `json:"Passed"`
	Failed       int     `json:"Failed"`
	Warnings     int     `json:"Warnings"`
	Checks       []Check `json:"Checks"`
}

type Engine struct {
	runner *scriptengine.Engine
	ledger *evidence.Ledger
}

func New(script, operationRoot string, ledger *evidence.Ledger) (*Engine, error) {
	runner, err := scriptengine.New(script, operationRoot, 4*time.Minute)
	if err != nil {
		return nil, err
	}
	return &Engine{runner: runner, ledger: ledger}, nil
}

func (e *Engine) Run(ctx context.Context) (Result, error) {
	result, err := scriptengine.RunJSON[Result](e.runner, ctx, "security-audit")
	if err != nil {
		_ = e.ledger.Append("audit.operation", "VGT-SafetySys", "failed")
		return Result{}, err
	}
	if err := e.ledger.Append("audit.operation", "VGT-SafetySys", "verified"); err != nil {
		return Result{}, err
	}
	return result, nil
}
