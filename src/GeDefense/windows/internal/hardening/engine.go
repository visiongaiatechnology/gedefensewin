// STATUS: DIAMANT VGT SUPREME
package hardening

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/cleanup"

	"github.com/visiongaiatechnology/gedefense/windows/internal/evidence"
	"github.com/visiongaiatechnology/gedefense/windows/internal/winexec"
)

type Result struct {
	TimestampUTC              string `json:"TimestampUtc"`
	ComputerName              string `json:"ComputerName"`
	WindowsProductName        string `json:"WindowsProductName"`
	WindowsEditionID          string `json:"WindowsEditionId"`
	WindowsDisplayVersion     string `json:"WindowsDisplayVersion"`
	WindowsBuild              string `json:"WindowsBuild"`
	Defender                  bool   `json:"Defender"`
	DefenderService           bool   `json:"DefenderService"`
	RealTimeProtection        bool   `json:"RealTimeProtection"`
	BehaviorProtection        bool   `json:"BehaviorProtection"`
	IOAVProtection            bool   `json:"IoavProtection"`
	TamperProtection          bool   `json:"TamperProtection"`
	CloudProtection           bool   `json:"CloudProtection"`
	CloudBlockLevel           string `json:"CloudBlockLevel"`
	SampleSubmission          bool   `json:"SampleSubmission"`
	SignatureAgeDays          int    `json:"SignatureAgeDays"`
	NetworkProtection         bool   `json:"NetworkProtection"`
	ASRRules                  int    `json:"AsrRules"`
	ASRBlockRules             int    `json:"AsrBlockRules"`
	ControlledFolderAccess    bool   `json:"ControlledFolderAccess"`
	Firewall                  bool   `json:"Firewall"`
	SecureBoot                bool   `json:"SecureBoot"`
	TPM                       bool   `json:"Tpm"`
	BitLocker                 bool   `json:"BitLocker"`
	VBS                       bool   `json:"Vbs"`
	CredentialGuard           bool   `json:"CredentialGuard"`
	MemoryIntegrity           bool   `json:"MemoryIntegrity"`
	LSAProtection             bool   `json:"LsaProtection"`
	SMBHardening              bool   `json:"SmbHardening"`
	PowerShellLogging         bool   `json:"PowerShellLogging"`
	VulnerableDriverBlocklist bool   `json:"VulnerableDriverBlocklist"`
	UACSecureDesktop          bool   `json:"UacSecureDesktop"`
	USBStorageBlocked         bool   `json:"UsbStorageBlocked"`
	RemoteDesktopDisabled     bool   `json:"RemoteDesktopDisabled"`
	WindowsUpdate             bool   `json:"WindowsUpdate"`
	// DefenderTelemetry carries the detailed, explicitly-nullable Defender and
	// firewall snapshot. It is nil for legacy payloads that do not emit it.
	DefenderTelemetry *DefenderTelemetry `json:"DefenderTelemetry"`
	// ApplyReport is present only for ApplyConfig operations.
	ApplyReport *SettingsApplyReport `json:"ApplyReport,omitempty"`
}

type ComponentStatus struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Category       string `json:"category"`
	Active         bool   `json:"active"`
	RebootRequired bool   `json:"rebootRequired"`
	Description    string `json:"description"`
}

type Engine struct {
	mu            sync.Mutex
	cacheMu       sync.RWMutex
	script        string
	operationRoot string
	ledger        *evidence.Ledger
	cached        Result
	cachedAt      time.Time
	refreshing    atomic.Bool
}

func New(script, operationRoot string, ledger *evidence.Ledger) (*Engine, error) {
	if !filepath.IsAbs(script) || !filepath.IsAbs(operationRoot) {
		return nil, errors.New("hardening paths must be absolute")
	}
	info, err := os.Lstat(script)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("hardening engine must be a regular non-symlink file")
	}
	if err := os.MkdirAll(operationRoot, 0o700); err != nil {
		return nil, err
	}
	return &Engine{script: script, operationRoot: operationRoot, ledger: ledger}, nil
}

func (e *Engine) Audit(ctx context.Context) (Result, error) {
	return e.execute(ctx, "Audit", "EnterpriseBalanced", "", "", "Audit:EnterpriseBalanced")
}

func (e *Engine) Posture(ctx context.Context) (Result, error) {
	e.cacheMu.RLock()
	cached, cachedAt := e.cached, e.cachedAt
	e.cacheMu.RUnlock()
	if !cachedAt.IsZero() && time.Since(cachedAt) <= 2*time.Minute {
		return cached, nil
	}
	if !cachedAt.IsZero() {
		if e.refreshing.CompareAndSwap(false, true) {
			go func() {
				defer e.refreshing.Store(false)
				refCtx, refCancel := context.WithTimeout(context.Background(), 2*time.Minute)
				defer refCancel()
				_, _ = e.Audit(refCtx)
			}()
		}
		return cached, nil
	}
	shortCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	res, err := e.Audit(shortCtx)
	if err != nil {
		e.cacheMu.RLock()
		cached, cachedAt = e.cached, e.cachedAt
		e.cacheMu.RUnlock()
		if !cachedAt.IsZero() {
			return cached, nil
		}
		return Result{}, fmt.Errorf("initial posture audit unavailable: %w", err)
	}
	return res, nil
}

func (e *Engine) Enforce(ctx context.Context, profile string) (Result, error) {
	if profile != "EnterpriseBalanced" && profile != "Isolation" {
		return Result{}, errors.New("profile rejected")
	}
	return e.execute(ctx, "Enforce", profile, "", "", "Enforce:"+profile)
}

func (e *Engine) Rollback(ctx context.Context) (Result, error) {
	return e.execute(ctx, "Rollback", "EnterpriseBalanced", "", "", "Rollback:EnterpriseBalanced")
}

func (e *Engine) Components(ctx context.Context) ([]ComponentStatus, error) {
	result, err := e.Audit(ctx)
	if err != nil {
		return nil, err
	}
	return componentsFromResult(result), nil
}

func (e *Engine) EnforceComponent(ctx context.Context, component string) ([]ComponentStatus, error) {
	if !isSupportedComponent(component) {
		return nil, errors.New("hardening component rejected")
	}
	result, err := e.execute(ctx, "Component", "EnterpriseBalanced", component, "", "Component:"+component)
	if err != nil {
		return nil, err
	}
	return componentsFromResult(result), nil
}

func isSupportedComponent(component string) bool {
	for _, definition := range componentDefinitions {
		if definition.ID == component {
			return true
		}
	}
	return false
}

func (e *Engine) execute(parent context.Context, mode, profile, component, configPath, ledgerAction string) (result Result, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	ctx, cancel := context.WithTimeout(parent, 2*time.Minute)
	defer cancel()
	output := filepath.Join(e.operationRoot, fmt.Sprintf("result-%d.json", time.Now().UnixNano()))
	defer cleanup.RemoveInto(&err, output)
	powerShell, pathErr := winexec.PowerShell()
	if pathErr != nil {
		if e.ledger != nil {
			_ = e.ledger.Append("hardening.operation", ledgerAction, "failed")
		}
		return Result{}, pathErr
	}
	arguments := []string{"-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "AllSigned", "-File", e.script, "-Mode", mode, "-Profile", profile, "-OutputPath", output}
	if component != "" {
		arguments = append(arguments, "-Component", component)
	}
	if configPath != "" {
		arguments = append(arguments, "-ConfigPath", configPath)
	}
	command := exec.CommandContext(ctx, powerShell, arguments...)
	command.WaitDelay = 3 * time.Second
	command.Cancel = func() error {
		if command.Process != nil && command.Process.Pid > 0 {
			_ = winexec.KillProcessTree(command.Process.Pid)
		}
		return command.Process.Kill()
	}
	var stderr bytes.Buffer
	command.Stdout = io.Discard
	command.Stderr = &stderr
	err = winexec.RunTracked(command)
	if err != nil {
		if e.ledger != nil {
			_ = e.ledger.Append("hardening.operation", ledgerAction, "failed")
		}
		return Result{}, fmt.Errorf("hardening operation failed: %w", err)
	}
	result, readErr := readBoundedResult(output)
	if readErr != nil {
		if e.ledger != nil {
			_ = e.ledger.Append("hardening.operation", ledgerAction, "failed")
		}
		return Result{}, readErr
	}
	e.cacheMu.Lock()
	e.cached = result
	e.cachedAt = time.Now()
	e.cacheMu.Unlock()
	if e.ledger != nil {
		if err := e.ledger.Append("hardening.operation", ledgerAction, "verified"); err != nil {
			return Result{}, err
		}
	}
	return result, nil
}

// maxHardeningResultBytes bounds the decoded PowerShell result file so a
// compromised or misconfigured engine cannot force unbounded memory growth.
const maxHardeningResultBytes = 1 << 20

func readBoundedResult(path string) (result Result, err error) {
	file, openErr := os.Open(path)
	if openErr != nil {
		return Result{}, openErr
	}
	defer cleanup.CloseInto(&err, file)
	info, statErr := file.Stat()
	if statErr != nil {
		return Result{}, statErr
	}
	if info.Size() <= 0 || info.Size() > maxHardeningResultBytes {
		return Result{}, errors.New("hardening result size rejected")
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, maxHardeningResultBytes+1))
	if readErr != nil {
		return Result{}, readErr
	}
	if len(raw) == 0 || len(raw) > maxHardeningResultBytes {
		return Result{}, errors.New("hardening result size rejected")
	}
	if err := json.Unmarshal(bytes.TrimPrefix(raw, []byte{0xef, 0xbb, 0xbf}), &result); err != nil {
		return Result{}, errors.New("hardening result decoding failed")
	}
	return result, nil
}
