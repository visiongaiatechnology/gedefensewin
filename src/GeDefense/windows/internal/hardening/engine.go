// STATUS: DIAMANT VGT SUPREME
package hardening

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

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
	script        string
	operationRoot string
	ledger        *evidence.Ledger
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
	return e.execute(ctx, "Audit", "EnterpriseBalanced", "")
}

func (e *Engine) Enforce(ctx context.Context, profile string) (Result, error) {
	if profile != "EnterpriseBalanced" && profile != "Isolation" {
		return Result{}, errors.New("profile rejected")
	}
	return e.execute(ctx, "Enforce", profile, "")
}

func (e *Engine) Rollback(ctx context.Context) (Result, error) {
	return e.execute(ctx, "Rollback", "EnterpriseBalanced", "")
}

func (e *Engine) Components(ctx context.Context) ([]ComponentStatus, error) {
	result, err := e.Audit(ctx)
	if err != nil {
		return nil, err
	}
	return componentsFromResult(result), nil
}

func (e *Engine) EnforceComponent(ctx context.Context, component string) ([]ComponentStatus, error) {
	allowed := map[string]struct{}{"DefenderCloud": {}, "ASR": {}, "ControlledFolderAccess": {}, "Firewall": {}, "CredentialGuard": {}, "MemoryIntegrity": {}, "LSASS": {}, "SMB": {}, "PowerShellLogging": {}, "UAC": {}, "USBStorage": {}, "RemoteDesktop": {}}
	if _, exists := allowed[component]; !exists {
		return nil, errors.New("hardening component rejected")
	}
	result, err := e.execute(ctx, "Component", "EnterpriseBalanced", component)
	if err != nil {
		return nil, err
	}
	return componentsFromResult(result), nil
}

func (e *Engine) execute(parent context.Context, mode, profile, component string) (Result, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	ctx, cancel := context.WithTimeout(parent, 3*time.Minute)
	defer cancel()
	output := filepath.Join(e.operationRoot, fmt.Sprintf("result-%d.json", time.Now().UnixNano()))
	powerShell, pathErr := winexec.PowerShell()
	if pathErr != nil {
		_ = e.ledger.Append("hardening.operation", mode+":"+profile, "failed")
		return Result{}, pathErr
	}
	arguments := []string{"-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "AllSigned", "-File", e.script, "-Mode", mode, "-Profile", profile, "-OutputPath", output}
	if component != "" {
		arguments = append(arguments, "-Component", component)
	}
	command := exec.CommandContext(ctx, powerShell, arguments...)
	var stderr bytes.Buffer
	command.Stdout = &bytes.Buffer{}
	command.Stderr = &stderr
	err := command.Run()
	if err != nil {
		_ = e.ledger.Append("hardening.operation", mode+":"+profile, "failed")
		return Result{}, fmt.Errorf("hardening operation failed: %w", err)
	}
	raw, readErr := os.ReadFile(output)
	_ = os.Remove(output)
	if readErr != nil {
		return Result{}, readErr
	}
	var result Result
	if err := json.Unmarshal(bytes.TrimPrefix(raw, []byte{0xef, 0xbb, 0xbf}), &result); err != nil {
		return Result{}, errors.New("hardening result decoding failed")
	}
	if err := e.ledger.Append("hardening.operation", mode+":"+profile, "verified"); err != nil {
		return Result{}, err
	}
	return result, nil
}

func componentsFromResult(result Result) []ComponentStatus {
	return []ComponentStatus{
		{ID: "DefenderCloud", Name: "Defender Cloud & Network", Category: "DEFENDER", Active: result.CloudProtection && result.NetworkProtection && result.RealTimeProtection, Description: "Cloudbasierter Blockschutz, PUA, sichere Samples und Netzwerkinspektion."},
		{ID: "ASR", Name: "Attack Surface Reduction", Category: "DEFENDER", Active: result.ASRRules >= 11 && result.ASRBlockRules >= 11, Description: "Elf priorisierte ASR-Regeln im Blockmodus."},
		{ID: "ControlledFolderAccess", Name: "Controlled Folder Access", Category: "RANSOMWARE", Active: result.ControlledFolderAccess, Description: "Schreibzugriffe auf geschützte Ordner werden durch Defender kontrolliert."},
		{ID: "Firewall", Name: "Windows Firewall", Category: "NETZWERK", Active: result.Firewall, Description: "Alle Profile aktiv; eingehende Verbindungen standardmäßig blockiert."},
		{ID: "CredentialGuard", Name: "Credential Guard", Category: "ISOLATION", Active: result.CredentialGuard, RebootRequired: !result.CredentialGuard, Description: "Anmeldegeheimnisse werden in VBS-isolierter Umgebung geschützt."},
		{ID: "MemoryIntegrity", Name: "Memory Integrity / HVCI", Category: "KERNEL", Active: result.MemoryIntegrity && result.VulnerableDriverBlocklist, RebootRequired: !result.MemoryIntegrity, Description: "Hypervisor-gestützte Codeintegrität und Microsoft-Treiberblockliste."},
		{ID: "LSASS", Name: "LSASS Protected Process", Category: "IDENTITÄT", Active: result.LSAProtection, RebootRequired: !result.LSAProtection, Description: "LSASS läuft als geschützter Prozess; WDigest-Credentials bleiben deaktiviert."},
		{ID: "SMB", Name: "SMB-Härtung", Category: "NETZWERK", Active: result.SMBHardening, RebootRequired: !result.SMBHardening, Description: "SMB1 deaktiviert und Signierung für Client und Server erzwungen."},
		{ID: "PowerShellLogging", Name: "PowerShell & Process Audit", Category: "TELEMETRIE", Active: result.PowerShellLogging, Description: "ScriptBlock-, Modul- und Prozessbefehlszeilen-Protokollierung."},
		{ID: "UAC", Name: "UAC Secure Desktop", Category: "IDENTITÄT", Active: result.UACSecureDesktop, Description: "Admin-Zustimmung und Secure Desktop sind erzwungen."},
		{ID: "USBStorage", Name: "USB-Massenspeicher sperren", Category: "ISOLATION", Active: result.USBStorageBlocked, RebootRequired: false, Description: "USBSTOR wird vollständig deaktiviert."},
		{ID: "RemoteDesktop", Name: "Remote Desktop deaktivieren", Category: "NETZWERK", Active: result.RemoteDesktopDisabled, Description: "Eingehende RDP-Sitzungen werden blockiert."},
	}
}
