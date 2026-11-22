// STATUS: DIAMANT VGT SUPREME
//go:build windows

package mhx

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
	"github.com/visiongaiatechnology/gedefense/windows/internal/winexec"
)

const (
	defenderOracleTimeout    = 45 * time.Second
	maximumOracleOutputBytes = 64 << 10
)

func locateDefenderCLI() (string, error) {
	candidates := make([]string, 0, 8)
	if programData := strings.TrimSpace(os.Getenv("ProgramData")); programData != "" {
		platformRoot := filepath.Join(programData, "Microsoft", "Windows Defender", "Platform")
		if entries, err := os.ReadDir(platformRoot); err == nil {
			versions := make([]string, 0, len(entries))
			for _, entry := range entries {
				if entry.IsDir() {
					versions = append(versions, entry.Name())
				}
			}
			sort.Sort(sort.Reverse(sort.StringSlice(versions)))
			for _, dir := range versions {
				if len(candidates) >= 16 {
					break
				}
				candidates = append(candidates, filepath.Join(platformRoot, dir, "MpCmdRun.exe"))
			}
		}
	}
	if programFiles := strings.TrimSpace(os.Getenv("ProgramFiles")); programFiles != "" {
		candidates = append(candidates, filepath.Join(programFiles, "Windows Defender", "MpCmdRun.exe"))
	}
	for _, candidate := range candidates {
		clean, err := winapi.ValidateLocalFixedRegularFile(candidate)
		if err != nil {
			continue
		}
		if err := winapi.VerifyAuthenticode(clean); err != nil {
			continue
		}
		return clean, nil
	}
	return "", errors.New("verified MpCmdRun.exe is unavailable")
}

func runDefenderFileOracle(ctx context.Context, targetPath string) (DefenderScanResult, error) {
	started := time.Now().UTC()
	if ctx == nil {
		return DefenderScanResult{}, errors.New("defender scan oracle requires context")
	}
	cleanTarget, err := winapi.ValidateLocalFixedRegularFile(targetPath)
	if err != nil {
		return DefenderScanResult{}, err
	}
	cliPath, err := locateDefenderCLI()
	if err != nil {
		return DefenderScanResult{}, err
	}
	scanCtx, cancel := context.WithTimeout(ctx, defenderOracleTimeout)
	defer cancel()

	// Custom single-file scan without automatic remediation so Titan/MHX retain
	// deterministic custody for Vault quarantine and evidence chain attribution.
	command := exec.CommandContext(scanCtx, cliPath, "-Scan", "-ScanType", "3", "-DisableRemediation", "-File", cleanTarget)
	command.WaitDelay = 3 * time.Second
	command.Cancel = func() error {
		if command.Process != nil && command.Process.Pid > 0 {
			_ = winexec.KillProcessTree(command.Process.Pid)
		}
		return command.Process.Kill()
	}
	stdout := &boundedBuffer{limit: maximumOracleOutputBytes}
	stderr := &boundedBuffer{limit: 16 << 10}
	command.Stdout = stdout
	command.Stderr = stderr
	runErr := winexec.RunTracked(command)
	exitCode := 0
	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}
	durationMS := time.Since(started).Milliseconds()
	outputText := strings.TrimSpace(stdout.buffer.String() + "\n" + stderr.buffer.String())
	threatName := parseMpCmdRunThreat(outputText)

	result := DefenderScanResult{
		TargetPath:   cleanTarget,
		ScannerPath:  cliPath,
		TimestampUTC: time.Now().UTC(),
		DurationMS:   durationMS,
		ExitCode:     exitCode,
	}
	switch {
	case scanCtx.Err() != nil:
		result.Status = "TIMEOUT"
		result.Detail = "MpCmdRun scan timed out"
		return result, errors.New(result.Detail)
	case exitCode == 0:
		result.Status = "CLEAN"
		result.Detail = "Keine Bedrohung durch Microsoft Defender gemeldet"
		return result, nil
	case exitCode == 2:
		result.Status = "THREAT_FOUND"
		result.ThreatFound = true
		if threatName == "" {
			threatName = "Microsoft Defender Threat Match"
		}
		result.ThreatName = threatName
		result.Detail = "Bedrohung erkannt: " + threatName
		return result, nil
	default:
		result.Status = "ERROR"
		result.Detail = "MpCmdRun exited with non-zero status"
		return result, errors.New(result.Detail)
	}
}
