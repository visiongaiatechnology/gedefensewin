// STATUS: DIAMANT VGT SUPREME
package scriptengine

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
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/winexec"
)

const maxResultBytes = 8 << 20

type Engine struct {
	mu            sync.Mutex
	script        string
	operationRoot string
	timeout       time.Duration
}

func New(script, operationRoot string, timeout time.Duration) (*Engine, error) {
	if !filepath.IsAbs(script) || !filepath.IsAbs(operationRoot) {
		return nil, errors.New("script engine paths must be absolute")
	}
	info, err := os.Lstat(script)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("script engine must be a regular non-symlink file")
	}
	if timeout < 10*time.Second || timeout > 10*time.Minute {
		return nil, errors.New("script engine timeout rejected")
	}
	if err := os.MkdirAll(operationRoot, 0o700); err != nil {
		return nil, err
	}
	return &Engine{script: script, operationRoot: operationRoot, timeout: timeout}, nil
}

func RunJSON[T any](engine *Engine, parent context.Context, operation string, extraArgs ...string) (T, error) {
	var result T
	if operation == "" || len(operation) > 48 {
		return result, errors.New("operation name rejected")
	}
	engine.mu.Lock()
	defer engine.mu.Unlock()
	ctx, cancel := context.WithTimeout(parent, engine.timeout)
	defer cancel()
	output := filepath.Join(engine.operationRoot, fmt.Sprintf("%s-%d.json", operation, time.Now().UnixNano()))
	arguments := []string{"-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "AllSigned", "-File", engine.script, "-OutputPath", output}
	arguments = append(arguments, extraArgs...)
	powerShell, err := winexec.PowerShell()
	if err != nil {
		return result, err
	}
	command := exec.CommandContext(ctx, powerShell, arguments...)
	var stderr bytes.Buffer
	command.Stdout = io.Discard
	command.Stderr = &limitedWriter{target: &stderr, remaining: 64 << 10}
	if err := command.Run(); err != nil {
		return result, fmt.Errorf("%s failed: %w: %s", operation, err, stderr.String())
	}
	defer os.Remove(output)
	file, err := os.Open(output)
	if err != nil {
		return result, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxResultBytes+1))
	if err != nil {
		return result, err
	}
	if len(raw) == 0 || len(raw) > maxResultBytes {
		return result, errors.New("script engine result size rejected")
	}
	if err := json.Unmarshal(bytes.TrimPrefix(raw, []byte{0xef, 0xbb, 0xbf}), &result); err != nil {
		return result, errors.New("script engine result decoding failed")
	}
	return result, nil
}

type limitedWriter struct {
	target    io.Writer
	remaining int
}

func (w *limitedWriter) Write(value []byte) (int, error) {
	original := len(value)
	if w.remaining <= 0 {
		return original, nil
	}
	if len(value) > w.remaining {
		value = value[:w.remaining]
	}
	written, err := w.target.Write(value)
	w.remaining -= written
	if err != nil {
		return written, err
	}
	return original, nil
}
