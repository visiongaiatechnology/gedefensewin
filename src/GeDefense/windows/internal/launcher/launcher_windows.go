// STATUS: DIAMANT VGT SUPREME
package launcher

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func Open() error {
	target, err := BootstrapURL()
	if err != nil {
		return err
	}
	for _, candidate := range edgeCandidates() {
		if info, statErr := os.Stat(candidate); statErr == nil && info.Mode().IsRegular() {
			return exec.Command(candidate, "--app="+target, "--no-first-run").Start()
		}
	}
	return exec.Command(filepath.Join(os.Getenv("SystemRoot"), "System32", "rundll32.exe"), "url.dll,FileProtocolHandler", target).Start()
}

func BootstrapURL() (string, error) {
	programData := os.Getenv("ProgramData")
	if programData == "" || !filepath.IsAbs(programData) {
		return "", errors.New("ProgramData is unavailable")
	}
	rawToken, err := os.ReadFile(filepath.Join(programData, "VGT", "GeDefense", "dashboard.token"))
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(rawToken))
	if len(token) != 43 {
		return "", errors.New("dashboard credential is invalid")
	}
	request, err := http.NewRequest(http.MethodPost, "http://127.0.0.1:17831/api/v1/session/bootstrap", bytes.NewReader([]byte("{}")))
	if err != nil {
		return "", err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	requestID, err := randomRequestID()
	if err != nil {
		return "", err
	}
	request.Header.Set("X-VGT-Request-ID", requestID)
	client := &http.Client{Timeout: 10 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	limited, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	if err != nil || len(limited) > 4096 || response.StatusCode != http.StatusCreated {
		return "", errors.New("dashboard bootstrap failed")
	}
	var payload struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(limited, &payload); err != nil || len(payload.Code) != 43 {
		return "", errors.New("dashboard bootstrap response is invalid")
	}
	return "http://127.0.0.1:17831/#bootstrap=" + url.QueryEscape(payload.Code), nil
}

func randomRequestID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	hexValue := hex.EncodeToString(raw)
	return hexValue[0:8] + "-" + hexValue[8:12] + "-" + hexValue[12:16] + "-" + hexValue[16:20] + "-" + hexValue[20:32], nil
}

func edgeCandidates() []string {
	return []string{
		filepath.Join(os.Getenv("ProgramFiles(x86)"), "Microsoft", "Edge", "Application", "msedge.exe"),
		filepath.Join(os.Getenv("ProgramFiles"), "Microsoft", "Edge", "Application", "msedge.exe"),
	}
}
