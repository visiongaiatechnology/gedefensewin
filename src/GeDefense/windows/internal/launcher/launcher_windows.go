// STATUS: DIAMANT VGT SUPREME
//go:build windows

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
	"path/filepath"
	"strings"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/localhttp"
	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
)

func Open() error {
	target, err := BootstrapURL()
	if err != nil {
		return err
	}
	return winapi.ShellOpenURL(target)
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
	client := localhttp.NewClient(8 * time.Second)
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
	decoder := json.NewDecoder(bytes.NewReader(limited))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil || len(payload.Code) != 43 {
		return "", errors.New("dashboard bootstrap response is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return "", errors.New("dashboard bootstrap response contains trailing data")
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
