// STATUS: PLATIN
//go:build windows

package launcher

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestBrowserArgumentsContainNoBootstrapSecret(t *testing.T) {
	profile := t.TempDir()
	arguments := browserArguments(profile, controlPlaneURL)
	joined := strings.Join(arguments, " ")
	if !strings.Contains(joined, "--kiosk") || !strings.Contains(joined, controlPlaneURL) {
		t.Fatalf("launch arguments missing kiosk target: %v", arguments)
	}
	for _, forbidden := range []string{"#bootstrap", "bootstrap=", "code=", "Bearer", "token="} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("launch arguments contain credential marker %q: %v", forbidden, arguments)
		}
	}
	if !strings.Contains(joined, "--user-data-dir="+profile) {
		t.Fatalf("launch arguments lost the dedicated profile: %v", arguments)
	}
	if controlPlaneURL != "http://127.0.0.1:17831/" {
		t.Fatalf("control-plane target unexpectedly carries more than the loopback origin: %q", controlPlaneURL)
	}
}

func TestFindChromiumBrowserReturnsTrustedPath(t *testing.T) {
	path := findChromiumBrowser()
	if path != "" {
		if !isExecutableFile(path) {
			t.Fatalf("findChromiumBrowser returned non-executable: %q", path)
		}
		if !isTrustedBrowserPath(path) {
			t.Fatalf("findChromiumBrowser returned an untrusted path: %q", path)
		}
	}
}

func TestIsTrustedBrowserPathRejectsUserWritableLocations(t *testing.T) {
	programFiles := os.Getenv("ProgramFiles")
	if !filepath.IsAbs(programFiles) {
		t.Skip("ProgramFiles is unavailable on this host")
	}
	trusted := filepath.Join(programFiles, "Microsoft", "Edge", "Application", "msedge.exe")
	if !isTrustedBrowserPath(trusted) {
		t.Fatalf("trusted system browser path rejected: %q", trusted)
	}
	localData := os.Getenv("LocalAppData")
	if filepath.IsAbs(localData) {
		userWritable := filepath.Join(localData, "Microsoft", "Edge", "Application", "msedge.exe")
		if isTrustedBrowserPath(userWritable) {
			t.Fatalf("user-writable browser path accepted: %q", userWritable)
		}
	}
	rejected := []string{
		"",
		"msedge.exe",
		`C:\Program Files\Microsoft\Edge\Application\notepad.exe`,
		`C:\Program Files\Microsoft\Edge\Application\msedge.bat`,
		filepath.Join(programFiles, "..", "Windows", "System32", "cmd.exe"),
		filepath.Join(os.TempDir(), "msedge.exe"),
	}
	for _, path := range rejected {
		if isTrustedBrowserPath(path) {
			t.Fatalf("untrusted browser path accepted: %q", path)
		}
	}
}

const testOperatorSessionToken = "vgs.operator-session-test-token"

func TestRegisterBrowserProcessUsesOperatorSessionAndReplayGuard(t *testing.T) {
	var seenReplayID string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/session/register-browser" {
			t.Errorf("unexpected registration request: %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer "+testOperatorSessionToken {
			t.Errorf("registration missing operator session authorization: %q", r.Header.Get("Authorization"))
		}
		seenReplayID = r.Header.Get("X-VGT-Request-ID")
		if len(seenReplayID) != 36 {
			t.Errorf("registration missing replay id: %q", seenReplayID)
		}
		var payload struct {
			PID    uint32 `json:"pid"`
			Client string `json:"client"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("registration body invalid: %v", err)
		}
		if payload.PID != 4242 || payload.Client != centerClientName {
			t.Errorf("registration payload wrong: %+v", payload)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"registered":true}`))
	}))
	defer server.Close()
	if err := registerBrowserProcess(server.URL, testOperatorSessionToken, 4242); err != nil {
		t.Fatalf("registration failed: %v", err)
	}
	if seenReplayID == "" {
		t.Fatal("replay guard was not used for browser registration")
	}

	rejecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer rejecting.Close()
	if err := registerBrowserProcess(rejecting.URL, testOperatorSessionToken, 4242); err == nil {
		t.Fatal("rejected browser registration reported success")
	}
}

func TestWindowSessionRenewsOperatorSessionAndPolls(t *testing.T) {
	var brokerCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/session/operator":
			if r.Header.Get("X-VGT-Operator-Broker") != "1" {
				t.Errorf("window session broker marker missing")
			}
			if r.Header.Get("X-VGT-Request-ID") == "" {
				t.Errorf("broker request missing replay id")
			}
			if r.Header.Get("Authorization") != "" {
				t.Errorf("broker request must not carry a bearer credential")
			}
			var payload struct {
				Client string `json:"client"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Errorf("broker body invalid: %v", err)
			}
			if payload.Client != "center-launcher" {
				t.Errorf("unexpected broker client: %q", payload.Client)
			}
			count := brokerCount.Add(1)
			w.WriteHeader(http.StatusCreated)
			_, _ = fmt.Fprintf(w,
				`{"token":"vgs.operator-%d","client":"center-launcher","scopes":["read","operate","policy","window"],"expiresUtc":%q,"subject":{"account":"TEST\\operator","administrator":true,"operator":true}}`,
				count, time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano))
		case "/api/v1/window/poll":
			if r.Header.Get("Authorization") != "Bearer vgs.operator-1" {
				t.Errorf("poll did not use the broker operator session: %q", r.Header.Get("Authorization"))
			}
			_, _ = w.Write([]byte(`{"command":"idle"}`))
		case "/api/v1/window/ack":
			if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer vgs.operator-") {
				t.Errorf("ack did not use the broker operator session: %q", r.Header.Get("Authorization"))
			}
			if r.Header.Get("X-VGT-Request-ID") == "" {
				t.Errorf("ack missing replay id")
			}
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		default:
			t.Errorf("unexpected request: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	session := newWindowSession(server.URL)
	defer session.close()
	authorization, err := session.authorization(context.Background())
	if err != nil || authorization != "Bearer vgs.operator-1" {
		t.Fatalf("window operator session acquisition failed: %q %v", authorization, err)
	}
	if err := pollWindow(context.Background(), session, 0); err != nil {
		t.Fatalf("window poll failed: %v", err)
	}
	if err := sendStateAck(context.Background(), session, "normal"); err != nil {
		t.Fatalf("window ack failed: %v", err)
	}
	// A revoked session must be re-acquired transparently from the broker.
	session.invalidate()
	if _, err := session.authorization(context.Background()); err != nil {
		t.Fatalf("window operator session renewal failed: %v", err)
	}
	if brokerCount.Load() != 2 {
		t.Fatalf("expected exactly one re-acquisition, got %d", brokerCount.Load())
	}
}

func TestWindowSessionFailsClosedWhenBrokerRejects(t *testing.T) {
	rejecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer rejecting.Close()
	session := newWindowSession(rejecting.URL)
	defer session.close()
	if _, err := session.authorization(context.Background()); err == nil {
		t.Fatal("rejected broker was treated as an authenticated window session")
	}
}

func TestDescribeMapsFailureKindsToSpecificGermanMessages(t *testing.T) {
	tests := []struct {
		kind            FailureKind
		summaryFragment string
		hintFragment    string
	}{
		{FailureBroker, "Dienst", "GeDefense-Dienst"},
		{FailureBrowser, "Chromium-Browser", "Program Files"},
		{FailureHost, "Fenster", "Center-Fenster"},
		{FailureStartup, "Browserprozess", "Browserstart"},
		{FailureProfile, "Profil", "Schreibrechte"},
		{FailureElevation, "Administratorrechten", "Als Administrator"},
	}
	for _, test := range tests {
		t.Run(string(test.kind), func(t *testing.T) {
			err := failure(test.kind, errors.New("underlying detail"))
			summary, hint := Describe(err)
			if !strings.Contains(summary, test.summaryFragment) {
				t.Fatalf("summary for %s is not specific: %q", test.kind, summary)
			}
			if !strings.Contains(hint, test.hintFragment) {
				t.Fatalf("hint for %s is not actionable: %q", test.kind, hint)
			}
			if KindOf(err) != test.kind {
				t.Fatalf("KindOf() = %q, want %q", KindOf(err), test.kind)
			}
			if !errors.Is(err, err.(*Failure).Err) {
				t.Fatalf("typed failure does not unwrap to its cause")
			}
		})
	}
}

func TestDescribeHandlesUnknownAndJoinedErrors(t *testing.T) {
	unknown := errors.New("raw internal condition")
	summary, hint := Describe(unknown)
	if summary == "" || hint == "" {
		t.Fatal("unknown failure lost its generic summary or hint")
	}
	if strings.Contains(summary, "raw internal condition") {
		t.Fatalf("internal error text leaked into the operator summary: %q", summary)
	}
	joined := errors.Join(errors.New("secondary"), failure(FailureBrowser, errors.New("no browser")))
	if KindOf(joined) != FailureBrowser {
		t.Fatalf("joined failure kind lost: %q", KindOf(joined))
	}
	if summary, _ := Describe(joined); !strings.Contains(summary, "Chromium-Browser") {
		t.Fatalf("joined failure was not categorized: %q", summary)
	}
}

func TestBrowserAttachDeadlineIsExtendedBeyondLegacyValue(t *testing.T) {
	if browserAttachDeadline != 45*time.Second {
		t.Fatalf("browser attach deadline = %v, want 45s", browserAttachDeadline)
	}
	if browserAttachDeadline <= 15*time.Second {
		t.Fatalf("browser attach deadline regressed to the legacy 15s value: %v", browserAttachDeadline)
	}
}

func TestDiagnosticLogPathUsesLocalAppData(t *testing.T) {
	root := t.TempDir()
	t.Setenv("LocalAppData", root)
	path, err := DiagnosticLogPath()
	if err != nil {
		t.Fatalf("diagnostic log path rejected a valid LocalAppData: %v", err)
	}
	expected := filepath.Join(root, "VGT", "GeDefense", "logs", "center-launch.log")
	if path != expected {
		t.Fatalf("DiagnosticLogPath() = %q, want %q", path, expected)
	}
	t.Setenv("LocalAppData", "relative")
	if _, err := DiagnosticLogPath(); err == nil {
		t.Fatal("relative LocalAppData was accepted")
	}
}

func TestLaunchDiagnosticIsUTCBoundedAndRotated(t *testing.T) {
	root := t.TempDir()
	t.Setenv("LocalAppData", root)
	path, err := DiagnosticLogPath()
	if err != nil {
		t.Fatal(err)
	}
	entry := launchDiagnostic{
		Category: string(FailureStartup),
		Elevated: true,
		Browser:  `C:\Program Files\Microsoft\Edge\Application\msedge.exe`,
		Detail:   strings.Repeat("x", 900),
	}
	for attempt := 0; attempt < 400; attempt++ {
		if err := writeLaunchDiagnostic(entry); err != nil {
			t.Fatalf("diagnostic write %d failed: %v", attempt, err)
		}
		if _, statErr := os.Stat(path + ".1"); statErr == nil {
			break
		}
	}
	rotatedInfo, err := os.Stat(path + ".1")
	if err != nil {
		t.Fatalf("diagnostic log was not rotated: %v", err)
	}
	if rotatedInfo.Size() > diagnosticLogMaxBytes {
		t.Fatalf("rotated generation exceeds the 256 KiB bound: %d", rotatedInfo.Size())
	}
	currentInfo, err := os.Stat(path)
	if err != nil {
		t.Fatalf("current diagnostic log missing after rotation: %v", err)
	}
	if currentInfo.Size() > diagnosticLogMaxBytes {
		t.Fatalf("current generation exceeds the 256 KiB bound: %d", currentInfo.Size())
	}
	current, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content := string(current)
	if !strings.Contains(content, "kind=startup") || !strings.Contains(content, "elevated=true") {
		t.Fatalf("diagnostic line lacks category/elevation: %q", content)
	}
	if !strings.Contains(content, "msedge.exe") {
		t.Fatalf("diagnostic line lacks the browser path: %q", content)
	}
	if strings.Contains(content, "\r\n") {
		t.Fatal("diagnostic line contains a Windows line break")
	}
	// The UTC timestamp is the first token of every line.
	firstLine := strings.SplitN(strings.TrimSpace(content), "\n", 2)[0]
	stamp := strings.SplitN(firstLine, " ", 2)[0]
	if _, err := time.Parse(time.RFC3339, stamp); err != nil {
		t.Fatalf("diagnostic timestamp is not RFC3339 UTC: %q (%v)", stamp, err)
	}
}

func TestFormatLaunchDiagnosticSanitizesControlBytes(t *testing.T) {
	line := formatLaunchDiagnostic(launchDiagnostic{
		Category: "startup\r\ninjected",
		Elevated: false,
		Detail:   "line one\r\nline two\x00end",
	}, time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC))
	if strings.ContainsAny(line, "\r\x00") {
		t.Fatalf("control bytes survived sanitation: %q", line)
	}
	if strings.Count(line, "\n") != 1 || !strings.HasSuffix(line, "\n") {
		t.Fatalf("diagnostic line must be one newline-terminated record: %q", line)
	}
	if !strings.HasPrefix(line, "2026-10-25T12:00:00Z") {
		t.Fatalf("diagnostic timestamp is not UTC RFC3339: %q", line)
	}
	if !strings.Contains(line, "kind=") || !strings.Contains(line, "injected") {
		t.Fatalf("diagnostic category was dropped: %q", line)
	}
}
