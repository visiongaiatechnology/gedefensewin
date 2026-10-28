// STATUS: DIAMANT VGT SUPREME
//go:build windows

package mhx

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
)

// buildProcessCreationXML renders a bounded Security 4688 fixture. Values are
// XML-escaped so command lines and paths exercise the parser, not the fixture.
func buildProcessCreationXML(recordID int64, eventID int, timestamp string, entries [][2]string) []byte {
	var builder strings.Builder
	builder.WriteString(`<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>`)
	fmt.Fprintf(&builder, `<EventID>%d</EventID>`, eventID)
	if timestamp != "" {
		fmt.Fprintf(&builder, `<TimeCreated SystemTime="%s"/>`, timestamp)
	}
	fmt.Fprintf(&builder, `<EventRecordID>%d</EventRecordID><Channel>Security</Channel></System><EventData>`, recordID)
	for _, entry := range entries {
		builder.WriteString(`<Data Name="`)
		if err := xml.EscapeText(&builder, []byte(entry[0])); err != nil {
			panic(err)
		}
		builder.WriteString(`">`)
		if err := xml.EscapeText(&builder, []byte(entry[1])); err != nil {
			panic(err)
		}
		builder.WriteString(`</Data>`)
	}
	builder.WriteString(`</EventData></Event>`)
	return []byte(builder.String())
}

func standardProcessCreationEntries(pid, creatorPID, image, commandLine, parent string) [][2]string {
	return [][2]string{
		{"SubjectUserSid", "S-1-5-18"},
		{"SubjectUserName", "HOST$"},
		{"SubjectDomainName", "WORKGROUP"},
		{"SubjectLogonId", "0x3e7"},
		{"NewProcessId", pid},
		{"NewProcessName", image},
		{"TokenElevationType", "%%1936"},
		{"ProcessId", creatorPID},
		{"CommandLine", commandLine},
		{"TargetUserSid", "S-1-5-18"},
		{"TargetUserName", "SYSTEM"},
		{"TargetDomainName", "NT AUTHORITY"},
		{"TargetLogonId", "0x3e7"},
		{"ParentProcessName", parent},
		{"MandatoryLabel", "S-1-16-16384"},
	}
}

const processCreationTestTimestamp = "2026-10-25T15:30:00.1234567Z"

func TestParseProcessCreationEventHexIdentifiers(t *testing.T) {
	raw := buildProcessCreationXML(123456, securityProcessCreationEventID, processCreationTestTimestamp, standardProcessCreationEntries(
		"0x1a4", "0x9c0", `C:\Windows\System32\cmd.exe`, `cmd.exe /c whoami`, `C:\Windows\System32\services.exe`,
	))
	event, recordID, err := parseProcessCreationEvent(raw)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if recordID != 123456 {
		t.Fatalf("record ID = %d, want 123456", recordID)
	}
	wantTime := time.Date(2026, 10, 25, 15, 30, 0, 123456700, time.UTC)
	if !event.TimestampUTC.Equal(wantTime) || !event.CreationUTC.Equal(wantTime) {
		t.Fatalf("timestamps = %v/%v, want %v", event.TimestampUTC, event.CreationUTC, wantTime)
	}
	if event.PID != 420 || event.ParentPID != 2496 {
		t.Fatalf("pids = %d/%d, want 420/2496", event.PID, event.ParentPID)
	}
	if event.Image != "cmd.exe" || event.ImagePath != `C:\Windows\System32\cmd.exe` {
		t.Fatalf("image = %q/%q", event.Image, event.ImagePath)
	}
	if event.CommandLine != `cmd.exe /c whoami` {
		t.Fatalf("command line = %q", event.CommandLine)
	}
	if event.ParentImage != "services.exe" || event.ParentPath != `C:\Windows\System32\services.exe` {
		t.Fatalf("parent = %q/%q", event.ParentImage, event.ParentPath)
	}
	if len(event.Ancestry) != 1 || event.Ancestry[0].PID != 2496 || event.Ancestry[0].Image != "services.exe" || event.Ancestry[0].Path != `C:\Windows\System32\services.exe` {
		t.Fatalf("ancestry = %+v", event.Ancestry)
	}
}

func TestParseProcessCreationEventDecimalAndCreatorOverride(t *testing.T) {
	entries := standardProcessCreationEntries("420", "2496", `C:\Windows\System32\cmd.exe`, `cmd.exe`, `C:\Windows\System32\services.exe`)
	entries = append(entries, [2]string{"CreatorProcessId", "0x64"})
	raw := buildProcessCreationXML(7, securityProcessCreationEventID, processCreationTestTimestamp, entries)
	event, recordID, err := parseProcessCreationEvent(raw)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if recordID != 7 || event.PID != 420 {
		t.Fatalf("record/pid = %d/%d", recordID, event.PID)
	}
	if event.ParentPID != 100 {
		t.Fatalf("parent PID = %d, want CreatorProcessId 100", event.ParentPID)
	}
}

func TestParseProcessCreationEventWithoutCommandLine(t *testing.T) {
	entries := [][2]string{
		{"NewProcessId", "0x200"},
		{"NewProcessName", `C:\Windows\System32\cmd.exe`},
		{"ProcessId", "0x4"},
	}
	raw := buildProcessCreationXML(9, securityProcessCreationEventID, processCreationTestTimestamp, entries)
	event, _, err := parseProcessCreationEvent(raw)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if event.CommandLine != "" {
		t.Fatalf("command line = %q, want empty", event.CommandLine)
	}
	if event.ParentPID != 4 || event.ParentImage != "" || len(event.Ancestry) != 0 {
		t.Fatalf("parent identity = %d/%q/%+v", event.ParentPID, event.ParentImage, event.Ancestry)
	}
}

func TestParseProcessCreationEventDegradesParentIdentity(t *testing.T) {
	// A malformed or reserved creator PID must not discard the child event; the
	// parent identity simply degrades to unknown (ParentPID 0).
	entries := standardProcessCreationEntries("0x1a4", "creator", `C:\Windows\System32\cmd.exe`, `cmd.exe`, `C:\Windows\System32\services.exe`)
	event, _, err := parseProcessCreationEvent(buildProcessCreationXML(1, securityProcessCreationEventID, processCreationTestTimestamp, entries))
	if err != nil {
		t.Fatalf("event with unusable creator PID was rejected: %v", err)
	}
	if event.ParentPID != 0 || len(event.Ancestry) != 1 || event.Ancestry[0].PID != 0 {
		t.Fatalf("parent degradation = %d/%+v", event.ParentPID, event.Ancestry)
	}
	// An unusable CreatorProcessId falls back to the legacy ProcessId field.
	entries = standardProcessCreationEntries("0x1a4", "0x9c0", `C:\Windows\System32\cmd.exe`, `cmd.exe`, "")
	entries = append(entries, [2]string{"CreatorProcessId", "0x1"})
	event, _, err = parseProcessCreationEvent(buildProcessCreationXML(1, securityProcessCreationEventID, processCreationTestTimestamp, entries))
	if err != nil {
		t.Fatalf("event with reserved CreatorProcessId was rejected: %v", err)
	}
	if event.ParentPID != 2496 {
		t.Fatalf("creator fallback = %d, want legacy ProcessId 2496", event.ParentPID)
	}
	// A bare parent image name still yields a basename-only ancestry hop.
	entries = standardProcessCreationEntries("0x1a4", "0x9c0", `C:\Windows\System32\cmd.exe`, `cmd.exe`, "services.exe")
	event, _, err = parseProcessCreationEvent(buildProcessCreationXML(1, securityProcessCreationEventID, processCreationTestTimestamp, entries))
	if err != nil {
		t.Fatalf("event with bare parent name was rejected: %v", err)
	}
	if event.ParentImage != "services.exe" || event.ParentPath != "" || len(event.Ancestry) != 1 || event.Ancestry[0].Path != "" {
		t.Fatalf("bare parent identity = %q/%q/%+v", event.ParentImage, event.ParentPath, event.Ancestry)
	}
	// An unusable parent path is skipped without dropping the child event.
	entries = standardProcessCreationEntries("0x1a4", "0x9c0", `C:\Windows\System32\cmd.exe`, `cmd.exe`, `C:\`+strings.Repeat("a", maximumProcessImagePathBytes+16))
	event, _, err = parseProcessCreationEvent(buildProcessCreationXML(1, securityProcessCreationEventID, processCreationTestTimestamp, entries))
	if err != nil {
		t.Fatalf("event with oversized parent path was rejected: %v", err)
	}
	if event.ParentImage != "" || event.ParentPath != "" || len(event.Ancestry) != 0 {
		t.Fatalf("oversized parent identity was not omitted: %q/%q/%+v", event.ParentImage, event.ParentPath, event.Ancestry)
	}
}

func TestParseProcessCreationEventRejectsMalformed(t *testing.T) {
	valid := func() [][2]string {
		return standardProcessCreationEntries("0x1a4", "0x9c0", `C:\Windows\System32\cmd.exe`, `cmd.exe /c whoami`, `C:\Windows\System32\services.exe`)
	}
	replace := func(entries [][2]string, name, value string) [][2]string {
		result := make([][2]string, 0, len(entries))
		for _, entry := range entries {
			if entry[0] == name {
				entry[1] = value
			}
			result = append(result, entry)
		}
		return result
	}
	remove := func(entries [][2]string, name string) [][2]string {
		result := make([][2]string, 0, len(entries))
		for _, entry := range entries {
			if entry[0] == name {
				continue
			}
			result = append(result, entry)
		}
		return result
	}
	oversizedFields := make([][2]string, 0, maximumProcessEventDataFields+1)
	for index := 0; index <= maximumProcessEventDataFields; index++ {
		oversizedFields = append(oversizedFields, [2]string{fmt.Sprintf("Field%d", index), "x"})
	}
	cases := []struct {
		name string
		raw  []byte
	}{
		{name: "empty", raw: nil},
		{name: "malformed-xml", raw: []byte(`<Event><System>`)},
		{name: "wrong-root", raw: []byte(`<NotAnEvent/>`)},
		{name: "wrong-event-id", raw: buildProcessCreationXML(1, 4689, processCreationTestTimestamp, valid())},
		{name: "missing-event-id", raw: buildProcessCreationXML(1, 0, processCreationTestTimestamp, valid())},
		{name: "missing-time", raw: buildProcessCreationXML(1, securityProcessCreationEventID, "", valid())},
		{name: "invalid-time", raw: buildProcessCreationXML(1, securityProcessCreationEventID, "not-a-time", valid())},
		{name: "missing-record-id", raw: buildProcessCreationXML(0, securityProcessCreationEventID, processCreationTestTimestamp, valid())},
		{name: "negative-record-id", raw: buildProcessCreationXML(-5, securityProcessCreationEventID, processCreationTestTimestamp, valid())},
		{name: "missing-new-process-id", raw: buildProcessCreationXML(1, securityProcessCreationEventID, processCreationTestTimestamp, remove(valid(), "NewProcessId"))},
		{name: "zero-new-process-id", raw: buildProcessCreationXML(1, securityProcessCreationEventID, processCreationTestTimestamp, replace(valid(), "NewProcessId", "0x0"))},
		{name: "reserved-new-process-id", raw: buildProcessCreationXML(1, securityProcessCreationEventID, processCreationTestTimestamp, replace(valid(), "NewProcessId", "0x3"))},
		{name: "invalid-new-process-id", raw: buildProcessCreationXML(1, securityProcessCreationEventID, processCreationTestTimestamp, replace(valid(), "NewProcessId", "0xzz"))},
		{name: "negative-new-process-id", raw: buildProcessCreationXML(1, securityProcessCreationEventID, processCreationTestTimestamp, replace(valid(), "NewProcessId", "-7"))},
		{name: "overflow-new-process-id", raw: buildProcessCreationXML(1, securityProcessCreationEventID, processCreationTestTimestamp, replace(valid(), "NewProcessId", "0x100000000"))},
		{name: "missing-image", raw: buildProcessCreationXML(1, securityProcessCreationEventID, processCreationTestTimestamp, remove(valid(), "NewProcessName"))},
		{name: "relative-image", raw: buildProcessCreationXML(1, securityProcessCreationEventID, processCreationTestTimestamp, replace(valid(), "NewProcessName", "cmd.exe"))},
		{name: "oversized-image-path", raw: buildProcessCreationXML(1, securityProcessCreationEventID, processCreationTestTimestamp, replace(valid(), "NewProcessName", `C:\`+strings.Repeat("a", maximumProcessImagePathBytes)))},
		{name: "oversized-image-name", raw: buildProcessCreationXML(1, securityProcessCreationEventID, processCreationTestTimestamp, replace(valid(), "NewProcessName", `C:\`+strings.Repeat("a", maximumProcessImageNameBytes+8)+".exe"))},
		{name: "oversized-command-line", raw: buildProcessCreationXML(1, securityProcessCreationEventID, processCreationTestTimestamp, replace(valid(), "CommandLine", strings.Repeat("x", maximumProcessCommandLineBytes+1)))},
		{name: "oversized-event-data", raw: buildProcessCreationXML(1, securityProcessCreationEventID, processCreationTestTimestamp, oversizedFields)},
		{name: "wrong-channel", raw: []byte(strings.Replace(string(buildProcessCreationXML(1, securityProcessCreationEventID, processCreationTestTimestamp, valid())), "<Channel>Security</Channel>", "<Channel>Application</Channel>", 1))},
	}
	for _, testCase := range cases {
		if _, _, err := parseProcessCreationEvent(testCase.raw); err == nil {
			t.Fatalf("%s: malformed event was accepted", testCase.name)
		}
	}
	oversizedDocument := append(buildProcessCreationXML(1, securityProcessCreationEventID, processCreationTestTimestamp, valid()), make([]byte, maximumProcessEventXMLBytes)...)
	if _, _, err := parseProcessCreationEvent(oversizedDocument); err == nil {
		t.Fatal("oversized event document was accepted")
	}
}

func TestParseProcessIdentifier(t *testing.T) {
	accepted := map[string]uint32{"0x1a4": 420, "0X1A4": 420, "420": 420, " 0x4 ": 4, "4": 4}
	for raw, want := range accepted {
		got, err := parseProcessIdentifier(raw)
		if err != nil || got != want {
			t.Fatalf("parse %q = %d/%v, want %d", raw, got, err, want)
		}
	}
	for _, raw := range []string{"", "0x", "0x0", "0", "3", "-4", "4.0", "0x100000000", "abc", strings.Repeat("9", 20)} {
		if _, err := parseProcessIdentifier(raw); err == nil {
			t.Fatalf("identifier %q was accepted", raw)
		}
	}
}

func TestSanitizeVersionString(t *testing.T) {
	cases := map[string]string{
		"PowerShell.EXE":         "PowerShell.EXE",
		" \tPowerShell.EXE\r\n":  "PowerShell.EXE",
		"Power\x00Shell\x01.EXE": "PowerShell.EXE",
		strings.Repeat("a", 300): strings.Repeat("a", maximumProcessVersionStringChars),
		"":                       "",
	}
	for input, want := range cases {
		if got := sanitizeVersionString(input); got != want {
			t.Fatalf("sanitize(%q) = %q, want %q", input, got, want)
		}
	}
}

func windowsPowerShellImagePath(t *testing.T) string {
	t.Helper()
	candidates := []string{
		filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
		filepath.Join(os.Getenv("SystemRoot"), "System32", "powershell.exe"),
	}
	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
			return candidate
		}
	}
	t.Skip("Windows PowerShell image is unavailable")
	return ""
}

func copyTestImage(t *testing.T, source, destination string) {
	t.Helper()
	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatalf("read source image: %v", err)
	}
	if err := os.WriteFile(destination, data, 0o600); err != nil {
		t.Fatalf("write destination image: %v", err)
	}
}

// assertEmbeddedSignerState documents the expected signer range: embedded
// signatures verify as Valid, catalog-only or unsigned files as NotSigned. An
// "Unknown" state would mean the path boundary or WinVerifyTrust plumbing is
// broken and is never acceptable for a local regular file.
func assertEmbeddedSignerState(t *testing.T, status string) {
	t.Helper()
	if status != "Valid" && status != "NotSigned" {
		t.Fatalf("signer status = %q, want Valid or NotSigned", status)
	}
}

func TestProcessImageProbeRejectsUnsafePaths(t *testing.T) {
	systemRoot := os.Getenv("SystemRoot")
	if systemRoot == "" {
		t.Skip("SystemRoot is unavailable")
	}
	valid := filepath.Join(systemRoot, "System32", "cmd.exe")
	if info, err := os.Stat(valid); err != nil || !info.Mode().IsRegular() {
		t.Skip("cmd.exe is unavailable")
	}
	unsafe := []string{
		"",
		"cmd.exe",
		`C:Windows\System32\cmd.exe`,
		`\\server\share\cmd.exe`,
		`\\.\C:\Windows\System32\cmd.exe`,
		`\\?\C:\Windows\System32\cmd.exe`,
		valid + ":stream",
		filepath.Dir(valid),
		filepath.Join(systemRoot, "System32", "vgt-missing-image-42.exe"),
		valid + "\x00.exe",
		`C:\` + strings.Repeat("a", maximumProcessImagePathBytes+1) + ".exe",
	}
	for _, candidate := range unsafe {
		if _, _, err := inspectProcessImagePath(candidate); err == nil {
			t.Fatalf("unsafe image path %q was accepted", candidate)
		}
	}
	clean, metadata, err := inspectProcessImagePath(valid)
	if err != nil {
		t.Fatalf("valid image path rejected: %v", err)
	}
	if !strings.EqualFold(clean, valid) || metadata.Size <= 0 {
		t.Fatalf("valid image metadata = %q/%+v", clean, metadata)
	}
}

func TestProcessImageProbeRejectsJunctionComponent(t *testing.T) {
	temp := t.TempDir()
	realDirectory := filepath.Join(temp, "real")
	if err := os.MkdirAll(realDirectory, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	target := filepath.Join(realDirectory, "image.exe")
	if err := os.WriteFile(target, []byte("vgt junction probe"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	junction := filepath.Join(temp, "junction")
	if output, err := exec.Command("cmd.exe", "/c", "mklink", "/J", junction, realDirectory).CombinedOutput(); err != nil {
		t.Logf("junction creation unavailable (%v: %s); intermediate reparse case skipped", err, strings.TrimSpace(string(output)))
		return
	}
	if _, _, err := inspectProcessImagePath(filepath.Join(junction, "image.exe")); err == nil {
		t.Fatalf("reparse-point image path was accepted")
	}
}

func TestProcessImageProbeReadsRealVersionResource(t *testing.T) {
	image := windowsPowerShellImagePath(t)
	probe := &processImageProbe{}
	version, key, accepted := probe.inspect(image)
	if !accepted {
		t.Fatalf("valid image path rejected: %q", image)
	}
	if !version.available {
		t.Fatalf("version resource unavailable for %q", image)
	}
	// Windows reports MUI variants ("PowerShell.EXE.MUI") for inbox system
	// binaries; normalization must still resolve the tracked LOLBin name.
	if _, known := knownLolbinOriginalName(version.originalFilename); !known {
		t.Fatalf("original filename %q is not normalized to a tracked LOLBin", version.originalFilename)
	}
	if version.companyName == "" {
		t.Fatalf("company name is empty for %q", image)
	}
	assertEmbeddedSignerState(t, probe.signerStatus(key))
}

func TestProcessImageProbeSignerStatusUnsigned(t *testing.T) {
	unsigned := filepath.Join(t.TempDir(), "unsigned.exe")
	if err := os.WriteFile(unsigned, []byte("VGT unsigned image probe"), 0o600); err != nil {
		t.Fatalf("write unsigned image: %v", err)
	}
	probe := &processImageProbe{}
	version, _, accepted := probe.inspect(unsigned)
	if !accepted {
		t.Fatalf("regular local file was rejected by the path boundary")
	}
	if version.available {
		t.Fatalf("unsigned file unexpectedly exposes a version resource")
	}
	if status := verifyProcessImageSigner(unsigned); status != "NotSigned" {
		t.Fatalf("signer status = %q, want NotSigned", status)
	}
}

func TestProcessImageProbeCacheBound(t *testing.T) {
	probe := &processImageProbe{}
	for index := 0; index < maximumProcessImageProbeCache+64; index++ {
		probe.store(imageProbeKey{path: fmt.Sprintf(`c:\vgt\%d.exe`, index), size: int64(index), modifiedNS: int64(index)}, imageProbeEntry{})
	}
	if len(probe.cache) > maximumProcessImageProbeCache || len(probe.order) > maximumProcessImageProbeCache {
		t.Fatalf("cache unbounded: %d entries/%d order", len(probe.cache), len(probe.order))
	}
	if _, ok := probe.lookup(imageProbeKey{path: `c:\vgt\0.exe`, size: 0, modifiedNS: 0}); ok {
		t.Fatal("oldest cache entry was not evicted")
	}
}

func TestTriageProcessCreationKnownLolbin(t *testing.T) {
	image := windowsPowerShellImagePath(t)
	probe := &processImageProbe{}
	event := ProcessEvent{
		TimestampUTC: time.Now().UTC(),
		PID:          4242,
		ParentPID:    4,
		Image:        "powershell.exe",
		ImagePath:    image,
		CommandLine:  `powershell.exe -NoProfile -Command Get-Date`,
	}
	if !probe.triageProcessCreation(&event) {
		t.Fatal("known LOLBin name was not observed")
	}
	if event.OriginalImageName == "" {
		t.Fatal("original filename was not populated")
	}
	if _, known := knownLolbinOriginalName(event.OriginalImageName); !known {
		t.Fatalf("original filename = %q, want a normalized LOLBin", event.OriginalImageName)
	}
	if event.ImageVersionCompany == "" {
		t.Fatal("image version company was not populated")
	}
	assertEmbeddedSignerState(t, event.SignerStatus)
}

func TestTriageProcessCreationRenamedLolbin(t *testing.T) {
	source := windowsPowerShellImagePath(t)
	// Neutral VGT fixture name: the test intentionally copies a signed system
	// binary to prove the PE OriginalFilename relocation detection. It lives in
	// t.TempDir() and is removed afterwards; a neutral name avoids false alarms
	// in endpoint monitoring during the test run.
	destination := filepath.Join(t.TempDir(), "vgt-renamed-probe.exe")
	copyTestImage(t, source, destination)
	probe := &processImageProbe{}
	event := ProcessEvent{
		TimestampUTC: time.Now().UTC(),
		PID:          4243,
		ParentPID:    4,
		Image:        "vgt-renamed-probe.exe",
		ImagePath:    destination,
		CommandLine:  `vgt-renamed-probe.exe -NoProfile`,
	}
	if !probe.triageProcessCreation(&event) {
		t.Fatal("renamed system binary was not observed via PE OriginalFilename")
	}
	if _, known := knownLolbinOriginalName(event.OriginalImageName); !known {
		t.Fatalf("original filename = %q, want a normalized LOLBin", event.OriginalImageName)
	}
	assertEmbeddedSignerState(t, event.SignerStatus)
	if isKnownLolbinImage(event.Image) {
		t.Fatal("test image name unexpectedly equals a tracked LOLBin name")
	}
}

func TestTriageProcessCreationEncodedCommandUnknownImage(t *testing.T) {
	probe := &processImageProbe{}
	event := ProcessEvent{
		TimestampUTC: time.Now().UTC(),
		PID:          4244,
		ParentPID:    4,
		Image:        "stage.exe",
		ImagePath:    `C:\Users\Public\vgt-missing-stage.exe`,
		CommandLine:  "stage.exe -EncodedCommand " + encodedUTF16LE("Get-Date"),
	}
	if !probe.triageProcessCreation(&event) {
		t.Fatal("encoded command with an unknown image name was not observed")
	}
	if event.SignerStatus != "" || event.OriginalImageName != "" {
		t.Fatalf("unreadable image was enriched: %+v", event)
	}
}

func TestTriageProcessCreationBehaviorSignalUnknownImage(t *testing.T) {
	probe := &processImageProbe{}
	event := ProcessEvent{
		TimestampUTC: time.Now().UTC(),
		PID:          4245,
		ParentPID:    4,
		Image:        "helper.exe",
		ImagePath:    `C:\Users\Public\vgt-missing-helper.exe`,
		CommandLine:  `helper.exe -urlcache -split -f https://example.invalid/a.exe`,
	}
	if !probe.triageProcessCreation(&event) {
		t.Fatal("behavioral signal was not observed")
	}
}

func TestTriageProcessCreationBenignUnknownImageDropped(t *testing.T) {
	notepad := filepath.Join(os.Getenv("SystemRoot"), "System32", "notepad.exe")
	if info, err := os.Stat(notepad); err != nil || !info.Mode().IsRegular() {
		t.Skip("notepad.exe is unavailable")
	}
	probe := &processImageProbe{}
	event := ProcessEvent{
		TimestampUTC: time.Now().UTC(),
		PID:          4246,
		ParentPID:    4,
		Image:        "notepad.exe",
		ImagePath:    notepad,
		CommandLine:  `notepad.exe C:\Temp\notes.txt`,
	}
	if probe.triageProcessCreation(&event) {
		t.Fatalf("benign unknown image was observed: %+v", event)
	}
	if event.SignerStatus != "" || event.OriginalImageName != "" || event.ImageVersionCompany != "" {
		t.Fatalf("dropped event received enrichment: %+v", event)
	}
	if len(probe.cache) != 1 {
		t.Fatalf("version probe cache = %d entries, want exactly the inspected image", len(probe.cache))
	}
}

func TestTriageProcessCreationRelativeImageKnownName(t *testing.T) {
	probe := &processImageProbe{}
	event := ProcessEvent{
		TimestampUTC: time.Now().UTC(),
		PID:          4247,
		ParentPID:    4,
		Image:        "cmd.exe",
		ImagePath:    "cmd.exe",
		CommandLine:  `cmd.exe /c whoami`,
	}
	if !probe.triageProcessCreation(&event) {
		t.Fatal("known LOLBin name with an unusable path was not observed")
	}
	if event.SignerStatus != "" || event.OriginalImageName != "" {
		t.Fatalf("relative image path was probed: %+v", event)
	}
}

// processCreationRecordForTest builds one native stream record for the process
// sensor with a name-based LOLBin image so the test does not depend on image
// files or signature state on the host.
func processCreationRecordForTest(t *testing.T, recordID int64, pid, imagePath string) winapi.EventLogRecord {
	t.Helper()
	entries := [][2]string{
		{"NewProcessId", pid},
		{"NewProcessName", imagePath},
		{"ProcessId", "0x4"},
		{"CommandLine", `cmd.exe /c echo vgt`},
		{"ParentProcessName", `C:\Windows\System32\services.exe`},
	}
	return winapi.EventLogRecord{
		RecordID:    recordID,
		Channel:     securityChannelName,
		XML:         buildProcessCreationXML(recordID, securityProcessCreationEventID, processCreationTestTimestamp, entries),
		TimeCreated: time.Now().UTC(),
	}
}

func TestProcessEventLogResumesCursorAfterStreamFailure(t *testing.T) {
	first := processCreationRecordForTest(t, 100, "0x1a4", `C:\vgt-not-present\cmd.exe`)
	second := processCreationRecordForTest(t, 101, "0x1a5", `C:\vgt-not-present\cmd.exe`)
	var mu sync.Mutex
	var starts []int64
	stream := func(ctx context.Context, channel, xpath string, startAfterRecordID int64) (<-chan winapi.EventLogRecord, <-chan error, error) {
		if !strings.Contains(xpath, "EventID=4688") {
			t.Errorf("xpath does not select 4688: %q", xpath)
		}
		mu.Lock()
		starts = append(starts, startAfterRecordID)
		attempt := len(starts)
		mu.Unlock()
		records := make(chan winapi.EventLogRecord, 2)
		failures := make(chan error, 1)
		switch attempt {
		case 1:
			records <- first
			close(failures)
			close(records)
		case 2:
			records <- second
			go func() {
				<-ctx.Done()
				close(failures)
				close(records)
			}()
		default:
			close(failures)
			close(records)
		}
		return records, failures, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	output := make(chan ProcessEvent, 8)
	health := make(chan time.Time, 8)
	faults := make(chan error, 8)
	probe := &processImageProbe{}
	var cursor int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		superviseSensor(ctx, "process telemetry test", func(attempt context.Context) error {
			return runProcessEventLog(attempt, &cursor, probe, output, health, faults, func() error { return nil }, stream)
		}, faults, 5*time.Millisecond, 10*time.Millisecond)
	}()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("process telemetry supervisor did not stop")
		}
	}()
	waitProcessEvent := func(label string, wantPID uint32) {
		t.Helper()
		select {
		case event := <-output:
			if event.PID != wantPID {
				t.Fatalf("%s: pid = %d, want %d", label, event.PID, wantPID)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: no process event delivered", label)
		}
	}
	waitProcessEvent("first attempt", 420)
	select {
	case <-faults:
	case <-time.After(5 * time.Second):
		t.Fatal("stream closure did not surface a supervisor fault")
	}
	waitProcessEvent("resumed attempt", 421)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("process telemetry supervisor did not stop")
	}
	mu.Lock()
	gotStarts := append([]int64(nil), starts...)
	mu.Unlock()
	if len(gotStarts) < 2 || gotStarts[0] != 0 || gotStarts[1] != 100 {
		t.Fatalf("cursor handoff = %v, want [0 100 ...]", gotStarts)
	}
	if cursor != 101 {
		t.Fatalf("cursor = %d, want 101", cursor)
	}
	select {
	case <-health:
	default:
		t.Fatal("process telemetry delivered no health heartbeat")
	}
}

func TestProcessEventLogRejectsMalformedRecordWithoutReplay(t *testing.T) {
	malformed := winapi.EventLogRecord{
		RecordID:    50,
		Channel:     securityChannelName,
		XML:         []byte("<Event><System>"),
		TimeCreated: time.Now().UTC(),
	}
	valid := processCreationRecordForTest(t, 51, "0x1a4", `C:\vgt-not-present\cmd.exe`)
	var mu sync.Mutex
	var starts []int64
	stream := func(ctx context.Context, channel, xpath string, startAfterRecordID int64) (<-chan winapi.EventLogRecord, <-chan error, error) {
		mu.Lock()
		starts = append(starts, startAfterRecordID)
		attempt := len(starts)
		mu.Unlock()
		records := make(chan winapi.EventLogRecord, 2)
		failures := make(chan error, 1)
		switch attempt {
		case 1:
			records <- malformed
			close(failures)
			close(records)
		case 2:
			records <- valid
			go func() {
				<-ctx.Done()
				close(failures)
				close(records)
			}()
		default:
			close(failures)
			close(records)
		}
		return records, failures, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	output := make(chan ProcessEvent, 8)
	health := make(chan time.Time, 8)
	faults := make(chan error, 8)
	probe := &processImageProbe{}
	var cursor int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		superviseSensor(ctx, "process telemetry test", func(attempt context.Context) error {
			return runProcessEventLog(attempt, &cursor, probe, output, health, faults, func() error { return nil }, stream)
		}, faults, 5*time.Millisecond, 10*time.Millisecond)
	}()
	select {
	case fault := <-faults:
		if fault == nil {
			t.Fatal("malformed record produced an empty fault")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("malformed record did not surface a fault")
	}
	select {
	case event := <-output:
		if event.PID != 420 {
			t.Fatalf("pid = %d, want 420 from the resume record", event.PID)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("sensor did not resume after the malformed record")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("process telemetry supervisor did not stop")
	}
	mu.Lock()
	gotStarts := append([]int64(nil), starts...)
	mu.Unlock()
	if len(gotStarts) < 2 || gotStarts[1] != 50 {
		t.Fatalf("cursor after malformed record = %v, want resume at 50", gotStarts)
	}
	if cursor != 51 {
		t.Fatalf("cursor = %d, want 51", cursor)
	}
}

func TestRunProcessEventLogReportsUnavailableAuditPolicy(t *testing.T) {
	subscribed := false
	stream := func(ctx context.Context, channel, xpath string, startAfterRecordID int64) (<-chan winapi.EventLogRecord, <-chan error, error) {
		subscribed = true
		return nil, nil, errors.New("unexpected subscription")
	}
	auditErr := errors.New("process telemetry: Security 4688 command-line auditing is disabled")
	err := runProcessEventLog(
		context.Background(),
		new(int64),
		&processImageProbe{},
		make(chan ProcessEvent, 1),
		make(chan time.Time, 1),
		make(chan error, 1),
		func() error { return auditErr },
		stream,
	)
	if !errors.Is(err, auditErr) {
		t.Fatalf("audit policy error = %v, want the availability fault", err)
	}
	if subscribed {
		t.Fatal("sensor subscribed to the event log despite the unavailable audit policy")
	}
}

func TestProcessAuditAvailability(t *testing.T) {
	if err := processAuditAvailability(); err != nil {
		// The policy is host-dependent; the sensor must report a clear fault
		// instead of panicking or silently claiming healthy telemetry.
		if !strings.Contains(err.Error(), "Security 4688") {
			t.Fatalf("audit availability error is not explanatory: %v", err)
		}
		t.Logf("host audit configuration: %v", err)
	}
}

func TestReadRegistryDWORDMissingValue(t *testing.T) {
	if _, err := readRegistryDWORD(`SOFTWARE\Microsoft\Windows\CurrentVersion`, "VGT-MHX-Missing-Value-42"); !errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) {
		t.Fatalf("missing registry value error = %v", err)
	}
	if _, err := readRegistryDWORD("", "value"); err == nil {
		t.Fatal("empty registry target was accepted")
	}
}
