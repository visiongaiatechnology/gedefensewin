// STATUS: DIAMANT VGT SUPREME
//go:build windows

package secretfs

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// buildSelfRelativeDescriptor builds a minimal self-relative SECURITY_DESCRIPTOR
// with one DACL so the DACL inspector can be tested without touching a real
// filesystem ACL (the test process may not be allowed to apply administrator-only
// DACLs without locking itself out).
func buildSelfRelativeDescriptor(t *testing.T, aceType byte, aceFlagsList []byte, sids []string) []byte {
	t.Helper()
	// Real self-relative descriptor: the DACL member is a 32-bit offset.
	header := make([]byte, 20)
	header[0] = 1 // SECURITY_DESCRIPTOR_REVISION
	binary.LittleEndian.PutUint16(header[2:4], 0x8000|daclPresentControl)
	daclOffset := len(header)
	binary.LittleEndian.PutUint32(header[16:20], uint32(daclOffset))

	aces := make([][]byte, 0, len(sids))
	for index, sid := range sids {
		aceFlags := byte(0)
		if index < len(aceFlagsList) {
			aceFlags = aceFlagsList[index]
		}
		sidBytes := encodeSID(t, sid)
		ace := make([]byte, 8+len(sidBytes))
		ace[0] = aceType
		ace[1] = aceFlags
		binary.LittleEndian.PutUint16(ace[2:4], uint16(len(ace)))
		binary.LittleEndian.PutUint32(ace[4:8], 0x001F01FF)
		copy(ace[8:], sidBytes)
		aces = append(aces, ace)
	}
	aclSize := 8
	for _, ace := range aces {
		aclSize += len(ace)
	}
	buffer := append([]byte(nil), header...)
	acl := make([]byte, aclSize)
	acl[0] = 2
	binary.LittleEndian.PutUint16(acl[2:4], uint16(aclSize))
	binary.LittleEndian.PutUint16(acl[4:6], uint16(len(aces)))
	position := 8
	for _, ace := range aces {
		copy(acl[position:], ace)
		position += len(ace)
	}
	buffer = append(buffer, acl...)
	return buffer
}

func encodeSID(t *testing.T, value string) []byte {
	t.Helper()
	switch value {
	case "S-1-5-18":
		return []byte{1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0}
	case "S-1-5-32-544":
		return []byte{1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x20, 0x02, 0, 0}
	case "S-1-5-32-545":
		return []byte{1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x21, 0x02, 0, 0}
	default:
		t.Fatalf("unsupported test SID %q", value)
		return nil
	}
}

// Inspect a real GetFileSecurityW result. This is the regression test for the
// self-relative layout bug: synthetic descriptors only prove the parser, real
// filesystem descriptors prove the actual service-start path.
func TestInspectPathDACLReadsRealFileDescriptor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	restricted, detail, err := inspectPathDACL(path)
	if err != nil {
		t.Fatalf("real DACL inspection failed: %v (%s)", err, detail)
	}
	_ = restricted // temp file DACL is permissive; only the parse must succeed
}

func TestInspectSecurityDescriptorAcceptsServiceOnlyDACL(t *testing.T) {
	buffer := buildSelfRelativeDescriptor(t, accessAllowedACEType, nil, []string{"S-1-5-18", "S-1-5-32-544"})
	restricted, detail, err := inspectSecurityDescriptor(buffer)
	if err != nil || !restricted {
		t.Fatalf("service DACL rejected: restricted=%t err=%v detail=%s", restricted, err, detail)
	}
}

func TestInspectSecurityDescriptorRejectsOperatorReadableDACL(t *testing.T) {
	buffer := buildSelfRelativeDescriptor(t, accessAllowedACEType, nil, []string{"S-1-5-18", "S-1-5-32-544", "S-1-5-32-545"})
	restricted, detail, err := inspectSecurityDescriptor(buffer)
	if err == nil && restricted {
		t.Fatal("DACL granting Users access was accepted")
	}
	if restricted {
		t.Fatalf("restricted=%t detail=%s", restricted, detail)
	}
}

func TestInspectSecurityDescriptorRejectsInheritedACE(t *testing.T) {
	buffer := buildSelfRelativeDescriptor(t, accessAllowedACEType, []byte{inheritedACEFlag, 0, 0}, []string{"S-1-5-18", "S-1-5-32-544", "S-1-5-32-545"})
	restricted, detail, _ := inspectSecurityDescriptor(buffer)
	if restricted {
		t.Fatalf("inherited ACE was accepted: %s", detail)
	}
}

func TestInspectSecurityDescriptorRejectsNullDACL(t *testing.T) {
	buffer := buildSelfRelativeDescriptor(t, accessAllowedACEType, nil, []string{"S-1-5-18"})
	binary.LittleEndian.PutUint16(buffer[2:4], 0x8000)
	restricted, detail, _ := inspectSecurityDescriptor(buffer)
	if restricted {
		t.Fatalf("NULL DACL was accepted: %s", detail)
	}
}

func TestFormatSID(t *testing.T) {
	for _, value := range []string{"S-1-5-18", "S-1-5-32-544", "S-1-5-32-545"} {
		formatted, err := formatSID(encodeSID(t, value))
		if err != nil || formatted != value {
			t.Fatalf("formatSID(%q)=%q err=%v", value, formatted, err)
		}
	}
}
