// STATUS: DIAMANT VGT SUPREME
//go:build windows

package parsercells

import (
	"errors"
	"fmt"
	"strings"
	"unsafe"
)

// AppContainer profile adapter. userenv.dll creates the per-cell profile that
// gives the parser a token with no capabilities (and therefore no network). The
// profile name is the only identity source and is derived from the validated
// cell UUID, never from caller-controlled text.

const (
	// parserCellProfilePrefix namespaces every profile this package creates so
	// crash cleanup can recognize its own leftovers without guessing.
	parserCellProfilePrefix = "VGT.ParserCell."
	// parserCellDisplayName is the bounded, constant display name.
	parserCellDisplayName = "GeDefense Parser Cell"
	// parserCellDescription is the bounded, constant profile description.
	parserCellDescription = "Ephemeral isolated document parser (GeDefense V6)"
)

var (
	procCreateAppContainerProfile = userenv.NewProc("CreateAppContainerProfile")
	procDeleteAppContainerProfile = userenv.NewProc("DeleteAppContainerProfile")
	procDeriveAppContainerSID     = userenv.NewProc("DeriveAppContainerSidFromAppContainerName")
)

// container is one created AppContainer profile: its validated name and the
// canonical SID string that the token must carry.
type container struct {
	Name string
	SID  string
}

// containerBackend is the injectable AppContainer adapter.
type containerBackend interface {
	Create(name string) (container, error)
	DeriveSID(name string) (string, error)
	Delete(name string) error
}

// windowsContainers is the production adapter backed by userenv.dll.
type windowsContainers struct{}

// newContainerName derives the strict profile name for a validated cell UUID.
func newContainerName(cellID string) (string, error) {
	if !validCellID(cellID) {
		return "", &Error{Op: "container.name", Kind: ErrInvalidState,
			Detail: "cell id is not a canonical UUID v4: " + sanitizeText(cellID)}
	}
	return parserCellProfilePrefix + cellID, nil
}

// validateContainerName enforces the exact "VGT.ParserCell.<uuid>" shape. It is
// applied to every name the package passes to userenv.dll, including names read
// back from crash-cleanup journals.
func validateContainerName(name string) error {
	if !strings.HasPrefix(name, parserCellProfilePrefix) {
		return &Error{Op: "container.name", Kind: ErrInvalidState,
			Detail: "profile name does not use the parser-cell prefix: " + sanitizeText(name)}
	}
	cellID := strings.TrimPrefix(name, parserCellProfilePrefix)
	if !validCellID(cellID) {
		return &Error{Op: "container.name", Kind: ErrInvalidState,
			Detail: "profile name does not embed a canonical UUID v4: " + sanitizeText(name)}
	}
	return nil
}

// cellIDFromContainerName extracts the validated cell UUID from a profile name.
func cellIDFromContainerName(name string) (string, error) {
	if err := validateContainerName(name); err != nil {
		return "", err
	}
	return strings.TrimPrefix(name, parserCellProfilePrefix), nil
}

// Create creates a new AppContainer profile with zero capabilities and returns
// its SID after a derive read-back. An existing profile is an error: a cell
// never reuses (and therefore never trusts) a pre-existing container.
func (windowsContainers) Create(name string) (container, error) {
	if err := validateContainerName(name); err != nil {
		return container{}, err
	}
	display, err := utf16Ptr(parserCellDisplayName)
	if err != nil {
		return container{}, fmt.Errorf("parsercells: profile display name: %w", err)
	}
	description, err := utf16Ptr(parserCellDescription)
	if err != nil {
		return container{}, fmt.Errorf("parsercells: profile description: %w", err)
	}
	namePointer, err := utf16Ptr(name)
	if err != nil {
		return container{}, fmt.Errorf("parsercells: profile name: %w", err)
	}
	var sidPointer uintptr
	result, _, _ := procCreateAppContainerProfile.Call(
		uintptr(unsafe.Pointer(namePointer)),
		uintptr(unsafe.Pointer(display)),
		uintptr(unsafe.Pointer(description)),
		0, // no capabilities: the kernel network lock
		0, // capability count zero
		uintptr(unsafe.Pointer(&sidPointer)),
	)
	if err := hresultError("CreateAppContainerProfile", result); err != nil {
		return container{}, fmt.Errorf("parsercells: %w", err)
	}
	if sidPointer == 0 {
		return container{}, &Error{Op: "container.create", Kind: ErrIsolationNotVerified,
			Detail: "CreateAppContainerProfile returned an empty SID"}
	}
	defer freeSID(sidPointer)
	createdSID, err := sidToString(sidPointer)
	if err != nil {
		return container{}, fmt.Errorf("parsercells: created SID conversion: %w", err)
	}
	derivedSID, err := deriveContainerSID(name)
	if err != nil {
		return container{}, fmt.Errorf("parsercells: SID derive read-back: %w", err)
	}
	if derivedSID != createdSID {
		return container{}, &Error{Op: "container.create", Kind: ErrIsolationNotVerified,
			Detail: "derived SID does not match created SID"}
	}
	return container{Name: name, SID: createdSID}, nil
}

// DeriveSID returns the SID of an existing profile.
func (windowsContainers) DeriveSID(name string) (string, error) {
	if err := validateContainerName(name); err != nil {
		return "", err
	}
	return deriveContainerSID(name)
}

// Delete removes the named profile. A missing profile satisfies the idempotent
// cleanup contract.
func (windowsContainers) Delete(name string) error {
	if err := validateContainerName(name); err != nil {
		return err
	}
	namePointer, err := utf16Ptr(name)
	if err != nil {
		return fmt.Errorf("parsercells: profile name: %w", err)
	}
	result, _, _ := procDeleteAppContainerProfile.Call(uintptr(unsafe.Pointer(namePointer)))
	if err := hresultError("DeleteAppContainerProfile", result); err != nil {
		if errors.Is(err, ErrContainerNotFound) {
			return nil
		}
		return fmt.Errorf("parsercells: %w", err)
	}
	return nil
}

// deriveContainerSID calls DeriveAppContainerSidFromAppContainerName and
// converts the SID into its canonical string form.
func deriveContainerSID(name string) (string, error) {
	namePointer, err := utf16Ptr(name)
	if err != nil {
		return "", fmt.Errorf("parsercells: profile name: %w", err)
	}
	var sidPointer uintptr
	result, _, _ := procDeriveAppContainerSID.Call(
		uintptr(unsafe.Pointer(namePointer)),
		uintptr(unsafe.Pointer(&sidPointer)),
	)
	if err := hresultError("DeriveAppContainerSidFromAppContainerName", result); err != nil {
		return "", fmt.Errorf("parsercells: %w", err)
	}
	if sidPointer == 0 {
		return "", &Error{Op: "container.derive", Kind: ErrIsolationNotVerified,
			Detail: "derived an empty SID"}
	}
	defer freeSID(sidPointer)
	return sidToString(sidPointer)
}

// platform adapter delegation.
func (p *windowsPlatform) CreateContainer(name string) (container, error) {
	return windowsContainers{}.Create(name)
}

func (p *windowsPlatform) DeriveContainerSID(name string) (string, error) {
	return windowsContainers{}.DeriveSID(name)
}

func (p *windowsPlatform) DeleteContainer(name string) error {
	return windowsContainers{}.Delete(name)
}
