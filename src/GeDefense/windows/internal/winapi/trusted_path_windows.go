// STATUS: PLATIN VGT SUPREME
//go:build windows

package winapi

// ValidateReparseFreeLocalPath proves that path is an absolute path on a local
// fixed drive whose existing components contain no symlink, junction or mount
// point. It is the anchor-side companion to the Authenticode path validation:
// callers that are about to grant trust based on a path prefix use this to make
// sure the prefix cannot be redirected through a reparse point.
//
// A component that does not exist yet is not an error; opening the final file
// fails closed on its own. Relative, UNC and device paths are rejected.
func ValidateReparseFreeLocalPath(path string) error {
	_, err := validateAuthenticodePath(path)
	return err
}
