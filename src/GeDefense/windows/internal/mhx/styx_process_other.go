// STATUS: PLATIN VGT SUPREME
//go:build !windows

package mhx

import "time"

type styxProcessResolver struct{}

func newStyxProcessResolver(_ func() time.Time) *styxProcessResolver {
	return &styxProcessResolver{}
}

func (r *styxProcessResolver) Resolve(_ int) (string, string) {
	return "", ""
}
