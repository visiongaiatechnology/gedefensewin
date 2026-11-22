// STATUS: DIAMANT VGT SUPREME
//go:build !windows

package mhx

import "errors"

type defaultContainmentExecutor struct{}

func (defaultContainmentExecutor) FreezeTree(TerminationTarget) ([]ContainmentProcess, error) {
	return nil, errors.New("windows process containment is only supported on Windows")
}

func (defaultContainmentExecutor) ResumeTree([]ContainmentProcess) (int, error) {
	return 0, errors.New("windows process containment is only supported on Windows")
}

func (defaultContainmentExecutor) TerminateTree([]ContainmentProcess) (int, error) {
	return 0, errors.New("windows process containment is only supported on Windows")
}
