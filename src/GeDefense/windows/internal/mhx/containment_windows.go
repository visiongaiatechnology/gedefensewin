// STATUS: DIAMANT VGT SUPREME
//go:build windows

package mhx

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
)

type defaultContainmentExecutor struct{}

func (defaultContainmentExecutor) FreezeTree(target TerminationTarget) ([]ContainmentProcess, error) {
	rootIdentity, err := openVerifiedTarget(target.PID, target.CreationUnixNano, target.ImagePath, winapi.ProcessSuspendResume)
	if err != nil {
		return nil, err
	}
	rootEntry := ContainmentProcess{
		PID:              target.PID,
		ParentPID:        0,
		Image:            filepath.Base(rootIdentity.ImagePath),
		ImagePath:        rootIdentity.ImagePath,
		CreationUnixNano: rootIdentity.CreationUnixNano,
		ActionState:      "FROZEN",
	}
	// Suspend root immediately before walking descendants so it cannot spawn
	// replacement child processes while the tree is enumerated.
	suspendErr := rootIdentity.Suspend()
	_ = rootIdentity.Close()
	if suspendErr != nil {
		return nil, suspendErr
	}

	tree := collectSafeDescendants(rootEntry)
	for i := 1; i < len(tree); i++ {
		child := &tree[i]
		id, openErr := openVerifiedTarget(child.PID, child.CreationUnixNano, child.ImagePath, winapi.ProcessSuspendResume)
		if openErr != nil {
			child.ActionState = "EXITED"
			continue
		}
		if err := id.Suspend(); err != nil {
			child.ActionState = "SUSPEND_FAILED"
		} else {
			child.ActionState = "FROZEN"
		}
		_ = id.Close()
	}
	return tree, nil
}

func (defaultContainmentExecutor) ResumeTree(processes []ContainmentProcess) (int, error) {
	if len(processes) == 0 {
		return 0, errors.New("no processes to resume")
	}
	// Resume children first, root last, so controlled startup dependencies stay clean.
	resumed := 0
	var firstErr error
	for i := len(processes) - 1; i >= 0; i-- {
		proc := processes[i]
		id, err := openVerifiedTarget(proc.PID, proc.CreationUnixNano, proc.ImagePath, winapi.ProcessSuspendResume)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		err = id.Resume()
		_ = id.Close()
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		resumed++
	}
	if resumed == 0 && firstErr != nil {
		return 0, firstErr
	}
	return resumed, nil
}

func (defaultContainmentExecutor) TerminateTree(processes []ContainmentProcess) (int, error) {
	if len(processes) == 0 {
		return 0, errors.New("no processes to terminate")
	}
	killed := 0
	var firstErr error
	for i := len(processes) - 1; i >= 0; i-- {
		proc := processes[i]
		id, err := openVerifiedTarget(proc.PID, proc.CreationUnixNano, proc.ImagePath, winapi.ProcessTerminate)
		if err != nil {
			continue
		}
		err = id.Terminate(0xC0000420)
		_ = id.Close()
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		killed++
	}
	if killed == 0 && firstErr != nil {
		return 0, firstErr
	}
	return killed, nil
}

func openVerifiedTarget(pid uint32, expectedCreationNano int64, expectedImagePath string, access uint32) (winapi.ProcessIdentity, error) {
	if pid <= 4 || pid == uint32(os.Getpid()) || isTrackedChild(pid) {
		return winapi.ProcessIdentity{}, errors.New("protected process boundary")
	}
	if expectedCreationNano <= 0 || strings.TrimSpace(expectedImagePath) == "" {
		return winapi.ProcessIdentity{}, errors.New("process identity evidence incomplete")
	}
	if IsProtectedOSProcess("", expectedImagePath) || isGeDefenseBinary(expectedImagePath) {
		return winapi.ProcessIdentity{}, errors.New("protected process boundary")
	}
	identity, err := winapi.OpenProcessIdentityAccess(pid, access)
	if err != nil {
		return winapi.ProcessIdentity{}, fmt.Errorf("open pid %d: %w", pid, err)
	}
	diff := time.Duration(identity.CreationUnixNano - expectedCreationNano)
	if diff < 0 {
		diff = -diff
	}
	if diff > 2*time.Second {
		_ = identity.Close()
		return winapi.ProcessIdentity{}, errors.New("process identity changed before containment: creation time mismatch")
	}
	if !winapi.SameImagePath(identity.ImagePath, expectedImagePath) {
		_ = identity.Close()
		return winapi.ProcessIdentity{}, errors.New("process image changed before containment: image path mismatch")
	}
	if IsProtectedOSProcess("", identity.ImagePath) || isGeDefenseBinary(identity.ImagePath) {
		_ = identity.Close()
		return winapi.ProcessIdentity{}, errors.New("protected process boundary")
	}
	return identity, nil
}

func collectSafeDescendants(root ContainmentProcess) []ContainmentProcess {
	result := []ContainmentProcess{root}
	all, err := winapi.ProcessList()
	if err != nil || len(all) == 0 {
		return result
	}
	childrenByParent := make(map[uint32][]winapi.ProcessEntry, len(all)/2+1)
	for _, entry := range all {
		if entry.PID <= 4 || entry.PID == root.PID {
			continue
		}
		childrenByParent[entry.ParentPID] = append(childrenByParent[entry.ParentPID], entry)
	}

	type queueItem struct {
		entry         winapi.ProcessEntry
		parentCreated int64
		depth         int
	}
	visited := map[uint32]struct{}{root.PID: {}}
	queue := make([]queueItem, 0, 16)
	for _, c := range childrenByParent[root.PID] {
		queue = append(queue, queueItem{entry: c, parentCreated: root.CreationUnixNano, depth: 1})
	}
	selfPID := uint32(os.Getpid())
	for len(queue) > 0 && len(result) < maximumContainmentTree {
		item := queue[0]
		queue = queue[1:]
		if item.depth > maximumContainmentDepth {
			continue
		}
		pid := item.entry.PID
		if _, seen := visited[pid]; seen || pid <= 4 || pid == selfPID || isTrackedChild(pid) {
			continue
		}
		visited[pid] = struct{}{}
		id, err := winapi.OpenProcessIdentityAccess(pid, winapi.ProcessQueryLimitedInformation)
		if err != nil {
			continue
		}
		childCreated := id.CreationUnixNano
		childPath := id.ImagePath
		_ = id.Close()
		// Guard against PPID reuse: a true descendant cannot predate its parent.
		if childCreated <= 0 || childCreated < item.parentCreated-int64(2*time.Second) {
			continue
		}
		if IsProtectedOSProcess(item.entry.Image, childPath) || isGeDefenseBinary(childPath) {
			continue
		}
		result = append(result, ContainmentProcess{
			PID:              pid,
			ParentPID:        item.entry.ParentPID,
			Image:            filepath.Base(childPath),
			ImagePath:        childPath,
			CreationUnixNano: childCreated,
			ActionState:      "DISCOVERED",
		})
		for _, grand := range childrenByParent[pid] {
			queue = append(queue, queueItem{entry: grand, parentCreated: childCreated, depth: item.depth + 1})
		}
	}
	return result
}
