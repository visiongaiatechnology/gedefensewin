// STATUS: PLATIN VGT SUPREME
//go:build windows

package winapi

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"
)

var (
	procStartTraceW    = advapi32.NewProc("StartTraceW")
	procEnableTraceEx2 = advapi32.NewProc("EnableTraceEx2")
	procControlTraceW  = advapi32.NewProc("ControlTraceW")
	procOpenTraceW     = advapi32.NewProc("OpenTraceW")
	procProcessTrace   = advapi32.NewProc("ProcessTrace")
	procCloseTrace     = advapi32.NewProc("CloseTrace")

	etwCallbackOnce sync.Once
	etwCallbackPtr  uintptr
	etwSessionsMu   sync.RWMutex
	etwSessions     = make(map[uintptr]*ETWSession)
	etwNextToken    atomic.Uintptr
)

// ETWSession owns one live real-time ETW trace session and its consumer thread.
type ETWSession struct {
	name         string
	providers    []ETWProviderConfig
	events       chan ETWEvent
	traceHandle  uint64
	openHandle   uint64
	token        uintptr
	resolveProps bool

	mu        sync.Mutex
	started   bool
	closed    bool
	lastError string
	wg        sync.WaitGroup

	readCount atomic.Uint64
	dropCount atomic.Uint64
}

// NewETWSession constructs a validated real-time ETW session without OS side effects.
func NewETWSession(cfg ETWConfig) (*ETWSession, error) {
	name := strings.TrimSpace(cfg.SessionName)
	if name == "" || len(name) > maxETWNameChars {
		return nil, errors.New("winapi etw: session name is required and bounded")
	}
	if len(cfg.Providers) == 0 || len(cfg.Providers) > 16 {
		return nil, errors.New("winapi etw: between 1 and 16 providers are required")
	}
	qSize := cfg.QueueSize
	if qSize <= 0 || qSize > maxETWEventQueue {
		qSize = maxETWEventQueue
	}
	providers := append([]ETWProviderConfig(nil), cfg.Providers...)
	return &ETWSession{
		name:         name,
		providers:    providers,
		events:       make(chan ETWEvent, qSize),
		openHandle:   invalidProcessedTraceHandle,
		resolveProps: true,
	}, nil
}

// Events returns the bounded read-only channel of received ETW events.
func (s *ETWSession) Events() <-chan ETWEvent {
	return s.events
}

// Status returns current session counters.
func (s *ETWSession) Status() ETWStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return ETWStatus{
		SessionName:   s.name,
		Running:       s.started && !s.closed,
		EventsRead:    s.readCount.Load(),
		DroppedEvents: s.dropCount.Load(),
		LastError:     s.lastError,
	}
}

// Start creates the ETW kernel trace session, enables configured providers,
// opens the real-time consumer handle, and spawns the ProcessTrace loop.
func (s *ETWSession) Start(ctx context.Context) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return errors.New("winapi etw: session already started")
	}
	if s.closed {
		s.mu.Unlock()
		return errors.New("winapi etw: session already closed")
	}

	nameUTF16, err := syscall.UTF16FromString(s.name)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	propsBuf, props := buildETWPropertiesBuffer(nameUTF16)

	var traceHandle uint64
	r1, _, _ := procStartTraceW.Call(
		uintptr(unsafe.Pointer(&traceHandle)),
		uintptr(unsafe.Pointer(&nameUTF16[0])),
		uintptr(unsafe.Pointer(&propsBuf[0])),
	)
	if r1 == uintptr(ErrorAlreadyExists) {
		_ = stopTraceByName(s.name)
		r1, _, _ = procStartTraceW.Call(
			uintptr(unsafe.Pointer(&traceHandle)),
			uintptr(unsafe.Pointer(&nameUTF16[0])),
			uintptr(unsafe.Pointer(&propsBuf[0])),
		)
	}
	runtime.KeepAlive(propsBuf)
	runtime.KeepAlive(props)
	if r1 != 0 {
		err := fmt.Errorf("winapi etw StartTraceW(%s): %w", s.name, syscall.Errno(r1))
		s.lastError = err.Error()
		s.mu.Unlock()
		return err
	}

	for _, prov := range s.providers {
		level := prov.Level
		if level == 0 {
			level = traceLevelInformation
		}
		guid := prov.GUID
		rEnable, _, _ := procEnableTraceEx2.Call(
			uintptr(traceHandle),
			uintptr(unsafe.Pointer(&guid)),
			uintptr(eventControlCodeEnableProvider),
			uintptr(level),
			uintptr(prov.MatchAnyKeyword),
			0,
			0,
			0,
		)
		if rEnable != 0 {
			_ = stopTraceByHandle(traceHandle, nameUTF16)
			err := fmt.Errorf("winapi etw EnableTraceEx2(%s): %w", formatGUID(guid), syscall.Errno(rEnable))
			s.lastError = err.Error()
			s.mu.Unlock()
			return err
		}
	}

	token := registerETWSession(s)
	var logfile eventTraceLogfileW
	logfile.LoggerName = &nameUTF16[0]
	logfile.ProcessTraceMode = processTraceModeRealTime | processTraceModeEventRecord
	logfile.EventRecordCallback = getETWRecordCallback()
	logfile.Context = token

	openHandle, _, openErr := procOpenTraceW.Call(uintptr(unsafe.Pointer(&logfile)))
	runtime.KeepAlive(nameUTF16)
	if uint64(openHandle) == invalidProcessedTraceHandle || openHandle == 0 {
		unregisterETWSession(token)
		_ = stopTraceByHandle(traceHandle, nameUTF16)
		err := fmt.Errorf("winapi etw OpenTraceW: %w", errnoResult(openErr))
		s.lastError = err.Error()
		s.mu.Unlock()
		return err
	}

	s.traceHandle = traceHandle
	s.openHandle = uint64(openHandle)
	s.token = token
	s.started = true
	s.wg.Add(1)
	s.mu.Unlock()

	go s.runProcessTrace()
	if ctx != nil {
		go func() {
			<-ctx.Done()
			_ = s.Close()
		}()
	}
	return nil
}

func (s *ETWSession) runProcessTrace() {
	defer s.wg.Done()
	handle := s.openHandle
	r1, _, _ := procProcessTrace.Call(uintptr(unsafe.Pointer(&handle)), 1, 0, 0)
	if r1 != 0 && r1 != 1223 { // ERROR_CANCELLED
		s.mu.Lock()
		if !s.closed {
			s.lastError = fmt.Sprintf("ProcessTrace: %v", syscall.Errno(r1))
		}
		s.mu.Unlock()
	}
}

// Close stops the real-time trace session and unblocks ProcessTrace idempotently.
func (s *ETWSession) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	traceHandle := s.traceHandle
	openHandle := s.openHandle
	token := s.token
	started := s.started
	s.mu.Unlock()

	if openHandle != invalidProcessedTraceHandle && openHandle != 0 {
		_, _, _ = procCloseTrace.Call(uintptr(openHandle))
	}
	if traceHandle != 0 {
		if nameUTF16, err := syscall.UTF16FromString(s.name); err == nil {
			_ = stopTraceByHandle(traceHandle, nameUTF16)
		}
	}
	if started {
		s.wg.Wait()
	}
	if token != 0 {
		unregisterETWSession(token)
	}
	return nil
}

func buildETWPropertiesBuffer(nameUTF16 []uint16) ([]byte, *eventTraceProperties) {
	propsSize := int(unsafe.Sizeof(eventTraceProperties{}))
	nameBytes := len(nameUTF16) * 2
	total := propsSize + nameBytes + 4
	buf := make([]byte, total)
	props := (*eventTraceProperties)(unsafe.Pointer(&buf[0]))
	props.Wnode.BufferSize = uint32(total)
	props.Wnode.Flags = wnodeFlagTracedGUID
	props.Wnode.ClientContext = 1 // QPC clock
	props.BufferSize = 64
	props.MinimumBuffers = 4
	props.MaximumBuffers = 64
	props.LogFileMode = eventTraceRealTimeMode | eventTraceNoPerProcessorBuffering
	props.FlushTimer = 1
	props.LoggerNameOffset = uint32(propsSize)
	return buf, props
}

func stopTraceByName(name string) error {
	nameUTF16, err := syscall.UTF16FromString(name)
	if err != nil {
		return err
	}
	buf, _ := buildETWPropertiesBuffer(nameUTF16)
	r1, _, _ := procControlTraceW.Call(0, uintptr(unsafe.Pointer(&nameUTF16[0])), uintptr(unsafe.Pointer(&buf[0])), uintptr(eventTraceControlStop))
	runtime.KeepAlive(buf)
	if r1 != 0 {
		return syscall.Errno(r1)
	}
	return nil
}

func stopTraceByHandle(handle uint64, nameUTF16 []uint16) error {
	buf, _ := buildETWPropertiesBuffer(nameUTF16)
	r1, _, _ := procControlTraceW.Call(uintptr(handle), 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(eventTraceControlStop))
	runtime.KeepAlive(buf)
	if r1 != 0 {
		return syscall.Errno(r1)
	}
	return nil
}

func registerETWSession(s *ETWSession) uintptr {
	token := etwNextToken.Add(1)
	if token == 0 {
		token = etwNextToken.Add(1)
	}
	etwSessionsMu.Lock()
	etwSessions[token] = s
	etwSessionsMu.Unlock()
	return token
}

func unregisterETWSession(token uintptr) {
	etwSessionsMu.Lock()
	delete(etwSessions, token)
	etwSessionsMu.Unlock()
}

func getETWRecordCallback() uintptr {
	etwCallbackOnce.Do(func() {
		etwCallbackPtr = syscall.NewCallback(func(rec *eventRecord) uintptr {
			if rec == nil {
				return 0
			}
			etwSessionsMu.RLock()
			sess := etwSessions[rec.UserContext]
			etwSessionsMu.RUnlock()
			if sess == nil {
				return 0
			}
			ev, err := parseEventRecord(rec, sess.resolveProps)
			if err != nil {
				return 0
			}
			sess.readCount.Add(1)
			select {
			case sess.events <- ev:
			default:
				sess.dropCount.Add(1)
			}
			return 0
		})
	})
	return etwCallbackPtr
}
