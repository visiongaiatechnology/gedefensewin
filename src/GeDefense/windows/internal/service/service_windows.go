// STATUS: DIAMANT VGT SUPREME
package service

import (
	"errors"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/sys/windows/svc"
)

type Runner func(stop <-chan struct{}) error

type handler struct{ run Runner }

func (h handler) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- h.run(stop) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case request := <-requests:
			switch request.Cmd {
			case svc.Interrogate:
				status <- request.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				close(stop)
				err := <-done
				status <- svc.Status{State: svc.Stopped}
				if err != nil {
					return true, 1
				}
				return false, 0
			}
		case err := <-done:
			status <- svc.Status{State: svc.Stopped}
			if err != nil {
				return true, 1
			}
			return false, 0
		}
	}
}

func Run(name string, runner Runner) error {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return err
	}
	if !isService {
		return errors.New("not running under the Windows Service Control Manager; use --console")
	}
	return svc.Run(name, handler{run: runner})
}

func RunConsole(runner Runner) error {
	stop := make(chan struct{})
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-signals
		close(stop)
	}()
	return runner(stop)
}
