// STATUS: DIAMANT VGT SUPREME
package main

import (
	"flag"
	"fmt"

	"github.com/visiongaiatechnology/gedefense/windows/internal/launcher"
	"github.com/visiongaiatechnology/gedefense/windows/internal/product"
	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
)

func main() {
	showVersion := flag.Bool("version", false, "show version")
	flag.Parse()
	if *showVersion {
		_ = winapi.MessageBox("VGT GeDefense Center", fmt.Sprintf("GeDefense Center %s", product.Version), winapi.MBIconInformation)
		return
	}
	mutex, existed, err := winapi.CreateMutex(`Local\VGT.GeDefense.Center.v4`)
	if err != nil {
		_ = winapi.MessageBox("VGT GeDefense Center", "GeDefense Center konnte nicht exklusiv gestartet werden.", winapi.MBIconError)
		return
	}
	defer winapi.CloseHandle(mutex)
	if existed {
		return
	}
	if err := launcher.Open(); err != nil {
		_ = winapi.MessageBox("VGT GeDefense Center", "GeDefense Center konnte nicht authentifiziert geöffnet werden.", winapi.MBIconError)
	}
}
