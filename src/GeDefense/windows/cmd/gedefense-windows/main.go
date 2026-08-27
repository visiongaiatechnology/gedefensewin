// STATUS: DIAMANT VGT SUPREME
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/visiongaiatechnology/gedefense/windows/internal/app"
	"github.com/visiongaiatechnology/gedefense/windows/internal/launcher"
	"github.com/visiongaiatechnology/gedefense/windows/internal/service"
)

const version = "2.3.2-vgt.win17"

func main() {
	console := flag.Bool("console", false, "run interactively")
	showVersion := flag.Bool("version", false, "print version")
	launch := flag.Bool("launch", false, "open the authenticated local security center")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	if *launch {
		if err := launcher.Open(); err != nil {
			log.Fatal(err)
		}
		return
	}

	executable, err := os.Executable()
	if err != nil {
		log.Fatal(err)
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(executable), ".."))
	runner := func(stop <-chan struct{}) error {
		application, createErr := app.New(root, version)
		if createErr != nil {
			return createErr
		}
		return application.Run(stop)
	}
	if *console {
		if err := service.RunConsole(runner); err != nil {
			log.Fatal(err)
		}
		return
	}
	if err := service.Run("VGTGeDefense", runner); err != nil {
		log.Fatal(err)
	}
}
