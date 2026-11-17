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
	"github.com/visiongaiatechnology/gedefense/windows/internal/product"
	"github.com/visiongaiatechnology/gedefense/windows/internal/service"
)

func main() {
	console := flag.Bool("console", false, "run interactively")
	showVersion := flag.Bool("version", false, "print version")
	launch := flag.Bool("launch", false, "open the authenticated local security center")
	prepareUpgrade := flag.Bool("prepare-upgrade", false, "migrate legacy state and verify service initialization before start")
	preserveUpgradeSetup := flag.Bool("preserve-upgrade-setup", false, "preserve completed first-run setup marker on installer upgrades")
	flag.Parse()
	if *showVersion {
		fmt.Println(product.Version)
		return
	}
	if *launch {
		if err := launcher.Open(); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *preserveUpgradeSetup {
		if err := app.PreserveSetupOnUpgrade(product.Version); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	executable, err := os.Executable()
	if err != nil {
		log.Fatal(err)
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(executable), ".."))
	if *prepareUpgrade {
		if err := app.PrepareUpgrade(root, product.Version); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if *console {
		runner := func(stop <-chan struct{}) error {
			if migErr := app.MigrateLegacyEvidenceOnStartup(); migErr != nil {
				log.Printf("legacy evidence startup migration warning: %v", migErr)
			}
			application, createErr := app.New(root, product.Version)
			if createErr != nil {
				return createErr
			}
			return application.Run(stop)
		}
		if err := service.RunConsole(runner); err != nil {
			log.Fatal(err)
		}
		return
	}
	if err := service.RunWithReady("VGTGeDefense", func(stop <-chan struct{}, ready func()) error {
		if migErr := app.MigrateLegacyEvidenceOnStartup(); migErr != nil {
			log.Printf("legacy evidence startup migration warning: %v", migErr)
		}
		application, createErr := app.New(root, product.Version)
		if createErr != nil {
			return createErr
		}
		return application.RunWithReady(stop, ready)
	}); err != nil {
		log.Fatal(err)
	}
}
