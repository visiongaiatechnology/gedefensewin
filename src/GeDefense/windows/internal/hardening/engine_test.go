// STATUS: DIAMANT VGT SUPREME
package hardening

import (
	"context"
	"testing"
	"time"
)

func TestPostureReturnsCachedResultImmediately(t *testing.T) {
	expected := Result{
		ComputerName:       "TEST-NODE",
		WindowsProductName: "Windows 11 Pro",
		Defender:           true,
		DefenderService:    true,
		RealTimeProtection: true,
	}
	engine := &Engine{
		cached:   expected,
		cachedAt: time.Now(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	result, err := engine.Posture(ctx)
	if err != nil {
		t.Fatalf("Posture() error = %v", err)
	}
	if result.ComputerName != expected.ComputerName {
		t.Fatalf("got ComputerName %q, want %q", result.ComputerName, expected.ComputerName)
	}
	if !result.Defender || !result.RealTimeProtection {
		t.Fatalf("cached result properties mismatched: %+v", result)
	}
}

func TestPostureReturnsStaleCacheWithoutBlocking(t *testing.T) {
	expected := Result{
		ComputerName:       "STALE-NODE",
		WindowsProductName: "Windows 11 Enterprise",
		Defender:           true,
	}
	// Cache is 10 minutes old (> 2 minutes threshold)
	engine := &Engine{
		cached:   expected,
		cachedAt: time.Now().Add(-10 * time.Minute),
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	start := time.Now()
	result, err := engine.Posture(ctx)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Posture() error = %v", err)
	}
	if elapsed > 100*time.Millisecond {
		t.Fatalf("Posture() blocked for %v, expected instant response from stale cache", elapsed)
	}
	if result.ComputerName != expected.ComputerName {
		t.Fatalf("got ComputerName %q, want %q", result.ComputerName, expected.ComputerName)
	}
}

func TestPostureColdStartNeverInventsHealthyState(t *testing.T) {
	engine := &Engine{script: `C:
onexistent\script.ps1`, operationRoot: t.TempDir()}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	result, err := engine.Posture(ctx)
	if err == nil {
		t.Fatal("unavailable initial audit must return an error")
	}
	if result.Defender || result.RealTimeProtection || result.Firewall {
		t.Fatalf("unverified security controls reported healthy: %+v", result)
	}
}
