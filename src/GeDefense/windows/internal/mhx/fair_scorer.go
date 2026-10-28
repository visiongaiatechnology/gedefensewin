// STATUS: DIAMANT VGT SUPREME
package mhx

import (
	"path/filepath"
	"strings"
)

type ThreatScoreResult struct {
	Score       int      `json:"score"`
	Level       string   `json:"level"`
	Action      string   `json:"action"`
	Factors     []string `json:"factors"`
	IsExempt    bool     `json:"isExempt"`
	AppIdent    string   `json:"appIdent"`
	StrikeEvent bool     `json:"strikeEvent"`
}

func CalculateFairScore(event ProcessEvent, isAllowed bool, appName string, sigMatched bool, sigID string, amsiPatched bool, lineageBreach bool, threatHit bool, titanCompromised bool) ThreatScoreResult {
	score := 0
	var factors []string

	if !isAllowed {
		score += 20
		factors = append(factors, "Nicht in autorisierter Whitelist eingetragen")
	}

	if lineageBreach {
		score += 55
		factors = append(factors, "Kritischer Abstammungsbruch (Lineage Breach)")
	}

	if amsiPatched {
		score += 55
		factors = append(factors, "Manipulierte Antimalware-Speicherschnittstelle (AMSI Patch Evasion)")
	}

	if sigMatched {
		score += 35
		factors = append(factors, "Killerdom CLI-Signatur Treffer: "+sigID)
	}

	if threatHit {
		score += 45
		factors = append(factors, "Aktive Verbindung zu bekannter C2-Botnet-Infrastruktur")
	}

	if titanCompromised {
		score += 45
		factors = append(factors, "Titan-Integritätsprüfung: Unautorisierter Persistenz-/Treiber-Eingriff")
	}

	// Minor context adjustments
	cmdLower := strings.ToLower(event.CommandLine)
	if strings.Contains(cmdLower, "bypass") || strings.Contains(cmdLower, "hidden") {
		score += 10
		factors = append(factors, "Verdächtige Ausführungs-Flags (-Bypass, -WindowStyle Hidden)")
	}

	if score > 100 {
		score = 100
	}

	result := ThreatScoreResult{
		Score:    score,
		Factors:  factors,
		IsExempt: isAllowed,
		AppIdent: appName,
	}
	classifyFairScore(&result)
	return result
}

// CalculateFairScoreForEvent adds provenance factors that are only available on
// the live process event (Authenticode state and PE OriginalFilename). This
// closes the "whitelist but unsigned/renamed" free-pass gap without weakening
// the existing score contract for callers that only have a path.
func CalculateFairScoreForEvent(event ProcessEvent, isAllowed bool, appName string, sigMatched bool, sigID string, amsiPatched bool, lineageBreach bool, threatHit bool, titanCompromised bool) ThreatScoreResult {
	result := CalculateFairScore(event, isAllowed, appName, sigMatched, sigID, amsiPatched, lineageBreach, threatHit, titanCompromised)
	if strings.EqualFold(event.SignerStatus, "NotSigned") {
		result.Score += 20
		result.Factors = append(result.Factors, "Nicht signiertes Image (kein gültiger Authenticode-Signer)")
	}
	if event.OriginalImageName != "" && event.ImagePath != "" {
		base := filepath.Base(event.ImagePath)
		if len(base) > 0 && len(event.OriginalImageName) <= 260 && !strings.EqualFold(base, event.OriginalImageName) {
			result.Score += 40
			result.Factors = append(result.Factors, "PE-OriginalFilename weicht vom Dateinamen ab: "+event.OriginalImageName)
		}
	}
	if result.Score > 100 {
		result.Score = 100
	}
	classifyFairScore(&result)
	return result
}

func classifyFairScore(result *ThreatScoreResult) {
	result.Level = "CLEAN"
	result.Action = "ALLOW"
	result.StrikeEvent = false
	if result.Score >= 75 {
		result.Level = "CRITICAL"
		result.Action = "KILLERDOM_STRIKE"
		result.StrikeEvent = true
	} else if result.Score >= 40 {
		result.Level = "WARNING"
		result.Action = "AUDIT_AND_WARN"
	}
}
