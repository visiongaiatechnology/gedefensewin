// STATUS: DIAMANT VGT SUPREME
//go:build windows

package mhx

import (
	"context"
	"encoding/xml"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
)

// The Defender sensor is a native wevtapi pull subscription to the Defender
// operational channel. It replaces the previous long-lived powershell.exe child
// process: no PowerShell, no child-process tree, no JSON wire protocol.
const (
	defenderOperationalChannel    = "Microsoft-Windows-Windows Defender/Operational"
	defenderSensorName            = "defender telemetry"
	defenderMaximumXMLBytes       = 1 << 20
	defenderMaximumMessageChars   = 4096
	defenderMaximumFieldValue     = 1024
	defenderMaximumFieldName      = 64
	defenderMaximumMessageFields  = 64
	defenderRestartInitialBackoff = time.Second
	defenderRestartMaximumBackoff = 30 * time.Second
)

// defenderEventIDs are the Defender operational events the engine correlates:
// detections (1116), remediation actions (1117) and disabled protection
// controls (5001, 5007, 5010, 5012).
var defenderEventIDs = []int{1116, 1117, 5001, 5007, 5010, 5012}

type defenderEvent struct {
	TimestampUTC string `json:"timestampUtc"`
	EventID      int    `json:"eventId"`
	RecordID     int64  `json:"recordId"`
	Message      string `json:"message"`
}

// defenderEventLogStream is the injectable wevtapi seam. Production uses
// winapi.StreamEventLog; tests substitute a deterministic stream to prove the
// restart/resume query without touching the live Defender log.
type defenderEventLogStream func(ctx context.Context, channel, xpath string, startAfterRecordID int64) (<-chan winapi.EventLogRecord, <-chan error, error)

type defenderWatcher struct{}

// Run keeps the Defender sensor alive across subscription failures. The
// signature is intentionally unchanged for engine.go; only the transport is
// native now. The EventRecordID cursor lives in this closure, so a supervised
// restart resumes after the last consumed record instead of losing the events
// that occurred during the restart gap.
func (defenderWatcher) Run(ctx context.Context, output chan<- defenderEvent, faults chan<- error) {
	var cursor int64
	superviseSensor(ctx, defenderSensorName, func(attempt context.Context) error {
		return streamDefenderEvents(attempt, winapi.StreamEventLog, &cursor, output, faults)
	}, faults, defenderRestartInitialBackoff, defenderRestartMaximumBackoff)
}

func streamDefenderEvents(ctx context.Context, stream defenderEventLogStream, cursor *int64, output chan<- defenderEvent, faults chan<- error) error {
	if stream == nil || cursor == nil {
		return errors.New("defender telemetry configuration rejected")
	}
	xpath, err := winapi.EventLogXPath(defenderEventIDs, *cursor)
	if err != nil {
		return err
	}
	records, streamFaults, err := stream(ctx, defenderOperationalChannel, xpath, *cursor)
	if err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case fault, ok := <-streamFaults:
			if !ok {
				streamFaults = nil
				continue
			}
			if fault != nil {
				return fault
			}
		case record, ok := <-records:
			if !ok {
				return eventLogStreamEnded(ctx, streamFaults)
			}
			if err := handleDefenderRecord(ctx, record, cursor, output, faults); err != nil {
				return err
			}
		}
	}
}

// handleDefenderRecord consumes one native record. The cursor advances after
// the record was consumed, including malformed records (reported as a fault) so
// a poison record cannot wedge a restarted stream; it never advances when the
// event delivery itself was interrupted by cancellation, so that event is
// replayed after a restart.
func handleDefenderRecord(ctx context.Context, record winapi.EventLogRecord, cursor *int64, output chan<- defenderEvent, faults chan<- error) error {
	if cursor == nil {
		return errors.New("defender cursor boundary rejected")
	}
	event, parseErr := parseDefenderRecord(record)
	if parseErr != nil {
		deliverFault(faults, parseErr)
		advanceDefenderCursor(cursor, record.RecordID)
		return nil
	}
	select {
	case output <- event:
		advanceDefenderCursor(cursor, record.RecordID)
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func advanceDefenderCursor(cursor *int64, recordID int64) {
	if cursor != nil && recordID > *cursor {
		*cursor = recordID
	}
}

// eventLogStreamEnded converts a closed event log stream into the attempt error.
// A fatal stream error wins over the generic "ended unexpectedly" error; a plain
// context cancellation stays silent.
func eventLogStreamEnded(ctx context.Context, streamFaults <-chan error) error {
	select {
	case fault, ok := <-streamFaults:
		if ok && fault != nil {
			return fault
		}
	default:
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return errors.New("event log telemetry stream ended unexpectedly")
}

type defenderEventXML struct {
	XMLName xml.Name `xml:"Event"`
	System  struct {
		EventID int `xml:"EventID"`
	} `xml:"System"`
	EventData struct {
		Data []defenderDataField `xml:"Data"`
	} `xml:"EventData"`
}

type defenderDataField struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:",chardata"`
}

// parseDefenderRecord converts one native record into the stable defenderEvent
// contract. The message is a bounded key=value rendering of EventData so the
// engine keeps receiving structured detection evidence without PowerShell's
// rendered message text.
func parseDefenderRecord(record winapi.EventLogRecord) (defenderEvent, error) {
	if len(record.XML) == 0 || len(record.XML) > defenderMaximumXMLBytes || record.RecordID <= 0 {
		return defenderEvent{}, errors.New("defender event boundary rejected")
	}
	var document defenderEventXML
	if err := xml.Unmarshal(record.XML, &document); err != nil {
		return defenderEvent{}, errors.New("defender event xml rejected")
	}
	if !defenderEventAllowed(document.System.EventID) {
		return defenderEvent{}, errors.New("defender event identity rejected")
	}
	timestamp := record.TimeCreated
	if timestamp.IsZero() {
		timestamp = time.Now()
	}
	return defenderEvent{
		TimestampUTC: timestamp.UTC().Format(time.RFC3339Nano),
		EventID:      document.System.EventID,
		RecordID:     record.RecordID,
		Message:      defenderEventMessage(document.EventData.Data),
	}, nil
}

func defenderEventAllowed(eventID int) bool {
	for _, allowed := range defenderEventIDs {
		if eventID == allowed {
			return true
		}
	}
	return false
}

// defenderEventMessage assembles at most defenderMaximumMessageChars characters
// of "Name=Value; ..." evidence. Field names and values are bounded and control
// characters are stripped; duplicate names keep the first occurrence.
func defenderEventMessage(fields []defenderDataField) string {
	var builder strings.Builder
	seen := make(map[string]struct{}, len(fields))
	written := 0
	for _, field := range fields {
		if written >= defenderMaximumMessageFields {
			break
		}
		name := sanitizeDefenderText(field.Name, defenderMaximumFieldName)
		value := sanitizeDefenderText(field.Value, defenderMaximumFieldValue)
		if name == "" {
			name = "data"
		}
		key := strings.ToLower(name)
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		entry := name + "=" + value
		if builder.Len() > 0 {
			if builder.Len()+2 >= defenderMaximumMessageChars {
				break
			}
			builder.WriteString("; ")
		}
		remaining := defenderMaximumMessageChars - builder.Len()
		builder.WriteString(truncateEventLogText(entry, remaining))
		written++
		if builder.Len() >= defenderMaximumMessageChars {
			break
		}
	}
	return builder.String()
}

// sanitizeDefenderText replaces invalid UTF-8, folds whitespace-like control
// characters to spaces and drops the remaining control characters.
func sanitizeDefenderText(value string, maximum int) string {
	if maximum <= 0 {
		return ""
	}
	value = strings.ToValidUTF8(value, "\uFFFD")
	var builder strings.Builder
	for _, character := range value {
		switch {
		case character == '\t' || character == '\n' || character == '\r' || character == ' ':
			builder.WriteByte(' ')
		case character < 0x20 || character == 0x7f:
			continue
		default:
			builder.WriteRune(character)
		}
		if builder.Len() >= maximum {
			break
		}
	}
	return strings.TrimSpace(builder.String())
}

// truncateEventLogText cuts a sanitized string to at most maximum bytes without
// splitting a UTF-8 sequence.
func truncateEventLogText(value string, maximum int) string {
	if maximum <= 0 {
		return ""
	}
	if len(value) <= maximum {
		return value
	}
	cut := maximum
	for cut > 0 && !utf8.RuneStart(value[cut]) {
		cut--
	}
	return value[:cut]
}
