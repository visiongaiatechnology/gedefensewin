// STATUS: DIAMANT VGT SUPREME
//go:build windows

package mhx

import (
	"context"
	"encoding/xml"
	"errors"
	"math"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
)

// The WFP sensor is a native wevtapi pull subscription to Security event 5157.
// The previous PowerShell bridge injected a cursor through the environment and
// parsed a JSON wire protocol; the native path keeps the same event contract and
// the same validation semantics with a committed EventRecordID cursor.
const (
	wfpSecurityChannel          = "Security"
	wfpSensorName               = "WFP block telemetry"
	wfpBlockEventID             = 5157
	wfpMaximumApplicationChars  = 2048
	wfpMaximumFilterOriginChars = 256
	wfpMaximumXMLBytes          = 1 << 20
	wfpMaximumFields            = 64
	wfpMaximumFieldNameChars    = 64
	wfpMaximumFieldValueChars   = 4096
	wfpHealthInterval           = 2 * time.Second
	wfpRestartInitialBackoff    = time.Second
	wfpRestartMaximumBackoff    = 30 * time.Second
)

var wfpBlockEventIDs = []int{wfpBlockEventID}

type wfpBlockEvent struct {
	TimestampUTC    time.Time `json:"-"`
	RecordID        int64     `json:"recordId"`
	PID             uint32    `json:"pid"`
	Application     string    `json:"application"`
	Direction       string    `json:"direction"`
	LocalPort       uint16    `json:"localPort"`
	RemoteIP        string    `json:"remoteIp"`
	RemotePort      uint16    `json:"remotePort"`
	Protocol        uint8     `json:"protocol"`
	FilterRuntimeID int64     `json:"filterRuntimeId"`
	FilterOrigin    string    `json:"filterOrigin,omitempty"`
	GeDefenseOrigin bool      `json:"-"`
}

type wfpBlockWatcher struct{}

// Run owns recovery for this independent sensor; failures cannot permanently
// disable it until the next service restart. The EventRecordID cursor survives
// each supervised attempt because it lives in this closure, never in the
// supervisor. Health is delivered from receipt time, never from event time.
func (wfpBlockWatcher) Run(ctx context.Context, output chan<- wfpBlockEvent, health chan<- time.Time, faults chan<- error) {
	var cursor int64
	superviseSensor(ctx, wfpSensorName, func(attempt context.Context) error {
		xpath, err := winapi.EventLogXPath(wfpBlockEventIDs, cursor)
		if err != nil {
			return err
		}
		records, streamFaults, err := winapi.StreamEventLog(attempt, wfpSecurityChannel, xpath, cursor)
		if err != nil {
			return err
		}
		deliverHealth(health, time.Now().UTC())
		ticker := time.NewTicker(wfpHealthInterval)
		defer ticker.Stop()
		for {
			select {
			case <-attempt.Done():
				return attempt.Err()
			case now := <-ticker.C:
				deliverHealth(health, now.UTC())
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
					return eventLogStreamEnded(attempt, streamFaults)
				}
				normalizeErr := normalizeWFPRecord(attempt, record, &cursor, output, health, time.Now().UTC())
				if normalizeErr == nil {
					continue
				}
				if attempt.Err() != nil {
					return attempt.Err()
				}
				deliverFault(faults, normalizeErr)
			}
		}
	}, faults, wfpRestartInitialBackoff, wfpRestartMaximumBackoff)
}

// normalizeWFPRecord is the pure, unit-testable event gate. It parses one
// native record, rejects malformed records without refreshing sensor health and
// commits the EventRecordID cursor for every structurally valid record: after a
// block event was delivered and also after a policy-filtered record (loopback,
// unspecified, multicast or unparsable remote address), matching the previous
// bridge's cursor semantics so filtered noise is not replayed on every restart.
// The cursor is never committed for malformed records or an interrupted
// delivery, so those records are retried after a supervisor restart.
func normalizeWFPRecord(ctx context.Context, record winapi.EventLogRecord, cursor *int64, output chan<- wfpBlockEvent, health chan<- time.Time, received time.Time) error {
	if cursor == nil {
		return errors.New("WFP cursor boundary rejected")
	}
	fields, err := parseWFPRecord(record)
	if err != nil {
		return err
	}
	if fields.RecordID <= *cursor {
		deliverHealth(health, received)
		return nil
	}
	address, addressErr := netip.ParseAddr(fields.RemoteIP)
	if addressErr != nil || !address.IsValid() || address.IsLoopback() || address.IsUnspecified() || address.IsMulticast() {
		*cursor = fields.RecordID
		deliverHealth(health, received)
		return nil
	}
	event := wfpBlockEvent{
		TimestampUTC:    fields.EventTime,
		RecordID:        fields.RecordID,
		PID:             fields.PID,
		Application:     fields.Application,
		Direction:       fields.Direction,
		LocalPort:       fields.LocalPort,
		RemoteIP:        address.Unmap().String(),
		RemotePort:      fields.RemotePort,
		Protocol:        fields.Protocol,
		FilterRuntimeID: fields.FilterRuntimeID,
		FilterOrigin:    fields.FilterOrigin,
		GeDefenseOrigin: strings.HasPrefix(fields.FilterOrigin, "VGT-GeDefense-TI-"),
	}
	select {
	case output <- event:
		*cursor = fields.RecordID
		deliverHealth(health, received)
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type wfpRecordFields struct {
	RecordID        int64
	PID             uint32
	Application     string
	Direction       string
	LocalPort       uint16
	RemoteIP        string
	RemotePort      uint16
	Protocol        uint8
	FilterRuntimeID int64
	FilterOrigin    string
	EventTime       time.Time
}

type wfpEventXML struct {
	XMLName xml.Name `xml:"Event"`
	System  struct {
		EventID int `xml:"EventID"`
	} `xml:"System"`
	EventData struct {
		Data []wfpDataField `xml:"Data"`
	} `xml:"EventData"`
}

type wfpDataField struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:",chardata"`
}

// parseWFPRecord converts the rendered XML and receipt metadata of one 5157
// record into validated fields. Structural or numeric inconsistencies are
// errors: such a record is not trustworthy telemetry and must not prove sensor
// liveness.
func parseWFPRecord(record winapi.EventLogRecord) (wfpRecordFields, error) {
	if len(record.XML) == 0 || len(record.XML) > wfpMaximumXMLBytes || record.RecordID <= 0 {
		return wfpRecordFields{}, errors.New("WFP record boundary rejected")
	}
	var document wfpEventXML
	if err := xml.Unmarshal(record.XML, &document); err != nil {
		return wfpRecordFields{}, errors.New("WFP record xml rejected")
	}
	if document.System.EventID != wfpBlockEventID {
		return wfpRecordFields{}, errors.New("WFP record identity rejected")
	}
	values, err := wfpFieldValues(document.EventData.Data)
	if err != nil {
		return wfpRecordFields{}, err
	}
	processID, ok := wfpParseUnsigned(values["processid"], 32)
	if !ok || processID == 0 {
		return wfpRecordFields{}, errors.New("WFP record process id rejected")
	}
	protocolValue, ok := wfpParseUnsigned(values["protocol"], 8)
	if !ok || protocolValue == 0 {
		return wfpRecordFields{}, errors.New("WFP record protocol rejected")
	}
	direction, outbound, ok := wfpDirection(values["direction"])
	if !ok {
		return wfpRecordFields{}, errors.New("WFP record direction rejected")
	}
	var remoteAddressKey, remotePortKey, localPortKey string
	if outbound {
		remoteAddressKey, remotePortKey, localPortKey = "destaddress", "destport", "sourceport"
	} else {
		remoteAddressKey, remotePortKey, localPortKey = "sourceaddress", "sourceport", "destport"
	}
	// The remote address itself is a policy decision, not a structural one:
	// an empty or unparseable address is a valid record the sensor rejects
	// (it still proves subscription liveness), exactly like the previous
	// bridge did. It is evaluated by normalizeWFPRecord.
	remoteIP := strings.TrimSpace(values[remoteAddressKey])
	remotePort, _ := wfpParseUnsigned(values[remotePortKey], 16)
	localPort, _ := wfpParseUnsigned(values[localPortKey], 16)
	filterRuntimeID := int64(0)
	if parsed, ok := wfpParseUnsigned(values["filterrtid"], 64); ok {
		if parsed > math.MaxInt64 {
			return wfpRecordFields{}, errors.New("WFP record filter runtime id rejected")
		}
		filterRuntimeID = int64(parsed)
	}
	application := truncateEventLogText(values["application"], wfpMaximumApplicationChars)
	filterOrigin := strings.TrimSpace(values["filterorigin"])
	if len(filterOrigin) > wfpMaximumFilterOriginChars {
		return wfpRecordFields{}, errors.New("WFP record filter origin rejected")
	}
	eventTime := record.TimeCreated
	if eventTime.IsZero() {
		return wfpRecordFields{}, errors.New("WFP record event time rejected")
	}
	return wfpRecordFields{
		RecordID:        record.RecordID,
		PID:             uint32(processID),
		Application:     application,
		Direction:       direction,
		LocalPort:       uint16(localPort),
		RemoteIP:        remoteIP,
		RemotePort:      uint16(remotePort),
		Protocol:        uint8(protocolValue),
		FilterRuntimeID: filterRuntimeID,
		FilterOrigin:    filterOrigin,
		EventTime:       eventTime.UTC(),
	}, nil
}

// wfpFieldValues bounds and case-folds the EventData fields. PowerShell's
// hashtable was case-insensitive, so field lookup stays case-insensitive.
func wfpFieldValues(fields []wfpDataField) (map[string]string, error) {
	values := make(map[string]string, len(fields))
	for index, field := range fields {
		if index >= wfpMaximumFields {
			return nil, errors.New("WFP record field boundary rejected")
		}
		name := strings.ToLower(strings.TrimSpace(field.Name))
		if name == "" || len(name) > wfpMaximumFieldNameChars || strings.IndexByte(name, 0) >= 0 {
			return nil, errors.New("WFP record field name rejected")
		}
		value := field.Value
		if len(value) > wfpMaximumFieldValueChars || !wfpValidText(value) {
			return nil, errors.New("WFP record field value rejected")
		}
		values[name] = truncateEventLogText(value, wfpMaximumFieldValueChars)
	}
	return values, nil
}

func wfpDirection(value string) (direction string, outbound bool, ok bool) {
	token := strings.ToLower(strings.TrimSpace(value))
	switch {
	case token == "%%14593" || strings.Contains(token, "outbound") || strings.Contains(token, "ausgehend"):
		return "Outbound", true, true
	case token == "%%14592" || strings.Contains(token, "inbound") || strings.Contains(token, "eingehend"):
		return "Inbound", false, true
	default:
		return "", false, false
	}
}

func wfpParseUnsigned(value string, bits int) (uint64, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	base := 10
	if len(value) > 2 && value[0] == '0' && (value[1] == 'x' || value[1] == 'X') {
		base = 16
		value = value[2:]
		if value == "" {
			return 0, false
		}
	}
	parsed, err := strconv.ParseUint(value, base, bits)
	if err != nil {
		return 0, false
	}
	return parsed, true
}

func wfpValidText(value string) bool {
	return utf8.ValidString(value)
}
