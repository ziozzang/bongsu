package live

import (
	"encoding/json"
	"fmt"
	"io"
)

// WriteEvent encodes an event in the SSE wire format:
//
//	id: <id>
//	event: <type>
//	data: <json>
//	<blank line>
//
// The id lets the browser resume with Last-Event-ID; the event name lets the
// client addEventListener per type; data is the JSON-encoded Event.
func WriteEvent(w io.Writer, e *Event) error {
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n", e.ID, e.Type, data); err != nil {
		return err
	}
	return nil
}

// WriteHeartbeat writes an SSE comment line to keep the connection (and any
// intermediary proxy) alive without delivering a data event.
func WriteHeartbeat(w io.Writer) error {
	_, err := io.WriteString(w, ":heartbeat\n\n")
	return err
}
