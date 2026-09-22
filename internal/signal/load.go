package signal

import (
	"encoding/json"
	"fmt"
	"os"
)

// LoadJSON reads a signal snapshot from a JSON file.
func LoadJSON(path string) (*Snapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read snapshot: %w", err)
	}
	var s Snapshot
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse snapshot: %w", err)
	}
	if s.UserAgent == "" && len(s.Headers) == 0 {
		return nil, fmt.Errorf("snapshot missing user_agent and headers")
	}
	return &s, nil
}
