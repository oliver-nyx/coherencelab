package adapters

import (
	"fmt"
	"path/filepath"

	httpcloakadapter "github.com/coherencelab/coherencelab/internal/adapters/httpcloak"
	curladapter "github.com/coherencelab/coherencelab/internal/adapters/curlimpersonate"
	pwadapter "github.com/coherencelab/coherencelab/internal/adapters/playwright"
	"github.com/coherencelab/coherencelab/internal/profile"
	"github.com/coherencelab/coherencelab/internal/signal"
)

// LoadSnapshot loads an identity snapshot from a JSON file using the given adapter.
func LoadSnapshot(adapterName, path string) (*signal.Snapshot, string, error) {
	switch adapterName {
	case "snapshot", "json", "":
		s, err := signal.LoadJSON(path)
		return s, "", err
	case "httpcloak":
		e, err := httpcloakadapter.LoadExport(path)
		if err != nil {
			return nil, "", err
		}
		id, _ := httpcloakadapter.ResolveProfileID(e)
		return httpcloakadapter.ToSnapshot(e, id), id, nil
	case "playwright", "patchright":
		e, err := pwadapter.LoadExport(path)
		if err != nil {
			return nil, "", err
		}
		id, _ := pwadapter.ResolveProfileID(e)
		return pwadapter.ToSnapshot(e, id), id, nil
	case "curl", "curl-impersonate", "curlimpersonate":
		return curladapter.LoadSnapshot(path)
	default:
		return nil, "", fmt.Errorf("unsupported adapter %q", adapterName)
	}
}

// ScanExport loads snapshot + profile for scan --import mode.
func ScanExport(adapterName, path, profilesDir, profileOverride string) (*signal.Snapshot, *profile.Profile, error) {
	snap, inferred, err := LoadSnapshot(adapterName, path)
	if err != nil {
		return nil, nil, err
	}
	profileID := profileOverride
	if profileID == "" {
		profileID = inferred
	}
	if profileID == "" {
		return nil, nil, fmt.Errorf("could not infer profile from %s — use --profile", filepath.Base(path))
	}
	p, err := profile.FindByID(profilesDir, profileID)
	if err != nil {
		return nil, nil, err
	}
	return snap, p, nil
}
