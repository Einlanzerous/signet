package sync

import (
	"os"

	"github.com/Einlanzerous/signet/internal/envfile"
)

// KeyState is the drift state of one managed key inside a file target.
type KeyState struct {
	Key   string `json:"key"`
	State string `json:"state"` // ok | missing | changed
}

// FileDrift is the drift report for one file target.
type FileDrift struct {
	Path        string     `json:"path"`
	MissingFile bool       `json:"missing_file"`
	Keys        []KeyState `json:"keys,omitempty"`
	Unmanaged   []string   `json:"unmanaged,omitempty"` // keys present in the file signet doesn't manage
}

// Clean reports whether the target matches the vault exactly.
func (d FileDrift) Clean() bool {
	if d.MissingFile {
		return false
	}
	for _, k := range d.Keys {
		if k.State != "ok" {
			return false
		}
	}
	return true
}

// CheckFile compares an on-disk env file against the wanted plaintext values
// (key → current vault value). The caller supplies decrypted values; this
// package never touches the vault key itself.
func CheckFile(path string, want map[string]string, managedKeys []string) FileDrift {
	drift := FileDrift{Path: path}
	pairs, err := envfile.ParseFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			drift.MissingFile = true
			for _, k := range managedKeys {
				drift.Keys = append(drift.Keys, KeyState{Key: k, State: "missing"})
			}
			return drift
		}
		// Unparseable counts as changed wholesale.
		for _, k := range managedKeys {
			drift.Keys = append(drift.Keys, KeyState{Key: k, State: "changed"})
		}
		return drift
	}
	got := envfile.Map(pairs)
	managed := map[string]bool{}
	for _, k := range managedKeys {
		managed[k] = true
		switch v, ok := got[k]; {
		case !ok:
			drift.Keys = append(drift.Keys, KeyState{Key: k, State: "missing"})
		case v != want[k]:
			drift.Keys = append(drift.Keys, KeyState{Key: k, State: "changed"})
		default:
			drift.Keys = append(drift.Keys, KeyState{Key: k, State: "ok"})
		}
	}
	for _, p := range pairs {
		if !managed[p.Key] {
			drift.Unmanaged = append(drift.Unmanaged, p.Key)
		}
	}
	return drift
}
