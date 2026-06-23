package api

import (
	"os"
	"strings"
)

// readWebAppSource returns the dashboard UI source for the source-scanning tests.
// The dashboard was decomposed from a single App.tsx into App.tsx + views/ +
// components/ + hooks/ + lib/, so a UI assertion may now live in any of those.
// This concatenates them all so the existing tests keep matching regardless of
// which file a given view/component was extracted into.
func readWebAppSource() ([]byte, error) {
	const base = "../../../web/src/"
	app, err := os.ReadFile(base + "App.tsx")
	if err != nil {
		return nil, err
	}
	out := append([]byte{}, app...)
	for _, dir := range []string{"views", "components", "hooks", "lib"} {
		entries, derr := os.ReadDir(base + dir)
		if derr != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			if !strings.HasSuffix(e.Name(), ".tsx") && !strings.HasSuffix(e.Name(), ".ts") {
				continue
			}
			data, rerr := os.ReadFile(base + dir + "/" + e.Name())
			if rerr != nil {
				continue
			}
			out = append(out, '\n')
			out = append(out, data...)
		}
	}
	return out, nil
}
