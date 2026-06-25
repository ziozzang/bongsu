package db

import "testing"

func TestNormalizePkgName(t *testing.T) {
	cases := []struct{ eco, name, want string }{
		{"pypi", "Pillow", "pillow"},
		{"pypi", "ruamel.yaml", "ruamel-yaml"},
		{"pypi", "zope_interface", "zope-interface"},
		{"pypi", "Flask__Cors", "flask-cors"},
		{"npm", "@Angular/Core", "@angular/core"},
		{"npm", "Lodash", "lodash"},
		{"maven", "com.fasterxml:Jackson", "com.fasterxml:Jackson"}, // case-preserving
		{"go", "Example.com/Foo", "example.com/foo"},
	}
	for _, c := range cases {
		if got := normalizePkgName(c.eco, c.name); got != c.want {
			t.Errorf("normalizePkgName(%q,%q) = %q, want %q", c.eco, c.name, got, c.want)
		}
	}
}

func TestParseBumblebeeCatalog(t *testing.T) {
	doc := `{
	  "schema_version":"0.1.0",
	  "entries":[
	    {"id":"MAL-2026-1","name":"evil 1.2.3","ecosystem":"npm","package":"Evil-Pkg","versions":["1.2.3","1.2.4"],"severity":"critical"},
	    {"id":"MAL-2026-2","name":"pillow compromise","ecosystem":"PyPI","package":"Pillow","versions":["9.0.0"]},
	    {"id":"MAL-2026-3","name":"range only","ecosystem":"npm","package":"noversions","versions":[]},
	    {"id":"","name":"no id","ecosystem":"npm","package":"x","versions":["1.0"]}
	  ]
	}`
	cat, entries, err := ParseBumblebeeCatalog([]byte(doc))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cat.SchemaVersion != "0.1.0" {
		t.Fatalf("schema version = %q", cat.SchemaVersion)
	}
	// MAL-1 -> 2 versions (flattened), MAL-2 -> 1; MAL-3 (no versions) and the
	// id-less entry are skipped => 3 stored entries.
	if len(entries) != 3 {
		t.Fatalf("want 3 flattened entries, got %d: %+v", len(entries), entries)
	}
	// ecosystem + name normalized at parse.
	var evil124, pillow *ExposureCatalogEntry
	for i := range entries {
		switch {
		case entries[i].CatalogID == "MAL-2026-1" && entries[i].Version == "1.2.4":
			evil124 = &entries[i]
		case entries[i].CatalogID == "MAL-2026-2":
			pillow = &entries[i]
		}
	}
	if evil124 == nil || evil124.Ecosystem != "npm" || evil124.NormalizedName != "evil-pkg" {
		t.Fatalf("npm entry normalization wrong: %+v", evil124)
	}
	if pillow == nil || pillow.Ecosystem != "pypi" || pillow.NormalizedName != "pillow" || pillow.Severity != "critical" {
		t.Fatalf("pypi entry normalization/default-severity wrong: %+v", pillow)
	}
}
