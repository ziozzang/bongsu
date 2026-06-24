package db

import (
	"reflect"
	"sort"
	"testing"

	"github.com/ziozzang/bongsu/internal/shared/models"
)

func TestDependencyKey(t *testing.T) {
	if got := DependencyKey("pkg:npm/lodash@4.17.21", "lodash"); got != "pkg:npm/lodash@4.17.21" {
		t.Fatalf("purl must win: %q", got)
	}
	if got := DependencyKey("", "LoDash"); got != "lodash" {
		t.Fatalf("name fallback must lowercase: %q", got)
	}
}

func TestBuildScanDependencyEdges(t *testing.T) {
	pkgs := []models.Package{
		{Name: "app", PURL: "pkg:npm/app@1.0.0", Dependencies: []string{"express", "lodash"}},
		{Name: "express", PURL: "pkg:npm/express@4.18.2", Dependencies: []string{"lodash"}},
		{Name: "lodash", PURL: "pkg:npm/lodash@4.17.21"},
	}
	edges := BuildScanDependencyEdges(pkgs)
	// Name-based deps resolve to the child's PURL key.
	want := [][2]string{
		{"pkg:npm/app@1.0.0", "pkg:npm/express@4.18.2"},
		{"pkg:npm/app@1.0.0", "pkg:npm/lodash@4.17.21"},
		{"pkg:npm/express@4.18.2", "pkg:npm/lodash@4.17.21"},
	}
	sortEdges(edges)
	sortEdges(want)
	if !reflect.DeepEqual(edges, want) {
		t.Fatalf("edges = %v, want %v", edges, want)
	}
}

func TestBuildScanDependencyEdgesUnresolvedKeepsName(t *testing.T) {
	pkgs := []models.Package{
		{Name: "app", PURL: "pkg:npm/app@1.0.0", Dependencies: []string{"not-inventoried"}},
	}
	edges := BuildScanDependencyEdges(pkgs)
	if len(edges) != 1 || edges[0][1] != "not-inventoried" {
		t.Fatalf("unresolved dep must record bare name edge: %v", edges)
	}
}

func sortEdges(e [][2]string) {
	sort.Slice(e, func(i, j int) bool {
		if e[i][0] != e[j][0] {
			return e[i][0] < e[j][0]
		}
		return e[i][1] < e[j][1]
	})
}
