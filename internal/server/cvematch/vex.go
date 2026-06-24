package cvematch

import (
	"encoding/json"
	"strings"
	"time"
)

// CycloneDX VEX interoperability. Bongsu's triage statuses are mapped to/from the
// CycloneDX `vulnerabilities[].analysis.state` vocabulary so analysis decisions
// (especially suppressions) can be exported to and imported from other tools.
//
// Mapping (lossy by nature — the two vocabularies are not 1:1):
//
//	Bongsu triage        CycloneDX VEX state     justification / response
//	-------------------  ----------------------  ------------------------------
//	false_positive       false_positive          —
//	ignored              not_affected            code_not_present
//	accepted_risk        exploitable             response: will_not_fix
//	fixed                resolved                —
//	in_progress          in_triage               —
//	open                 in_triage               —
//
// On import the inverse is applied; not_affected collapses to false_positive
// (Bongsu's "this finding does not apply" status).

// VEXStatement is one analysis decision, the unit both exported and imported.
type VEXStatement struct {
	VulnerabilityID string // CVE/advisory id
	ComponentPURL   string // affected component (may be empty -> applies to the vuln broadly)
	PkgName         string
	Status          string // Bongsu triage status
	Reason          string
	Detail          string
}

func vexStateForTriage(status string) (state, justification, response string) {
	switch status {
	case "false_positive":
		return "false_positive", "", ""
	case "ignored":
		return "not_affected", "code_not_present", ""
	case "accepted_risk":
		return "exploitable", "", "will_not_fix"
	case "fixed":
		return "resolved", "", ""
	case "in_progress":
		return "in_triage", "", ""
	default: // open / unknown
		return "in_triage", "", ""
	}
}

func triageFromVEXState(state string) (status string, ok bool) {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "not_affected", "false_positive":
		return "false_positive", true
	case "resolved", "resolved_with_pedigree":
		return "fixed", true
	case "in_triage":
		return "in_progress", true
	case "exploitable":
		return "accepted_risk", true
	default:
		return "", false
	}
}

// cdxVEX is the minimal CycloneDX shape needed for a standalone VEX document.
type cdxVEX struct {
	BOMFormat       string         `json:"bomFormat"`
	SpecVersion     string         `json:"specVersion"`
	Version         int            `json:"version"`
	Metadata        cdxVEXMetadata `json:"metadata"`
	Vulnerabilities []cdxVuln      `json:"vulnerabilities"`
}

type cdxVEXMetadata struct {
	Timestamp string `json:"timestamp"`
	Tools     []struct {
		Vendor string `json:"vendor"`
		Name   string `json:"name"`
	} `json:"tools"`
}

type cdxVuln struct {
	ID       string        `json:"id"`
	Analysis cdxAnalysis   `json:"analysis"`
	Affects  []cdxAffects  `json:"affects,omitempty"`
	Props    []cdxProperty `json:"properties,omitempty"`
}

type cdxAnalysis struct {
	State         string   `json:"state"`
	Justification string   `json:"justification,omitempty"`
	Response      []string `json:"response,omitempty"`
	Detail        string   `json:"detail,omitempty"`
}

type cdxAffects struct {
	Ref string `json:"ref"`
}

// BuildCycloneDXVEX renders analysis statements as a standalone CycloneDX VEX
// document. nowRFC3339 is passed in (the workflow/runtime forbids wall-clock in
// some contexts and it keeps the function pure/testable).
func BuildCycloneDXVEX(stmts []VEXStatement, nowRFC3339 string) ([]byte, error) {
	doc := cdxVEX{BOMFormat: "CycloneDX", SpecVersion: "1.5", Version: 1}
	doc.Metadata.Timestamp = nowRFC3339
	doc.Metadata.Tools = append(doc.Metadata.Tools, struct {
		Vendor string `json:"vendor"`
		Name   string `json:"name"`
	}{Vendor: "ziozzang", Name: "bongsu"})

	for _, s := range stmts {
		state, justification, response := vexStateForTriage(s.Status)
		v := cdxVuln{ID: s.VulnerabilityID}
		v.Analysis = cdxAnalysis{State: state, Justification: justification, Detail: vexDetail(s)}
		if response != "" {
			v.Analysis.Response = []string{response}
		}
		if s.ComponentPURL != "" {
			v.Affects = []cdxAffects{{Ref: s.ComponentPURL}}
		}
		if s.PkgName != "" {
			v.Props = []cdxProperty{{Name: "bongsu:pkg_name", Value: s.PkgName}}
		}
		doc.Vulnerabilities = append(doc.Vulnerabilities, v)
	}
	return json.Marshal(doc)
}

func vexDetail(s VEXStatement) string {
	parts := make([]string, 0, 2)
	if s.Reason != "" {
		parts = append(parts, s.Reason)
	}
	if s.Detail != "" {
		parts = append(parts, s.Detail)
	}
	return strings.Join(parts, ": ")
}

// ParseCycloneDXVEX extracts the analysis decisions from an uploaded CycloneDX
// VEX document, mapping each to a Bongsu triage status. Statements whose state
// has no Bongsu equivalent (or is missing an id) are skipped.
func ParseCycloneDXVEX(data []byte) ([]VEXStatement, error) {
	var doc cdxVEX
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	var out []VEXStatement
	for _, v := range doc.Vulnerabilities {
		if v.ID == "" {
			continue
		}
		status, ok := triageFromVEXState(v.Analysis.State)
		if !ok {
			continue
		}
		stmt := VEXStatement{
			VulnerabilityID: v.ID,
			Status:          status,
			Reason:          strings.TrimSpace(v.Analysis.Justification),
			Detail:          strings.TrimSpace(v.Analysis.Detail),
		}
		if len(v.Affects) > 0 {
			stmt.ComponentPURL = v.Affects[0].Ref
		}
		for _, p := range v.Props {
			if p.Name == "bongsu:pkg_name" {
				stmt.PkgName = p.Value
			}
		}
		out = append(out, stmt)
	}
	return out, nil
}

// nowRFC3339 is a tiny indirection so callers in normal request context can pass
// the real time; tests pass a fixed value.
func NowRFC3339() string { return time.Now().UTC().Format(time.RFC3339) }
