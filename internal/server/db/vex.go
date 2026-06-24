package db

import (
	"context"
	"fmt"

	"github.com/ziozzang/bongsu/internal/shared/models"
)

// ListVulnerabilityTriageForExport returns the analysis decisions to emit as a
// VEX document: every triage row scoped to the host plus the global
// (host_id=”) decisions that apply everywhere. Open rows are included so a
// consumer sees the full analysis state; the caller decides what to emit.
func (db *DB) ListVulnerabilityTriageForExport(ctx context.Context, hostID string) ([]models.VulnerabilityTriage, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, vulnerability_id, COALESCE(host_id,''), COALESCE(pkg_name,''), status,
		        COALESCE(reason,''), COALESCE(comment,''), COALESCE(updated_by,''), updated_at
		   FROM vulnerability_triage
		  WHERE host_id=$1 OR host_id=''
		  ORDER BY vulnerability_id, pkg_name`, hostID)
	if err != nil {
		return nil, fmt.Errorf("list triage for export: %w", err)
	}
	defer rows.Close()
	var out []models.VulnerabilityTriage
	for rows.Next() {
		var t models.VulnerabilityTriage
		if err := rows.Scan(&t.ID, &t.VulnerabilityID, &t.HostID, &t.PkgName, &t.Status,
			&t.Reason, &t.Comment, &t.UpdatedBy, &t.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
