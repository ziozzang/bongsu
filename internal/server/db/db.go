package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/ziozzang/bongsu/internal/shared/models"
)

type DB struct {
	*sql.DB
}

func New(ctx context.Context, dsn string) (*DB, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("ping db: %w", err)
	}
	return &DB{db}, nil
}

func (db *DB) RunMigrations(ctx context.Context) error {
	files, err := os.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("read migrations dir: %w", err)
	}
	for _, f := range files {
		if f.IsDir() || !(len(f.Name()) > 4 && f.Name()[len(f.Name())-4:] == ".sql") {
			log.Printf("rematch scan row: %v", err)
			continue
		}
		data, err := os.ReadFile("migrations/" + f.Name())
		if err != nil {
			return fmt.Errorf("read migration %s: %w", f.Name(), err)
		}
		if _, err := db.ExecContext(ctx, string(data)); err != nil {
			return fmt.Errorf("run migration %s: %w", f.Name(), err)
		}
	}
	return nil
}

func (db *DB) UpsertHost(ctx context.Context, h *models.Host) error {
	q := `INSERT INTO hosts (id, hostname, ip_address, os_name, os_version, kernel, arch, cpu_model, cpu_cores, memory_mb, agent_version, api_key_hash, last_seen, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, '', now(), now(), now())
ON CONFLICT (id) DO UPDATE SET hostname=$2, ip_address=$3, os_name=$4, os_version=$5, kernel=$6, arch=$7, cpu_model=$8, cpu_cores=$9, memory_mb=$10, agent_version=$11, last_seen=now(), updated_at=now()`
	_, err := db.ExecContext(ctx, q,
		h.ID, h.Hostname, h.IPAddress, h.OSName, h.OSVersion,
		h.Kernel, h.Arch, h.CPUModel, h.CPUCores, h.MemoryMB, h.AgentVersion,
	)
	return err
}

func (db *DB) CreateScan(ctx context.Context, s *models.Scan) error {
	q := `INSERT INTO scans (id, host_id, scan_type, status, started_at, created_at) VALUES ($1, $2, $3, $4, $5, now())`
	_, err := db.ExecContext(ctx, q, s.ID, s.HostID, s.ScanType, s.Status, s.StartedAt)
	return err
}

func (db *DB) CompleteScan(ctx context.Context, id string) error {
	q := `UPDATE scans SET status='completed', finished_at=now() WHERE id=$1`
	_, err := db.ExecContext(ctx, q, id)
	return err
}

func (db *DB) DeleteScan(ctx context.Context, id string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	tables := []string{"vulnerabilities", "packages", "container_assets", "user_accounts", "process_snapshots", "port_info"}
	for _, t := range tables {
		if _, err := tx.ExecContext(ctx, fmt.Sprintf("DELETE FROM %s WHERE scan_id=$1", t), id); err != nil {
			return fmt.Errorf("delete from %s: %w", t, err)
		}
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM scans WHERE id=$1", id); err != nil {
		return fmt.Errorf("delete scan: %w", err)
	}
	return tx.Commit()
}

func defaultString(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func ClassifySecuritySource(source, affectedProducts string) (string, string) {
	type affectedProduct struct {
		Ecosystem string `json:"ecosystem"`
	}
	var products []affectedProduct
	if affectedProducts != "" {
		_ = json.Unmarshal([]byte(affectedProducts), &products)
	}
	ecosystem := ""
	if len(products) > 0 {
		ecosystem = products[0].Ecosystem
	}
	if ecosystem != "" {
		switch strings.ToLower(ecosystem) {
		case "debian", "ubuntu", "alpine", "red hat", "rhel", "suse", "almalinux", "amazon linux", "wolfi", "chainguard":
			return "os-package", ecosystem
		default:
			return "code-library", ecosystem
		}
	}
	switch strings.ToLower(source) {
	case "osv":
		return "code-library", ""
	case "trivy":
		return "os-package", ""
	case "nvd":
		return "general-cve", ""
	default:
		return "custom", ""
	}
}

type affectedProduct struct {
	Name      string   `json:"name"`
	Ecosystem string   `json:"ecosystem"`
	Fixed     []string `json:"fixed"`
	Ranges    []struct {
		Type   string `json:"type"`
		Events []struct {
			Introduced   string `json:"introduced"`
			Fixed        string `json:"fixed"`
			LastAffected string `json:"last_affected"`
			Limit        string `json:"limit"`
		} `json:"events"`
	} `json:"ranges"`
}

func packageCategory(pkgType, ecosystem string) string {
	eco := strings.ToLower(ecosystem)
	pt := strings.ToLower(pkgType)
	switch eco {
	case "debian", "ubuntu", "alpine", "red hat", "rhel", "suse", "almalinux", "amazon linux", "wolfi", "chainguard":
		return "os-package"
	case "pypi", "npm", "go", "maven", "crates.io", "nuget", "rubygems", "packagist", "hex", "pub":
		return "code-library"
	}
	switch pt {
	case "debian", "ubuntu", "deb", "alpine", "apk", "redhat", "centos", "rocky", "alma", "amazon", "rpm", "suse", "wolfi":
		return "os-package"
	case "python-pkg", "pip", "poetry", "node-pkg", "npm", "yarn", "pnpm", "gomod", "go", "gobinary", "golang", "jar", "maven", "cargo", "rustbinary", "composer", "gem", "nuget":
		return "code-library"
	default:
		return ""
	}
}

func normalizeEcosystem(eco string) string {
	eco = strings.ToLower(strings.TrimSpace(eco))
	switch eco {
	case "python", "python-pkg", "pip":
		return "pypi"
	case "node", "node-pkg", "javascript":
		return "npm"
	case "golang", "gomod":
		return "go"
	case "ruby", "gem":
		return "rubygems"
	case "rust", "cargo":
		return "crates.io"
	case "debian:10", "debian:11", "debian:12", "debian:13":
		return "debian"
	case "ubuntu:18.04", "ubuntu:20.04", "ubuntu:22.04", "ubuntu:24.04":
		return "ubuntu"
	case "redhat", "red hat enterprise linux", "centos", "rocky", "almalinux", "alma", "amazon":
		return "rhel"
	default:
		if strings.HasPrefix(eco, "debian:") {
			return "debian"
		}
		if strings.HasPrefix(eco, "ubuntu:") {
			return "ubuntu"
		}
		return eco
	}
}

func compatibleSecurityCandidate(pkgName, pkgType, pkgEco, installedVersion, cveCategory, cveEco, affectedProducts string) (affectedProduct, bool) {
	var products []affectedProduct
	if affectedProducts == "" || json.Unmarshal([]byte(affectedProducts), &products) != nil {
		return affectedProduct{}, false
	}
	pkgCat := packageCategory(pkgType, pkgEco)
	pkgNormEco := normalizeEcosystem(pkgEco)
	cveNormEco := normalizeEcosystem(cveEco)
	for _, p := range products {
		if !strings.EqualFold(p.Name, pkgName) {
			continue
		}
		affectedEco := normalizeEcosystem(p.Ecosystem)
		effectiveEco := affectedEco
		if effectiveEco == "" {
			effectiveEco = cveNormEco
		}
		if effectiveEco == "" {
			continue
		}
		if len(p.Fixed) == 0 {
			continue
		}
		if !versionIsAffected(installedVersion, p) {
			continue
		}
		affectedCat := packageCategory("", effectiveEco)
		effectiveCat := cveCategory
		if effectiveCat == "" || effectiveCat == "general-cve" {
			effectiveCat = affectedCat
		}
		if pkgCat == "" || effectiveCat == "" || pkgCat != effectiveCat {
			continue
		}
		if pkgNormEco == "" || effectiveEco == "" || pkgNormEco != effectiveEco {
			continue
		}
		return p, true
	}
	return affectedProduct{}, false
}

func versionIsAffected(installed string, p affectedProduct) bool {
	if installed == "" {
		return false
	}
	if len(p.Ranges) > 0 {
		for _, r := range p.Ranges {
			if versionInRange(installed, r.Events) {
				return true
			}
		}
		return false
	}
	for _, fixed := range p.Fixed {
		if less, ok := versionLess(installed, fixed); ok && less {
			return true
		}
	}
	return false
}

func versionInRange(installed string, events []struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
	Limit        string `json:"limit"`
}) bool {
	active := false
	for _, ev := range events {
		if ev.Introduced != "" {
			if ev.Introduced == "0" {
				active = true
			} else if cmp, ok := compareVersions(installed, ev.Introduced); ok {
				active = cmp >= 0
			} else {
				return false
			}
		}
		if active && ev.Fixed != "" {
			if less, ok := versionLess(installed, ev.Fixed); ok {
				active = less
			} else {
				return false
			}
		}
		if active && ev.LastAffected != "" {
			if cmp, ok := compareVersions(installed, ev.LastAffected); ok {
				active = cmp <= 0
			} else {
				return false
			}
		}
		if active && ev.Limit != "" {
			if less, ok := versionLess(installed, ev.Limit); ok {
				active = less
			} else {
				return false
			}
		}
	}
	return active
}

func versionLess(a, b string) (bool, bool) {
	cmp, ok := compareVersions(a, b)
	return cmp < 0, ok
}

func compareVersions(a, b string) (int, bool) {
	as := versionSegments(a)
	bs := versionSegments(b)
	if len(as) == 0 || len(bs) == 0 {
		return 0, false
	}
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		av, bv := 0, 0
		if i < len(as) {
			av = as[i]
		}
		if i < len(bs) {
			bv = bs[i]
		}
		if av < bv {
			return -1, true
		}
		if av > bv {
			return 1, true
		}
	}
	return 0, true
}

func versionSegments(v string) []int {
	v = strings.TrimSpace(v)
	if i := strings.Index(v, ":"); i >= 0 {
		v = v[i+1:]
	}
	parts := strings.FieldsFunc(v, func(r rune) bool {
		return r < '0' || r > '9'
	})
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil
		}
		out = append(out, n)
	}
	return out
}

const pkgCols = `p.id, p.scan_id, p.host_id, p.asset_type, p.asset_id, p.source, p.container, p.container_id, p.image_name, p.image_id, p.name, p.version, p.arch, p.pkg_type, p.ecosystem, p.purl, p.src_name, p.file_path, p.layer_id, p.target, p.created_at`

const pkgVulnJoin = ` LEFT JOIN (SELECT package_id, MAX(cvss_score) as max_cvss, COUNT(*) as vuln_count FROM vulnerabilities WHERE NOT (fixed_version IS NOT NULL AND fixed_version != '' AND installed_version IS NOT NULL AND installed_version != '' AND regexp_replace(regexp_replace(installed_version, '^[0-9]+:', ''), '[^0-9.]', '.', 'g') != '' AND regexp_replace(regexp_replace(fixed_version, '^[0-9]+:', ''), '[^0-9.]', '.', 'g') != '' AND array_remove(string_to_array(regexp_replace(regexp_replace(installed_version, '^[0-9]+:', ''), '[^0-9.]', '.', 'g'), '.'), '')::numeric[] >= array_remove(string_to_array(regexp_replace(regexp_replace(fixed_version, '^[0-9]+:', ''), '[^0-9.]', '.', 'g'), '.'), '')::numeric[]) AND NOT EXISTS (SELECT 1 FROM packages p2 WHERE p2.id = vulnerabilities.package_id AND p2.pkg_type IN ('python-pkg','pip','node-pkg','npm','gomod','go','gobinary','cargo','rustbinary','jar','maven','composer','gem','nuget') AND SUBSTRING(vulnerabilities.vulnerability_id FROM '^[A-Z]+') IN ('DEBIAN','DSA','DLA','ALPINE','SUSE','ALSA','UBUNTU','RHSA')) AND vulnerability_id NOT LIKE 'CGA-%' AND fixed_version !~ '^[0-9a-f]{40}$'
			AND NOT (EXISTS (SELECT 1 FROM packages p3 WHERE p3.id = vulnerabilities.package_id AND p3.pkg_type = 'debian') AND SUBSTRING(vulnerabilities.vulnerability_id FROM '^[A-Z]+') IN ('ALPINE','SUSE','ALSA','RHSA','UBUNTU'))
			AND NOT (EXISTS (SELECT 1 FROM packages p3 WHERE p3.id = vulnerabilities.package_id AND p3.pkg_type IN ('apk','alpine')) AND SUBSTRING(vulnerabilities.vulnerability_id FROM '^[A-Z]+') IN ('DEBIAN','DSA','DLA','SUSE','ALSA','RHSA','UBUNTU'))
			AND NOT (EXISTS (SELECT 1 FROM packages p3 WHERE p3.id = vulnerabilities.package_id AND p3.pkg_type = 'ubuntu') AND SUBSTRING(vulnerabilities.vulnerability_id FROM '^[A-Z]+') IN ('ALPINE','SUSE','ALSA','RHSA'))
			AND NOT (EXISTS (SELECT 1 FROM packages p3 WHERE p3.id = vulnerabilities.package_id AND p3.pkg_type = 'wolfi') AND SUBSTRING(vulnerabilities.vulnerability_id FROM '^[A-Z]+') IN ('DEBIAN','DSA','DLA','ALPINE','SUSE','ALSA','RHSA','UBUNTU'))
			AND NOT EXISTS (
				SELECT 1 FROM cve_database c
				WHERE c.vulnerability_id = vulnerabilities.vulnerability_id
				AND c.affected_products->0->>'ecosystem' IS NOT NULL
				AND (SELECT pkg_type FROM packages WHERE id = vulnerabilities.package_id) IN ('python-pkg','pip','node-pkg','npm','gomod','go','gobinary','cargo','rustbinary','jar','maven','composer','gem','nuget')
				AND c.affected_products->0->>'ecosystem' != CASE (SELECT pkg_type FROM packages WHERE id = vulnerabilities.package_id)
					WHEN 'python-pkg' THEN 'PyPI' WHEN 'pip' THEN 'PyPI'
					WHEN 'node-pkg' THEN 'npm' WHEN 'npm' THEN 'npm'
					WHEN 'gomod' THEN 'Go' WHEN 'go' THEN 'Go' WHEN 'gobinary' THEN 'Go'
					WHEN 'gem' THEN 'RubyGems'
					WHEN 'cargo' THEN 'crates.io' WHEN 'rustbinary' THEN 'crates.io'
					WHEN 'jar' THEN 'Maven' WHEN 'maven' THEN 'Maven'
					WHEN 'composer' THEN 'Packagist'
					WHEN 'nuget' THEN 'NuGet'
				END
			) GROUP BY package_id) vx ON vx.package_id = p.id`

const pkgVulnSelect = `, COALESCE(vx.max_cvss, 0), COALESCE(vx.vuln_count, 0)`

const pkgInsertCols = `id, scan_id, host_id, asset_type, asset_id, source, container, container_id, image_name, image_id, name, version, arch, pkg_type, ecosystem, purl, src_name, file_path, layer_id, target`

func scanPkg(scanner interface{ Scan(...interface{}) error }, p *models.Package) error {
	return scanner.Scan(&p.ID, &p.ScanID, &p.HostID, &p.AssetType, &p.AssetID, &p.Source, &p.Container,
		&p.ContainerID, &p.ImageName, &p.ImageID, &p.Name, &p.Version, &p.Arch, &p.PkgType, &p.Ecosystem, &p.PURL, &p.SrcName,
		&p.FilePath, &p.LayerID, &p.Target, &p.CreatedAt,
		&p.MaxCVSS, &p.VulnCount)
}

func (db *DB) InsertPackages(ctx context.Context, pkgs []models.Package) error {
	if len(pkgs) == 0 {
		return nil
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	q := fmt.Sprintf(`INSERT INTO packages (%s, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,now())`, pkgInsertCols)
	stmt, err := tx.PrepareContext(ctx, q)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for i := range pkgs {
		_, err := stmt.ExecContext(ctx,
			pkgs[i].ID, pkgs[i].ScanID, pkgs[i].HostID,
			defaultString(pkgs[i].AssetType, "host"), pkgs[i].AssetID,
			pkgs[i].Source, pkgs[i].Container, pkgs[i].ContainerID, pkgs[i].ImageName, pkgs[i].ImageID,
			pkgs[i].Name, pkgs[i].Version, pkgs[i].Arch, pkgs[i].PkgType, pkgs[i].Ecosystem, pkgs[i].PURL,
			pkgs[i].SrcName, pkgs[i].FilePath, pkgs[i].LayerID, pkgs[i].Target,
		)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (db *DB) InsertContainers(ctx context.Context, containers []models.ContainerAsset) error {
	if len(containers) == 0 {
		return nil
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	q := `INSERT INTO container_assets (id, scan_id, host_id, runtime, container_id, name, image_name, image_id, image_digest, state, labels, started_at, created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12,now())`
	stmt, err := tx.PrepareContext(ctx, q)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for i := range containers {
		labels := defaultString(containers[i].Labels, "{}")
		_, err := stmt.ExecContext(ctx,
			containers[i].ID, containers[i].ScanID, containers[i].HostID,
			defaultString(containers[i].Runtime, "docker"), containers[i].ContainerID,
			containers[i].Name, containers[i].ImageName, containers[i].ImageID,
			containers[i].ImageDigest, containers[i].State, labels, containers[i].StartedAt,
		)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

const vulnCols = `id, package_id, scan_id, host_id, vulnerability_id, severity, title, description, pkg_name, installed_version, fixed_version, cvss_score, cvss_vector, primary_url, pkg_path, layer_id, container, created_at`

const vulnTriageJoin = ` LEFT JOIN LATERAL (
	SELECT status, reason, comment, expires_at, updated_by, updated_at
	FROM vulnerability_triage
	WHERE vulnerability_id = v.vulnerability_id
	  AND (host_id = '' OR host_id = v.host_id)
	  AND (pkg_name = '' OR pkg_name = v.pkg_name)
	  AND (expires_at IS NULL OR expires_at > now())
	ORDER BY (host_id != '') DESC, (pkg_name != '') DESC, updated_at DESC
	LIMIT 1
) vt ON true`

const vulnTriageCols = `, COALESCE(vt.status, 'open'), COALESCE(vt.reason, ''), COALESCE(vt.comment, ''), vt.expires_at, COALESCE(vt.updated_by, ''), vt.updated_at`

func scanVuln(scanner interface{ Scan(...interface{}) error }, v *models.Vulnerability) error {
	return scanner.Scan(&v.ID, &v.PackageID, &v.ScanID, &v.HostID,
		&v.VulnerabilityID, &v.Severity, &v.Title, &v.Description,
		&v.PkgName, &v.InstalledVer, &v.FixedVersion, &v.CVSSScore,
		&v.CVSSVector, &v.PrimaryURL, &v.PkgPath, &v.LayerID, &v.Container,
		&v.CreatedAt, &v.TriageStatus, &v.TriageReason, &v.TriageComment, &v.TriageExpiresAt, &v.TriageUpdatedBy, &v.TriageUpdatedAt)
}

func (db *DB) InsertVulnerabilities(ctx context.Context, vulns []models.Vulnerability) error {
	if len(vulns) == 0 {
		return nil
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	q := fmt.Sprintf(`INSERT INTO vulnerabilities (%s) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,now())`, vulnCols)
	stmt, err := tx.PrepareContext(ctx, q)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for i := range vulns {
		_, err := stmt.ExecContext(ctx,
			vulns[i].ID, vulns[i].PackageID, vulns[i].ScanID, vulns[i].HostID,
			vulns[i].VulnerabilityID, vulns[i].Severity, vulns[i].Title,
			vulns[i].Description, vulns[i].PkgName, vulns[i].InstalledVer,
			vulns[i].FixedVersion, vulns[i].CVSSScore, vulns[i].CVSSVector, vulns[i].PrimaryURL,
			vulns[i].PkgPath, vulns[i].LayerID, vulns[i].Container,
		)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (db *DB) InsertUserAccounts(ctx context.Context, users []models.UserAccount) error {
	if len(users) == 0 {
		return nil
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	q := `INSERT INTO user_accounts (id, scan_id, host_id, username, uid, gid, home_dir, shell) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`
	stmt, err := tx.PrepareContext(ctx, q)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for i := range users {
		_, err := stmt.ExecContext(ctx,
			users[i].ID, users[i].ScanID, users[i].HostID,
			users[i].Username, users[i].UID, users[i].GID, users[i].HomeDir, users[i].Shell,
		)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (db *DB) InsertProcessSnapshots(ctx context.Context, procs []models.ProcessSnapshot) error {
	if len(procs) == 0 {
		return nil
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	q := `INSERT INTO process_snapshots (id, scan_id, host_id, pid, name, cmdline, user_name, cpu_usage, mem_usage) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`
	stmt, err := tx.PrepareContext(ctx, q)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for i := range procs {
		_, err := stmt.ExecContext(ctx,
			procs[i].ID, procs[i].ScanID, procs[i].HostID,
			procs[i].PID, procs[i].Name, procs[i].Cmdline, procs[i].User,
			procs[i].CPUUsage, procs[i].MemUsage,
		)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (db *DB) InsertPorts(ctx context.Context, ports []models.PortInfo) error {
	if len(ports) == 0 {
		return nil
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	q := `INSERT INTO port_info (id, scan_id, host_id, name, port, protocol, address, pid) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`
	stmt, err := tx.PrepareContext(ctx, q)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for i := range ports {
		_, err := stmt.ExecContext(ctx,
			ports[i].ID, ports[i].ScanID, ports[i].HostID,
			ports[i].Name, ports[i].Port, ports[i].Protocol, ports[i].Address, ports[i].PID,
		)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (db *DB) ListScans(ctx context.Context, hostID string, hostIDs []string, limit, offset int) ([]models.Scan, int, error) {
	countQ := `SELECT count(*) FROM scans WHERE 1=1`
	dataQ := `SELECT id, host_id, scan_type, status, started_at, finished_at, created_at FROM scans WHERE 1=1`
	args := []any{}
	n := 1

	if hostID != "" {
		countQ += fmt.Sprintf(" AND host_id=$%d", n)
		dataQ += fmt.Sprintf(" AND host_id=$%d", n)
		args = append(args, hostID)
		n++
	} else if len(hostIDs) > 0 {
		countQ += fmt.Sprintf(" AND host_id = ANY($%d)", n)
		dataQ += fmt.Sprintf(" AND host_id = ANY($%d)", n)
		args = append(args, pqStringArray(hostIDs))
		n++
	}

	var total int
	countArgs := make([]any, len(args))
	copy(countArgs, args)
	if err := db.QueryRowContext(ctx, countQ, countArgs...).Scan(&total); err != nil {
		return nil, 0, err
	}

	dataQ += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", n, n+1)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, dataQ, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var scans []models.Scan
	for rows.Next() {
		var s models.Scan
		if err := rows.Scan(&s.ID, &s.HostID, &s.ScanType, &s.Status, &s.StartedAt, &s.FinishedAt, &s.CreatedAt); err != nil {
			return nil, 0, err
		}
		scans = append(scans, s)
	}
	return scans, total, nil
}

func (db *DB) CreateScanRequest(ctx context.Context, req *models.ScanRequest) error {
	if req.ID == "" {
		req.ID = uuid.New().String()
	}
	if req.ScanType == "" {
		req.ScanType = "manual"
	}
	if req.Status == "" {
		req.Status = "pending"
	}
	_, err := db.ExecContext(ctx, `INSERT INTO scan_requests (id, host_id, requested_by, scan_type, packages_only, reason, status, created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,now())`,
		req.ID, req.HostID, req.RequestedBy, req.ScanType, req.PackagesOnly, req.Reason, req.Status)
	return err
}

func (db *DB) QueueSecurityDBRescans(ctx context.Context, requestedBy, reason string, lastSeenAfter time.Time) (int, error) {
	q := `SELECT id FROM hosts`
	args := []any{}
	if !lastSeenAfter.IsZero() {
		q += ` WHERE last_seen >= $1`
		args = append(args, lastSeenAfter)
	}
	q += ` ORDER BY hostname`

	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	queued := 0
	for rows.Next() {
		var hostID string
		if err := rows.Scan(&hostID); err != nil {
			return queued, err
		}
		res, err := tx.ExecContext(ctx, `
INSERT INTO scan_requests (id, host_id, requested_by, scan_type, packages_only, reason, status, created_at)
SELECT $1,$2,$3,'security-db-update',true,$4,'pending',now()
WHERE NOT EXISTS (
	SELECT 1 FROM scan_requests
	WHERE host_id=$2 AND status IN ('pending','claimed')
)`, uuid.New().String(), hostID, requestedBy, reason)
		if err != nil {
			return queued, err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			queued++
		}
	}
	if err := rows.Err(); err != nil {
		return queued, err
	}
	return queued, tx.Commit()
}

func (db *DB) ListScanRequests(ctx context.Context, hostID, status string, limit, offset int) ([]models.ScanRequest, int, error) {
	baseQ := `FROM scan_requests WHERE 1=1`
	args := []any{}
	n := 1
	if hostID != "" {
		baseQ += fmt.Sprintf(" AND host_id=$%d", n)
		args = append(args, hostID)
		n++
	}
	if status != "" {
		baseQ += fmt.Sprintf(" AND status=$%d", n)
		args = append(args, status)
		n++
	}
	var total int
	if err := db.QueryRowContext(ctx, "SELECT count(*) "+baseQ, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	q := `SELECT id, host_id, requested_by, scan_type, packages_only, reason, status, error_message, claimed_at, completed_at, created_at ` + baseQ + fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", n, n+1)
	args = append(args, limit, offset)
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []models.ScanRequest
	for rows.Next() {
		var r models.ScanRequest
		if err := rows.Scan(&r.ID, &r.HostID, &r.RequestedBy, &r.ScanType, &r.PackagesOnly, &r.Reason, &r.Status, &r.ErrorMessage, &r.ClaimedAt, &r.CompletedAt, &r.CreatedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, r)
	}
	return out, total, nil
}

func (db *DB) ClaimScanRequest(ctx context.Context, hostID string) (*models.ScanRequest, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	q := `UPDATE scan_requests
SET status='claimed', claimed_at=now(), error_message=''
WHERE id = (
	SELECT id FROM scan_requests
	WHERE status='pending' AND (host_id='' OR host_id=$1)
	ORDER BY created_at ASC
	FOR UPDATE SKIP LOCKED
	LIMIT 1
)
RETURNING id, host_id, requested_by, scan_type, packages_only, reason, status, error_message, claimed_at, completed_at, created_at`
	var r models.ScanRequest
	err = tx.QueryRowContext(ctx, q, hostID).Scan(&r.ID, &r.HostID, &r.RequestedBy, &r.ScanType, &r.PackagesOnly, &r.Reason, &r.Status, &r.ErrorMessage, &r.ClaimedAt, &r.CompletedAt, &r.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, tx.Commit()
	}
	if err != nil {
		return nil, err
	}
	return &r, tx.Commit()
}

func (db *DB) CompleteScanRequest(ctx context.Context, id, status, message string) error {
	if status != "completed" && status != "failed" && status != "cancelled" {
		return fmt.Errorf("invalid scan request status: %s", status)
	}
	_, err := db.ExecContext(ctx, `UPDATE scan_requests
SET status=$2, error_message=$3, completed_at=now()
WHERE id=$1 AND status IN ('pending','claimed')`, id, status, message)
	return err
}

type AuditLogFilter struct {
	ActorType    string
	ActorID      string
	Action       string
	ResourceType string
	ResourceID   string
	Status       string
}

func (db *DB) RecordAuditLog(ctx context.Context, logEntry *models.AuditLog) error {
	if logEntry.ID == "" {
		logEntry.ID = uuid.New().String()
	}
	if logEntry.Status == "" {
		logEntry.Status = "ok"
	}
	if len(logEntry.Metadata) == 0 {
		logEntry.Metadata = json.RawMessage(`{}`)
	}
	_, err := db.ExecContext(ctx, `INSERT INTO audit_logs
(id, actor_type, actor_id, action, resource_type, resource_id, status, ip_address, user_agent, metadata, created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,now())`,
		logEntry.ID, logEntry.ActorType, logEntry.ActorID, logEntry.Action, logEntry.ResourceType, logEntry.ResourceID,
		logEntry.Status, logEntry.IPAddress, logEntry.UserAgent, logEntry.Metadata)
	return err
}

func (db *DB) ListAuditLogs(ctx context.Context, f AuditLogFilter, limit, offset int) ([]models.AuditLog, int, error) {
	baseQ := `FROM audit_logs WHERE 1=1`
	args := []any{}
	n := 1
	add := func(col, value string) {
		if value == "" {
			return
		}
		baseQ += fmt.Sprintf(" AND %s=$%d", col, n)
		args = append(args, value)
		n++
	}
	add("actor_type", f.ActorType)
	add("actor_id", f.ActorID)
	add("action", f.Action)
	add("resource_type", f.ResourceType)
	add("resource_id", f.ResourceID)
	add("status", f.Status)

	var total int
	if err := db.QueryRowContext(ctx, "SELECT count(*) "+baseQ, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	q := `SELECT id, actor_type, actor_id, action, resource_type, resource_id, status, ip_address, user_agent, metadata, created_at ` + baseQ + fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", n, n+1)
	args = append(args, limit, offset)
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []models.AuditLog
	for rows.Next() {
		var item models.AuditLog
		if err := rows.Scan(&item.ID, &item.ActorType, &item.ActorID, &item.Action, &item.ResourceType, &item.ResourceID, &item.Status, &item.IPAddress, &item.UserAgent, &item.Metadata, &item.CreatedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

type AccessScope struct {
	All     bool
	HostIDs []string
}

func (s AccessScope) CanReadHost(hostID string) bool {
	if s.All {
		return true
	}
	for _, id := range s.HostIDs {
		if id == hostID {
			return true
		}
	}
	return false
}

func (s AccessScope) Empty() bool {
	return !s.All && len(s.HostIDs) == 0
}

func pqStringArray(v []string) any {
	return pq.Array(v)
}

func (db *DB) GetAccessScope(ctx context.Context, externalID string) (AccessScope, error) {
	rows, err := db.QueryContext(ctx, `
SELECT p.resource_type, p.resource_id
FROM access_subjects s
JOIN access_policies p ON p.subject_id = s.id
WHERE s.external_id=$1 AND p.permission IN ('read','admin')`, externalID)
	if err != nil {
		return AccessScope{}, err
	}
	defer rows.Close()
	scope := AccessScope{}
	for rows.Next() {
		var rt, rid string
		if err := rows.Scan(&rt, &rid); err != nil {
			return AccessScope{}, err
		}
		switch rt {
		case "all":
			scope.All = true
		case "host":
			if rid != "" && rid != "*" {
				scope.HostIDs = append(scope.HostIDs, rid)
			}
		}
	}
	return scope, rows.Err()
}

func (db *DB) UpsertAccessSubject(ctx context.Context, id, subjectType, externalID, displayName string) error {
	if id == "" {
		id = uuid.New().String()
	}
	_, err := db.ExecContext(ctx, `INSERT INTO access_subjects (id, subject_type, external_id, display_name, created_at, updated_at)
VALUES ($1,$2,$3,$4,now(),now())
ON CONFLICT (subject_type, external_id) DO UPDATE SET display_name=EXCLUDED.display_name, updated_at=now()`,
		id, subjectType, externalID, displayName)
	return err
}

func (db *DB) UpsertAccessPolicy(ctx context.Context, id, subjectExternalID, resourceType, resourceID, permission string) error {
	if id == "" {
		id = uuid.New().String()
	}
	if resourceID == "" {
		resourceID = "*"
	}
	_, err := db.ExecContext(ctx, `INSERT INTO access_policies (id, subject_id, resource_type, resource_id, permission, created_at)
SELECT $1, s.id, $3, $4, $5, now()
FROM access_subjects s
WHERE s.external_id=$2
ON CONFLICT (subject_id, resource_type, resource_id, permission) DO NOTHING`,
		id, subjectExternalID, resourceType, resourceID, permission)
	return err
}

func (db *DB) UpsertVulnerabilityTriage(ctx context.Context, t *models.VulnerabilityTriage) error {
	if t.ID == "" {
		t.ID = uuid.New().String()
	}
	if t.VulnerabilityID == "" {
		return fmt.Errorf("vulnerability_id is required")
	}
	if t.Status == "" {
		t.Status = "open"
	}
	err := db.QueryRowContext(ctx, `INSERT INTO vulnerability_triage
(id, vulnerability_id, host_id, pkg_name, status, reason, comment, expires_at, updated_by, created_at, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,now(),now())
ON CONFLICT (vulnerability_id, host_id, pkg_name) DO UPDATE SET
	status=EXCLUDED.status,
	reason=EXCLUDED.reason,
	comment=EXCLUDED.comment,
	expires_at=EXCLUDED.expires_at,
	updated_by=EXCLUDED.updated_by,
	updated_at=now()
RETURNING id, created_at, updated_at`,
		t.ID, t.VulnerabilityID, t.HostID, t.PkgName, t.Status, t.Reason, t.Comment, t.ExpiresAt, t.UpdatedBy,
	).Scan(&t.ID, &t.CreatedAt, &t.UpdatedAt)
	return err
}

func (db *DB) ListHosts(ctx context.Context) ([]models.Host, error) {
	q := `SELECT id, hostname, ip_address, os_name, os_version, kernel, arch, cpu_model, cpu_cores, memory_mb, agent_version, last_seen, created_at FROM hosts ORDER BY hostname`
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hosts []models.Host
	for rows.Next() {
		var h models.Host
		if err := rows.Scan(&h.ID, &h.Hostname, &h.IPAddress, &h.OSName, &h.OSVersion,
			&h.Kernel, &h.Arch, &h.CPUModel, &h.CPUCores, &h.MemoryMB, &h.AgentVersion,
			&h.LastSeen, &h.CreatedAt); err != nil {
			return nil, err
		}
		hosts = append(hosts, h)
	}
	return hosts, nil
}

func (db *DB) GetHost(ctx context.Context, id string) (*models.Host, error) {
	q := `SELECT id, hostname, ip_address, os_name, os_version, kernel, arch, cpu_model, cpu_cores, memory_mb, agent_version, last_seen, created_at FROM hosts WHERE id=$1`
	var h models.Host
	err := db.QueryRowContext(ctx, q, id).Scan(&h.ID, &h.Hostname, &h.IPAddress, &h.OSName,
		&h.OSVersion, &h.Kernel, &h.Arch, &h.CPUModel, &h.CPUCores, &h.MemoryMB,
		&h.AgentVersion, &h.LastSeen, &h.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &h, nil
}

const latestScansSub = `(SELECT DISTINCT ON (host_id) id FROM scans WHERE status='completed' ORDER BY host_id, created_at DESC)`

type VulnFilter struct {
	HostID       string
	HostIDs      []string
	Severity     string
	TriageStatus string
	PkgName      string
	Container    string
	MinCVSS      float64
	SortBy       string
	SortDesc     bool
	HideFixed    bool
	HideNoFix    bool
	HideMismatch bool
}

func (db *DB) ListVulnerabilities(ctx context.Context, f VulnFilter, limit, offset int) ([]models.Vulnerability, int, error) {
	useLatest := f.HostID == ""
	baseQ := `FROM vulnerabilities v`
	args := []any{}
	argN := 1

	if useLatest {
		baseQ += ` JOIN ` + latestScansSub + ` ls ON v.scan_id = ls.id`
	}

	baseQ += vulnTriageJoin
	baseQ += ` WHERE 1=1`

	if f.HostID != "" {
		baseQ += fmt.Sprintf(" AND v.host_id=$%d", argN)
		args = append(args, f.HostID)
		argN++
	} else if len(f.HostIDs) > 0 {
		baseQ += fmt.Sprintf(" AND v.host_id = ANY($%d)", argN)
		args = append(args, pqStringArray(f.HostIDs))
		argN++
	}
	if f.Severity != "" {
		baseQ += fmt.Sprintf(" AND v.severity=$%d", argN)
		args = append(args, f.Severity)
		argN++
	}
	if f.TriageStatus != "" {
		baseQ += fmt.Sprintf(" AND COALESCE(vt.status, 'open')=$%d", argN)
		args = append(args, f.TriageStatus)
		argN++
	}
	if f.PkgName != "" {
		baseQ += fmt.Sprintf(" AND v.pkg_name ILIKE $%d", argN)
		args = append(args, "%"+f.PkgName+"%")
		argN++
	}
	if f.Container != "" {
		baseQ += fmt.Sprintf(" AND v.container=$%d", argN)
		args = append(args, f.Container)
		argN++
	}
	if f.MinCVSS > 0 {
		baseQ += fmt.Sprintf(" AND v.cvss_score>=$%d", argN)
		args = append(args, f.MinCVSS)
		argN++
	}

	if f.HideFixed {
		baseQ += ` AND NOT (
			v.fixed_version IS NOT NULL AND v.fixed_version != ''
			AND v.installed_version IS NOT NULL AND v.installed_version != ''
			AND regexp_replace(regexp_replace(v.installed_version, '^[0-9]+:', ''), '[^0-9.]', '.', 'g') != ''
			AND regexp_replace(regexp_replace(v.fixed_version, '^[0-9]+:', ''), '[^0-9.]', '.', 'g') != ''
			AND array_remove(string_to_array(regexp_replace(regexp_replace(v.installed_version, '^[0-9]+:', ''), '[^0-9.]', '.', 'g'), '.'), '')::numeric[]
			  >= array_remove(string_to_array(regexp_replace(regexp_replace(v.fixed_version, '^[0-9]+:', ''), '[^0-9.]', '.', 'g'), '.'), '')::numeric[]
		)`
		baseQ += ` AND v.vulnerability_id NOT LIKE 'CGA-%'`
		baseQ += ` AND v.fixed_version !~ '^[0-9a-f]{40}$'`
	}
	if f.HideNoFix {
		baseQ += ` AND (v.fixed_version IS NOT NULL AND v.fixed_version != '')`
	}
	if f.HideMismatch {
		// Language packages should not get OS-specific advisories
		baseQ += ` AND NOT EXISTS (SELECT 1 FROM packages p WHERE p.id = v.package_id AND p.pkg_type IN ('python-pkg','pip','node-pkg','npm','gomod','go','gobinary','cargo','rustbinary','jar','maven','composer','gem','nuget') AND SUBSTRING(v.vulnerability_id FROM '^[A-Z]+') IN ('DEBIAN','DSA','DLA','ALPINE','SUSE','ALSA','CGA','UBUNTU','RHSA'))`
		// OS packages should only get advisories for their own OS
		// Debian: allow DEBIAN,DSA,DLA,CVE,GHSA | block ALPINE,SUSE,ALSA,RHSA,UBUNTU
		baseQ += ` AND NOT (EXISTS (SELECT 1 FROM packages p WHERE p.id = v.package_id AND p.pkg_type = 'debian') AND SUBSTRING(v.vulnerability_id FROM '^[A-Z]+') IN ('ALPINE','SUSE','ALSA','RHSA','UBUNTU'))`
		// Alpine: allow ALPINE,CVE,GHSA | block DEBIAN,DSA,DLA,SUSE,ALSA,RHSA,UBUNTU
		baseQ += ` AND NOT (EXISTS (SELECT 1 FROM packages p WHERE p.id = v.package_id AND p.pkg_type IN ('apk','alpine')) AND SUBSTRING(v.vulnerability_id FROM '^[A-Z]+') IN ('DEBIAN','DSA','DLA','SUSE','ALSA','RHSA','UBUNTU'))`
		// Ubuntu: allow UBUNTU,DEBIAN,DSA,DLA,CVE,GHSA | block ALPINE,SUSE,ALSA,RHSA
		baseQ += ` AND NOT (EXISTS (SELECT 1 FROM packages p WHERE p.id = v.package_id AND p.pkg_type = 'ubuntu') AND SUBSTRING(v.vulnerability_id FROM '^[A-Z]+') IN ('ALPINE','SUSE','ALSA','RHSA'))`
		// Wolfi: allow CVE,GHSA only | block DEBIAN,DSA,DLA,ALPINE,SUSE,ALSA,RHSA,UBUNTU
		baseQ += ` AND NOT (EXISTS (SELECT 1 FROM packages p WHERE p.id = v.package_id AND p.pkg_type = 'wolfi') AND SUBSTRING(v.vulnerability_id FROM '^[A-Z]+') IN ('DEBIAN','DSA','DLA','ALPINE','SUSE','ALSA','RHSA','UBUNTU'))`
	}
	var total int
	countArgs := make([]any, len(args))
	copy(countArgs, args)
	if err := db.QueryRowContext(ctx, "SELECT count(*) "+baseQ, countArgs...).Scan(&total); err != nil {
		return nil, 0, err
	}

	sortExpr := vulnSortExpr(f.SortBy, f.SortDesc)
	dataQ := fmt.Sprintf(`SELECT v.%s%s `, vulnCols, vulnTriageCols) + baseQ + fmt.Sprintf(" ORDER BY %s LIMIT $%d OFFSET $%d", sortExpr, argN, argN+1)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, dataQ, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var vulns []models.Vulnerability
	for rows.Next() {
		var v models.Vulnerability
		if err := scanVuln(rows, &v); err != nil {
			return nil, 0, err
		}
		vulns = append(vulns, v)
	}
	return vulns, total, nil
}

func (db *DB) GetHostVulnCounts(ctx context.Context, hostID string) (map[string]int, error) {
	q := `SELECT severity, count(*) FROM vulnerabilities WHERE host_id=$1 GROUP BY severity`
	rows, err := db.QueryContext(ctx, q, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	counts := map[string]int{}
	for rows.Next() {
		var sev string
		var cnt int
		if err := rows.Scan(&sev, &cnt); err != nil {
			return nil, err
		}
		counts[sev] = cnt
	}
	return counts, nil
}

func (db *DB) GetVulnCountsByHost(ctx context.Context) (map[string]map[string]int, error) {
	q := `SELECT host_id, severity, count(*) FROM vulnerabilities GROUP BY host_id, severity`
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := map[string]map[string]int{}
	for rows.Next() {
		var hostID, sev string
		var cnt int
		if err := rows.Scan(&hostID, &sev, &cnt); err != nil {
			return nil, err
		}
		if result[hostID] == nil {
			result[hostID] = map[string]int{}
		}
		result[hostID][sev] = cnt
	}
	return result, nil
}

func (db *DB) GetVulnCountsByScan(ctx context.Context, scanID string) (map[string]int, int, error) {
	rows, err := db.QueryContext(ctx, `SELECT severity, count(*) FROM vulnerabilities WHERE scan_id=$1 GROUP BY severity`, scanID)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	counts := map[string]int{}
	total := 0
	for rows.Next() {
		var sev string
		var cnt int
		if err := rows.Scan(&sev, &cnt); err != nil {
			return nil, 0, err
		}
		counts[sev] = cnt
		total += cnt
	}
	return counts, total, rows.Err()
}

func (db *DB) GetLatestPackages(ctx context.Context, hostID string, limit, offset int) ([]models.Package, int, error) {
	countQ := fmt.Sprintf(`SELECT count(*) FROM packages p JOIN %s ls ON p.scan_id = ls.id WHERE p.host_id=$1`, latestScansSub)
	dataQ := fmt.Sprintf(`SELECT %s%s FROM packages p JOIN %s ls ON p.scan_id = ls.id%s WHERE p.host_id=$1 ORDER BY p.name LIMIT $2 OFFSET $3`, pkgCols, pkgVulnSelect, latestScansSub, pkgVulnJoin)

	var total int
	if err := db.QueryRowContext(ctx, countQ, hostID).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := db.QueryContext(ctx, dataQ, hostID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var pkgs []models.Package
	for rows.Next() {
		var p models.Package
		if err := scanPkg(rows, &p); err != nil {
			return nil, 0, err
		}
		pkgs = append(pkgs, p)
	}
	return pkgs, total, nil
}

func (db *DB) GetLatestPackagesForSBOM(ctx context.Context, hostID string) ([]models.Package, error) {
	q := fmt.Sprintf(`SELECT %s%s FROM packages p JOIN %s ls ON p.scan_id = ls.id%s WHERE p.host_id=$1 ORDER BY p.asset_type, p.container, p.name, p.version`,
		pkgCols, pkgVulnSelect, latestScansSub, pkgVulnJoin)
	rows, err := db.QueryContext(ctx, q, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var pkgs []models.Package
	for rows.Next() {
		var p models.Package
		if err := scanPkg(rows, &p); err != nil {
			return nil, err
		}
		pkgs = append(pkgs, p)
	}
	return pkgs, rows.Err()
}

type PackageFilter struct {
	HostID     string
	HostIDs    []string
	Container  string
	PkgType    string
	Source     string
	NameSearch string
	SortBy     string
	SortDesc   bool
	Limit      int
	Offset     int
}

func (db *DB) SearchPackages(ctx context.Context, f PackageFilter) ([]models.Package, int, error) {
	useLatest := f.HostID == ""
	baseQ := `FROM packages p` + pkgVulnJoin
	args := []any{}
	n := 1

	if useLatest {
		baseQ += ` JOIN ` + latestScansSub + ` ls ON p.scan_id = ls.id`
	}

	baseQ += ` WHERE 1=1`

	if f.HostID != "" {
		baseQ += fmt.Sprintf(" AND p.host_id=$%d", n)
		args = append(args, f.HostID)
		n++
	} else if len(f.HostIDs) > 0 {
		baseQ += fmt.Sprintf(" AND p.host_id = ANY($%d)", n)
		args = append(args, pqStringArray(f.HostIDs))
		n++
	}
	if f.Container != "" {
		if f.Container == "(host)" {
			baseQ += " AND (p.container = '' OR p.container IS NULL)"
		} else {
			baseQ += fmt.Sprintf(" AND p.container=$%d", n)
			args = append(args, f.Container)
			n++
		}
	}
	if f.PkgType != "" {
		baseQ += fmt.Sprintf(" AND p.pkg_type=$%d", n)
		args = append(args, f.PkgType)
		n++
	}
	if f.Source != "" {
		baseQ += fmt.Sprintf(" AND p.source=$%d", n)
		args = append(args, f.Source)
		n++
	}
	if f.NameSearch != "" {
		baseQ += fmt.Sprintf(" AND p.name ILIKE $%d", n)
		args = append(args, "%"+f.NameSearch+"%")
		n++
	}

	var total int
	countArgs := make([]any, len(args))
	copy(countArgs, args)
	if err := db.QueryRowContext(ctx, "SELECT count(*) "+baseQ, countArgs...).Scan(&total); err != nil {
		return nil, 0, err
	}

	dataQ := fmt.Sprintf(`SELECT %s%s `, pkgCols, pkgVulnSelect) + baseQ + fmt.Sprintf(" ORDER BY %s LIMIT $%d OFFSET $%d", pkgSortExpr(f.SortBy, f.SortDesc), n, n+1)
	args = append(args, f.Limit, f.Offset)

	rows, err := db.QueryContext(ctx, dataQ, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var pkgs []models.Package
	for rows.Next() {
		var p models.Package
		if err := scanPkg(rows, &p); err != nil {
			return nil, 0, err
		}
		pkgs = append(pkgs, p)
	}
	return pkgs, total, nil
}

func (db *DB) GetPackageHostID(ctx context.Context, packageID string) (string, error) {
	var hostID string
	err := db.QueryRowContext(ctx, `SELECT host_id FROM packages WHERE id=$1`, packageID).Scan(&hostID)
	return hostID, err
}

type FilterOptions struct {
	HostIDs    []string `json:"host_ids"`
	Containers []string `json:"containers"`
	PkgTypes   []string `json:"pkg_types"`
	Sources    []string `json:"sources"`
}

func (db *DB) GetVulnFilterOptions(ctx context.Context) (*FilterOptions, error) {
	opts := &FilterOptions{}
	rows, err := db.QueryContext(ctx, `SELECT DISTINCT v.host_id FROM vulnerabilities v JOIN `+latestScansSub+` ls ON v.scan_id = ls.id ORDER BY v.host_id`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var v string
		rows.Scan(&v)
		opts.HostIDs = append(opts.HostIDs, v)
	}
	rows.Close()

	rows, err = db.QueryContext(ctx, `SELECT DISTINCT COALESCE(NULLIF(v.container, ''), '(host)') FROM vulnerabilities v JOIN `+latestScansSub+` ls ON v.scan_id = ls.id ORDER BY 1`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var v string
		rows.Scan(&v)
		opts.Containers = append(opts.Containers, v)
	}
	rows.Close()

	return opts, nil
}

type CveSearchFilter struct {
	Query    string
	PkgName  string
	Severity string
	HostIDs  []string
	MinCVSS  float64
	SortBy   string
	SortDesc bool
}

func (db *DB) SearchCVEs(ctx context.Context, f CveSearchFilter, limit, offset int) ([]models.Vulnerability, int, error) {
	baseQ := `FROM vulnerabilities v JOIN ` + latestScansSub + ` ls ON v.scan_id = ls.id` + vulnTriageJoin + ` WHERE 1=1`
	args := []any{}
	argN := 1

	if f.Query != "" {
		baseQ += fmt.Sprintf(" AND (v.vulnerability_id ILIKE $%d OR v.title ILIKE $%d OR v.description ILIKE $%d)", argN, argN, argN)
		args = append(args, "%"+f.Query+"%")
		argN++
	}
	if f.PkgName != "" {
		baseQ += fmt.Sprintf(" AND v.pkg_name ILIKE $%d", argN)
		args = append(args, "%"+f.PkgName+"%")
		argN++
	}
	if f.Severity != "" {
		baseQ += fmt.Sprintf(" AND v.severity=$%d", argN)
		args = append(args, f.Severity)
		argN++
	}
	if len(f.HostIDs) > 0 {
		baseQ += fmt.Sprintf(" AND v.host_id = ANY($%d)", argN)
		args = append(args, pqStringArray(f.HostIDs))
		argN++
	}
	if f.MinCVSS > 0 {
		baseQ += fmt.Sprintf(" AND v.cvss_score>=$%d", argN)
		args = append(args, f.MinCVSS)
		argN++
	}

	var total int
	countArgs := make([]any, len(args))
	copy(countArgs, args)
	if err := db.QueryRowContext(ctx, "SELECT count(*) "+baseQ, countArgs...).Scan(&total); err != nil {
		return nil, 0, err
	}

	sortExpr := vulnSortExpr(f.SortBy, f.SortDesc)
	dataQ := fmt.Sprintf(`SELECT v.%s%s `, vulnCols, vulnTriageCols) + baseQ + fmt.Sprintf(" ORDER BY %s LIMIT $%d OFFSET $%d", sortExpr, argN, argN+1)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, dataQ, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var vulns []models.Vulnerability
	for rows.Next() {
		var v models.Vulnerability
		if err := scanVuln(rows, &v); err != nil {
			return nil, 0, err
		}
		vulns = append(vulns, v)
	}
	return vulns, total, nil
}

func (db *DB) EnrichVulnerabilities(ctx context.Context) (int, error) {
	// Step 1: exact vulnerability_id match — fill severity + fixed_version + title/description
	q1 := `
	UPDATE vulnerabilities v
	SET severity = COALESCE(c.severity, v.severity),
	    cvss_score = CASE WHEN v.cvss_score = 0 OR c.cvss_score > v.cvss_score THEN c.cvss_score ELSE v.cvss_score END,
	    cvss_vector = COALESCE(NULLIF(c.cvss_vector, ''), v.cvss_vector),
	    fixed_version = COALESCE(NULLIF(v.fixed_version, ''), COALESCE(c.affected_products->0->'fixed'->>0, '')),
	    title = CASE WHEN c.title != '' THEN c.title ELSE v.title END,
	    description = CASE WHEN c.description != '' THEN c.description ELSE v.description END
	FROM cve_database c
	WHERE c.vulnerability_id = v.vulnerability_id
	  AND (v.severity = '' OR v.cvss_score = 0 OR v.fixed_version = '' OR v.title = '' OR v.description = '' OR c.cvss_score > v.cvss_score)
	  AND (c.cvss_score > 0 OR c.affected_products->0->'fixed'->>0 IS NOT NULL OR c.title != '')`
	r1, err := db.ExecContext(ctx, q1)
	if err != nil {
		return 0, err
	}
	n1, _ := r1.RowsAffected()

	// Step 2: CVE number extraction match (DEBIAN-CVE-*, ALPINE-CVE-*, etc.)
	q2 := `
	WITH v_cves AS (
		SELECT id as vid, SUBSTRING(vulnerability_id FROM 'CVE-\d+-\d+') as cve
		FROM vulnerabilities
		WHERE (severity = '' OR cvss_score = 0 OR fixed_version = '' OR title = '') AND vulnerability_id ~ 'CVE-'
	),
	c_cves AS (
		SELECT DISTINCT ON (cve) severity, cvss_score, cvss_vector,
		    affected_products->0->'fixed'->>0 as fixed_ver, cve,
		    title as cve_title, description as cve_desc
		FROM (
			SELECT severity, cvss_score, cvss_vector, affected_products,
				   SUBSTRING(vulnerability_id FROM 'CVE-\d+-\d+') as cve,
				   title, description
			FROM cve_database WHERE cvss_score > 0 OR affected_products->0->'fixed'->>0 IS NOT NULL OR title != ''
		) sub
		ORDER BY cve, cvss_score DESC
	)
	UPDATE vulnerabilities v
	SET severity = COALESCE(c.severity, v.severity),
	    cvss_score = CASE WHEN v.cvss_score = 0 OR c.cvss_score > v.cvss_score THEN c.cvss_score ELSE v.cvss_score END,
	    cvss_vector = COALESCE(NULLIF(c.cvss_vector, ''), v.cvss_vector),
	    fixed_version = COALESCE(NULLIF(v.fixed_version, ''), COALESCE(c.fixed_ver, '')),
	    title = CASE WHEN c.cve_title != '' THEN c.cve_title ELSE v.title END,
	    description = CASE WHEN c.cve_desc != '' THEN c.cve_desc ELSE v.description END
	FROM v_cves vc JOIN c_cves c ON c.cve = vc.cve
	WHERE v.id = vc.vid`
	r2, err := db.ExecContext(ctx, q2)
	if err != nil {
		return int(n1), err
	}
	n2, _ := r2.RowsAffected()
	return int(n1) + int(n2), nil
}

func (db *DB) GetFilterOptions(ctx context.Context) (*FilterOptions, error) {
	opts := &FilterOptions{}

	rows, err := db.QueryContext(ctx, `SELECT DISTINCT host_id FROM packages ORDER BY host_id`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var v string
		rows.Scan(&v)
		opts.HostIDs = append(opts.HostIDs, v)
	}
	rows.Close()

	rows, err = db.QueryContext(ctx, `SELECT DISTINCT COALESCE(NULLIF(container, ''), '(host)') FROM packages ORDER BY 1`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var v string
		rows.Scan(&v)
		opts.Containers = append(opts.Containers, v)
	}
	rows.Close()

	rows, err = db.QueryContext(ctx, `SELECT DISTINCT pkg_type FROM packages ORDER BY pkg_type`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var v string
		rows.Scan(&v)
		opts.PkgTypes = append(opts.PkgTypes, v)
	}
	rows.Close()

	rows, err = db.QueryContext(ctx, `SELECT DISTINCT source FROM packages ORDER BY source`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var v string
		rows.Scan(&v)
		opts.Sources = append(opts.Sources, v)
	}
	rows.Close()

	return opts, nil
}

func pkgSortExpr(col string, desc bool) string {
	allowed := map[string]string{
		"name": "p.name", "version": "p.version", "pkg_type": "p.pkg_type",
		"container": "p.container", "source": "p.source", "file_path": "p.file_path",
		"asset_type": "p.asset_type", "ecosystem": "p.ecosystem", "image_name": "p.image_name",
		"max_cvss": "COALESCE(vx.max_cvss, 0)", "vuln_count": "COALESCE(vx.vuln_count, 0)",
	}
	expr, ok := allowed[col]
	if !ok {
		expr = "p.name"
	}
	dir := "ASC"
	if desc {
		dir = "DESC"
	}
	return expr + " " + dir + " NULLS LAST"
}

func vulnSortExpr(col string, desc bool) string {
	allowed := map[string]string{
		"vulnerability_id": "v.vulnerability_id", "severity": "CASE v.severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END",
		"cvss_score": "v.cvss_score", "pkg_name": "v.pkg_name",
		"host_id": "v.host_id", "container": "v.container", "installed_version": "v.installed_version",
		"fixed_version": "v.fixed_version", "created_at": "v.created_at",
	}
	expr, ok := allowed[col]
	if !ok {
		expr = "v.cvss_score"
	}
	dir := "ASC"
	if desc {
		dir = "DESC"
	}
	return expr + " " + dir + " NULLS LAST"
}

func (db *DB) GetVulnsByPackageID(ctx context.Context, packageID string) ([]models.Vulnerability, error) {
	q := `SELECT v.` + vulnCols + vulnTriageCols + ` FROM vulnerabilities v` + vulnTriageJoin + ` WHERE v.package_id=$1 AND NOT (v.fixed_version IS NOT NULL AND v.fixed_version != '' AND v.installed_version IS NOT NULL AND v.installed_version != '' AND regexp_replace(regexp_replace(v.installed_version, '^[0-9]+:', ''), '[^0-9.]', '.', 'g') != '' AND regexp_replace(regexp_replace(v.fixed_version, '^[0-9]+:', ''), '[^0-9.]', '.', 'g') != '' AND v.fixed_version !~ '^[0-9a-f]{40}$'
			AND array_remove(string_to_array(regexp_replace(regexp_replace(v.installed_version, '^[0-9]+:', ''), '[^0-9.]', '.', 'g'), '.'), '')::numeric[] >= array_remove(string_to_array(regexp_replace(regexp_replace(v.fixed_version, '^[0-9]+:', ''), '[^0-9.]', '.', 'g'), '.'), '')::numeric[]) AND v.vulnerability_id NOT LIKE 'CGA-%' AND v.fixed_version !~ '^[0-9a-f]{40}$'
			AND NOT EXISTS (
				SELECT 1 FROM cve_database c
				WHERE c.vulnerability_id = v.vulnerability_id
				AND c.affected_products->0->>'ecosystem' IS NOT NULL
				AND EXISTS (SELECT 1 FROM packages p WHERE p.id = v.package_id AND p.pkg_type IN ('python-pkg','pip','node-pkg','npm','gomod','go','gobinary','cargo','rustbinary','jar','maven','composer','gem','nuget'))
				AND c.affected_products->0->>'ecosystem' != CASE (SELECT pkg_type FROM packages WHERE id = v.package_id)
					WHEN 'python-pkg' THEN 'PyPI' WHEN 'pip' THEN 'PyPI'
					WHEN 'node-pkg' THEN 'npm' WHEN 'npm' THEN 'npm'
					WHEN 'gomod' THEN 'Go' WHEN 'go' THEN 'Go' WHEN 'gobinary' THEN 'Go'
					WHEN 'gem' THEN 'RubyGems'
					WHEN 'cargo' THEN 'crates.io' WHEN 'rustbinary' THEN 'crates.io'
					WHEN 'jar' THEN 'Maven' WHEN 'maven' THEN 'Maven'
					WHEN 'composer' THEN 'Packagist'
					WHEN 'nuget' THEN 'NuGet'
				END
			) ORDER BY v.cvss_score DESC`
	rows, err := db.QueryContext(ctx, q, packageID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var vulns []models.Vulnerability
	for rows.Next() {
		var v models.Vulnerability
		if err := scanVuln(rows, &v); err != nil {
			return nil, err
		}
		vulns = append(vulns, v)
	}
	return vulns, nil
}

const CveCols = `id, vulnerability_id, source, category, ecosystem, severity, cvss_score, cvss_vector, title, description, published_date, modified_date, affected_products, refs, raw_data, updated_at`

func ScanCveEntry(scanner interface{ Scan(...interface{}) error }, e *models.CveEntry) error {
	return scanner.Scan(&e.ID, &e.VulnerabilityID, &e.Source, &e.Category, &e.Ecosystem, &e.Severity, &e.CVSSScore, &e.CVSSVector,
		&e.Title, &e.Description, &e.PublishedDate, &e.ModifiedDate,
		&e.AffectedProducts, &e.References, &e.RawData, &e.UpdatedAt)
}

func (db *DB) UpsertCveEntries(ctx context.Context, entries []models.CveEntry) (int, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `INSERT INTO cve_database (id, vulnerability_id, source, category, ecosystem, severity, cvss_score, cvss_vector, title, description, published_date, modified_date, affected_products, refs, raw_data, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, now())
ON CONFLICT (vulnerability_id, source) DO UPDATE SET
	category=EXCLUDED.category, ecosystem=EXCLUDED.ecosystem,
	severity=EXCLUDED.severity, cvss_score=EXCLUDED.cvss_score, cvss_vector=EXCLUDED.cvss_vector,
	title=EXCLUDED.title, description=EXCLUDED.description,
	published_date=EXCLUDED.published_date, modified_date=EXCLUDED.modified_date,
	affected_products=EXCLUDED.affected_products, refs=EXCLUDED.refs,
	raw_data=EXCLUDED.raw_data, updated_at=now()`)
	if err != nil {
		tx.Rollback()
		return 0, fmt.Errorf("prepare insert: %w", err)
	}
	defer stmt.Close()

	count := 0
	var firstErr error
	for i := range entries {
		e := &entries[i]
		if e.ID == "" {
			e.ID = uuid.New().String()
		}
		// Auto-calculate CVSS score from vector if missing
		if e.CVSSScore == 0 && e.CVSSVector != "" {
			e.CVSSScore = calcCvssScore(e.CVSSVector)
		}
		// Auto-normalize severity from score
		if e.CVSSScore > 0 && (e.Severity == "" || e.Severity == "MODERATE") {
			if e.CVSSScore >= 9.0 {
				e.Severity = "CRITICAL"
			} else if e.CVSSScore >= 7.0 {
				e.Severity = "HIGH"
			} else if e.CVSSScore >= 4.0 {
				e.Severity = "MEDIUM"
			} else {
				e.Severity = "LOW"
			}
		}
		if e.Category == "" || e.Ecosystem == "" {
			e.Category, e.Ecosystem = ClassifySecuritySource(e.Source, e.AffectedProducts)
		}
		if _, err := stmt.ExecContext(ctx, e.ID, e.VulnerabilityID, e.Source, e.Category, e.Ecosystem, e.Severity,
			e.CVSSScore, e.CVSSVector, e.Title, e.Description,
			e.PublishedDate, e.ModifiedDate, e.AffectedProducts, e.References, e.RawData); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("insert %s: %w", e.VulnerabilityID, err)
			}
			log.Printf("rematch scan row: %v", err)
			continue
		}
		count++
	}
	if count == 0 && firstErr != nil {
		return 0, firstErr
	}
	return count, tx.Commit()
}

func (db *DB) SearchCveDatabase(ctx context.Context, query, severity, source string, minCVSS float64, sortBy, sortOrder string, limit, offset int) ([]models.CveEntry, int, error) {
	baseQ := `FROM cve_database WHERE 1=1`
	args := []any{}
	argN := 1

	if query != "" {
		baseQ += fmt.Sprintf(" AND (vulnerability_id ILIKE $%d OR title ILIKE $%d OR description ILIKE $%d)", argN, argN, argN)
		args = append(args, "%"+query+"%")
		argN++
	}
	if severity != "" {
		baseQ += fmt.Sprintf(" AND severity=$%d", argN)
		args = append(args, severity)
		argN++
	}
	if source != "" {
		baseQ += fmt.Sprintf(" AND source=$%d", argN)
		args = append(args, source)
		argN++
	}
	if minCVSS > 0 {
		baseQ += fmt.Sprintf(" AND cvss_score>=$%d", argN)
		args = append(args, minCVSS)
		argN++
	}

	var total int
	countArgs := make([]any, len(args))
	copy(countArgs, args)
	if err := db.QueryRowContext(ctx, "SELECT count(*) "+baseQ, countArgs...).Scan(&total); err != nil {
		return nil, 0, err
	}

	sortCol := "cvss_score"
	switch sortBy {
	case "vulnerability_id", "severity", "cvss_score", "source", "title", "published_date":
		sortCol = sortBy
	}
	sortDir := "DESC"
	if sortOrder == "asc" {
		sortDir = "ASC"
	}
	nullHandling := ""
	if sortCol == "cvss_score" {
		nullHandling = " NULLS LAST"
	}
	dataQ := fmt.Sprintf("SELECT %s ", CveCols) + baseQ + fmt.Sprintf(" ORDER BY %s %s%s LIMIT $%d OFFSET $%d", sortCol, sortDir, nullHandling, argN, argN+1)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, dataQ, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var entries []models.CveEntry
	for rows.Next() {
		var e models.CveEntry
		if err := ScanCveEntry(rows, &e); err != nil {
			return nil, 0, err
		}
		entries = append(entries, e)
	}
	return entries, total, nil
}

func calcCvssScore(vector string) float64 {
	if vector == "" {
		return 0
	}
	prefix := ""
	if strings.HasPrefix(vector, "CVSS:") {
		idx := strings.Index(vector, "/")
		if idx <= 0 {
			return 0
		}
		prefix = vector[:idx+1]
		vector = vector[idx+1:]
	}

	parts := strings.Split(vector, "/")
	kv := make(map[string]string)
	for _, p := range parts {
		if sep := strings.Index(p, ":"); sep > 0 {
			kv[p[:sep]] = p[sep+1:]
		}
	}

	if strings.HasPrefix(prefix, "CVSS:4.0") {
		return calcCvss40(kv)
	}
	if strings.HasPrefix(prefix, "CVSS:3") {
		return calcCvss3x(kv)
	}
	if strings.HasPrefix(prefix, "CVSS:2") || kv["Au"] != "" {
		return calcCvss2(kv)
	}
	return 0
}

func calcCvss2(kv map[string]string) float64 {
	av := map[string]float64{"L": 0.395, "A": 0.646, "N": 1.0}
	ac := map[string]float64{"H": 0.35, "M": 0.61, "L": 0.71}
	au := map[string]float64{"M": 0.45, "S": 0.56, "N": 0.704}
	cia := map[string]float64{"N": 0.0, "P": 0.275, "C": 0.66}
	avVal, ok := av[kv["AV"]]
	if !ok {
		return 0
	}
	acVal, ok := ac[kv["AC"]]
	if !ok {
		return 0
	}
	auVal, ok := au[kv["Au"]]
	if !ok {
		return 0
	}
	cVal, ok := cia[kv["C"]]
	if !ok {
		return 0
	}
	iVal, ok := cia[kv["I"]]
	if !ok {
		return 0
	}
	aVal, ok := cia[kv["A"]]
	if !ok {
		return 0
	}
	impact := 10.41 * (1 - (1-cVal)*(1-iVal)*(1-aVal))
	exploit := 20 * avVal * acVal * auVal
	if impact == 0 {
		return 0
	}
	fImpact := 1.176
	return roundup1(((0.6 * impact) + (0.4 * exploit) - 1.5) * fImpact)
}

func calcCvss3x(kv map[string]string) float64 {
	avW := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
	acW := map[string]float64{"L": 0.77, "H": 0.44}
	prWU := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	prWC := map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}
	uiW := map[string]float64{"N": 0.85, "R": 0.62}
	cW := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	iW := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	aW := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}

	scopeChanged := kv["S"] == "C"

	pr := prWU[kv["PR"]]
	if scopeChanged {
		pr = prWC[kv["PR"]]
	}

	iss := 1 - (1-cW[kv["C"]])*(1-iW[kv["I"]])*(1-aW[kv["A"]])
	if iss <= 0 {
		return 0
	}

	var impact float64
	if scopeChanged {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = iss * 6.42
	}
	if impact <= 0 {
		return 0
	}

	exploitability := 8.22 * avW[kv["AV"]] * acW[kv["AC"]] * pr * uiW[kv["UI"]]

	var base float64
	if scopeChanged {
		base = math.Min(1.08*(impact+exploitability), 10)
	} else {
		base = math.Min(impact+exploitability, 10)
	}
	return math.Round(base*10) / 10
}

var cvss40Lookup = map[string]float64{
	// EQ1=0, EQ2=0
	"000000": 10, "000001": 9.9, "000010": 9.8, "000011": 9.5, "000020": 9.5, "000021": 9.2,
	"000100": 10, "000101": 9.6, "000110": 9.3, "000111": 8.7, "000120": 9.1, "000121": 8.1,
	"000200": 9.3, "000201": 9, "000210": 8.9, "000211": 8, "000220": 8.1, "000221": 6.8,
	"001000": 9.8, "001001": 9.5, "001010": 9.5, "001011": 9.2, "001020": 9, "001021": 8.4,
	"001100": 9.3, "001101": 9.2, "001110": 8.9, "001111": 8.1, "001120": 8.1, "001121": 6.5,
	"001200": 8.8, "001201": 8, "001210": 7.8, "001211": 7, "001220": 6.9, "001221": 4.8,
	"002001": 9.2, "002011": 8.2, "002021": 7.2,
	"002101": 7.9, "002111": 6.9, "002121": 5,
	"002201": 6.9, "002211": 5.5, "002221": 2.7,
	// EQ1=0, EQ2=1
	"010000": 9.9, "010001": 9.7, "010010": 9.5, "010011": 9.2, "010020": 9.2, "010021": 8.5,
	"010100": 9.5, "010101": 9.1, "010110": 9, "010111": 8.3, "010120": 8.4, "010121": 7.1,
	"010200": 9.2, "010201": 8.1, "010210": 8.2, "010211": 7.1, "010220": 7.2, "010221": 5.3,
	"011000": 9.5, "011001": 9.3, "011010": 9.2, "011011": 8.5, "011020": 8.5, "011021": 7.3,
	"011100": 9.2, "011101": 8.2, "011110": 8, "011111": 7.2, "011120": 7, "011121": 5.9,
	"011200": 8.4, "011201": 7, "011210": 7.1, "011211": 5.2, "011220": 5, "011221": 3,
	"012001": 8.6, "012011": 7.5, "012021": 5.2,
	"012101": 7.1, "012111": 5.2, "012121": 2.9,
	"012201": 6.3, "012211": 2.9, "012221": 1.7,
	// EQ1=1, EQ2=0
	"100000": 9.8, "100001": 9.5, "100010": 9.4, "100011": 8.7, "100020": 9.1, "100021": 8.1,
	"100100": 9.4, "100101": 8.9, "100110": 8.6, "100111": 7.4, "100120": 7.7, "100121": 6.4,
	"100200": 8.7, "100201": 7.5, "100210": 7.4, "100211": 6.3, "100220": 6.3, "100221": 4.9,
	"101000": 9.4, "101001": 8.9, "101010": 8.8, "101011": 7.7, "101020": 7.6, "101021": 6.7,
	"101100": 8.6, "101101": 7.6, "101110": 7.4, "101111": 5.8, "101120": 5.9, "101121": 5,
	"101200": 7.2, "101201": 5.7, "101210": 5.7, "101211": 5.2, "101220": 5.2, "101221": 2.5,
	"102001": 8.3, "102011": 7, "102021": 5.4,
	"102101": 6.5, "102111": 5.8, "102121": 2.6,
	"102201": 5.3, "102211": 2.1, "102221": 1.3,
	// EQ1=1, EQ2=1
	"110000": 9.5, "110001": 9, "110010": 8.8, "110011": 7.6, "110020": 7.6, "110021": 7,
	"110100": 9, "110101": 7.7, "110110": 7.5, "110111": 6.2, "110120": 6.1, "110121": 5.3,
	"110200": 7.7, "110201": 6.6, "110210": 6.8, "110211": 5.9, "110220": 5.2, "110221": 3,
	"111000": 8.9, "111001": 7.8, "111010": 7.6, "111011": 6.7, "111020": 6.2, "111021": 5.8,
	"111100": 7.4, "111101": 5.9, "111110": 5.7, "111111": 5.7, "111120": 4.7, "111121": 2.3,
	"111200": 6.1, "111201": 5.2, "111210": 5.7, "111211": 2.9, "111220": 2.4, "111221": 1.6,
	"112001": 7.1, "112011": 5.9, "112021": 3,
	"112101": 5.8, "112111": 2.6, "112121": 1.5,
	"112201": 2.3, "112211": 1.3, "112221": 0.6,
	// EQ1=2, EQ2=0
	"200000": 9.3, "200001": 8.7, "200010": 8.6, "200011": 7.2, "200020": 7.5, "200021": 5.8,
	"200100": 8.6, "200101": 7.4, "200110": 7.4, "200111": 6.1, "200120": 5.6, "200121": 3.4,
	"200200": 7, "200201": 5.4, "200210": 5.2, "200211": 4, "200220": 4, "200221": 2.2,
	"201000": 8.5, "201001": 7.5, "201010": 7.4, "201011": 5.5, "201020": 6.2, "201021": 5.1,
	"201100": 7.2, "201101": 5.7, "201110": 5.5, "201111": 4.1, "201120": 4.6, "201121": 1.9,
	"201200": 5.3, "201201": 3.6, "201210": 3.4, "201211": 1.9, "201220": 1.9, "201221": 0.8,
	"202001": 6.4, "202011": 5.1, "202021": 2,
	"202101": 4.7, "202111": 2.1, "202121": 1.1,
	"202201": 2.4, "202211": 0.9, "202221": 0.4,
	// EQ1=2, EQ2=1
	"210000": 8.8, "210001": 7.5, "210010": 7.3, "210011": 5.3, "210020": 6, "210021": 5,
	"210100": 7.3, "210101": 5.5, "210110": 5.9, "210111": 4, "210120": 4.1, "210121": 2,
	"210200": 5.4, "210201": 4.3, "210210": 4.5, "210211": 2.2, "210220": 2, "210221": 1.1,
	"211000": 7.5, "211001": 5.5, "211010": 5.8, "211011": 4.5, "211020": 4, "211021": 2.1,
	"211100": 6.1, "211101": 5.1, "211110": 4.8, "211111": 1.8, "211120": 2, "211121": 0.9,
	"211200": 4.6, "211201": 1.8, "211210": 1.7, "211211": 0.7, "211220": 0.8, "211221": 0.2,
	"212001": 5.3, "212011": 2.4, "212021": 1.4,
	"212101": 2.4, "212111": 1.2, "212121": 0.5,
	"212201": 1, "212211": 0.3, "212221": 0.1,
}

func calcCvss40(kv map[string]string) float64 {
	// EQ1: AV/PR/UI (Table 24)
	avN := kv["AV"] == "N"
	prN := kv["PR"] == "N"
	uiN := kv["UI"] == "N"
	var eq1 int
	if avN && prN && uiN {
		eq1 = 0
	} else if (avN && prN && (kv["UI"] == "A" || kv["UI"] == "P")) ||
		(avN && kv["PR"] == "L" && uiN) ||
		(kv["AV"] == "A" && prN && uiN) {
		eq1 = 1
	} else {
		eq1 = 2
	}

	// EQ2: AC/AT (Table 25)
	var eq2 int
	if kv["AC"] == "L" && kv["AT"] == "N" {
		eq2 = 0
	} else {
		eq2 = 1
	}

	// EQ3: VC/VI/VA (Table 26)
	var eq3 int
	if kv["VC"] == "H" || kv["VI"] == "H" || kv["VA"] == "H" {
		eq3 = 0
	} else if kv["VC"] == "L" || kv["VI"] == "L" || kv["VA"] == "L" {
		eq3 = 1
	} else {
		eq3 = 2
	}

	// EQ4: SC/SI/SA (Table 27)
	var eq4 int
	if kv["SC"] == "H" || kv["SI"] == "H" || kv["SA"] == "H" {
		eq4 = 0
	} else if kv["SC"] == "L" || kv["SI"] == "L" || kv["SA"] == "L" {
		eq4 = 1
	} else {
		eq4 = 2
	}

	// EQ5: E (Table 28)
	e := kv["E"]
	if e == "" {
		e = "X"
	}
	var eq5 int
	switch e {
	case "A":
		eq5 = 0
	case "P":
		eq5 = 1
	default: // U or X
		eq5 = 2
	}

	// EQ6: VC+CR / VI+IR / VA+AR (Table 29)
	// CR/IR/AR default to X (Not Defined), treated as H for EQ6
	cr := kv["CR"]
	if cr == "" {
		cr = "X"
	}
	ir := kv["IR"]
	if ir == "" {
		ir = "X"
	}
	ar := kv["AR"]
	if ar == "" {
		ar = "X"
	}
	eq6 := 1
	if (kv["VC"] == "H" && (cr == "H" || cr == "X")) ||
		(kv["VI"] == "H" && (ir == "H" || ir == "X")) ||
		(kv["VA"] == "H" && (ar == "H" || ar == "X")) {
		eq6 = 0
	}

	key := fmt.Sprintf("%d%d%d%d%d%d", eq1, eq2, eq3, eq4, eq5, eq6)
	if score, ok := cvss40Lookup[key]; ok {
		return score
	}
	return 0
}

func severityFromScore(score float64) string {
	if score >= 9.0 {
		return "CRITICAL"
	} else if score >= 7.0 {
		return "HIGH"
	} else if score >= 4.0 {
		return "MEDIUM"
	} else if score >= 0.1 {
		return "LOW"
	}
	return ""
}

func (db *DB) NormalizeVulnSeverity(ctx context.Context) (int, error) {
	res, err := db.ExecContext(ctx, `
		UPDATE vulnerabilities
		SET severity = CASE
			WHEN cvss_score >= 9.0 THEN 'CRITICAL'
			WHEN cvss_score >= 7.0 THEN 'HIGH'
			WHEN cvss_score >= 4.0 THEN 'MEDIUM'
			WHEN cvss_score >= 0.1 THEN 'LOW'
			ELSE severity
		END
		WHERE cvss_score > 0 AND severity != CASE
			WHEN cvss_score >= 9.0 THEN 'CRITICAL'
			WHEN cvss_score >= 7.0 THEN 'HIGH'
			WHEN cvss_score >= 4.0 THEN 'MEDIUM'
			WHEN cvss_score >= 0.1 THEN 'LOW'
			ELSE ''
		END`)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func (db *DB) CalcCvssScores(ctx context.Context) (int, error) {
	rows, err := db.QueryContext(ctx, `SELECT id, cvss_vector FROM cve_database WHERE cvss_vector LIKE 'CVSS:4%' OR (cvss_vector != '' AND cvss_score = 0)`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	type update struct {
		id       string
		score    float64
		severity string
	}
	var updates []update

	for rows.Next() {
		var id, vector string
		if err := rows.Scan(&id, &vector); err != nil {
			continue
		}
		score := calcCvssScore(vector)
		severity := severityFromScore(score)
		updates = append(updates, update{id: id, score: score, severity: severity})
	}

	if len(updates) == 0 {
		return 0, nil
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `UPDATE cve_database SET cvss_score=$1, severity=CASE WHEN $2 != '' THEN $2 ELSE severity END WHERE id=$3`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	for _, u := range updates {
		if _, err := stmt.ExecContext(ctx, u.score, u.severity, u.id); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(updates), nil
}

func (db *DB) GetCveSources(ctx context.Context) ([]string, error) {
	rows, err := db.QueryContext(ctx, `SELECT DISTINCT source FROM cve_database WHERE source != '' ORDER BY source`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sources []string
	for rows.Next() {
		var s string
		rows.Scan(&s)
		sources = append(sources, s)
	}
	return sources, nil
}

type CveSourceStats struct {
	Source     string     `json:"source"`
	Count      int        `json:"count"`
	LastUpdate *time.Time `json:"last_update"`
}

func (db *DB) GetCveSourceStats(ctx context.Context) ([]CveSourceStats, error) {
	rows, err := db.QueryContext(ctx, `SELECT source, COUNT(*), MAX(updated_at) FROM cve_database WHERE source != '' GROUP BY source ORDER BY source`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var stats []CveSourceStats
	for rows.Next() {
		var s CveSourceStats
		rows.Scan(&s.Source, &s.Count, &s.LastUpdate)
		stats = append(stats, s)
	}
	return stats, nil
}

type RematchResult struct {
	Matched  int `json:"matched"`
	NewVulns int `json:"new_vulns"`
	Updated  int `json:"updated"`
	Skipped  int `json:"skipped"`
}

func (db *DB) RematchCVEs(ctx context.Context) (*RematchResult, error) {
	query := fmt.Sprintf(`
		SELECT p.id, p.name, p.version, p.host_id, p.scan_id, p.container, p.file_path,
		       p.pkg_type, p.ecosystem,
		       c.vulnerability_id, c.severity, c.cvss_score, c.cvss_vector,
		       c.title, c.description, c.refs, c.category, c.ecosystem, c.affected_products
		FROM packages p
		JOIN (%s) ls ON p.scan_id = ls.id
		JOIN cve_database c ON c.affected_products @> jsonb_build_array(jsonb_build_object('name', p.name))
		LIMIT 50000
	`, latestScansSub)

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("match query: %w", err)
	}
	defer rows.Close()

	type match struct {
		pkgID, pkgName, version, hostID, scanID, container, filePath string
		pkgType, pkgEco                                              string
		vulnID, severity, title, description, refs                   string
		category, cveEco, affectedProducts                           string
		cvssScore                                                    float64
		cvssVector                                                   string
	}
	var matches []match

	for rows.Next() {
		var m match
		if err := rows.Scan(&m.pkgID, &m.pkgName, &m.version, &m.hostID, &m.scanID,
			&m.container, &m.filePath, &m.pkgType, &m.pkgEco,
			&m.vulnID, &m.severity, &m.cvssScore, &m.cvssVector,
			&m.title, &m.description, &m.refs, &m.category, &m.cveEco, &m.affectedProducts); err != nil {
			continue
		}
		matches = append(matches, m)
	}

	result := &RematchResult{Matched: len(matches)}
	var newVulns []models.Vulnerability

	for _, m := range matches {
		affected, ok := compatibleSecurityCandidate(m.pkgName, m.pkgType, m.pkgEco, m.version, m.category, m.cveEco, m.affectedProducts)
		if !ok {
			result.Skipped++
			continue
		}
		var exists bool
		if err := db.QueryRowContext(ctx,
			"SELECT EXISTS(SELECT 1 FROM vulnerabilities WHERE package_id=$1 AND vulnerability_id=$2 AND scan_id=$3)",
			m.pkgID, m.vulnID, m.scanID).Scan(&exists); err != nil || exists {
			result.Skipped++
			continue
		}

		primaryURL := ""
		var refList []struct {
			URL string `json:"url"`
		}
		if json.Unmarshal([]byte(m.refs), &refList) == nil {
			for _, r := range refList {
				if r.URL != "" {
					primaryURL = r.URL
					break
				}
			}
		}

		sev := m.severity
		if m.cvssScore >= 9.0 {
			sev = "CRITICAL"
		} else if m.cvssScore >= 7.0 {
			sev = "HIGH"
		} else if m.cvssScore >= 4.0 {
			sev = "MEDIUM"
		} else if m.cvssScore > 0 {
			sev = "LOW"
		}

		v := models.Vulnerability{
			ID: uuid.New().String(), PackageID: m.pkgID, ScanID: m.scanID, HostID: m.hostID,
			VulnerabilityID: m.vulnID, Severity: sev, Title: truncate(m.title, 500),
			Description: truncate(m.description, 2000), PkgName: m.pkgName, PkgPath: m.filePath,
			InstalledVer: m.version, FixedVersion: affected.Fixed[0], CVSSScore: m.cvssScore, CVSSVector: m.cvssVector,
			PrimaryURL: primaryURL, Container: m.container,
		}
		newVulns = append(newVulns, v)
	}

	if len(newVulns) > 0 {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return nil, err
		}
		defer tx.Rollback()

		stmt, err := tx.PrepareContext(ctx, `INSERT INTO vulnerabilities
(id, package_id, scan_id, host_id, vulnerability_id, severity, title, description,
 pkg_name, pkg_path, installed_version, fixed_version, cvss_score, cvss_vector,
 primary_url, container, layer_id, created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,now())`)
		if err != nil {
			return nil, fmt.Errorf("prepare: %w", err)
		}
		defer stmt.Close()

		for _, v := range newVulns {
			if _, err := stmt.ExecContext(ctx, v.ID, v.PackageID, v.ScanID, v.HostID,
				v.VulnerabilityID, v.Severity, v.Title, v.Description,
				v.PkgName, v.PkgPath, v.InstalledVer, v.FixedVersion,
				v.CVSSScore, v.CVSSVector, v.PrimaryURL, v.Container, ""); err != nil {
				continue
			}
			result.NewVulns++
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}

// CVSS 3.x base score calculator
func calcCVSS3BaseScore(vector string) float64 {
	parts := map[string]string{}
	for _, seg := range splitCVSS(vector) {
		kv := splitCVSSKV(seg)
		if len(kv) == 2 {
			parts[kv[0]] = kv[1]
		}
	}

	av := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
	ac := map[string]float64{"L": 0.77, "H": 0.44}
	ui := map[string]float64{"N": 0.85, "R": 0.62}
	cia := map[string]float64{"N": 0.0, "L": 0.22, "H": 0.56}

	avVal, ok := av[parts["AV"]]
	if !ok {
		return 0
	}
	acVal, ok := ac[parts["AC"]]
	if !ok {
		return 0
	}
	uiVal, ok := ui[parts["UI"]]
	if !ok {
		return 0
	}
	cVal := cia[parts["C"]]
	iVal := cia[parts["I"]]
	aVal := cia[parts["A"]]

	scopeChanged := parts["S"] == "C"

	prVal := 0.0
	switch parts["PR"] {
	case "N":
		prVal = 0.85
	case "L":
		if scopeChanged {
			prVal = 0.68
		} else {
			prVal = 0.62
		}
	case "H":
		if scopeChanged {
			prVal = 0.50
		} else {
			prVal = 0.27
		}
	default:
		return 0
	}

	iss := 1 - ((1 - cVal) * (1 - iVal) * (1 - aVal))
	var impact float64
	if scopeChanged {
		impact = 7.52*(iss-0.029) - 3.25*pow15(iss-0.02)
	} else {
		impact = 6.42 * iss
	}

	if impact <= 0 {
		return 0
	}

	exploit := 8.22 * avVal * acVal * prVal * uiVal

	var base float64
	if scopeChanged {
		base = 1.08 * (impact + exploit)
	} else {
		base = impact + exploit
	}
	if base > 10 {
		base = 10
	}
	return roundup1(base)
}

func pow15(x float64) float64 { y := x * x; y = y * y; return y * y * x }

func roundup1(x float64) float64 { return float64(int(x*10+0.95)) / 10 }

func splitCVSS(v string) []string {
	var res []string
	for _, s := range stringsSplit(v, "/") {
		if len(s) >= 5 && s[:5] == "CVSS:" {
			continue
		}
		res = append(res, s)
	}
	return res
}

func splitCVSSKV(s string) []string {
	for i, c := range s {
		if c == ':' {
			return []string{s[:i], s[i+1:]}
		}
	}
	return nil
}

func stringsSplit(s, sep string) []string {
	var res []string
	for {
		i := indexOfStr(s, sep)
		if i < 0 {
			res = append(res, s)
			break
		}
		res = append(res, s[:i])
		s = s[i+len(sep):]
	}
	return res
}

func indexOfStr(s, sub string) int {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func (db *DB) RecalcCVSSFromVectors(ctx context.Context) (int, error) {
	rows, err := db.QueryContext(ctx, `SELECT id, cvss_vector FROM cve_database WHERE cvss_vector != '' AND cvss_score = 0`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	type entry struct{ id, vector string }
	var entries []entry
	for rows.Next() {
		var e entry
		rows.Scan(&e.id, &e.vector)
		entries = append(entries, e)
	}

	count := 0
	for _, e := range entries {
		score := calcCvssScore(e.vector)
		if score > 0 {
			sev := severityFromScore(score)
			if _, err := db.ExecContext(ctx, `UPDATE cve_database SET cvss_score=$1, severity=$2 WHERE id=$3`, score, sev, e.id); err == nil {
				count++
			}
		}
	}
	return count, nil
}
