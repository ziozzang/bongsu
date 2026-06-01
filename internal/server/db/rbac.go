package db

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/ziozzang/bongsu/internal/shared/models"
)

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


func (db *DB) GetAccessScope(ctx context.Context, subjectRef string) (AccessScope, error) {
	return db.getAccessScopeForPermissions(ctx, subjectRef, []string{"read", "admin"})
}

func (db *DB) GetExportScope(ctx context.Context, subjectRef string) (AccessScope, error) {
	return db.getAccessScopeForPermissions(ctx, subjectRef, []string{"export", "admin"})
}

func (db *DB) HasResourcePermission(ctx context.Context, subjectRef, resourceType string, permissions []string) (bool, error) {
	subjectType, externalID := parseAccessSubjectRef(subjectRef)
	if len(permissions) == 0 {
		return false, nil
	}
	args := []any{externalID, resourceType, pqStringArray(permissions)}
	typeFilter := ""
	if subjectType != "" {
		typeFilter = " AND s.subject_type=$4"
		args = append(args, subjectType)
	}
	var ok bool
	err := db.QueryRowContext(ctx, `
SELECT EXISTS (
	SELECT 1
	FROM access_subjects s
	JOIN access_policies p ON p.subject_id = s.id
	WHERE s.external_id=$1`+typeFilter+`
	  AND (p.resource_type=$2 OR p.resource_type='all')
	  AND (p.resource_id='*' OR p.resource_id='')
	  AND p.permission = ANY($3)
)`, args...).Scan(&ok)
	return ok, err
}

func (db *DB) getAccessScopeForPermissions(ctx context.Context, subjectRef string, permissions []string) (AccessScope, error) {
	subjectType, externalID := parseAccessSubjectRef(subjectRef)
	if len(permissions) == 0 {
		return AccessScope{}, nil
	}
	args := []any{externalID, pqStringArray(permissions)}
	typeFilter := ""
	if subjectType != "" {
		typeFilter = " AND s.subject_type=$3"
		args = append(args, subjectType)
	}
	rows, err := db.QueryContext(ctx, `
SELECT p.resource_type, p.resource_id
FROM access_subjects s
JOIN access_policies p ON p.subject_id = s.id
WHERE s.external_id=$1`+typeFilter+` AND p.permission = ANY($2)`, args...)
	if err != nil {
		return AccessScope{}, err
	}
	defer rows.Close()
	scope := AccessScope{}
	containerRefs := []string{}
	imageRefs := []string{}
	assetGroupRefs := []string{}
	containerWildcard := false
	imageWildcard := false
	assetGroupWildcard := false
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
				scope.HostIDs = appendUnique(scope.HostIDs, rid)
			}
		case "container":
			if rid == "*" {
				containerWildcard = true
			} else if rid != "" {
				containerRefs = append(containerRefs, rid)
			}
		case "image":
			if rid == "*" {
				imageWildcard = true
			} else if rid != "" {
				imageRefs = append(imageRefs, rid)
			}
		case "asset_group":
			if rid == "*" {
				assetGroupWildcard = true
			} else if rid != "" {
				assetGroupRefs = append(assetGroupRefs, rid)
			}
		}
	}
	if err := rows.Err(); err != nil {
		return AccessScope{}, err
	}
	if scope.All {
		return scope, nil
	}
	hostIDs, err := db.hostIDsForContainerPolicies(ctx, containerRefs, containerWildcard)
	if err != nil {
		return AccessScope{}, err
	}
	for _, id := range hostIDs {
		scope.HostIDs = appendUnique(scope.HostIDs, id)
	}
	hostIDs, err = db.hostIDsForImagePolicies(ctx, imageRefs, imageWildcard)
	if err != nil {
		return AccessScope{}, err
	}
	for _, id := range hostIDs {
		scope.HostIDs = appendUnique(scope.HostIDs, id)
	}
	hostIDs, err = db.hostIDsForAssetGroupPolicies(ctx, assetGroupRefs, assetGroupWildcard)
	if err != nil {
		return AccessScope{}, err
	}
	for _, id := range hostIDs {
		scope.HostIDs = appendUnique(scope.HostIDs, id)
	}
	return scope, nil
}

func parseAccessSubjectRef(ref string) (string, string) {
	ref = strings.TrimSpace(ref)
	for _, sep := range []string{":", "/"} {
		left, right, ok := strings.Cut(ref, sep)
		if !ok {
			continue
		}
		left = strings.ToLower(strings.TrimSpace(left))
		right = strings.TrimSpace(right)
		if (left == "user" || left == "group") && right != "" {
			return left, right
		}
	}
	return "", ref
}

func (db *DB) hostIDsForContainerPolicies(ctx context.Context, refs []string, wildcard bool) ([]string, error) {
	if !wildcard && len(refs) == 0 {
		return nil, nil
	}
	q := `SELECT DISTINCT c.host_id FROM container_assets c JOIN ` + latestScansSub + ` ls ON c.scan_id = ls.id`
	args := []any{}
	if !wildcard {
		q += ` WHERE c.container_id = ANY($1) OR c.name = ANY($1)`
		args = append(args, pqStringArray(refs))
	}
	return db.queryStringList(ctx, q, args...)
}

func (db *DB) hostIDsForImagePolicies(ctx context.Context, refs []string, wildcard bool) ([]string, error) {
	if !wildcard && len(refs) == 0 {
		return nil, nil
	}
	q := `SELECT DISTINCT c.host_id FROM container_assets c JOIN ` + latestScansSub + ` ls ON c.scan_id = ls.id`
	args := []any{}
	if !wildcard {
		q += ` WHERE c.image_name = ANY($1) OR c.image_id = ANY($1) OR c.image_digest = ANY($1)`
		args = append(args, pqStringArray(refs))
	}
	return db.queryStringList(ctx, q, args...)
}

func (db *DB) hostIDsForAssetGroupPolicies(ctx context.Context, refs []string, wildcard bool) ([]string, error) {
	if wildcard {
		return db.queryStringList(ctx, `SELECT id FROM hosts`)
	}
	if len(refs) == 0 {
		return nil, nil
	}
	hostIDs := []string{}
	for _, ref := range refs {
		key, value, ok := parseAssetGroupRef(ref)
		if !ok {
			continue
		}
		var (
			ids []string
			err error
		)
		switch key {
		case "owner":
			ids, err = db.queryStringList(ctx, `SELECT id FROM hosts WHERE owner=$1`, value)
		case "team":
			ids, err = db.queryStringList(ctx, `SELECT id FROM hosts WHERE team=$1`, value)
		case "environment":
			ids, err = db.queryStringList(ctx, `SELECT id FROM hosts WHERE environment=$1`, value)
		case "criticality":
			ids, err = db.queryStringList(ctx, `SELECT id FROM hosts WHERE criticality=$1`, value)
		case "tag":
			tagKey, tagValue, ok := strings.Cut(value, "=")
			if !ok || strings.TrimSpace(tagKey) == "" {
				continue
			}
			ids, err = db.queryStringList(ctx, `SELECT id FROM hosts WHERE tags ->> $1 = $2`, strings.TrimSpace(tagKey), strings.TrimSpace(tagValue))
		default:
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, id := range ids {
			hostIDs = appendUnique(hostIDs, id)
		}
	}
	return hostIDs, nil
}

func parseAssetGroupRef(ref string) (string, string, bool) {
	key, value, ok := strings.Cut(ref, ":")
	if !ok {
		key, value, ok = strings.Cut(ref, "=")
	}
	key = strings.ToLower(strings.TrimSpace(key))
	value = strings.TrimSpace(value)
	if !ok || key == "" || value == "" {
		return "", "", false
	}
	return key, value, true
}

func (db *DB) queryStringList(ctx context.Context, q string, args ...any) ([]string, error) {
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = appendUnique(out, v)
	}
	return out, rows.Err()
}

func appendUnique(items []string, item string) []string {
	if item == "" {
		return items
	}
	for _, existing := range items {
		if existing == item {
			return items
		}
	}
	return append(items, item)
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

func (db *DB) ListAccessSubjects(ctx context.Context) ([]models.AccessSubject, error) {
	rows, err := db.QueryContext(ctx, `SELECT id, subject_type, external_id, display_name, created_at, updated_at
FROM access_subjects
ORDER BY external_id, subject_type`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.AccessSubject{}
	for rows.Next() {
		var item models.AccessSubject
		if err := rows.Scan(&item.ID, &item.SubjectType, &item.ExternalID, &item.DisplayName, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (db *DB) ListAccessPolicies(ctx context.Context, subjectExternalID string) ([]models.AccessPolicy, error) {
	q := `SELECT p.id, p.subject_id, s.subject_type, s.external_id, p.resource_type, p.resource_id, p.permission, p.created_at
FROM access_policies p
JOIN access_subjects s ON s.id = p.subject_id`
	args := []any{}
	if subjectExternalID != "" {
		subjectType, externalID := parseAccessSubjectRef(subjectExternalID)
		q += ` WHERE s.external_id=$1`
		args = append(args, externalID)
		if subjectType != "" {
			q += ` AND s.subject_type=$2`
			args = append(args, subjectType)
		}
	}
	q += ` ORDER BY s.external_id, p.resource_type, p.resource_id, p.permission`
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.AccessPolicy{}
	for rows.Next() {
		var item models.AccessPolicy
		if err := rows.Scan(&item.ID, &item.SubjectID, &item.SubjectType, &item.SubjectExternalID, &item.ResourceType, &item.ResourceID, &item.Permission, &item.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (db *DB) DeleteAccessSubject(ctx context.Context, id string) (*models.AccessSubject, int, error) {
	var policyCount int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM access_policies WHERE subject_id=$1`, id).Scan(&policyCount); err != nil {
		return nil, 0, err
	}
	var item models.AccessSubject
	err := db.QueryRowContext(ctx, `DELETE FROM access_subjects WHERE id=$1
RETURNING id, subject_type, external_id, display_name, created_at, updated_at`, id).
		Scan(&item.ID, &item.SubjectType, &item.ExternalID, &item.DisplayName, &item.CreatedAt, &item.UpdatedAt)
	if err != nil {
		return nil, 0, err
	}
	return &item, policyCount, nil
}

func (db *DB) DeleteAccessPolicy(ctx context.Context, id string) (*models.AccessPolicy, error) {
	var item models.AccessPolicy
	err := db.QueryRowContext(ctx, `WITH deleted AS (
	DELETE FROM access_policies
	WHERE id=$1
	RETURNING id, subject_id, resource_type, resource_id, permission, created_at
)
SELECT d.id, d.subject_id, s.subject_type, s.external_id, d.resource_type, d.resource_id, d.permission, d.created_at
FROM deleted d
JOIN access_subjects s ON s.id = d.subject_id`, id).
		Scan(&item.ID, &item.SubjectID, &item.SubjectType, &item.SubjectExternalID, &item.ResourceType, &item.ResourceID, &item.Permission, &item.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &item, nil
}

func (db *DB) UpsertAccessPolicy(ctx context.Context, id, subjectID, subjectExternalID, resourceType, resourceID, permission string) error {
	if id == "" {
		id = uuid.New().String()
	}
	if resourceID == "" {
		resourceID = "*"
	}
	if subjectID == "" {
		var err error
		subjectID, err = db.resolveAccessSubjectID(ctx, subjectExternalID)
		if err != nil {
			return err
		}
	} else {
		var exists bool
		if err := db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM access_subjects WHERE id=$1)`, subjectID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("access subject id %q not found", subjectID)
		}
	}
	_, err := db.ExecContext(ctx, `INSERT INTO access_policies (id, subject_id, resource_type, resource_id, permission, created_at)
VALUES ($1, $2, $3, $4, $5, now())
ON CONFLICT (subject_id, resource_type, resource_id, permission) DO NOTHING`,
		id, subjectID, resourceType, resourceID, permission)
	return err
}

func (db *DB) resolveAccessSubjectID(ctx context.Context, subjectExternalID string) (string, error) {
	subjectType, externalID := parseAccessSubjectRef(subjectExternalID)
	args := []any{externalID}
	typeFilter := ""
	if subjectType != "" {
		typeFilter = " AND subject_type=$2"
		args = append(args, subjectType)
	}
	rows, err := db.QueryContext(ctx, `SELECT id FROM access_subjects WHERE external_id=$1`+typeFilter+` ORDER BY subject_type`, args...)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return "", err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	if len(ids) == 0 {
		return "", fmt.Errorf("access subject %q not found", subjectExternalID)
	}
	if len(ids) > 1 {
		return "", fmt.Errorf("access subject %q is ambiguous; use user:%s or group:%s", subjectExternalID, externalID, externalID)
	}
	return ids[0], nil
}

