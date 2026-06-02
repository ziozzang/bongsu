package db

import (
	"context"
	"fmt"
	"strings"
	"time"
)

type AssetGroup struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	RuleType    string    `json:"rule_type"`
	RuleExpr    string    `json:"rule_expr"`
	HostCount   int       `json:"host_count,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

const assetGroupCols = `id, name, description, rule_type, rule_expr, created_at, updated_at`

func (db *DB) CreateAssetGroup(ctx context.Context, g *AssetGroup) error {
	q := `INSERT INTO asset_groups (id, name, description, rule_type, rule_expr, created_at, updated_at)
	      VALUES ($1, $2, $3, $4, $5, now(), now())`
	_, err := db.ExecContext(ctx, q, g.ID, g.Name, g.Description, g.RuleType, g.RuleExpr)
	if err != nil {
		return fmt.Errorf("create asset group: %w", err)
	}
	return nil
}

func (db *DB) GetAssetGroup(ctx context.Context, id string) (*AssetGroup, error) {
	var g AssetGroup
	q := `SELECT ` + assetGroupCols + `, (SELECT COUNT(*) FROM asset_group_members WHERE group_id = $1) FROM asset_groups WHERE id = $1`
	err := db.QueryRowContext(ctx, q, id).Scan(&g.ID, &g.Name, &g.Description, &g.RuleType, &g.RuleExpr, &g.CreatedAt, &g.UpdatedAt, &g.HostCount)
	if err != nil {
		return nil, fmt.Errorf("get asset group: %w", err)
	}
	return &g, nil
}

func (db *DB) ListAssetGroups(ctx context.Context) ([]AssetGroup, error) {
	q := `SELECT ` + assetGroupCols + `, (SELECT COUNT(*) FROM asset_group_members m WHERE m.group_id = ag.id) FROM asset_groups ag ORDER BY name`
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("list asset groups: %w", err)
	}
	defer rows.Close()
	var out []AssetGroup
	for rows.Next() {
		var g AssetGroup
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.RuleType, &g.RuleExpr, &g.CreatedAt, &g.UpdatedAt, &g.HostCount); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func (db *DB) UpdateAssetGroup(ctx context.Context, g *AssetGroup) error {
	q := `UPDATE asset_groups SET name=$2, description=$3, rule_type=$4, rule_expr=$5, updated_at=now() WHERE id=$1`
	res, err := db.ExecContext(ctx, q, g.ID, g.Name, g.Description, g.RuleType, g.RuleExpr)
	if err != nil {
		return fmt.Errorf("update asset group: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("asset group not found")
	}
	return nil
}

func (db *DB) DeleteAssetGroup(ctx context.Context, id string) error {
	res, err := db.ExecContext(ctx, `DELETE FROM asset_groups WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete asset group: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("asset group not found")
	}
	return nil
}

func (db *DB) AddHostToAssetGroup(ctx context.Context, groupID, hostID string) error {
	_, err := db.ExecContext(ctx,
		`INSERT INTO asset_group_members (group_id, host_id, added_at) VALUES ($1, $2, now()) ON CONFLICT DO NOTHING`,
		groupID, hostID)
	if err != nil {
		return fmt.Errorf("add host to asset group: %w", err)
	}
	return nil
}

func (db *DB) RemoveHostFromAssetGroup(ctx context.Context, groupID, hostID string) error {
	res, err := db.ExecContext(ctx,
		`DELETE FROM asset_group_members WHERE group_id = $1 AND host_id = $2`,
		groupID, hostID)
	if err != nil {
		return fmt.Errorf("remove host from asset group: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("host not in group")
	}
	return nil
}

func (db *DB) GetAssetGroupHostIDs(ctx context.Context, groupID string) ([]string, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT host_id FROM asset_group_members WHERE group_id = $1 ORDER BY host_id`,
		groupID)
	if err != nil {
		return nil, fmt.Errorf("get asset group hosts: %w", err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (db *DB) ExpandDynamicGroup(ctx context.Context, groupID string) ([]string, error) {
	group, err := db.GetAssetGroup(ctx, groupID)
	if err != nil {
		return nil, err
	}
	if group.RuleType != "dynamic" || group.RuleExpr == "" {
		return db.GetAssetGroupHostIDs(ctx, groupID)
	}
	hosts, err := db.ListHosts(ctx)
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, h := range hosts {
		if matchDynamicRule(group.RuleExpr, h.Owner, h.Team, h.Environment, h.Criticality, h.Tags) {
			ids = append(ids, h.ID)
		}
	}
	return ids, nil
}

func matchDynamicRule(expr, owner, team, environment, criticality, tags string) bool {
	conditions := strings.Split(expr, ",")
	for _, cond := range conditions {
		cond = strings.TrimSpace(cond)
		if cond == "" {
			continue
		}
		if strings.HasPrefix(cond, "tags:") {
			tagPart := strings.TrimPrefix(cond, "tags:")
			if idx := strings.Index(tagPart, "="); idx >= 0 {
				key := tagPart[:idx]
				val := tagPart[idx+1:]
				if !strings.Contains(strings.ToLower(tags), strings.ToLower(`"`+key+`":"`+val+`"`)) {
					return false
				}
			} else {
				if !strings.Contains(strings.ToLower(tags), strings.ToLower(`"`+tagPart+`"`)) {
					return false
				}
			}
		} else {
			kv := strings.SplitN(cond, "=", 2)
			if len(kv) != 2 {
				return false
			}
			key := strings.TrimSpace(kv[0])
			val := strings.TrimSpace(kv[1])
			switch strings.ToLower(key) {
			case "owner":
				if !strings.EqualFold(owner, val) {
					return false
				}
			case "team":
				if !strings.EqualFold(team, val) {
					return false
				}
			case "environment":
				if !strings.EqualFold(environment, val) {
					return false
				}
			case "criticality":
				if !strings.EqualFold(criticality, val) {
					return false
				}
			default:
				return false
			}
		}
	}
	return true
}
