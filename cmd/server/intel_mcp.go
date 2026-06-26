package main

import (
	"context"
	"flag"
	"log"
	"os"
	"time"

	"github.com/ziozzang/bongsu/internal/server/db"
	"github.com/ziozzang/bongsu/internal/server/intel"
)

// runIntelMCP serves Bongsu's read-only intelligence tools over MCP stdio for a
// single run. The jikji agent loads it via
// `jikjictl ... --tools-from "bongsu-server intel-mcp --run-id <id>"`; it serves
// under exactly the run's stored RBAC scope and audits every call to that run.
// stderr carries diagnostics; stdout is the JSON-RPC channel only.
func runIntelMCP(args []string) int {
	fs := flag.NewFlagSet("intel-mcp", flag.ContinueOnError)
	runID := fs.String("run-id", "", "intel run id whose RBAC scope and audit log to use")
	dsn := fs.String("dsn", envOr("BONGSU_DB_DSN", "postgres://bongsu:bongsu@localhost:5432/bongsu?sslmode=disable"), "database DSN")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	connectCtx, connectCancel := context.WithTimeout(ctx, 30*time.Second)
	database, err := db.New(connectCtx, *dsn)
	connectCancel()
	if err != nil {
		log.Printf("intel-mcp: connect db: %v", err)
		return 1
	}
	defer database.Close()

	store := intel.NewStore(database, 1024)
	defer store.Close()

	// Two modes:
	//   --run-id <id>  per-run scope: loads the run's RBAC snapshot and audits
	//                  every tool call to that run (the stdio per-run path).
	//   (no run-id)    service-scope: the persistent MCP jikji is configured with
	//                  at its boot (HTTP /v1/runs model). Authorization is enforced
	//                  at the API trigger (/api/intel/runs); the run operates at a
	//                  service scope (admin by default, relaxable by the operator's
	//                  jikji config). Tool-call audit is reconstructed from the run
	//                  events by RunScenario, so the MCP side does not audit here.
	var scope *intel.Scope
	auditRun := *runID
	if *runID != "" {
		scope, err = store.LoadRunScope(ctx, *runID)
		if err != nil {
			log.Printf("intel-mcp: load run scope for %s: %v", *runID, err)
			return 1
		}
	} else {
		scope = &intel.Scope{Admin: true} // service scope
	}

	reg := intel.DefaultRegistry(database)
	srv := intel.NewMCPServer(reg, scope)
	if auditRun != "" {
		srv = srv.WithAudit(func(seq int, tool string, argsJSON, result []byte, isErr bool, dur time.Duration) {
			errMsg := ""
			if isErr {
				errMsg = string(result)
			}
			store.RecordToolCall(auditRun, seq, tool, argsJSON, result, false, dur, errMsg)
		})
	}

	if err := srv.Serve(ctx, os.Stdin, os.Stdout); err != nil && ctx.Err() == nil {
		log.Printf("intel-mcp: serve: %v", err)
		return 1
	}
	return 0
}
