import React, { useState, useEffect, useCallback } from 'react';
import { api, type Stats, type HealthStatus, type CveDbStatsResponse, type CveDbQuality, type AgentFleetStatus, type SecurityDbOperationalStatus, type InstallerStatus, type Host, type VulnTrendRow, type ScanActivityRow, type VulnSummaryRow, type CveSourceStat, type CveRematchPolicy, type CveEpssMergeStats } from '../api';
import { type ScanRequestFilters, type VulnerabilityFilters, type HostFilters } from '../lib/viewTypes';
import { Loading, LoadError, EmptyState } from '../components/primitives';
import { RangeSwitcher } from '../components/controls';
import { StackedAreaChart, BarSeries, DonutChart, KpiCard, SEV_KEYS } from '../components/charts';
import { formatAge } from '../lib/format';
import { subscribeLiveBus } from '../hooks/useLiveEvents';

export function DashboardView({ onOpenScanRequests, onOpenVulnerabilities, onOpenHosts }: { onOpenScanRequests: (filters: ScanRequestFilters) => void; onOpenVulnerabilities: (filters: VulnerabilityFilters) => void; onOpenHosts: (filters: HostFilters) => void }) {
  const [stats, setStats] = useState<Stats | null>(null);
  const [statsError, setStatsError] = useState('');
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [securityDbConfigured, setSecurityDbConfigured] = useState(false);
  const [cveSources, setCveSources] = useState<CveSourceStat[]>([]);
  const [cveRematchPolicy, setCveRematchPolicy] = useState<CveRematchPolicy | null>(null);
  const [cveAffectedIndex, setCveAffectedIndex] = useState<HealthStatus['cve_affected_package_index'] | null>(null);
  const [cveReferenceIndex, setCveReferenceIndex] = useState<HealthStatus['cve_reference_key_index'] | CveDbStatsResponse['reference_key_index'] | null>(null);
  const [cveEpssMerge, setCveEpssMerge] = useState<CveEpssMergeStats | null>(null);
  const [cveDbQuality, setCveDbQuality] = useState<CveDbQuality | null>(null);
  const [cveStatsMeta, setCveStatsMeta] = useState<Pick<CveDbStatsResponse, 'cache_status' | 'generated_at' | 'durations_ms' | 'osv_ecosystems' | 'osv_ecosystems_error'> | null>(null);
  const [installerStatus, setInstallerStatus] = useState<InstallerStatus | null>(null);
  const [securityDbStatus, setSecurityDbStatus] = useState<SecurityDbOperationalStatus | null>(null);
  const [agentFleetStatus, setAgentFleetStatus] = useState<AgentFleetStatus | null>(null);
  const [dashboardHosts, setDashboardHosts] = useState<Host[]>([]);
  const [agentCounts, setAgentCounts] = useState<Record<string, number>>({});
  const [totalPkgs, setTotalPkgs] = useState(0);
  const [ownerSummary, setOwnerSummary] = useState<VulnSummaryRow[]>([]);
  const [teamSummary, setTeamSummary] = useState<VulnSummaryRow[]>([]);
  const [environmentSummary, setEnvironmentSummary] = useState<VulnSummaryRow[]>([]);
  const [criticalitySummary, setCriticalitySummary] = useState<VulnSummaryRow[]>([]);
  const [trendRange, setTrendRange] = useState('30');
  const [trendRows, setTrendRows] = useState<VulnTrendRow[]>([]);
  const [scanRows, setScanRows] = useState<ScanActivityRow[]>([]);
  const [chartsLoading, setChartsLoading] = useState(true);
  const [updating, setUpdating] = useState(false);
  const [updateMsg, setUpdateMsg] = useState('');
  const [rematching, setRematching] = useState(false);
  const [rematchMsg, setRematchMsg] = useState('');
  const [rematchMinQuality, setRematchMinQuality] = useState('');
  const [rematchCandidateLimit, setRematchCandidateLimit] = useState('');
  const [cvssRecalcBusy, setCvssRecalcBusy] = useState(false);
  const [cvssRecalcMsg, setCvssRecalcMsg] = useState('');
  const [securityRecalcBusy, setSecurityRecalcBusy] = useState(false);
  const [securityRecalcMsg, setSecurityRecalcMsg] = useState('');
  const [retentionMsg, setRetentionMsg] = useState('');
  const [retentionBusy, setRetentionBusy] = useState(false);
  const [securityBundleMsg, setSecurityBundleMsg] = useState('');
  const [securityBundleBusy, setSecurityBundleBusy] = useState(false);
  const [securityBundleIncludeTrivy, setSecurityBundleIncludeTrivy] = useState(true);
  const applyCveStats = useCallback((r: CveDbStatsResponse) => {
    setCveSources(r.sources || []);
    setCveRematchPolicy(r.rematch_policy || null);
    setCveAffectedIndex(r.affected_package_index || null);
    setCveEpssMerge(r.epss_merge || null);
    setCveReferenceIndex(r.reference_key_index || null);
    setCveDbQuality(r.cve_db_quality || null);
    setCveStatsMeta({ cache_status: r.cache_status, generated_at: r.generated_at, durations_ms: r.durations_ms, osv_ecosystems: r.osv_ecosystems, osv_ecosystems_error: r.osv_ecosystems_error });
  }, []);
  const applySecurityDbStatus = useCallback((r: SecurityDbOperationalStatus) => {
    setSecurityDbStatus(r);
    setSecurityDbConfigured(!!r.security_db?.configured);
    if (r.cve_affected_package_index) setCveAffectedIndex(r.cve_affected_package_index);
    if (r.cve_reference_key_index) setCveReferenceIndex(r.cve_reference_key_index);
    if (r.cve_db_quality) setCveDbQuality(r.cve_db_quality);
  }, []);
  const refreshSecurityDbStatus = useCallback(() => {
    api.securityDbStatus().then(applySecurityDbStatus).catch(() => {});
  }, [applySecurityDbStatus]);

  const loadStats = useCallback(() => {
    setStatsError('');
    api.stats().then(setStats).catch((e) => setStatsError(e instanceof Error ? e.message : 'Failed to load stats'));
  }, []);
  useEffect(() => { loadStats(); }, [loadStats]);
  // Live KPI refresh: when a low-frequency aggregate event arrives over SSE,
  // refetch the (RBAC-scoped, server-cached) stats + fleet rather than the
  // server pushing a snapshot — so scoped viewers never receive global counts.
  // finding.new is intentionally excluded (it bursts; scan.completed covers it).
  const reloadLiveKpis = useCallback(() => {
    loadStats();
    api.agentFleetStatus().then(r => { setAgentFleetStatus(r); if (r.installer) setInstallerStatus(r.installer); }).catch(() => {});
  }, [loadStats]);
  useEffect(() => {
    const agg = new Set(['scan.completed', 'scan.failed', 'agent.online', 'agent.offline', 'secdb.updated']);
    return subscribeLiveBus((e) => { if (agg.has(e.type)) reloadLiveKpis(); });
  }, [reloadLiveKpis]);
  useEffect(() => {
    api.rawHealth().then(h => {
      setHealth(h);
      setSecurityDbConfigured(!!h.security_db?.configured);
      setCveAffectedIndex(h.cve_affected_package_index || null);
      setCveDbQuality(h.cve_db_quality || null);
    }).catch(() => {});
    refreshSecurityDbStatus();
  }, [updating, refreshSecurityDbStatus]);
  useEffect(() => {
    if (!health?.cve_reference_index_rebuild?.running && !health?.cve_affected_index_rebuild?.running) return;
    const timer = window.setInterval(() => {
      api.rawHealth().then(h => {
        setHealth(h);
        setSecurityDbConfigured(!!h.security_db?.configured);
        setCveAffectedIndex(h.cve_affected_package_index || null);
        setCveDbQuality(h.cve_db_quality || null);
      }).catch(() => {});
      api.cveDbStats().then(applyCveStats).catch(() => {});
      refreshSecurityDbStatus();
    }, 5000);
    return () => window.clearInterval(timer);
  }, [health?.cve_reference_index_rebuild?.running, health?.cve_affected_index_rebuild?.running, applyCveStats, refreshSecurityDbStatus]);
  useEffect(() => {
    api.cveDbStats().then(applyCveStats).catch(() => {});
    api.installerStatus().then(setInstallerStatus).catch(() => {});
    api.securityDbStatus().then(applySecurityDbStatus).catch(() => {});
    api.agentFleetStatus().then(r => {
      setAgentFleetStatus(r);
      if (r.installer) setInstallerStatus(r.installer);
    }).catch(() => {});
    api.packages({ limit: '1' }).then(r => setTotalPkgs(r.total)).catch(() => {});
    api.hosts().then(items => {
      setDashboardHosts(items || []);
      setAgentCounts(items.reduce((acc, h) => {
        const status = h.agent_status || 'unknown';
        acc[status] = (acc[status] || 0) + 1;
        return acc;
      }, {} as Record<string, number>));
    }).catch(() => {});
    api.vulnSummary({ group_by: 'owner' }).then(r => setOwnerSummary(r.items || [])).catch(() => {});
    api.vulnSummary({ group_by: 'team' }).then(r => setTeamSummary(r.items || [])).catch(() => {});
    api.vulnSummary({ group_by: 'environment' }).then(r => setEnvironmentSummary(r.items || [])).catch(() => {});
    api.vulnSummary({ group_by: 'criticality' }).then(r => setCriticalitySummary(r.items || [])).catch(() => {});
  }, [applyCveStats]);

  useEffect(() => {
    let active = true;
    setChartsLoading(true);
    Promise.all([
      api.vulnTrends({ days: trendRange }).catch(() => ({ items: [] as VulnTrendRow[] })),
      api.scanActivity({ days: trendRange }).catch(() => ({ days: 0, items: [] as ScanActivityRow[] })),
    ]).then(([t, s]) => {
      if (!active) return;
      setTrendRows(t.items || []);
      setScanRows(s.items || []);
      setChartsLoading(false);
    });
    return () => { active = false; };
  }, [trendRange]);

  const handleUpdate = async () => {
    setUpdating(true);
    setUpdateMsg('');
    try {
      const r = await api.updateTrivyDB();
      setUpdateMsg(r.message || 'Updated');
    } catch {
      setUpdateMsg('Update failed (check server logs)');
    }
    setUpdating(false);
  };

  const handleSecurityUpdate = async () => {
    setUpdating(true);
    setUpdateMsg('');
    try {
      await api.updateSecurityDB();
      setUpdateMsg('Security sources sync started/completed');
      api.cveDbStats().then(applyCveStats).catch(() => {});
      refreshSecurityDbStatus();
    } catch {
      setUpdateMsg('Security source sync failed or is not configured');
    }
    setUpdating(false);
  };

  const handleAffectedIndexRebuild = async () => {
    setUpdating(true);
    setUpdateMsg('');
    try {
      const r = await api.rebuildCveAffectedIndex();
      if (r.status === 'queued') {
        setUpdateMsg('Affected package index rebuild queued');
      } else if (r.status === 'running') {
        setUpdateMsg('Affected package index rebuild is already running');
      } else {
        setCveAffectedIndex(r.index || null);
        const duration = r.duration_ms ? ` in ${(r.duration_ms / 1000).toFixed(1)}s` : '';
        setUpdateMsg(`Affected package index rebuilt: ${(r.indexed || 0).toLocaleString()} entries${duration}`);
      }
      if (r.affected_index_rebuild) {
        setHealth(prev => ({ ...(prev || {} as HealthStatus), cve_affected_index_rebuild: r.affected_index_rebuild }));
      }
      api.rawHealth().then(setHealth).catch(() => {});
      api.cveDbStats().then(applyCveStats).catch(() => {});
      refreshSecurityDbStatus();
    } catch {
      setUpdateMsg('Affected package index rebuild failed');
    }
    setUpdating(false);
  };

  const handleReferenceIndexRebuild = async () => {
    setUpdating(true);
    setUpdateMsg('');
    try {
      const r = await api.rebuildCveReferenceIndex();
      if (r.status === 'queued') {
        setUpdateMsg('Reference key index rebuild queued');
      } else if (r.status === 'running') {
        setUpdateMsg('Reference key index rebuild is already running');
      } else {
        const duration = r.duration_ms ? ` in ${(r.duration_ms / 1000).toFixed(1)}s` : '';
        setUpdateMsg(`Reference key index rebuilt: ${(r.indexed || 0).toLocaleString()} keys${duration}`);
      }
      if (r.reference_index_rebuild) {
        setHealth(prev => ({ ...(prev || {} as HealthStatus), cve_reference_index_rebuild: r.reference_index_rebuild }));
      }
      api.rawHealth().then(setHealth).catch(() => {});
      api.cveDbStats().then(applyCveStats).catch(() => {});
      refreshSecurityDbStatus();
    } catch {
      setUpdateMsg('Reference key index rebuild failed');
    }
    setUpdating(false);
  };

  const handleRematch = async () => {
    setRematching(true);
    setRematchMsg('');
    try {
      const minQuality = Number(rematchMinQuality);
      const candidateLimit = Number(rematchCandidateLimit);
      const body: { min_source_matchable_percent?: number; candidate_limit?: number } = {};
      if (Number.isFinite(minQuality) && minQuality > 0) body.min_source_matchable_percent = minQuality;
      if (Number.isFinite(candidateLimit) && candidateLimit > 0) body.candidate_limit = Math.floor(candidateLimit);
      const r = await api.rematchCVEs(body);
      const qualityMsg = minQuality > 0 ? ` with source quality >= ${minQuality}%` : '';
      const limitMsg = candidateLimit > 0 ? `, candidate limit ${Math.floor(candidateLimit).toLocaleString()}` : '';
      const limitedMsg = r.limited ? `, limited at ${r.candidate_limit.toLocaleString()} candidates` : '';
      const scanned = r.scanned_candidates || r.matched + r.skipped;
      const scannedMsg = r.scanned_candidates ? ` from ${r.scanned_candidates.toLocaleString()} scanned candidates` : '';
      const skippedPct = scanned > 0 ? `, ${(r.skipped * 100 / scanned).toFixed(1)}% skipped` : '';
      const sourceMsg = r.eligible_sources !== undefined ? `, ${r.eligible_sources.toLocaleString()} eligible sources${r.excluded_sources ? `, ${r.excluded_sources.toLocaleString()} excluded` : ''}` : '';
      const revisionMsg = r.security_db_revision ? `, DB rev ${r.security_db_revision}` : r.security_db_revision_error ? ', DB revision unavailable' : '';
      setRematchMsg(`Matched ${r.matched.toLocaleString()} packages${scannedMsg}${qualityMsg}${limitMsg}, found ${r.new_vulns.toLocaleString()} new vulnerabilities (${r.skipped.toLocaleString()} skipped${skippedPct}${limitedMsg}${sourceMsg}${revisionMsg})`);
      api.stats().then(setStats).catch(() => {});
    } catch {
      setRematchMsg('Rematch failed (check server logs)');
    }
    setRematching(false);
  };

  const minQualityForDisplay = Number.parseFloat(rematchMinQuality);
  const sourceBelowQuality = (s: CveSourceStat) =>
    Number.isFinite(minQualityForDisplay) && minQualityForDisplay > 0 && (s.matchable_percent || 0) < minQualityForDisplay;
  const cveTotalRecords = cveSources.reduce((sum, s) => sum + (s.count || 0), 0);
  const cveTotalMatchable = cveSources.reduce((sum, s) => sum + (s.matchable || 0), 0);
  const cveMatchablePercent = cveTotalRecords > 0 ? (cveTotalMatchable * 100) / cveTotalRecords : 0;
  const cveRematchEligibleCount = cveRematchPolicy?.eligible_sources ?? cveSources.filter(s => s.rematch_eligible !== false).length;
  const cveRematchExcludedCount = cveRematchPolicy?.excluded_sources ?? cveSources.filter(s => s.rematch_eligible === false).length;
  const cveRematchPolicyText = cveRematchPolicy
    ? `${cveRematchPolicy.sources?.length ? `${cveRematchPolicy.sources.length} allowlisted` : 'all sources'}, min ${(cveRematchPolicy.min_source_matchable_percent || 0).toFixed(1)}%`
    : 'policy pending';
  const epssMergeCoverage = cveEpssMerge?.non_epss_coverage_percent ?? cveEpssMerge?.merge_coverage_percent ?? 0;
  const epssUniverseCoverage = cveEpssMerge?.epss_universe_match_percent ?? cveEpssMerge?.merge_coverage_percent ?? 0;
  const epssMergeColor = !cveEpssMerge || cveEpssMerge.epss_cves === 0
    ? 'var(--medium)'
    : epssMergeCoverage < 90
      ? 'var(--high)'
      : 'var(--low)';
  const cveAffectedIndexIndexedOnly = cveAffectedIndex?.summary_mode === 'indexed-only';
  const cveAffectedIndexUnhealthy = !!(cveAffectedIndex?.stale || (cveAffectedIndex?.orphans || 0) > 0 || (cveAffectedIndex?.missing_matchable_sources?.length || 0) > 0 || cveAffectedIndex?.error);
  const cveAffectedIndexColor = cveAffectedIndexUnhealthy ? 'var(--high)' : cveAffectedIndexIndexedOnly ? 'var(--medium)' : 'var(--low)';
  const affectedRebuild = health?.cve_affected_index_rebuild;
  const affectedRebuildLast = affectedRebuild?.last_result;
  const affectedRebuildRunning = !!affectedRebuild?.running;
  const affectedRebuildColor = affectedRebuildRunning
    ? 'var(--medium)'
    : affectedRebuildLast?.status === 'error'
      ? 'var(--critical)'
      : affectedRebuildLast?.status === 'ok'
        ? 'var(--low)'
        : 'var(--text-muted)';
  const cveReferenceIndexUnhealthy = !!(!cveReferenceIndex || cveReferenceIndex.stale || (cveReferenceIndex.orphans || 0) > 0 || (cveReferenceIndex.coverage_percent ?? 0) < 90);
  const cveReferenceIndexColor = cveReferenceIndexUnhealthy ? 'var(--high)' : 'var(--low)';
  const referenceRebuild = health?.cve_reference_index_rebuild;
  const referenceRebuildLast = referenceRebuild?.last_result;
  const referenceRebuildRunning = !!referenceRebuild?.running;
  const referenceRebuildColor = referenceRebuildRunning
    ? 'var(--medium)'
    : referenceRebuildLast?.status === 'error'
      ? 'var(--critical)'
      : referenceRebuildLast?.status === 'ok'
        ? 'var(--low)'
        : 'var(--text-muted)';
  const cveQualityStatus = cveDbQuality?.status || 'pending';
  const cveQualityColor = cveQualityStatus === 'degraded'
    ? 'var(--critical)'
    : cveQualityStatus === 'warning' || cveQualityStatus === 'pending'
      ? 'var(--medium)'
      : 'var(--low)';
  const cveQualityWarnings = cveDbQuality?.warnings || [];
  const securityDbWarnings = securityDbStatus?.warnings || [];
  const securityDbActions = securityDbStatus?.recommended_actions || [];
  const securitySourceRegistry = securityDbStatus?.security_sources || [];
  const securitySourceRegistryOk = securitySourceRegistry.filter(s => s.enabled && s.last_status === 'ok' && (s.record_count || 0) > 0).length;
  const securitySourceRegistryEnabled = securitySourceRegistry.filter(s => s.enabled).length;
  const securitySourceRegistryRecords = securitySourceRegistry.reduce((sum, s) => sum + (s.record_count || 0), 0);
  const latestSecuritySourceRegistry = securitySourceRegistry.reduce<typeof securitySourceRegistry[number] | null>((latest, source) => {
    if (!source.last_sync_finished_at) return latest;
    if (!latest?.last_sync_finished_at) return source;
    return new Date(source.last_sync_finished_at).getTime() > new Date(latest.last_sync_finished_at).getTime() ? source : latest;
  }, null);
  const latestSecuritySourceExport = securitySourceRegistry.reduce<typeof securitySourceRegistry[number] | null>((latest, source) => {
    if (!source.last_exported_at) return latest;
    if (!latest?.last_exported_at) return source;
    return new Date(source.last_exported_at).getTime() > new Date(latest.last_exported_at).getTime() ? source : latest;
  }, null);
  const securitySourceRegistryBroken = !!securityDbStatus?.security_sources_error || securitySourceRegistry.some(s => s.enabled && (s.last_status !== 'ok' || (s.record_count || 0) === 0 || s.last_error));
  const securityDbExportStatus = securityDbStatus?.security_db_export;
  const latestSecuritySourceDataUpdate = securityDbExportStatus?.latest_source_update_at;
  const latestSecuritySourceRegistryTime = latestSecuritySourceRegistry?.last_sync_finished_at;
  const latestSecuritySourceDisplay = latestSecuritySourceDataUpdate && (!latestSecuritySourceRegistryTime || new Date(latestSecuritySourceDataUpdate).getTime() > new Date(latestSecuritySourceRegistryTime).getTime())
    ? { label: 'data', source: 'cve rows', at: latestSecuritySourceDataUpdate }
    : latestSecuritySourceRegistryTime
      ? { label: 'registry', source: latestSecuritySourceRegistry?.id || 'source', at: latestSecuritySourceRegistryTime }
      : null;
  const securityDbExportStale = securityDbExportStatus?.status === 'stale' || securityDbExportStatus?.status === 'never';
  const securitySourceRegistryColor = securitySourceRegistryBroken
    ? 'var(--critical)'
    : securityDbExportStale
      ? 'var(--medium)'
    : securitySourceRegistry.length > 0
      ? 'var(--low)'
      : 'var(--medium)';
  const cveStatsCacheStatus = cveStatsMeta?.cache_status || 'unknown';
  const cveStatsGeneratedAt = cveStatsMeta?.generated_at ? new Date(cveStatsMeta.generated_at).toLocaleString() : 'not loaded';
  const cveStatsDuration = cveStatsMeta?.durations_ms?.total;
  const osvEcosystems = cveStatsMeta?.osv_ecosystems || [];
  const osvEcosystemRows = osvEcosystems.reduce((sum, eco) => sum + (eco.indexed_rows || 0), 0);
  const oldestOsvEcosystem = osvEcosystems.reduce<typeof osvEcosystems[number] | null>((oldest, eco) => {
    const at = eco.raw_last_update || eco.last_update;
    const oldestAt = oldest ? (oldest.raw_last_update || oldest.last_update) : null;
    if (!at) return oldest;
    if (!oldestAt) return eco;
    return new Date(at).getTime() < new Date(oldestAt).getTime() ? eco : oldest;
  }, null);
  const osvEcosystemColor = cveStatsMeta?.osv_ecosystems_error
    ? 'var(--high)'
    : osvEcosystems.length > 0
      ? 'var(--low)'
      : 'var(--medium)';
  const weakestCveSource = cveSources.reduce<CveSourceStat | null>((worst, source) =>
    !worst || (source.matchable_percent ?? 0) < (worst.matchable_percent ?? 0) ? source : worst, null);
  const latestCveSource = cveSources.reduce<CveSourceStat | null>((latest, source) => {
    if (!source.last_update) return latest;
    if (!latest?.last_update) return source;
    return new Date(source.last_update).getTime() > new Date(latest.last_update).getTime() ? source : latest;
  }, null);
  const latestSecurityDbSource = latestCveSource?.last_update
    ? { source: latestCveSource.source, last_update: latestCveSource.last_update }
    : health?.security_db_freshness?.latest_source && health.security_db_freshness.latest_last_update
      ? { source: health.security_db_freshness.latest_source, last_update: health.security_db_freshness.latest_last_update }
      : null;
  const osvCveSource = cveSources.find(source => source.source.toLowerCase() === 'osv') || null;
  const staleCveSources = health?.security_db_freshness?.stale_sources || [];
  const missingCveSources = health?.security_db_freshness?.missing_sources || [];
  const staleCveSourceByName = new Map(staleCveSources.map(s => [s.source.toLowerCase(), s]));
  const staleCveSourceCount = staleCveSources.length;
  const cveSourceAlertCount = staleCveSourceCount + missingCveSources.length;
  const oldestCveAgeDays = health?.security_db_freshness?.oldest_age_seconds
    ? health.security_db_freshness.oldest_age_seconds / 86400
    : 0;
  const securityDbFreshnessStatus = health?.security_db_freshness?.status || '';
  const effectiveSecurityDbStatus = health?.security_db?.effective_status || securityDbFreshnessStatus;
  const securitySourcesReady = !!health?.security_db?.configured && (
    health?.security_db?.status === 'ok' ||
    effectiveSecurityDbStatus === 'ok'
  );
  const securitySourcesLabel = !health?.security_db?.configured
    ? 'not configured'
    : securitySourcesReady
      ? 'ok'
      : effectiveSecurityDbStatus || health?.security_db?.status || 'unknown';
  const cveDbStatus = !securityDbConfigured
    ? 'not configured'
    : health?.security_db?.running
      ? 'syncing'
      : securityDbStatus?.status === 'warning'
        ? 'warning'
      : health?.security_db_freshness?.stale
        ? 'stale'
        : securityDbStatus?.status === 'degraded'
          ? 'degraded'
        : effectiveSecurityDbStatus === 'ok'
          ? 'ok'
          : effectiveSecurityDbStatus || health?.security_db?.status || 'unknown';
  const cveDbStatusColor = !securityDbConfigured || cveDbStatus === 'stale'
    ? 'var(--critical)'
    : cveDbStatus === 'degraded'
      ? 'var(--critical)'
    : cveDbStatus === 'syncing' || cveDbStatus === 'unknown' || cveDbStatus === 'warning'
      ? 'var(--medium)'
      : 'var(--low)';
  const securitySyncNext = health?.security_db?.next_sync && !health.security_db.next_sync.startsWith('0001-')
    ? new Date(health.security_db.next_sync).toLocaleString()
    : '';
  const securitySyncLast = health?.security_db?.last_attempt && !health.security_db.last_attempt.startsWith('0001-')
    ? new Date(health.security_db.last_attempt).toLocaleString()
    : '';
  const securitySyncStatus = health?.security_db?.running
    ? 'syncing'
    : effectiveSecurityDbStatus === 'ok'
      ? 'ok'
    : health?.security_db?.status === 'never' && latestSecurityDbSource?.last_update
      ? 'waiting'
      : health?.security_db?.status || '-';
  const securitySyncDetail = securitySyncLast
    ? `last sync ${securitySyncLast}`
    : health?.security_db?.effective_last_sync
      ? `effective ${effectiveSecurityDbStatus || 'unknown'} from ${(health.security_db.effective_source || 'source').toUpperCase()} ${new Date(health.security_db.effective_last_sync).toLocaleString()}`
    : latestSecurityDbSource?.last_update
      ? `latest source ${latestSecurityDbSource.source.toUpperCase()} ${new Date(latestSecurityDbSource.last_update).toLocaleString()}`
      : securitySyncNext
        ? `next ${securitySyncNext}`
        : `interval ${health?.security_db?.interval || '-'}`;
  const cveFreshnessColor = missingCveSources.length > 0 || staleCveSourceCount > 0 || health?.security_db_freshness?.stale ? 'var(--critical)' : 'var(--low)';
  const cveMatchableColor = cveMatchablePercent < 50 && cveTotalRecords > 0
    ? 'var(--critical)'
    : cveMatchablePercent < 80 && cveTotalRecords > 0
      ? 'var(--medium)'
      : 'var(--low)';
  const lastRecalc = health?.security_recalculation?.last_result;
  const lastManualRematch = health?.cve_db_rematch?.last_result;
  const lastAutoRescan = health?.security_db_auto_rescan?.last_result;
  const lastSecurityBundleImport = securityDbStatus?.security_db_bundle_import?.last_result;
  const lastRecalcLimited = !!lastRecalc?.rematch_limited;
  const lastManualRematchLimited = !!lastManualRematch?.limited;
  const lastRecalcColor = lastRecalc?.status === 'error'
    ? 'var(--critical)'
    : lastRecalcLimited
      ? 'var(--high)'
    : lastRecalc?.status === 'ok'
      ? 'var(--low)'
      : 'var(--medium)';
  const lastRecalcTitle = lastRecalcLimited
    ? `Rematch hit candidate limit ${lastRecalc?.rematch_candidate_limit || 0}`
    : lastRecalc?.errors?.length ? lastRecalc.errors.join('\n') : lastRecalc?.reason || '';
  const lastManualRematchColor = lastManualRematch?.status === 'error'
    ? 'var(--critical)'
    : lastManualRematchLimited
      ? 'var(--high)'
      : lastManualRematch?.status === 'ok'
        ? 'var(--low)'
        : 'var(--medium)';
  const lastAutoRescanColor = lastAutoRescan?.status === 'error'
    ? 'var(--critical)'
    : lastAutoRescan?.status === 'disabled'
      ? 'var(--medium)'
      : lastAutoRescan?.status === 'ok'
        ? 'var(--low)'
        : 'var(--medium)';
  const rescanProgress = stats?.security_db_rescan_progress || {};
  const rescanCompletePercent = Number(rescanProgress.complete_percent || 0);
  const rescanProgressColor = (rescanProgress.failed || 0) > 0
    ? 'var(--critical)'
    : (rescanProgress.open || 0) > 0
      ? 'var(--medium)'
      : (rescanProgress.total || 0) > 0
        ? 'var(--low)'
        : 'var(--text-muted)';
  const scanCoverage = stats?.security_db_scan_coverage || {};
  const scanCoveragePercent = Number(scanCoverage.coverage_percent || 0);
  const scanCoverageColor = (scanCoverage.stale_hosts || 0) > 0 || (scanCoverage.unknown_hosts || 0) > 0
    ? 'var(--medium)'
    : (scanCoverage.current_hosts || 0) > 0
      ? 'var(--low)'
      : 'var(--text-muted)';
  const triageActiveCounts = stats?.triage_active_counts || {};
  const triageExpiringSoonCounts = stats?.triage_expiring_soon_counts || {};
  const suppressedTriageCount = ['accepted_risk', 'false_positive', 'fixed', 'ignored']
    .reduce((sum, status) => sum + (triageActiveCounts[status] || 0), 0);
  const triageExpiringSoonTotal = Object.values(triageExpiringSoonCounts).reduce((sum, count) => sum + count, 0);
  const effectiveAgentCounts = stats?.agent_status_counts || agentCounts;
  const effectiveInventoryCounts = stats?.inventory_status_counts || {};
  const inventoryCoveragePercent = stats?.inventory_coverage_percent ?? 0;
  const inventoryFreshPercent = stats?.inventory_fresh_percent ?? 0;
  const agentFleetWarnings = agentFleetStatus?.warnings || [];
  const agentFleetActions = agentFleetStatus?.recommended_actions || [];
  const agentVersionDriftCounts = agentFleetStatus?.agent_version_drift_counts || stats?.agent_version_drift_counts || {};
  const latestAgentVersion = agentFleetStatus?.latest_agent_version || stats?.latest_agent_version || installerStatus?.agent?.version || '';
  const currentAgentCount = agentVersionDriftCounts.current ?? (latestAgentVersion ? dashboardHosts.filter(h => h.agent_version === latestAgentVersion).length : 0);
  const outdatedAgentCount = agentVersionDriftCounts.outdated ?? (latestAgentVersion ? dashboardHosts.filter(h => h.agent_version && h.agent_version !== latestAgentVersion).length : 0);
  const unknownAgentVersionCount = agentVersionDriftCounts.unknown ?? dashboardHosts.filter(h => !h.agent_version).length;
  const agentFleetOutdatedPercent = agentFleetStatus?.outdated_percent ?? (dashboardHosts.length ? (outdatedAgentCount / dashboardHosts.length) * 100 : 0);
  const inventoryCoverageColor = inventoryCoveragePercent < 70
    ? 'var(--critical)'
    : inventoryCoveragePercent < 90
      ? 'var(--medium)'
      : 'var(--low)';

  const handleCvssRecalc = async () => {
    setCvssRecalcBusy(true);
    setCvssRecalcMsg('');
    try {
      const r = await api.recalcCveCVSS();
      const revisionMsg = r.security_db_revision ? `, DB rev ${r.security_db_revision}` : r.security_db_revision_error ? ', DB revision unavailable' : '';
      setCvssRecalcMsg(`Recalculated ${r.updated.toLocaleString()} CVSS records${revisionMsg}`);
      api.cveDbStats().then(applyCveStats).catch(() => {});
      refreshSecurityDbStatus();
    } catch {
      setCvssRecalcMsg('CVSS recalculation failed or requires admin API key');
    }
    setCvssRecalcBusy(false);
  };

  const handleSecurityRecalc = async () => {
    setSecurityRecalcBusy(true);
    setSecurityRecalcMsg('');
    try {
      const r = await api.recalculateSecurityDB({ reason: 'manual dashboard recalculation' });
      const revisionMsg = r.security_db_revision ? `, DB rev ${r.security_db_revision}` : r.security_db_revision_error ? ', DB revision unavailable' : '';
      setSecurityRecalcMsg(`Security recalculation ${r.status}${revisionMsg}`);
      api.rawHealth().then(setHealth).catch(() => {});
      refreshSecurityDbStatus();
    } catch {
      setSecurityRecalcMsg('Security recalculation queue failed or requires admin API key');
    }
    setSecurityRecalcBusy(false);
  };

  const openCurrentDBRescans = (status: string, stale?: boolean) => {
    const revision = stats?.security_db_revision || health?.security_db_revision || '';
    if (!revision) return;
    onOpenScanRequests({ status, scan_type: 'security-db-update', security_db_revision: revision, ...(stale ? { stale: 'true' } : {}) });
  };

  const handleRetentionPrune = async (dryRun: boolean) => {
    setRetentionBusy(true);
    setRetentionMsg('');
    try {
      const r = await api.pruneRetention({ dry_run: dryRun });
      const inventoryRows = r.packages + r.vulnerabilities + r.containers + r.users + r.processes + r.ports;
      const affected = r.scans + inventoryRows + r.scan_requests + r.audit_logs;
      const scanCutoff = r.scan_cutoff ? new Date(r.scan_cutoff).toLocaleString() : `${r.scan_days}d`;
      const requestCutoff = r.request_cutoff ? new Date(r.request_cutoff).toLocaleString() : `${r.request_days}d`;
      const auditCutoff = r.audit_cutoff ? new Date(r.audit_cutoff).toLocaleString() : `${r.audit_days}d`;
      setRetentionMsg(`${dryRun ? 'Dry run' : 'Pruned'}: ${affected.toLocaleString()} records (${r.scans} scans before ${scanCutoff}, ${inventoryRows} inventory rows, ${r.scan_requests} requests before ${requestCutoff}, ${r.audit_logs} audit logs before ${auditCutoff})`);
    } catch {
      setRetentionMsg('Retention prune failed or requires admin API key');
    }
    setRetentionBusy(false);
  };

  const handleSecurityBundleExport = async () => {
    setSecurityBundleBusy(true);
    setSecurityBundleMsg('Preparing bundle on the server — the full CVE DB is packaged and checksummed before the download starts, which takes roughly 30–90 seconds. The download begins automatically when ready...');
    try {
      await api.exportSecurityDBBundle(securityBundleIncludeTrivy);
      setSecurityBundleMsg(`Exported airgap bundle${securityBundleIncludeTrivy ? ' with Trivy DB when available' : ' without Trivy DB'}`);
    } catch {
      setSecurityBundleMsg('Security DB bundle export failed or requires admin API key');
    }
    setSecurityBundleBusy(false);
  };

  const handleSecurityBundleImport = async (file?: File) => {
    if (!file) return;
    setSecurityBundleBusy(true);
    setSecurityBundleMsg(`Uploading ${file.name}…`);
    try {
      const r = await api.importSecurityDBBundle(file);
      // The import runs in the background (the upload streams ~170MB and the DB
      // replace + index rebuild take several minutes), so the upload returns a
      // "started" acknowledgement and we poll the security DB status for the
      // result instead of holding the request open.
      const records = typeof r.bundle_cve_records === 'number' ? `~${r.bundle_cve_records.toLocaleString()} CVE records` : 'the bundle';
      setSecurityBundleMsg(`Import started in the background (${records}). This takes several minutes; the dashboard updates automatically when it completes.`);
      const startedAt = Date.now();
      const poll = setInterval(() => {
        if (Date.now() - startedAt > 30 * 60 * 1000) { clearInterval(poll); setSecurityBundleBusy(false); return; }
        api.securityDbStatus().then(st => {
          const last = st?.security_db_bundle_import?.last_result;
          const status = last?.status;
          if (status === 'ok') {
            clearInterval(poll);
            const imp = typeof last?.imported === 'number' ? last.imported.toLocaleString() : '';
            setSecurityBundleMsg(`Imported ${imp} CVE records${last?.trivy_db_loaded ? ' and Trivy DB' : ''}; recalculation started`);
            api.rawHealth().then(h => { setHealth(h); setSecurityDbConfigured(!!h.security_db?.configured); }).catch(() => {});
            api.cveDbStats().then(applyCveStats).catch(() => {});
            api.stats().then(setStats).catch(() => {});
            refreshSecurityDbStatus();
            setSecurityBundleBusy(false);
          } else if (status === 'error') {
            clearInterval(poll);
            setSecurityBundleMsg(`Bundle import failed: ${last?.message || last?.error || 'see audit log'}`);
            setSecurityBundleBusy(false);
          }
        }).catch(() => {});
      }, 5000);
    } catch {
      setSecurityBundleMsg('Security DB bundle import failed or requires admin API key');
      setSecurityBundleBusy(false);
    }
  };

  // ── Ops console derived data ────────────────────────────────────────────────
  const trendTotals = trendRows.map(r => r.total_vulns);
  const lastTrend = trendRows[trendRows.length - 1];
  // delta vs ~7 days ago within the loaded series (or earliest available point)
  const deltaAt = (sel: (r: VulnTrendRow) => number): number | null => {
    if (trendRows.length < 2) return null;
    const idx = Math.max(0, trendRows.length - 1 - 7);
    const ref = trendRows[idx];
    if (!lastTrend || !ref || ref === lastTrend) return null;
    return sel(lastTrend) - sel(ref);
  };
  const totalDelta = deltaAt(r => r.total_vulns);
  const critDelta = deltaAt(r => r.critical_count);
  const exploitedDelta = deltaAt(r => r.exploited_count);
  const sparkSlice = (sel: (r: VulnTrendRow) => number) => trendRows.slice(-14).map(sel);
  const enoughHistory = trendRows.length >= 2;
  const enoughScans = scanRows.length >= 2;

  const sevCounts = stats?.active_risk_level_counts || {};
  const donutSegments = [
    { label: 'Critical', value: sevCounts.critical || 0, color: '#f04444' },
    { label: 'High', value: sevCounts.high || 0, color: '#f07830' },
    { label: 'Medium', value: sevCounts.medium || 0, color: '#e0b020' },
    { label: 'Low', value: sevCounts.low || 0, color: '#30c060' },
  ];

  if (!stats) return statsError ? <LoadError message={statsError} onRetry={loadStats} /> : <Loading />;

  return (
    <>
      <section className="product-intro">
        <div>
          <div className="eyebrow">Self-hosted vulnerability watchtower</div>
          <h1>bongsu</h1>
          <p>
            Named after 봉수대, the Korean signal-fire watchtower, Bongsu gathers package evidence from hosts and running containers,
            separates OS packages from code libraries, and matches them against CVSS-aware vulnerability databases.
          </p>
        </div>
        <div className="install-box">
          <div className="label">One-line agent install</div>
          <code>curl -fsSL -H "X-Install-Token: $BONGSU_INSTALL_TOKEN" "{window.location.origin}/api/install.sh" | sudo bash</code>
          {installerStatus && (
            <div style={{ marginTop: '0.75rem', display: 'flex', flexWrap: 'wrap', gap: '0.375rem' }}>
              <span className="badge" style={{ color: installerStatus.ready ? 'var(--low)' : 'var(--critical)' }}>
                installer {installerStatus.ready ? 'ready' : 'not ready'}
              </span>
              <span className="badge" style={{ color: installerStatus.agent.ready ? 'var(--low)' : 'var(--critical)' }}>
                agent {installerStatus.agent.ready ? (installerStatus.agent.version || `${Math.round((installerStatus.agent.bytes || 0) / 1024 / 1024)}MB`) : installerStatus.agent.error || 'missing'}
              </span>
              <span className="badge" style={{ color: installerStatus.trivy.ready ? 'var(--low)' : 'var(--medium)' }}>
                trivy {installerStatus.trivy.ready ? `${Math.round((installerStatus.trivy.bytes || 0) / 1024 / 1024)}MB` : installerStatus.trivy.error || 'optional'}
              </span>
            </div>
          )}
          {agentFleetWarnings.length > 0 && (
            <div style={{ marginTop: '0.5rem', color: 'var(--medium)', fontSize: '0.8125rem' }}>
              Agent fleet: {agentFleetWarnings.slice(0, 2).join('; ')}{agentFleetWarnings.length > 2 ? `; +${agentFleetWarnings.length - 2} more` : ''}
            </div>
          )}
          {agentFleetActions.length > 0 && (
            <div style={{ marginTop: '0.25rem', color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
              Action: {agentFleetActions[0]}
            </div>
          )}
        </div>
      </section>

      {/* ── Operations console ──────────────────────────────────────────────── */}
      <div className="console-head">
        <div>
          <h2 className="console-title">Operations Console</h2>
          <div className="console-sub">Fleet vulnerability posture and scan activity</div>
        </div>
        <RangeSwitcher value={trendRange} onChange={setTrendRange} />
      </div>

      <div className="kpi-grid">
        <KpiCard
          label="Total Findings"
          value={(lastTrend?.total_vulns ?? stats.active_vulnerabilities ?? stats.total_vulnerabilities).toLocaleString()}
          accent="var(--primary)"
          delta={totalDelta}
          spark={sparkSlice(r => r.total_vulns)}
          onClick={() => onOpenVulnerabilities({})}
        />
        <KpiCard
          label="Critical Risk"
          value={(stats.active_risk_level_counts?.critical || 0).toLocaleString()}
          accent="var(--critical)"
          delta={critDelta}
          spark={sparkSlice(r => r.critical_count)}
          sparkColor="#f04444"
          onClick={() => onOpenVulnerabilities({ riskLevel: 'critical' })}
        />
        <KpiCard
          label="Exploited"
          value={(lastTrend?.exploited_count || 0).toLocaleString()}
          accent="var(--high)"
          delta={exploitedDelta}
          spark={sparkSlice(r => r.exploited_count)}
          sparkColor="#f07830"
          onClick={() => onOpenVulnerabilities({ exploitedOnly: true })}
        />
        <KpiCard
          label="SLA Overdue"
          value={(stats.overdue_sla_count || 0).toLocaleString()}
          accent="var(--medium)"
          sub={<>C {stats.overdue_sla_risk_counts?.critical || 0} · H {stats.overdue_sla_risk_counts?.high || 0}</>}
          onClick={() => onOpenVulnerabilities({ overdueOnly: true })}
        />
        <KpiCard
          label="Hosts"
          value={(stats.total_hosts || 0).toLocaleString()}
          accent="var(--low)"
          sub={<>{(lastTrend?.host_count ?? stats.total_hosts) || 0} reporting</>}
          onClick={() => onOpenHosts({})}
        />
      </div>

      <div className="console-charts">
        <div className="card chart-card chart-card-wide">
          <div className="card-header">
            <h2>Findings over time</h2>
            <span className="chart-legend">
              {SEV_KEYS.map(s => (
                <span key={s.key} className="chart-legend-item"><span className="chart-legend-dot" style={{ background: s.raw }} />{s.label}</span>
              ))}
            </span>
          </div>
          <div className="chart-body">
            {chartsLoading ? <Loading /> : enoughHistory ? <StackedAreaChart rows={trendRows} /> : <EmptyState message="Not enough history yet — charts appear after 2+ days of snapshots." />}
          </div>
        </div>
        <div className="card chart-card">
          <div className="card-header"><h2>Severity distribution</h2></div>
          <div className="chart-body">
            {donutSegments.reduce((s, x) => s + x.value, 0) > 0
              ? <DonutChart segments={donutSegments} />
              : <EmptyState message="No active findings." />}
          </div>
        </div>
      </div>

      <div className="card chart-card" style={{ marginBottom: '1.5rem' }}>
        <div className="card-header">
          <h2>Scan activity ({trendRange}d)</h2>
          <span className="chart-legend">
            <span className="chart-legend-item"><span className="chart-legend-dot" style={{ background: '#7c6cf0' }} />Completed</span>
            <span className="chart-legend-item"><span className="chart-legend-dot" style={{ background: '#e0b020' }} />Degraded</span>
            <span className="chart-legend-item"><span className="chart-legend-dot" style={{ background: '#f04444' }} />Failed</span>
            <span className="chart-legend-item"><span className="chart-legend-dot chart-legend-line" />Packages</span>
          </span>
        </div>
        <div className="chart-body">
          {chartsLoading ? <Loading /> : enoughScans ? <BarSeries rows={scanRows} /> : <EmptyState message="Not enough scan activity yet." />}
        </div>
      </div>

      <div className="stats-grid">
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--primary)' }} />
          <div className="label">Total Hosts</div>
          <div className="value">{stats.total_hosts}</div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--high)' }} />
          <div className="label">Active Findings</div>
          <div className="value" style={{ color: 'var(--high)' }}>{(stats.active_vulnerabilities ?? stats.total_vulnerabilities).toLocaleString()}</div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--text-secondary)' }} />
          <div className="label">Raw Vulnerability Rows</div>
          <div className="value">{stats.total_vulnerabilities.toLocaleString()}</div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--critical)' }} />
          <div className="label">Critical Risk</div>
          <div className="value" style={{ color: 'var(--critical)' }}>{stats.active_risk_level_counts?.critical || 0}</div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--high)' }} />
          <div className="label">High Risk</div>
          <div className="value" style={{ color: 'var(--high)' }}>{stats.active_risk_level_counts?.high || 0}</div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--medium)' }} />
          <div className="label">Medium Risk</div>
          <div className="value" style={{ color: 'var(--medium)' }}>{stats.active_risk_level_counts?.medium || 0}</div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--low)' }} />
          <div className="label">Low Risk</div>
          <div className="value" style={{ color: 'var(--low)' }}>{stats.active_risk_level_counts?.low || 0}</div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--critical)' }} />
          <div className="label">SLA Overdue</div>
          <button
            type="button"
            className="value"
            onClick={() => onOpenVulnerabilities({ overdueOnly: true })}
            style={{ color: 'var(--critical)', background: 'transparent', border: 0, padding: 0, cursor: 'pointer' }}
            title="Open overdue actionable vulnerabilities"
          >
            {stats.overdue_sla_count || 0}
          </button>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            C {stats.overdue_sla_risk_counts?.critical || 0} / H {stats.overdue_sla_risk_counts?.high || 0}
          </div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--high)' }} />
          <div className="label">High Risk Overdue</div>
          <button
            type="button"
            className="value"
            onClick={() => onOpenVulnerabilities({ overdueOnly: true, riskLevel: 'high' })}
            style={{ color: 'var(--high)', background: 'transparent', border: 0, padding: 0, cursor: 'pointer' }}
            title="Open overdue high-risk vulnerabilities"
          >
            {stats.overdue_sla_risk_counts?.high || 0}
          </button>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            Medium {stats.overdue_sla_risk_counts?.medium || 0} / Low {stats.overdue_sla_risk_counts?.low || 0}
          </div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: suppressedTriageCount ? 'var(--medium)' : 'var(--low)' }} />
          <div className="label">Suppressed Findings</div>
          <button
            type="button"
            className="value"
            onClick={() => onOpenVulnerabilities({ triageStatus: 'accepted_risk' })}
            style={{ color: suppressedTriageCount ? 'var(--medium)' : 'var(--low)', background: 'transparent', border: 0, padding: 0, cursor: 'pointer' }}
            title="Open accepted-risk findings"
          >
            {suppressedTriageCount}
          </button>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            Accepted {triageActiveCounts.accepted_risk || 0} / FP {triageActiveCounts.false_positive || 0}
          </div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: triageExpiringSoonTotal ? 'var(--high)' : 'var(--low)' }} />
          <div className="label">Expiring Exceptions</div>
          <button
            type="button"
            className="value"
            onClick={() => onOpenVulnerabilities({ triageStatus: 'accepted_risk' })}
            style={{ color: triageExpiringSoonTotal ? 'var(--high)' : 'var(--low)', background: 'transparent', border: 0, padding: 0, cursor: 'pointer' }}
            title="Open accepted-risk findings with expiry dates"
          >
            {triageExpiringSoonTotal}
          </button>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            Next {stats.triage_expiring_soon_days || 14}d, accepted {triageExpiringSoonCounts.accepted_risk || 0}
          </div>
        </div>
      </div>
      <div className="stats-grid" style={{ marginTop: '1rem' }}>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--low)' }} />
          <div className="label">Agents Online</div>
          <button
            type="button"
            className="value"
            onClick={() => onOpenHosts({ agent_status: 'online' })}
            style={{ color: 'var(--low)', background: 'transparent', border: 0, padding: 0, cursor: 'pointer' }}
            title="Open online hosts"
          >
            {effectiveAgentCounts.online || 0}
          </button>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--medium)' }} />
          <div className="label">Agents Stale</div>
          <button
            type="button"
            className="value"
            onClick={() => onOpenHosts({ agent_status: 'stale' })}
            style={{ color: 'var(--medium)', background: 'transparent', border: 0, padding: 0, cursor: 'pointer' }}
            title="Open stale hosts"
          >
            {effectiveAgentCounts.stale || 0}
          </button>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--critical)' }} />
          <div className="label">Agents Offline</div>
          <button
            type="button"
            className="value"
            onClick={() => onOpenHosts({ agent_status: 'offline' })}
            style={{ color: 'var(--critical)', background: 'transparent', border: 0, padding: 0, cursor: 'pointer' }}
            title="Open offline hosts"
          >
            {effectiveAgentCounts.offline || 0}
          </button>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: outdatedAgentCount || unknownAgentVersionCount ? 'var(--medium)' : 'var(--low)' }} />
          <div className="label">Agent Version Drift</div>
          <button
            type="button"
            className="value"
            onClick={() => onOpenHosts({ agent_version_state: 'outdated' })}
            style={{ color: outdatedAgentCount ? 'var(--medium)' : 'var(--low)', background: 'transparent', border: 0, padding: 0, cursor: 'pointer' }}
            title="Open hosts running an older agent than the installer binary"
          >
            {outdatedAgentCount}
          </button>
          <div className="mono" style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>
            current {currentAgentCount} / unknown {unknownAgentVersionCount}{agentFleetStatus ? ` / ${agentFleetOutdatedPercent.toFixed(1)}% outdated` : ''}
          </div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: inventoryCoverageColor }} />
          <div className="label">SBOM Coverage</div>
          <button
            type="button"
            className="value"
            onClick={() => onOpenHosts({ inventory_status: 'none' })}
            style={{ color: inventoryCoverageColor, background: 'transparent', border: 0, padding: 0, cursor: 'pointer' }}
            title="Open hosts without completed or degraded inventory scans"
          >
            {inventoryCoveragePercent.toFixed(1)}%
          </button>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {stats.inventory_covered_hosts || 0} / {stats.total_hosts} hosts, {inventoryFreshPercent.toFixed(1)}% fresh
          </div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--primary)' }} />
          <div className="label">Tracked Packages</div>
          <div className="value">{(stats.inventory_latest_packages ?? totalPkgs).toLocaleString()}</div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--primary)' }} />
          <div className="label">CVE DB Records</div>
          <div className="value">{cveTotalRecords.toLocaleString()}</div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--primary)' }} />
          <div className="label">CVE Sources</div>
          <div className="value">{cveSources.length || '-'}</div>
        </div>
      </div>
      <div className="stats-grid" style={{ marginTop: '1rem' }}>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--low)' }} />
          <div className="label">Healthy SBOM</div>
          <button type="button" className="value" onClick={() => onOpenHosts({ inventory_status: 'healthy' })} style={{ color: 'var(--low)', background: 'transparent', border: 0, padding: 0, cursor: 'pointer' }}>{effectiveInventoryCounts.healthy || 0}</button>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--medium)' }} />
          <div className="label">Degraded SBOM</div>
          <button type="button" className="value" onClick={() => onOpenHosts({ inventory_status: 'degraded' })} style={{ color: 'var(--medium)', background: 'transparent', border: 0, padding: 0, cursor: 'pointer' }}>{effectiveInventoryCounts.degraded || 0}</button>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--medium)' }} />
          <div className="label">Stale SBOM</div>
          <button type="button" className="value" onClick={() => onOpenHosts({ inventory_status: 'stale' })} style={{ color: 'var(--medium)', background: 'transparent', border: 0, padding: 0, cursor: 'pointer' }}>{effectiveInventoryCounts.stale || 0}</button>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--high)' }} />
          <div className="label">Empty SBOM</div>
          <button type="button" className="value" onClick={() => onOpenHosts({ inventory_status: 'empty' })} style={{ color: 'var(--high)', background: 'transparent', border: 0, padding: 0, cursor: 'pointer' }}>{effectiveInventoryCounts.empty || 0}</button>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--critical)' }} />
          <div className="label">No Completed Scan</div>
          <button type="button" className="value" onClick={() => onOpenHosts({ inventory_status: 'none' })} style={{ color: 'var(--critical)', background: 'transparent', border: 0, padding: 0, cursor: 'pointer' }}>{effectiveInventoryCounts.none || 0}</button>
        </div>
      </div>
      <div className="stats-grid" style={{ marginTop: '1rem' }}>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--medium)' }} />
          <div className="label">Scan Requests Pending</div>
          <div className="value" style={{ color: 'var(--medium)' }}>{stats.scan_request_counts?.pending || 0}</div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--primary)' }} />
          <div className="label">Scan Requests Claimed</div>
          <div className="value">{stats.scan_request_counts?.claimed || 0}</div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--critical)' }} />
          <div className="label">Scan Requests Failed</div>
          <div className="value" style={{ color: 'var(--critical)' }}>{stats.scan_request_counts?.failed || 0}</div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--medium)' }} />
          <div className="label">Scan Requests Degraded</div>
          <div className="value" style={{ color: 'var(--medium)' }}>{stats.scan_request_counts?.degraded || 0}</div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--medium)' }} />
          <div className="label">Stale Pending Requests</div>
          <button
            type="button"
            className="value"
            onClick={() => onOpenScanRequests({ status: 'pending', stale: 'true' })}
            style={{ color: 'var(--medium)', background: 'transparent', border: 0, padding: 0, cursor: 'pointer' }}
            title="Open pending scan requests older than the configured timeout"
          >
            {stats.scan_request_stale_counts?.pending || 0}
          </button>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--critical)' }} />
          <div className="label">Stale Claimed Requests</div>
          <button
            type="button"
            className="value"
            onClick={() => onOpenScanRequests({ status: 'claimed', stale: 'true' })}
            style={{ color: 'var(--critical)', background: 'transparent', border: 0, padding: 0, cursor: 'pointer' }}
            title="Open claimed scan requests older than the configured timeout"
          >
            {stats.scan_request_stale_counts?.claimed || 0}
          </button>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--medium)' }} />
          <div className="label">Current DB Rescan Pending</div>
          <button
            type="button"
            className="value"
            onClick={() => openCurrentDBRescans('pending')}
            disabled={!(stats?.security_db_revision || health?.security_db_revision)}
            style={{ color: 'var(--medium)', background: 'transparent', border: 0, padding: 0, cursor: stats?.security_db_revision || health?.security_db_revision ? 'pointer' : 'default' }}
            title="Open pending security DB rescans for the current revision"
          >
            {stats.security_db_rescan_request_counts?.pending || 0}
          </button>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--primary)' }} />
          <div className="label">Current DB Rescan Claimed</div>
          <button
            type="button"
            className="value"
            onClick={() => openCurrentDBRescans('claimed')}
            disabled={!(stats?.security_db_revision || health?.security_db_revision)}
            style={{ background: 'transparent', border: 0, padding: 0, color: 'var(--text)', cursor: stats?.security_db_revision || health?.security_db_revision ? 'pointer' : 'default' }}
            title="Open claimed security DB rescans for the current revision"
          >
            {stats.security_db_rescan_request_counts?.claimed || 0}
          </button>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--medium)' }} />
          <div className="label">Current DB Stale Pending</div>
          <button
            type="button"
            className="value"
            onClick={() => openCurrentDBRescans('pending', true)}
            disabled={!(stats?.security_db_revision || health?.security_db_revision)}
            style={{ color: 'var(--medium)', background: 'transparent', border: 0, padding: 0, cursor: stats?.security_db_revision || health?.security_db_revision ? 'pointer' : 'default' }}
            title="Open stale pending security DB rescans for the current revision"
          >
            {stats.security_db_rescan_stale_counts?.pending || 0}
          </button>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--critical)' }} />
          <div className="label">Current DB Stale Claimed</div>
          <button
            type="button"
            className="value"
            onClick={() => openCurrentDBRescans('claimed', true)}
            disabled={!(stats?.security_db_revision || health?.security_db_revision)}
            style={{ color: 'var(--critical)', background: 'transparent', border: 0, padding: 0, cursor: stats?.security_db_revision || health?.security_db_revision ? 'pointer' : 'default' }}
            title="Open stale claimed security DB rescans for the current revision"
          >
            {stats.security_db_rescan_stale_counts?.claimed || 0}
          </button>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--medium)' }} />
          <div className="label">Current DB Rescan Degraded</div>
          <button
            type="button"
            className="value"
            onClick={() => openCurrentDBRescans('degraded')}
            disabled={!(stats?.security_db_revision || health?.security_db_revision)}
            style={{ color: 'var(--medium)', background: 'transparent', border: 0, padding: 0, cursor: stats?.security_db_revision || health?.security_db_revision ? 'pointer' : 'default' }}
            title="Open degraded security DB rescans for the current revision"
          >
            {stats.security_db_rescan_request_counts?.degraded || 0}
          </button>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--critical)' }} />
          <div className="label">Current DB Rescan Failed</div>
          <button
            type="button"
            className="value"
            onClick={() => openCurrentDBRescans('failed')}
            disabled={!(stats?.security_db_revision || health?.security_db_revision)}
            style={{ color: 'var(--critical)', background: 'transparent', border: 0, padding: 0, cursor: stats?.security_db_revision || health?.security_db_revision ? 'pointer' : 'default' }}
            title="Open failed security DB rescans for the current revision"
          >
            {stats.security_db_rescan_request_counts?.failed || 0}
          </button>
        </div>
        <div className="stat-card" title={rescanProgress.revision ? `Revision ${rescanProgress.revision}` : 'Current security DB revision'}>
          <div className="accent-bar" style={{ background: rescanProgressColor }} />
          <div className="label">Current DB Rescan Done</div>
          <div className="value" style={{ color: rescanProgressColor }}>{rescanCompletePercent.toFixed(1)}%</div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {(rescanProgress.terminal || 0).toLocaleString()} done, {(rescanProgress.open || 0).toLocaleString()} open of {(rescanProgress.total || 0).toLocaleString()}
          </div>
        </div>
        <div className="stat-card" title={scanCoverage.revision ? `Latest completed/degraded scan revision coverage for ${scanCoverage.revision}` : 'Latest completed/degraded scan revision coverage'}>
          <div className="accent-bar" style={{ background: scanCoverageColor }} />
          <div className="label">Current DB Scan Coverage</div>
          <div className="value" style={{ color: scanCoverageColor }}>{scanCoveragePercent.toFixed(1)}%</div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {(scanCoverage.current_hosts || 0).toLocaleString()} current, {((scanCoverage.stale_hosts || 0) + (scanCoverage.unknown_hosts || 0)).toLocaleString()} stale/unknown
          </div>
        </div>
      </div>
      <div className="db-status-bar" style={{ marginTop: '1.5rem' }}>
        <h3>Vulnerability Database</h3>
        <span className={`status-dot ${health?.trivy_db_ready ? 'ready' : 'not-ready'}`}>
          Trivy: {health?.trivy_db?.status || (health?.trivy_db_ready ? 'ok' : 'not loaded')}
        </span>
        {health?.security_db && (
          <span className={`status-dot ${securitySourcesReady ? 'ready' : 'not-ready'}`} title={health.security_db.status_detail || ''}>
            Sources: {securitySourcesLabel}{health.security_db.status === 'never' && health.security_db.effective_status === 'ok' ? ' (persisted)' : ''}
          </span>
        )}
        {health?.security_recalculation && (
          <span className={`status-dot ${health.security_recalculation.running || health.security_recalculation.pending ? 'not-ready' : 'ready'}`} title={health.security_recalculation.pending_reason || ''}>
            Recalc: {health.security_recalculation.running ? 'running' : health.security_recalculation.pending ? 'queued' : 'idle'}
          </span>
        )}
        {health?.security_db_freshness && (
          <span
            className={`status-dot ${health.security_db_freshness.status === 'ok' ? 'ready' : 'not-ready'}`}
            title={health.security_db_freshness.oldest_source ? `Oldest source: ${health.security_db_freshness.oldest_source}` : ''}
          >
            DB fresh: {health.security_db_freshness.status}
          </span>
        )}
        {health?.security_db_revision && (
          <span className="mono" title="Current merged security database revision" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            DB rev: {health.security_db_revision}
          </span>
        )}
        {lastSecurityBundleImport && (
          <span
            className={`status-dot ${lastSecurityBundleImport.status === 'ok' ? 'ready' : 'not-ready'}`}
            title={lastSecurityBundleImport.bundle_created_at ? `Bundle created ${new Date(lastSecurityBundleImport.bundle_created_at).toLocaleString()}` : lastSecurityBundleImport.message || lastSecurityBundleImport.error || ''}
          >
            Bundle import: {lastSecurityBundleImport.status === 'ok'
              ? `${lastSecurityBundleImport.bundle_source_count ?? '-'} sources${lastSecurityBundleImport.security_db_revision ? `, rev ${lastSecurityBundleImport.security_db_revision}` : ''}`
              : lastSecurityBundleImport.stage || lastSecurityBundleImport.status}
          </span>
        )}
        {(health?.trivy_db_last_update || health?.trivy_db?.last_update) && (
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Trivy updated: {new Date(health.trivy_db_last_update || health.trivy_db?.last_update || '').toLocaleString()}
          </span>
        )}
        <button
          className="update-btn"
          onClick={handleUpdate}
          disabled={updating}
          style={{ marginLeft: 'auto' }}
        >
          {updating ? 'Updating...' : 'Update Trivy DB'}
        </button>
        <button
          className="update-btn"
          onClick={handleSecurityUpdate}
          disabled={updating || !securityDbConfigured}
          title={securityDbConfigured ? 'Sync OSV/NVD/Trivy source database' : 'Set BONGSU_SECURITY_DB_SYNC_CMD on the server'}
          style={{ marginLeft: '0.5rem' }}
        >
          Sync Sources
        </button>
        <input
          className="compact-input"
          type="number"
          min="0"
          max="100"
          step="1"
          value={rematchMinQuality}
          onChange={(e) => setRematchMinQuality(e.target.value)}
          placeholder="Min matchable %"
          title="Only use CVE sources whose matchable record ratio is at least this percent"
          style={{ width: '9rem', marginLeft: '0.5rem' }}
        />
        <input
          className="compact-input"
          type="number"
          min="1"
          step="10000"
          value={rematchCandidateLimit}
          onChange={(e) => setRematchCandidateLimit(e.target.value)}
          placeholder={`Limit ${cveRematchPolicy?.candidate_limit?.toLocaleString() || 'default'}`}
          title="Maximum CVE-package candidates to evaluate for this manual rematch"
          style={{ width: '11rem', marginLeft: '0.5rem' }}
        />
        <button
          className="update-btn"
          onClick={handleRematch}
          disabled={rematching}
          style={{ marginLeft: '0.5rem' }}
        >
          {rematching ? 'Matching...' : 'Rematch CVEs'}
        </button>
        <button
          className="update-btn"
          onClick={handleCvssRecalc}
          disabled={cvssRecalcBusy}
          style={{ marginLeft: '0.5rem' }}
        >
          {cvssRecalcBusy ? 'Recalculating...' : 'Recalc CVSS'}
        </button>
        <button
          className="update-btn"
          onClick={handleSecurityRecalc}
          disabled={securityRecalcBusy}
          style={{ marginLeft: '0.5rem' }}
        >
          {securityRecalcBusy ? 'Queueing...' : 'Full Recalc'}
        </button>
        <button
          className="update-btn"
          onClick={handleAffectedIndexRebuild}
          disabled={updating}
          style={{ marginLeft: '0.5rem' }}
        >
          Rebuild Affected Index
        </button>
        <button
          className="update-btn"
          onClick={handleReferenceIndexRebuild}
          disabled={updating}
          style={{ marginLeft: '0.5rem' }}
        >
          Rebuild Reference Index
        </button>
      </div>
      <div className="stats-grid" style={{ marginTop: '1rem' }}>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: cveDbStatusColor }} />
          <div className="label">CVE DB Status</div>
          <div className="value" style={{ color: cveDbStatusColor }}>{cveDbStatus}</div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {health?.security_db_revision ? `rev ${health.security_db_revision}` : `${cveSources.length || 0} sources tracked`}
          </div>
          <div style={{ color: cveStatsCacheStatus === 'stale' ? 'var(--medium)' : 'var(--text-muted)', fontSize: '0.75rem', marginTop: '0.25rem' }}>
            stats {cveStatsCacheStatus}{cveStatsDuration !== undefined ? ` · ${cveStatsDuration}ms` : ''} · {cveStatsGeneratedAt}
          </div>
          {osvCveSource?.last_update && (
            <div style={{ color: 'var(--text-muted)', fontSize: '0.75rem', marginTop: '0.25rem' }}>
              OSV updated {new Date(osvCveSource.last_update).toLocaleString()}
            </div>
          )}
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: cveQualityColor }} />
          <div className="label">CVE DB Quality</div>
          <div className="value" style={{ color: cveQualityColor }}>{cveQualityStatus}</div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {(cveDbQuality?.warning_count || 0).toLocaleString()} warnings, {(cveDbQuality?.temporary_placeholders || 0).toLocaleString()} temp IDs
          </div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: cveDbStatusColor }} />
          <div className="label">Security Sync</div>
          <div className="value" style={{ color: cveDbStatusColor }}>{securitySyncStatus}</div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {securitySyncDetail}
          </div>
          {securitySyncNext && securitySyncStatus !== 'syncing' && (
            <div style={{ color: 'var(--text-muted)', fontSize: '0.75rem', marginTop: '0.25rem' }}>
              next {securitySyncNext}
            </div>
          )}
        </div>
        <div className="stat-card" title={latestSecuritySourceDisplay ? `Latest ${latestSecuritySourceDisplay.label} update ${new Date(latestSecuritySourceDisplay.at).toLocaleString()}` : securityDbStatus?.security_sources_error || ''}>
          <div className="accent-bar" style={{ background: securitySourceRegistryColor }} />
          <div className="label">Source Registry</div>
          <div className="value" style={{ color: securitySourceRegistryColor }}>
            {securitySourceRegistry.length ? `${securitySourceRegistryOk}/${securitySourceRegistryEnabled || securitySourceRegistry.length}` : '-'}
          </div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {securityDbStatus?.security_sources_error
              ? 'registry status unavailable'
              : securitySourceRegistry.length
                ? `${securitySourceRegistryRecords.toLocaleString()} records tracked`
                : 'waiting for source registry'}
          </div>
          {latestSecuritySourceDisplay && (
            <div style={{ color: 'var(--text-muted)', fontSize: '0.75rem', marginTop: '0.25rem' }}>
              latest {latestSecuritySourceDisplay.source} {new Date(latestSecuritySourceDisplay.at).toLocaleString()}
            </div>
          )}
          {latestSecuritySourceExport?.last_exported_at && (
            <div style={{ color: 'var(--text-muted)', fontSize: '0.75rem', marginTop: '0.25rem' }}>
              export {latestSecuritySourceExport.id} {new Date(latestSecuritySourceExport.last_exported_at).toLocaleString()}
            </div>
          )}
          {securityDbExportStale && (
            <div style={{ color: 'var(--medium)', fontSize: '0.75rem', marginTop: '0.25rem' }}>
              export {securityDbExportStatus?.status}{securityDbExportStatus?.outdated_source_count ? `, ${securityDbExportStatus.outdated_source_count} changed` : ''}
            </div>
          )}
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--primary)' }} />
          <div className="label">CVE DB Records</div>
          <div className="value">{cveTotalRecords.toLocaleString()}</div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {cveSources.length || 0} merged sources
          </div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: cveMatchableColor }} />
          <div className="label">CVE Matchable</div>
          <div className="value" style={{ color: cveMatchableColor }}>{cveTotalRecords ? cveMatchablePercent.toFixed(1) : '0.0'}%</div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {cveTotalMatchable.toLocaleString()} records with ecosystem/range data
          </div>
        </div>
        <div className="stat-card" title={oldestOsvEcosystem?.last_update ? `Oldest OSV raw source ${oldestOsvEcosystem.ecosystem} updated ${new Date(oldestOsvEcosystem.raw_last_update || oldestOsvEcosystem.last_update).toLocaleString()}${oldestOsvEcosystem.indexed_last_update ? `, index rebuilt ${new Date(oldestOsvEcosystem.indexed_last_update).toLocaleString()}` : ''}` : cveStatsMeta?.osv_ecosystems_error || ''}>
          <div className="accent-bar" style={{ background: osvEcosystemColor }} />
          <div className="label">OSV Ecosystems</div>
          <div className="value" style={{ color: osvEcosystemColor }}>{osvEcosystems.length || '-'}</div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {cveStatsMeta?.osv_ecosystems_error
              ? 'ecosystem stats delayed'
              : oldestOsvEcosystem
                ? `${osvEcosystemRows.toLocaleString()} rows, ${oldestOsvEcosystem.ecosystem} raw oldest`
                : 'waiting for OSV index stats'}
          </div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: cveAffectedIndexColor }} />
          <div className="label">Affected Index</div>
          <div className="value" style={{ color: cveAffectedIndexColor }}>{cveAffectedIndexIndexedOnly ? 'indexed' : cveAffectedIndex?.stale ? 'stale' : `${(cveAffectedIndex?.coverage_percent ?? 0).toFixed(1)}%`}</div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {cveAffectedIndexIndexedOnly
              ? `${(cveAffectedIndex?.indexed_cves || 0).toLocaleString()} indexed CVEs, ${(cveAffectedIndex?.orphans || 0).toLocaleString()} orphans`
              : `${(cveAffectedIndex?.indexed_cves || 0).toLocaleString()} / ${(cveAffectedIndex?.matchable_cves || 0).toLocaleString()} CVEs, ${(cveAffectedIndex?.orphans || 0).toLocaleString()} orphans`}
          </div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: affectedRebuildColor }} />
          <div className="label">Affected Rebuild</div>
          <div className="value" style={{ color: affectedRebuildColor }}>
            {affectedRebuildRunning ? 'running' : affectedRebuildLast?.status || 'idle'}
          </div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {affectedRebuildRunning
              ? `${Math.round((affectedRebuild?.duration_ms || 0) / 1000)}s elapsed`
              : affectedRebuildLast?.finished_at
                ? `${(affectedRebuildLast.indexed || 0).toLocaleString()} entries, ${(affectedRebuildLast.duration_ms || 0) > 0 ? `${((affectedRebuildLast.duration_ms || 0) / 1000).toFixed(1)}s` : 'duration pending'}`
                : 'no recent rebuild'}
          </div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: cveReferenceIndexColor }} />
          <div className="label">Reference Index</div>
          <div className="value" style={{ color: cveReferenceIndexColor }}>{cveReferenceIndex?.stale ? 'stale' : `${(cveReferenceIndex?.coverage_percent ?? 0).toFixed(1)}%`}</div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {(cveReferenceIndex?.count || 0).toLocaleString()} keys, {(cveReferenceIndex?.canonical_cves || 0).toLocaleString()} canonical CVEs
          </div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: referenceRebuildColor }} />
          <div className="label">Reference Rebuild</div>
          <div className="value" style={{ color: referenceRebuildColor }}>
            {referenceRebuildRunning ? 'running' : referenceRebuildLast?.status || 'idle'}
          </div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {referenceRebuildRunning
              ? `${Math.round((referenceRebuild?.duration_ms || 0) / 1000)}s elapsed`
              : referenceRebuildLast?.finished_at
                ? `${(referenceRebuildLast.indexed || 0).toLocaleString()} keys, ${(referenceRebuildLast.duration_ms || 0) > 0 ? `${((referenceRebuildLast.duration_ms || 0) / 1000).toFixed(1)}s` : 'duration pending'}`
                : 'no recent rebuild'}
          </div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: epssMergeColor }} />
          <div className="label">EPSS Merge</div>
          <div className="value" style={{ color: epssMergeColor }}>{epssMergeCoverage.toFixed(1)}%</div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {(cveEpssMerge?.non_epss_cves_with_epss || 0).toLocaleString()} / {(cveEpssMerge?.non_epss_cves || 0).toLocaleString()} local CVEs, {epssUniverseCoverage.toFixed(1)}% EPSS universe
          </div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: weakestCveSource && (weakestCveSource.matchable_percent ?? 0) < 50 ? 'var(--medium)' : 'var(--low)' }} />
          <div className="label">Weakest CVE Source</div>
          <div className="value">{weakestCveSource ? weakestCveSource.source.toUpperCase() : '-'}</div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {weakestCveSource ? `${(weakestCveSource.matchable_percent ?? 0).toFixed(1)}% matchable` : 'waiting for source stats'}
          </div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: cveRematchExcludedCount > 0 ? 'var(--medium)' : 'var(--low)' }} />
          <div className="label">Rematch Eligible Sources</div>
          <div className="value" style={{ color: cveRematchExcludedCount > 0 ? 'var(--medium)' : 'var(--low)' }}>{cveRematchEligibleCount}</div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {cveRematchExcludedCount} excluded, {cveRematchPolicyText}
          </div>
        </div>
        <div className="stat-card" title={lastRecalcTitle}>
          <div className="accent-bar" style={{ background: lastRecalcColor }} />
          <div className="label">Last Recalculation</div>
          <div className="value" style={{ color: lastRecalcColor }}>{lastRecalc?.status || '-'}</div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {lastRecalc?.finished_at
              ? lastRecalcLimited
                ? `limited at ${(lastRecalc.rematch_candidates || 0).toLocaleString()} matches, ${(lastRecalc.rematch_scanned_candidates || 0).toLocaleString()} scanned`
                : `${new Date(lastRecalc.finished_at).toLocaleString()} · ${lastRecalc.rematch_new_vulns || 0} new · ${(lastRecalc.stale_rematch_scanned || 0).toLocaleString()} cleaned${lastRecalc.rematch_eligible_sources !== undefined ? ` · ${lastRecalc.rematch_eligible_sources} src` : ''}`
              : 'waiting for audit result'}
          </div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: lastManualRematchColor }} />
          <div className="label">Manual Rematch</div>
          <div className="value" style={{ color: lastManualRematchColor }}>{lastManualRematch?.status || '-'}</div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {lastManualRematch?.finished_at
              ? `${(lastManualRematch.matched || 0).toLocaleString()} matches, ${(lastManualRematch.scanned_candidates || 0).toLocaleString()} scanned${lastManualRematch.eligible_sources !== undefined ? ` · ${lastManualRematch.eligible_sources} src` : ''}`
              : 'no manual run yet'}
          </div>
        </div>
        <div className="stat-card" title={lastAutoRescan?.error || lastAutoRescan?.reason || ''}>
          <div className="accent-bar" style={{ background: lastAutoRescanColor }} />
          <div className="label">Auto Rescan Queue</div>
          <div className="value" style={{ color: lastAutoRescanColor }}>{lastAutoRescan?.status || '-'}</div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {lastAutoRescan?.finished_at
              ? `${(lastAutoRescan.queued || 0).toLocaleString()} queued, ${(lastAutoRescan.already_pending || 0).toLocaleString()} pending of ${(lastAutoRescan.eligible || 0).toLocaleString()} hosts`
              : 'waiting for DB update'}
          </div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: cveFreshnessColor }} />
          <div className="label">CVE Source Alerts</div>
          <div className="value" style={{ color: cveFreshnessColor }}>{cveSourceAlertCount}</div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {missingCveSources.length ? `missing ${missingCveSources.join(', ')}` : health?.security_db_freshness?.oldest_source ? `${health.security_db_freshness.oldest_source} oldest, ${oldestCveAgeDays.toFixed(1)}d` : 'freshness pending'}
          </div>
        </div>
      </div>
      {health?.trivy_db?.last_error && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: 'var(--critical)' }}>Trivy DB: {health.trivy_db.last_error}</div>}
      {health?.security_db?.last_error && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: 'var(--critical)' }}>Security sources: {health.security_db.last_error}</div>}
      {health?.security_db_revision_error && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: 'var(--critical)' }}>Security DB revision: {health.security_db_revision_error}</div>}
      {health?.security_db_freshness?.error && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: 'var(--critical)' }}>Security DB freshness: {health.security_db_freshness.error}</div>}
      {securityDbWarnings.length > 0 && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: securityDbStatus?.status === 'degraded' ? 'var(--critical)' : 'var(--medium)' }}>Security DB: {securityDbWarnings.slice(0, 3).join('; ')}{securityDbWarnings.length > 3 ? `; +${securityDbWarnings.length - 3} more` : ''}</div>}
      {securityDbActions.length > 0 && <div style={{ marginTop: '0.25rem', fontSize: '0.8125rem', color: 'var(--text-muted)' }}>Action: {securityDbActions.slice(0, 2).join('; ')}</div>}
      {securityDbStatus?.security_sources_error && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: 'var(--critical)' }}>Security source registry: {securityDbStatus.security_sources_error}</div>}
      {securitySourceRegistryBroken && !securityDbStatus?.security_sources_error && (
        <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: 'var(--medium)' }}>
          Source registry attention: {securitySourceRegistry.filter(s => s.enabled && (s.last_status !== 'ok' || (s.record_count || 0) === 0 || s.last_error)).slice(0, 5).map(s => `${s.id} ${s.last_status}${s.record_count ? ` (${s.record_count.toLocaleString()})` : ''}`).join(', ')}
        </div>
      )}
      {cveQualityWarnings.length > 0 && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: cveQualityStatus === 'degraded' ? 'var(--critical)' : 'var(--medium)' }}>CVE DB quality: {cveQualityWarnings.slice(0, 3).join(', ')}{cveQualityWarnings.length > 3 ? `, +${cveQualityWarnings.length - 3} more` : ''}</div>}
      {cveStatsMeta?.osv_ecosystems_error && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: 'var(--medium)' }}>OSV ecosystem stats: {cveStatsMeta.osv_ecosystems_error}</div>}
      {cveAffectedIndex?.detail_error && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: 'var(--medium)' }}>Affected index detailed stats delayed; showing indexed-only health snapshot.</div>}
      {cveDbQuality?.affected_index_detail_error && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: 'var(--medium)' }}>Affected index quality: {cveDbQuality.affected_index_detail_error}</div>}
      {cveDbQuality?.reference_index_detail_error && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: 'var(--medium)' }}>Reference index quality: {cveDbQuality.reference_index_detail_error}</div>}
      {cveEpssMerge && cveEpssMerge.epss_cves > 0 && cveEpssMerge.enriched_records === 0 && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: 'var(--high)' }}>EPSS source is loaded but no non-EPSS CVE rows are enriched.</div>}
      {cveAffectedIndex?.stale && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: 'var(--high)' }}>Affected index is older than matchable CVE rows. Rebuild the index before trusting rematch coverage.</div>}
      {(cveAffectedIndex?.missing_matchable_sources?.length || 0) > 0 && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: 'var(--high)' }}>Affected index missing matchable sources: {cveAffectedIndex?.missing_matchable_sources?.join(', ')}</div>}
      {(cveAffectedIndex?.orphans || 0) > 0 && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: 'var(--high)' }}>Affected index orphan rows: {(cveAffectedIndex?.orphans || 0).toLocaleString()}</div>}
      {lastRecalcLimited && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: 'var(--high)' }}>CVE rematch hit candidate limit: {(lastRecalc?.rematch_candidates || 0).toLocaleString()} / {(lastRecalc?.rematch_candidate_limit || 0).toLocaleString()} matches, {(lastRecalc?.rematch_scanned_candidates || 0).toLocaleString()} raw candidates scanned</div>}
      {lastManualRematchLimited && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: 'var(--high)' }}>Manual CVE rematch hit candidate limit: {(lastManualRematch?.matched || 0).toLocaleString()} / {(lastManualRematch?.candidate_limit || 0).toLocaleString()} matches, {(lastManualRematch?.scanned_candidates || 0).toLocaleString()} raw candidates scanned</div>}
      {missingCveSources.length > 0 && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: 'var(--critical)' }}>Missing CVE sources: {missingCveSources.join(', ')}</div>}
      {health?.security_db_freshness?.oldest_last_update && (
        <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: 'var(--text-muted)' }}>
          Oldest CVE source: {health.security_db_freshness.oldest_source || '-'} updated {new Date(health.security_db_freshness.oldest_last_update).toLocaleString()}
        </div>
      )}
      {updateMsg && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: updateMsg.includes('fail') ? 'var(--critical)' : 'var(--low)' }}>{updateMsg}</div>}
      {rematchMsg && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: rematchMsg.includes('fail') ? 'var(--critical)' : '#4ade80' }}>{rematchMsg}</div>}
      {cvssRecalcMsg && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: cvssRecalcMsg.includes('fail') ? 'var(--critical)' : '#4ade80' }}>{cvssRecalcMsg}</div>}
      {securityRecalcMsg && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: securityRecalcMsg.includes('fail') ? 'var(--critical)' : '#4ade80' }}>{securityRecalcMsg}</div>}
      <div className="db-status-bar" style={{ marginTop: '1rem' }}>
        <h3>Airgap Security Bundle</h3>
        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Export outside, import inside air-gapped environments</span>
        <label style={{ display: 'flex', alignItems: 'center', gap: 4, marginLeft: 'auto', fontSize: '0.75rem', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
          <input type="checkbox" checked={securityBundleIncludeTrivy} onChange={(e) => setSecurityBundleIncludeTrivy(e.target.checked)} />
          Include Trivy DB
        </label>
        <button className="update-btn" onClick={handleSecurityBundleExport} disabled={securityBundleBusy} style={{ marginLeft: '0.5rem' }}>
          Export Bundle
        </button>
        <label className="update-btn" style={{ marginLeft: '0.5rem', cursor: securityBundleBusy ? 'default' : 'pointer', opacity: securityBundleBusy ? 0.6 : 1 }}>
          Import Bundle
          <input
            type="file"
            accept=".tar.gz,.tgz,application/gzip"
            disabled={securityBundleBusy}
            onChange={(e) => {
              const file = e.target.files?.[0];
              e.currentTarget.value = '';
              handleSecurityBundleImport(file);
            }}
            style={{ display: 'none' }}
          />
        </label>
      </div>
      {securityBundleMsg && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: securityBundleMsg.includes('failed') ? 'var(--critical)' : 'var(--text-muted)' }}>{securityBundleMsg}</div>}
      <div className="db-status-bar" style={{ marginTop: '1rem' }}>
        <h3>Operational Retention</h3>
        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Defaults: scans 180d, requests 90d, audit 365d</span>
        <button className="update-btn" onClick={() => handleRetentionPrune(true)} disabled={retentionBusy} style={{ marginLeft: 'auto' }}>Dry Run</button>
        <button
          className="delete-btn"
          onClick={() => { if (confirm('Prune old scans, completed scan requests, and audit logs using server retention defaults?')) handleRetentionPrune(false); }}
          disabled={retentionBusy}
        >
          Prune
        </button>
      </div>
      {retentionMsg && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: retentionMsg.includes('failed') ? 'var(--critical)' : 'var(--text-muted)' }}>{retentionMsg}</div>}
      {(ownerSummary.length > 0 || teamSummary.length > 0 || environmentSummary.length > 0 || criticalitySummary.length > 0) && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '1rem', marginTop: '1rem' }}>
          <SummaryTable title="Owner Remediation Queue" groupBy="owner" rows={ownerSummary} onOpenVulnerabilities={onOpenVulnerabilities} />
          <SummaryTable title="Team Remediation Queue" groupBy="team" rows={teamSummary} onOpenVulnerabilities={onOpenVulnerabilities} />
          <SummaryTable title="Environment Risk Queue" groupBy="environment" rows={environmentSummary} onOpenVulnerabilities={onOpenVulnerabilities} />
          <SummaryTable title="Criticality Risk Queue" groupBy="criticality" rows={criticalitySummary} onOpenVulnerabilities={onOpenVulnerabilities} />
        </div>
      )}
      {cveSources.length > 0 && (
        <div className="card" style={{ marginTop: '1rem' }}>
          <div className="card-header"><h2>CVE Database Sources</h2></div>
          <table>
            <thead><tr><th>Source</th><th>Records</th><th>Matchable</th><th>Matchable %</th><th>Rematch</th><th>Ecosystem</th><th>Fixed</th><th>Ranges</th><th>CVSS</th><th>Last Update</th></tr></thead>
            <tbody>
              {cveSources.map(s => {
                const belowQuality = sourceBelowQuality(s);
                const excludedByPolicy = s.rematch_eligible === false;
                const staleSource = staleCveSourceByName.get(s.source.toLowerCase());
                const rowWarn = belowQuality || excludedByPolicy || staleSource;
                return (
                  <tr key={s.source} style={rowWarn ? { background: staleSource ? 'rgba(248, 113, 113, 0.08)' : 'rgba(224, 176, 32, 0.08)' } : undefined}>
                    <td>
                      <span style={{ fontWeight: 600 }}>{s.source.toUpperCase()}</span>
                      {staleSource && <span className="badge" title={staleSource.last_update ? `last update ${new Date(staleSource.last_update).toLocaleString()}` : 'missing last update'} style={{ marginLeft: 6, color: 'var(--critical)' }}>stale</span>}
                      {belowQuality && <span className="badge" style={{ marginLeft: 6, color: 'var(--medium)' }}>below gate</span>}
                      {excludedByPolicy && <span className="badge" title={s.rematch_exclusion || ''} style={{ marginLeft: 6, color: 'var(--medium)' }}>policy excluded</span>}
                    </td>
                    <td className="mono">{s.count.toLocaleString()}</td>
                    <td className="mono">{(s.matchable || 0).toLocaleString()}</td>
                    <td className="mono" style={{ color: belowQuality || excludedByPolicy ? 'var(--medium)' : undefined }}>{(s.matchable_percent ?? 0).toFixed(1)}%</td>
                    <td>
                      <span className="badge" title={s.rematch_exclusion || ''} style={{ color: excludedByPolicy ? 'var(--medium)' : 'var(--low)' }}>
                        {excludedByPolicy ? 'excluded' : 'eligible'}
                      </span>
                    </td>
                    <td className="mono">{(s.with_ecosystem || 0).toLocaleString()}</td>
                    <td className="mono">{(s.with_fixed || 0).toLocaleString()}</td>
                    <td className="mono">{(s.with_ranges || 0).toLocaleString()}</td>
                    <td className="mono">{(s.with_cvss || 0).toLocaleString()}</td>
                    <td className="mono" style={{ fontSize: '0.8125rem', color: staleSource ? 'var(--critical)' : undefined }}>
                      {s.last_update ? new Date(s.last_update).toLocaleString() : '-'}
                      {staleSource?.age_seconds !== undefined && <div style={{ fontSize: '0.75rem' }}>{formatAge(staleSource.age_seconds)} old</div>}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      <div className="info-card" style={{ marginTop: '1.5rem' }}>
        <div className="info-header">
          <div className="info-icon">🏔</div>
          <div>
            <h3>Bongsu</h3>
            <p>
              Bongsu is named after a Korean signal-fire watchtower. It centralizes package evidence from hosts and containers,
              then matches that inventory against CVSS-aware vulnerability databases.
            </p>
            <p>
              Agents collect package inventories periodically. The server stores host, container, image, and package context so operators
              can inspect findings by host, package, container, and vulnerability.
            </p>
            <div className="info-links">
              <span><strong>Hosts</strong> - registered systems and SBOM state</span>
              <span><strong>Packages</strong> - package search and CVSS ordering</span>
              <span><strong>Vulnerabilities</strong> - CVE detail, triage, and filtering</span>
            </div>
          </div>
        </div>
      </div>
      <div style={{ textAlign: 'right', marginTop: '1rem' }}>
        <a href="https://github.com/ziozzang/bongsu" target="_blank" rel="noopener" style={{ color: 'var(--text-muted)', fontSize: '0.8125rem', textDecoration: 'none' }}>
          github.com/ziozzang/bongsu ↗
        </a>
      </div>
    </>
  );
}

function SummaryTable({ title, groupBy, rows, onOpenVulnerabilities }: { title: string; groupBy: 'owner' | 'team' | 'environment' | 'criticality'; rows: VulnSummaryRow[]; onOpenVulnerabilities: (filters: VulnerabilityFilters) => void }) {
  const topRows = rows.slice(0, 8);
  const openRow = (row: VulnSummaryRow, extra?: VulnerabilityFilters) => {
    onOpenVulnerabilities({ [groupBy]: row.group, ...extra });
  };
  return (
    <div className="card">
      <div className="card-header"><h2>{title}</h2></div>
      <table>
        <thead>
          <tr><th>Group</th><th>Total</th><th>Critical Risk</th><th>High Risk</th><th>Overdue</th></tr>
        </thead>
        <tbody>
          {topRows.map(row => (
            <tr key={row.group}>
              <td><button type="button" className="link-button" onClick={() => openRow(row)}>{row.group}</button></td>
              <td className="mono"><button type="button" className="link-button mono" onClick={() => openRow(row)}>{row.total.toLocaleString()}</button></td>
              <td className="mono" style={{ color: 'var(--critical)', fontWeight: row.risk?.critical ? 700 : 400 }}><button type="button" className="link-button mono" onClick={() => openRow(row, { riskLevel: 'critical' })}>{row.risk?.critical || 0}</button></td>
              <td className="mono" style={{ color: 'var(--high)', fontWeight: row.risk?.high ? 700 : 400 }}><button type="button" className="link-button mono" onClick={() => openRow(row, { riskLevel: 'high' })}>{row.risk?.high || 0}</button></td>
              <td className="mono" style={{ color: row.overdue ? 'var(--critical)' : 'var(--text-muted)', fontWeight: row.overdue ? 700 : 400 }}><button type="button" className="link-button mono" onClick={() => openRow(row, { overdueOnly: true })}>{row.overdue || 0}</button></td>
            </tr>
          ))}
          {topRows.length === 0 && <tr className="empty-row"><td colSpan={5}>No findings</td></tr>}
        </tbody>
      </table>
    </div>
  );
}
