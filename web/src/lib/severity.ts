// Severity/risk/AI label + tone + color helpers, and the SeverityTone type.
// Pure functions extracted verbatim from App.tsx (UI decomposition).
import type { VulnAnalysis } from '../api';

export type SeverityTone = 'critical' | 'high' | 'medium' | 'low' | 'unknown' | 'neutral' | 'accent';

export function findingSourceLabel(source?: string): string {
  switch (source || 'scanner') {
    case 'scanner': return 'Scanner';
    case 'cve-db': return 'CVE DB';
    default: return source || 'Scanner';
  }
}

export function riskLevelLabel(level?: string): string {
  return level ? level.replace('_', ' ') : 'low';
}

export function riskLevelColor(level?: string): string {
  switch ((level || '').toLowerCase()) {
    case 'critical': return 'var(--critical)';
    case 'high': return 'var(--high)';
    case 'medium': return 'var(--medium)';
    default: return 'var(--text-muted)';
  }
}

// recommendedActionLabel / recommendedActionTone map an LLM recommended_action
// to a human label and a Badge tone for the AI assessment surfaces.
export function recommendedActionLabel(action?: string): string {
  switch ((action || '').toLowerCase()) {
    case 'false_positive': return 'False positive';
    case 'accept_risk': return 'Accept risk';
    case 'remediate': return 'Remediate';
    case 'investigate': return 'Investigate';
    case 'monitor': return 'Monitor';
    default: return action ? action.replace(/_/g, ' ') : 'Unknown';
  }
}
export function recommendedActionTone(action?: string): SeverityTone {
  switch ((action || '').toLowerCase()) {
    case 'remediate': return 'high';
    case 'investigate': return 'medium';
    case 'false_positive': return 'low';
    case 'accept_risk': return 'accent';
    default: return 'neutral';
  }
}
// riskLevelTone maps an LLM risk_level string to a Badge tone.
export function riskLevelTone(level?: string): SeverityTone {
  switch ((level || '').toLowerCase()) {
    case 'critical': return 'critical';
    case 'high': return 'high';
    case 'medium': return 'medium';
    case 'low': return 'low';
    default: return 'unknown';
  }
}
// isVulnAnalysis is the type guard for api.vulnAnalysis's union return.
export function isVulnAnalysis(r: VulnAnalysis | { analysis: null }): r is VulnAnalysis {
  return 'recommended_action' in r;
}

// aiPolicyModeTone / aiPolicyModeBlurb describe the AI action policy mode for
// the AI Triage and AI Approvals surfaces.
export function aiPolicyModeTone(mode?: string): SeverityTone {
  switch ((mode || '').toLowerCase()) {
    case 'auto': return 'medium';
    case 'assisted': return 'accent';
    case 'suggest': return 'low';
    default: return 'neutral';
  }
}
export function aiPolicyModeBlurb(mode?: string): string {
  switch ((mode || '').toLowerCase()) {
    case 'off': return 'AI actions are disabled — nothing is applied or queued.';
    case 'suggest': return 'AI proposes actions only; nothing is auto-applied or queued for approval.';
    case 'assisted': return 'Low-risk actions are auto-applied; the rest are queued for approval.';
    case 'auto': return 'All confident actions are auto-applied without approval.';
    default: return 'Current AI action policy.';
  }
}
// aiApprovalStatusTone maps an approval status to its Badge tone.
export function aiApprovalStatusTone(status?: string): SeverityTone {
  switch ((status || '').toLowerCase()) {
    case 'pending': return 'medium';
    case 'approved': return 'low';
    case 'rejected': return 'neutral';
    default: return 'neutral';
  }
}
// aiActionLabel renders an action_type as a compact human label.
export function aiActionLabel(action?: string): string {
  return action || 'unknown';
}
// aiProposedSummary renders the key fields of a proposed action compactly,
// reading the Record<string, unknown> defensively.
export function aiProposedSummary(actionType: string, proposed: Record<string, unknown>): string {
  if (actionType === 'triage.suppress') {
    const status = proposed.triage_status;
    if (typeof status === 'string' && status) return `→ ${status}`;
  }
  try {
    const s = JSON.stringify(proposed);
    return s.length > 80 ? `${s.slice(0, 80)}…` : s;
  } catch {
    return '-';
  }
}
// strField reads a string field from a Record<string, unknown> defensively.
export function strField(rec: Record<string, unknown>, key: string): string {
  const v = rec[key];
  return typeof v === 'string' ? v : v != null ? String(v) : '';
}

export const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const;

export function severityColor(sev?: string): string {
  switch ((sev || '').toUpperCase()) {
    case 'CRITICAL': return 'var(--critical)';
    case 'HIGH': return 'var(--high)';
    case 'MEDIUM': return 'var(--medium)';
    case 'LOW': return 'var(--low)';
    default: return 'var(--unknown)';
  }
}
