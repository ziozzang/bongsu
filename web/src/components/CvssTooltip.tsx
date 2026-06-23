import { useState } from 'react';
import { api, type Vuln } from '../api';
import { severityColor } from '../lib/severity';
import { verCmp } from '../lib/version';

export function CvssTooltip({ pkgId, score, onSelectVuln }: { pkgId: string; score: number | undefined; onSelectVuln?: (v: Vuln) => void }) {
  const s = score ?? 0;
  const [vulns, setVulns] = useState<Vuln[] | null>(null);
  const [pos, setPos] = useState<{ x: number; y: number } | null>(null);
  const [show, setShow] = useState(false);
  const timerRef = useState<ReturnType<typeof setTimeout> | null>(null);

  const handleEnter = (e: React.MouseEvent) => {
    const rect = (e.target as HTMLElement).getBoundingClientRect();
    setPos({ x: rect.left, y: rect.bottom + 4 });
    setShow(true);
    if (!vulns) {
      api.packageVulns(pkgId).then(setVulns).catch(() => setVulns([]));
    }
  };

  const handleLeave = () => {
    setShow(false);
  };

  const sevColor = severityColor;

  if (s <= 0) return <span className="mono">-</span>;

  return (
    <>
      <span className="mono" style={{ color: s >= 9 ? 'var(--critical)' : s >= 7 ? 'var(--high)' : s >= 4 ? 'var(--medium)' : 'var(--low)', cursor: 'help' }}
        onMouseEnter={handleEnter} onMouseLeave={handleLeave}>
        {s.toFixed(1)}
      </span>
      {show && pos && (
        <div style={{
          position: 'fixed', left: Math.min(pos.x, window.innerWidth - 340), top: pos.y,
          background: '#1e2030', border: '1px solid var(--border)', borderRadius: 8,
          padding: '0.75rem', minWidth: 280, maxWidth: 360, zIndex: 1000,
          boxShadow: '0 8px 24px rgba(0,0,0,0.4)', fontSize: '0.8125rem',
          maxHeight: 320, overflowY: 'auto',
        }} onMouseEnter={() => setShow(true)} onMouseLeave={handleLeave}>
          {!vulns ? <span style={{ color: 'var(--text-muted)' }}>Loading...</span> :
           vulns.length === 0 ? <span style={{ color: 'var(--text-muted)' }}>No details</span> :
           vulns.map(v => (
             <div key={v.id} style={{ padding: '0.375rem 0', borderBottom: '1px solid var(--border)' }}>
               <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                 <span className="mono" style={{ fontSize: '0.75rem' }}>
                   {onSelectVuln
                     ? <a href="#" onClick={(e) => { e.preventDefault(); e.stopPropagation(); onSelectVuln(v); setShow(false); }} style={{ color: 'var(--primary)' }}>{v.vulnerability_id}</a>
                     : v.primary_url ? <a href={v.primary_url} target="_blank" rel="noopener" style={{ color: 'var(--primary)' }}>{v.vulnerability_id}</a> : v.vulnerability_id}
                 </span>
                 <span style={{ color: sevColor(v.severity), fontWeight: 600, fontSize: '0.75rem' }}>{v.severity} {v.cvss_score > 0 ? v.cvss_score.toFixed(1) : ''}</span>
               </div>
               {v.title && <div style={{ color: 'var(--text-muted)', fontSize: '0.75rem', marginTop: 2 }}>{v.title}</div>}
               {(v.advisory_evidence || []).length > 0 && <div className="mono" style={{ color: '#22c55e', fontSize: '0.6875rem', marginTop: 2 }}>Advisory: {(v.advisory_evidence || []).map(e => e.source).join(', ')}</div>}
               <div style={{ color: 'var(--text-muted)', fontSize: '0.6875rem', marginTop: 2 }}>
                 {v.installed_version}
                 {v.fixed_version && v.installed_version
                   ? (() => {
                       const cmp = verCmp(v.installed_version, v.fixed_version);
                       const sym = cmp >= 0 ? '≥' : '<';
                       const color = cmp >= 0 ? '#22c55e' : 'var(--critical)';
                       return <span style={{ margin: '0 4px', color, fontWeight: 700 }}>{sym}</span>;
                     })()
                   : v.fixed_version ? ' → ' : ''}
                 {v.fixed_version || ''}
                 {v.fixed_version && v.installed_version && verCmp(v.installed_version, v.fixed_version) >= 0 &&
                   <span style={{ color: '#22c55e', fontWeight: 600, marginLeft: 4, fontSize: '0.625rem', background: 'rgba(34,197,94,0.15)', padding: '1px 4px', borderRadius: 3 }}>FIXED</span>}
               </div>
             </div>
           ))
          }
        </div>
      )}
    </>
  );
}
