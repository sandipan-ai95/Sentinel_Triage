import { useEffect, useMemo, useState } from 'react';
import './App.css';

type Alert = {
  id: string;
  title: string;
  subtitle: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  triageSeverity?: 'critical' | 'high' | 'medium' | 'low';
  source: string;
  age: string;
  recommendation: string;
  confidence: number;
  summary: string;
  probabilities: Record<string, number>;
  vulnerability?: Record<string, string>;
};

const alerts: Alert[] = [
  {
    id: 'ALT-8421', title: 'Repeated privileged sign-in failures', subtitle: 'lab-ad-01 · demo-admin · 10.42.8.17', severity: 'critical', source: 'Identity', age: '8s', recommendation: 'High-priority review', confidence: 0.94, summary: 'Thirty-four failed authentication events on a privileged lab account from one source IP in eight minutes.', probabilities: { needs_immediate_escalation: 0.94, likely_false_positive: 0.04, needs_more_context: 0.22, likely_requires_human_review: 0.99 },
  },
  {
    id: 'ALT-8420', title: 'Unusual DNS request burst', subtitle: 'lab-web-02 · resolver · 10.42.8.44', severity: 'high', source: 'Network', age: '1m', recommendation: 'Request enrichment', confidence: 0.72, summary: 'Repeated DNS queries to domains not commonly used by the host.', probabilities: { needs_immediate_escalation: 0.58, likely_false_positive: 0.12, needs_more_context: 0.68, likely_requires_human_review: 0.84 },
  },
  { id: 'ALT-8418', title: 'New package installed', subtitle: 'ci-runner-03 · build-agent', severity: 'low', source: 'Endpoint', age: '3m', recommendation: 'Likely benign', confidence: 0.88, summary: 'A package was installed during the expected build window on a CI runner.', probabilities: { needs_immediate_escalation: 0.1, likely_false_positive: 0.3, needs_more_context: 0.49, likely_requires_human_review: 0.55 } },
  { id: 'ALT-8415', title: 'Endpoint policy violation', subtitle: 'lab-fin-01 · finance-demo', severity: 'high', source: 'Policy', age: '9m', recommendation: 'High-priority review', confidence: 0.81, summary: 'A privileged export operation occurred outside the approved maintenance window.', probabilities: { needs_immediate_escalation: 0.72, likely_false_positive: 0.07, needs_more_context: 0.31, likely_requires_human_review: 0.91 } },
];

const navigation = [
  { label: 'Alert queue', count: '12', active: true }, { label: 'Incidents', count: '4' }, { label: 'Investigation' },
  { label: 'Policy performance', section: 'INSIGHTS' }, { label: 'Model shadow mode' }, { label: 'Data sources', section: 'PLATFORM' }, { label: 'Audit log' },
];

const API_URL = import.meta.env.VITE_API_URL ?? 'http://localhost:8000';

export default function App() {
  const [liveAlerts, setLiveAlerts] = useState(alerts);
  const [dataState, setDataState] = useState<'loading' | 'live' | 'demo'>('loading');
  const [activeView, setActiveView] = useState('Alert queue');
  const [sortBy, setSortBy] = useState('recommendation');
  const [selectedId, setSelectedId] = useState(alerts[0].id);
  const [decision, setDecision] = useState('');
  const [queueMetrics, setQueueMetrics] = useState({ newAlerts: 0, needsAttention: 0, averageReward: 0, analystDecisions: 0, trainingExamples: 0 });

  useEffect(() => {
    let active = true;
    const loadAlerts = () => fetch(`${API_URL}/api/alerts?limit=50`)
      .then((response) => {
        if (!response.ok) throw new Error('Alert API unavailable');
        return response.json();
      })
      .then((records) => {
        if (!active) return;
        const mapped: Alert[] = records.map((record: Record<string, unknown>) => ({
          id: String(record.id),
          title: String((record.vulnerability as Record<string, unknown> | undefined)?.vulnerabilityName ?? record.rule_name),
          subtitle: formatSubtitle(record),
          severity: triageSeverity(String(record.recommendation)),
          triageSeverity: triageSeverity(String(record.recommendation)),
          source: String(record.source),
          age: formatAge(String(record.timestamp)),
          recommendation: formatRecommendation(String(record.effective_recommendation ?? record.recommendation)),
          confidence: Number(record.confidence ?? 0),
          summary: String(record.raw_summary),
          probabilities: (record.probabilities ?? {}) as Record<string, number>,
          vulnerability: (record.vulnerability ?? {}) as Record<string, string>,
        }));
        if (mapped.length) {
          setLiveAlerts(mapped);
          setSelectedId((current) => mapped.some((alert) => alert.id === current) ? current : mapped[0].id);
          setDataState('live');
        } else {
          setDataState('demo');
        }
      })
      .catch(() => active && setDataState('demo'));
    const loadMetrics = () => fetch(`${API_URL}/api/metrics`)
      .then((response) => response.json())
      .then((metrics) => active && setQueueMetrics({ newAlerts: metrics.new_alerts ?? 0, needsAttention: metrics.needs_attention ?? 0, averageReward: metrics.average_reward ?? 0, analystDecisions: metrics.analyst_decisions ?? 0, trainingExamples: metrics.training_examples ?? 0 }))
      .catch(() => undefined);
    const refresh = () => { loadAlerts(); loadMetrics(); };
    refresh();
    const refreshTimer = window.setInterval(refresh, 15000);
    return () => { active = false; window.clearInterval(refreshTimer); };
  }, []);

  const sortedAlerts = useMemo(() => {
    const items = [...liveAlerts];
    return items.sort((a, b) => {
      if (sortBy === 'confidence') return b.confidence - a.confidence;
      if (sortBy === 'severity') return ['critical', 'high', 'medium', 'low'].indexOf(b.severity) - ['critical', 'high', 'medium', 'low'].indexOf(a.severity);
      const priority: Record<string, number> = { 'High-priority review': 4, 'Request enrichment': 3, 'Standard review': 2, 'Likely benign': 1 };
      return (priority[b.recommendation] ?? 0) - (priority[a.recommendation] ?? 0) || b.confidence - a.confidence;
    });
  }, [liveAlerts, sortBy]);

  const selectedAlert = liveAlerts.find((alert) => alert.id === selectedId) ?? liveAlerts[0];
  const submitDecision = async (decisionValue: string) => {
    const response = await fetch(`${API_URL}/api/alerts/${selectedAlert.id}/decisions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ actor: 'analyst.local', decision: decisionValue }),
    });
    if (!response.ok) throw new Error('Decision could not be recorded');
    const result = await response.json();
    if (decisionValue === 'escalate_incident') {
      setLiveAlerts((current) => current.map((alert) => alert.id === selectedAlert.id ? {
        ...alert,
        recommendation: 'High-priority review',
        severity: 'critical',
        triageSeverity: 'critical',
        probabilities: { ...alert.probabilities, needs_immediate_escalation: 1, likely_requires_human_review: 1 },
      } : alert));
    }
    setDecision(`${decisionValue.replace(/_/g, ' ')} recorded · reward ${result.reward > 0 ? '+1' : '-1'}`);
  };

  return (
    <div className="app-shell">
      <header className="topbar"><div className="brand"><span className="brand-mark">⌁</span><strong>Sentinel Triage</strong></div><div className="health"><span className="status-dot" /> All collectors healthy <span className="separator">·</span> Last event 8 sec ago</div></header>
      <div className="workspace">
        <aside className="sidebar"><nav aria-label="Primary navigation">{navigation.map((item) => <div key={item.label}>{item.section && <div className="nav-section">{item.section}</div>}<button className={`nav-item ${activeView === item.label ? 'active' : ''}`} type="button" onClick={() => setActiveView(item.label)}><span>{item.label}</span>{navCount(item.label, item.count, queueMetrics, liveAlerts.length)}</button></div>)}</nav></aside>
        <main className="main-content">
          {activeView === 'Alert queue' ? <>
          <div className="page-heading"><div><h1>Alert queue</h1><p>Human review required for every recommendation</p></div><div className={`live-label ${dataState === 'demo' ? 'demo-label' : ''}`}><span className="status-dot" /> {dataState === 'loading' ? 'Connecting to alert API' : dataState === 'live' ? 'Live ingestion' : 'Demo data · API unavailable'}</div></div>
          <section className="metrics" aria-label="Queue metrics"><Metric label="New alerts" value={String(queueMetrics.newAlerts)} note={`${queueMetrics.needsAttention} need attention`} /><Metric label="Median triage" value="Live" note="From current queue" /><Metric label="Analyst overrides" value={String(queueMetrics.needsAttention)} note="Human feedback queue" /><Metric label="Shadow reward" value={queueMetrics.averageReward >= 0 ? `+${queueMetrics.averageReward.toFixed(1)}` : queueMetrics.averageReward.toFixed(1)} note="Contextual bandit" /></section>
          <section className="content-grid">
            <div className="panel queue-panel"><div className="panel-header"><h2>Prioritized alerts <span>by Jev triage priority</span></h2><select aria-label="Sort alerts" value={sortBy} onChange={(event) => setSortBy(event.target.value)}><option value="recommendation">Triage priority</option><option value="severity">Source severity</option><option value="confidence">Confidence</option></select></div><div className="alert-list">{sortedAlerts.map((alert) => <button type="button" className={`alert-row ${selectedId === alert.id ? 'selected' : ''}`} key={alert.id} onClick={() => { setSelectedId(alert.id); setDecision(''); }}><span className={`severity-dot ${alert.triageSeverity ?? alert.severity}`} /><span className="alert-copy"><strong>{alert.title}</strong><small>{alert.id} · {alert.subtitle} · source {alert.severity}</small></span><time>{alert.age}</time></button>)}</div></div>
            <div className="panel review-panel"><div className="panel-header"><h2>Analyst review</h2><span>Recommendation only</span></div><div className="review-body"><div className="review-title"><div><h2>{selectedAlert.title}</h2><small>{selectedAlert.id} · {selectedAlert.source} · {selectedAlert.subtitle}</small></div><span className={`severity-pill ${selectedAlert.severity}`}><i /> {selectedAlert.severity}</span></div><p className="summary">{selectedAlert.summary}</p><div className="eyebrow">JEV DECISION SIGNALS</div><div className="signals"><Signal label="Immediate escalation" value={percent(selectedAlert.probabilities.needs_immediate_escalation)} fill={(selectedAlert.probabilities.needs_immediate_escalation ?? 0) * 100} tone="pink" /><Signal label="Likely false positive" value={percent(selectedAlert.probabilities.likely_false_positive)} fill={(selectedAlert.probabilities.likely_false_positive ?? 0) * 100} tone="green" /><Signal label="Needs more context" value={percent(selectedAlert.probabilities.needs_more_context)} fill={(selectedAlert.probabilities.needs_more_context ?? 0) * 100} tone="gold" /><Signal label="Human review required" value={percent(selectedAlert.probabilities.likely_requires_human_review)} fill={(selectedAlert.probabilities.likely_requires_human_review ?? 0) * 100} tone="pink" /></div><div className="eyebrow">POLICY RECOMMENDATION</div><div className="recommendation"><div><strong>{selectedAlert.recommendation}</strong><small>Confidence-weighted baseline policy · INC-219 · Identity anomalies</small></div><span>Human review</span></div><div className="actions"><button className="primary" type="button" onClick={() => submitDecision('approve_recommendation')}>Approve recommendation</button><button type="button" onClick={() => submitDecision('escalate_incident')}>Escalate incident</button><button type="button" onClick={() => submitDecision('mark_false_positive')}>Mark false positive</button><button type="button" onClick={() => submitDecision('request_enrichment')}>Request enrichment</button></div>{decision && <div className="decision-toast" role="status">{decision}</div>}<div className="audit"><div className="eyebrow">AUDIT TIMELINE</div><p>Jev signals recorded with prompt version triage-v3.1</p><p>Baseline policy recommended {selectedAlert.recommendation.toLowerCase()}</p><p>Analyst feedback becomes a contextual-bandit training example</p></div></div></div>
          </section>
          </> : <WorkspacePlaceholder title={activeView} alerts={liveAlerts} metrics={queueMetrics} onOpenQueue={() => setActiveView('Alert queue')} onSelectAlert={(id) => { setSelectedId(id); setActiveView('Alert queue'); }} />}
        </main>
      </div>
    </div>
  );
}

function Metric({ label, value, note }: { label: string; value: string; note: string }) { return <div className="metric"><span>{label}</span><strong>{value}</strong><small>{note}</small></div>; }
function Signal({ label, value, fill, tone }: { label: string; value: string; fill: number; tone: string }) { return <div className="signal"><div><span>{label}</span><b>{value}</b></div><div className="signal-track"><i className={tone} style={{ width: `${fill}%` }} /></div></div>; }
function WorkspacePlaceholder({ title, alerts, metrics, onOpenQueue, onSelectAlert }: { title: string; alerts: Alert[]; metrics: { newAlerts: number; needsAttention: number; averageReward: number; analystDecisions: number; trainingExamples: number }; onOpenQueue: () => void; onSelectAlert: (id: string) => void }) {
  const attention = alerts.filter((alert) => alert.recommendation === 'High-priority review' || alert.recommendation === 'Request enrichment');
  const sources = Array.from(new Set(alerts.map((alert) => alert.source)));
  return <div className="placeholder-wrap"><div className="page-heading"><div><h1>{title}</h1><p>Live workspace connected to the analyst queue</p></div><span className="live-label"><span className="status-dot" /> Synced</span></div>
    {title === 'Incidents' && <WorkspaceList heading="Incident-linked alerts" items={alerts.filter((alert) => alert.recommendation === 'Link To Existing Incident')} empty="No alerts linked to incidents yet." onSelectAlert={onSelectAlert} />}
    {title === 'Investigation' && <WorkspaceList heading="Needs analyst attention" items={attention} empty="No alerts currently need attention." onSelectAlert={onSelectAlert} />}
    {title === 'Policy performance' && <WorkspaceStats stats={[["Analyst decisions", String(metrics.analystDecisions)], ["Training examples", String(metrics.trainingExamples)], ["Average reward", metrics.averageReward.toFixed(1)], ["Attention queue", String(metrics.needsAttention)]]} />}
    {title === 'Model shadow mode' && <WorkspaceStats stats={[["Provider", "OpenRouter Jev"], ["Live scored alerts", String(alerts.length)], ["Shadow policy", "Human review only"], ["Autonomous actions", "Disabled"]]} />}
    {title === 'Data sources' && <WorkspaceStats stats={sources.map((source) => [source, `${alerts.filter((alert) => alert.source === source).length} live alerts`])} />}
    {title === 'Audit log' && <WorkspaceStats stats={[["Recorded decisions", String(metrics.analystDecisions)], ["Reward examples", String(metrics.trainingExamples)], ["Latest state", "Analyst feedback persisted"], ["Enforcement actions", "None"]]} />}
    <button className="primary workspace-return" type="button" onClick={onOpenQueue}>Open alert queue</button>
  </div>;
}
function WorkspaceList({ heading, items, empty, onSelectAlert }: { heading: string; items: Alert[]; empty: string; onSelectAlert: (id: string) => void }) { return <div className="panel workspace-list"><div className="panel-header"><h2>{heading}</h2><span>{items.length} items</span></div>{items.length ? items.map((alert) => <button className="workspace-row" type="button" key={alert.id} onClick={() => onSelectAlert(alert.id)}><span className={`severity-dot ${alert.triageSeverity ?? alert.severity}`} /><span><strong>{alert.title}</strong><small>{alert.id} · {alert.recommendation}</small></span><time>{alert.age}</time></button>) : <p className="workspace-empty">{empty}</p>}</div>; }
function WorkspaceStats({ stats }: { stats: string[][] }) { return <div className="workspace-stats">{stats.map(([label, value]) => <div className="metric" key={label}><span>{label}</span><strong>{value}</strong><small>Live from triage workspace</small></div>)}</div>; }
function navCount(label: string, count: string | undefined, metrics: { newAlerts: number; needsAttention: number }, alertCount: number) { if (label === 'Alert queue') return <span className="nav-count">{metrics.newAlerts || alertCount}</span>; if (label === 'Incidents') return <span className="nav-count">{metrics.needsAttention}</span>; return count ? <span className="nav-count">{count}</span> : null; }
function formatRecommendation(value: string) { return ({ high_priority_review: 'High-priority review', request_enrichment: 'Request enrichment', standard_review: 'Standard review', low_priority_review: 'Low-priority review', link_to_existing_incident: 'Link to existing incident' } as Record<string, string>)[value] ?? value; }
function triageSeverity(recommendation: string): Alert['severity'] { if (recommendation === 'high_priority_review') return 'critical'; if (recommendation === 'request_enrichment') return 'medium'; if (recommendation === 'low_priority_review') return 'low'; return 'high'; }
function formatSubtitle(record: Record<string, unknown>) {
  const vulnerability = record.vulnerability as Record<string, unknown> | undefined;
  if (vulnerability?.cveID) return [vulnerability.cveID, vulnerability.vendorProject, vulnerability.product].filter(Boolean).join(' · ');
  return [record.host, record.user, record.source_ip].filter(Boolean).join(' · ');
}
function percent(value: number | undefined) { return `${Math.round((value ?? 0) * 100)}%`; }
function formatAge(timestamp: string) {
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(timestamp).getTime()) / 1000));
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  return `${Math.floor(seconds / 3600)}h`;
}
