// frontend/src/components/StatsPanel.jsx
// Right-side analytics panel aligned to the Phase 4 spec.

import { useState } from 'react';
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';

import { C } from '../theme';

const GOLD = C.amber;

const ATTACK_COLORS = {
  scanner: '#3B82F6',
  sqli: '#EF4444',
  xss: '#F59E0B',
  lfi: '#10B981',
  path: '#14B8A6',
  php: '#8B5CF6',
  rfi: '#EC4899',
  cmdi: '#F97316',
  ldap: '#A855F7',
  nosql: '#EAB308',
  unknown: '#64748B',
};

const OCEAN = '#38BDF8';
const BASELINE_BAR = '#38BDF8';
const TRANSFORMER_BAR = '#F59E0B';
const HISTOGRAM_COLORS = [
  '#10B981',
  '#22C55E',
  '#84CC16',
  '#EAB308',
  '#F59E0B',
  '#F97316',
  '#FB7185',
  '#A855F7',
  '#6366F1',
  '#38BDF8',
];

const styles = {
  root: {
    height: '100%',
    display: 'flex',
    flexDirection: 'column',
    minHeight: 0,
    backgroundColor: C.bg,
  },
  scroll: {
    flex: 1,
    overflowY: 'auto',
    padding: '20px 18px 20px 18px',
    display: 'flex',
    flexDirection: 'column',
    gap: '16px',
    minHeight: 0,
  },
  section: {
    backgroundColor: C.surface,
    border: `1px solid ${C.grid}`,
    borderRadius: '14px',
    padding: '16px',
    boxShadow: '0 12px 24px rgba(0, 0, 0, 0.18)',
  },
  sectionHeader: {
    display: 'flex',
    alignItems: 'baseline',
    justifyContent: 'space-between',
    gap: '12px',
    marginBottom: '14px',
  },
  sectionTitle: {
    margin: 0,
    fontSize: '14px',
    fontWeight: 700,
    letterSpacing: '0.04em',
    textTransform: 'uppercase',
    color: C.text,
  },
  sectionNote: {
    fontSize: '12px',
    color: C.muted,
  },
  grid4: {
    display: 'grid',
    gridTemplateColumns: 'repeat(2, minmax(0, 1fr))',
    gap: '12px',
  },
  snapshotSectionBody: {
    display: 'grid',
    gridTemplateColumns: 'minmax(0, 1fr) minmax(0, 1fr)',
    gap: '16px',
    alignItems: 'start',
  },
  snapshotPane: {
    minWidth: 0,
  },
  telemetryPane: {
    minWidth: 0,
    paddingLeft: '16px',
    position: 'relative',
  },
  sectionTopGrid: {
    display: 'grid',
    gridTemplateColumns: 'minmax(0, 1fr) minmax(0, 1fr)',
    gap: '16px',
    alignItems: 'baseline',
    marginBottom: '14px',
  },
  headerCell: {
    minWidth: 0,
  },
  telemetryHeaderCell: {
    minWidth: 0,
    paddingLeft: '16px',
    position: 'relative',
  },
  dividerLine: {
    position: 'absolute',
    left: 0,
    top: 0,
    bottom: 0,
    width: '1px',
    backgroundColor: C.grid,
  },
  paneHeader: {
    display: 'flex',
    alignItems: 'baseline',
    justifyContent: 'space-between',
    gap: '12px',
    marginBottom: '14px',
  },
  statCard: {
    background: 'linear-gradient(180deg, rgba(30,45,61,0.78) 0%, rgba(15,25,35,0.92) 100%)',
    border: `1px solid ${C.grid}`,
    borderRadius: '12px',
    padding: '12px 14px',
    minHeight: '100.6px',
  },
  statLabel: {
    fontSize: '11px',
    textTransform: 'uppercase',
    letterSpacing: '0.06em',
    color: C.muted,
    marginBottom: '8px',
  },
  statValue: {
    fontSize: '28px',
    fontWeight: 800,
    lineHeight: 1,
    marginBottom: '8px',
    color: GOLD,
    fontVariantNumeric: 'tabular-nums',
  },
  statSub: {
    fontSize: '12px',
    color: C.muted,
  },
  chartWrap: {
    width: '100%',
    height: '180px',
  },
  telemetryGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(2, minmax(0, 1fr))',
    gap: '12px',
  },
  telemetryCard: {
    background: 'linear-gradient(180deg, rgba(30,45,61,0.78) 0%, rgba(15,25,35,0.92) 100%)',
    border: `1px solid ${C.grid}`,
    borderRadius: '12px',
    padding: '12px 14px',
  },
  telemetryValue: {
    fontSize: '22px',
    fontWeight: 800,
    color: GOLD,
    fontVariantNumeric: 'tabular-nums',
    lineHeight: 1,
    marginBottom: '6px',
  },
  telemetryLabel: {
    fontSize: '11px',
    textTransform: 'uppercase',
    letterSpacing: '0.06em',
    color: C.muted,
    marginBottom: '6px',
  },
  telemetrySub: {
    fontSize: '12px',
    color: C.muted,
  },
  sectionActionWrap: {
    display: 'flex',
    alignItems: 'center',
    gap: '10px',
  },
  sectionToggleBtn: {
    appearance: 'none',
    borderRadius: '999px',
    padding: '6px 10px',
    fontSize: '11px',
    fontWeight: 700,
    letterSpacing: '0.04em',
    cursor: 'pointer',
    border: `1px solid ${C.grid}`,
    backgroundColor: 'rgba(15, 25, 35, 0.72)',
    color: C.text,
  },
  sectionToggleBtnActive: {
    border: `1px solid rgba(56, 189, 248, 0.45)`,
    backgroundColor: 'rgba(56, 189, 248, 0.14)',
    color: BASELINE_BAR,
  },
  comparisonGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(3, minmax(0, 1fr))',
    gap: '12px',
  },
  comparisonCard: {
    background: 'linear-gradient(180deg, rgba(30,45,61,0.78) 0%, rgba(15,25,35,0.92) 100%)',
    border: `1px solid ${C.grid}`,
    borderRadius: '12px',
    padding: '14px',
    minHeight: '96px',
  },
  split: {
    display: 'grid',
    gridTemplateColumns: 'minmax(0, 1fr)',
    gap: '16px',
  },
  legendWrap: {
    display: 'grid',
    gridTemplateColumns: 'repeat(2, minmax(0, 1fr))',
    gap: '8px 12px',
    marginTop: '14px',
  },
  legendItem: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    minWidth: 0,
  },
  swatch: {
    width: '10px',
    height: '10px',
    borderRadius: '999px',
    flexShrink: 0,
  },
  legendLabel: {
    fontSize: '12px',
    color: C.text,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  legendValue: {
    marginLeft: 'auto',
    fontSize: '12px',
    color: GOLD,
    fontVariantNumeric: 'tabular-nums',
  },
  emptyState: {
    height: '180px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    borderRadius: '12px',
    border: `1px dashed ${C.grid}`,
    color: C.muted,
    fontSize: '13px',
    backgroundColor: 'rgba(15, 25, 35, 0.5)',
  },
  errorBar: {
    padding: '12px 14px',
    borderRadius: '12px',
    border: `1px solid rgba(239, 68, 68, 0.35)`,
    backgroundColor: 'rgba(127, 29, 29, 0.24)',
    color: '#FCA5A5',
    fontSize: '13px',
  },
  logWrap: {
    borderRadius: '12px',
    border: `1px solid ${C.grid}`,
    overflow: 'hidden',
    backgroundColor: 'rgba(15, 25, 35, 0.6)',
  },
  logHeader: {
    display: 'grid',
    gridTemplateColumns: '82px minmax(0, 1.7fr) 88px 88px 92px',
    gap: '12px',
    padding: '10px 12px',
    borderBottom: `1px solid ${C.grid}`,
    backgroundColor: 'rgba(15, 25, 35, 0.9)',
    color: C.muted,
    fontSize: '11px',
    fontWeight: 700,
    letterSpacing: '0.05em',
    textTransform: 'uppercase',
  },
  logList: {
    display: 'flex',
    flexDirection: 'column',
    maxHeight: '360px',
    overflowY: 'auto',
  },
  logRow: {
    display: 'grid',
    gridTemplateColumns: '82px minmax(0, 1.7fr) 88px 88px 92px',
    gap: '12px',
    alignItems: 'center',
    padding: '10px 12px',
    borderBottom: `1px solid rgba(30, 45, 61, 0.65)`,
    fontSize: '12px',
  },
  timeCol: {
    color: C.muted,
    fontVariantNumeric: 'tabular-nums',
  },
  pathCol: {
    minWidth: 0,
    color: C.text,
    fontFamily: "'Consolas', 'SFMono-Regular', monospace",
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  scoreCol: {
    color: GOLD,
    fontVariantNumeric: 'tabular-nums',
    fontWeight: 700,
  },
  decisionCol: {
    fontWeight: 700,
    textTransform: 'uppercase',
  },
  typeCol: {
    color: C.text,
    textTransform: 'uppercase',
    fontSize: '11px',
    letterSpacing: '0.04em',
  },
  pathList: {
    display: 'flex',
    flexDirection: 'column',
    gap: '10px',
  },
  pathRow: {
    display: 'grid',
    gridTemplateColumns: '1fr auto',
    gap: '12px',
    alignItems: 'center',
    padding: '10px 12px',
    borderRadius: '10px',
    border: `1px solid ${C.grid}`,
    backgroundColor: 'rgba(15, 25, 35, 0.56)',
  },
  pathLabel: {
    minWidth: 0,
    color: C.text,
    fontFamily: "'Consolas', 'SFMono-Regular', monospace",
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  pathValue: {
    color: GOLD,
    fontSize: '12px',
    fontWeight: 700,
    fontVariantNumeric: 'tabular-nums',
  },
};

function formatInt(value) {
  return new Intl.NumberFormat('en-US').format(value ?? 0);
}

function formatPct(value) {
  return `${Number(value ?? 0).toFixed(1)}%`;
}

function formatTime(timestamp) {
  if (!timestamp) return '--:--:--';
  return new Date(timestamp * 1000).toLocaleTimeString('en-US', {
    hour12: false,
  });
}

function formatDuration(totalSeconds) {
  const seconds = Math.max(0, Number(totalSeconds ?? 0));
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const remainder = Math.floor(seconds % 60);

  if (hours > 0) {
    return `${hours}h ${minutes}m`;
  }
  if (minutes > 0) {
    return `${minutes}m ${remainder}s`;
  }
  return `${remainder}s`;
}

function formatSignedPct(value) {
  const num = Number(value ?? 0) * 100;
  const sign = num > 0 ? '+' : '';
  return `${sign}${num.toFixed(1)}%`;
}

function buildAttackChartData(attackTypeCounts) {
  return Object.entries(attackTypeCounts ?? {})
    .filter(([, count]) => count > 0)
    .map(([name, value]) => ({
      name,
      value,
      color: ATTACK_COLORS[name] ?? C.muted,
    }))
    .sort((a, b) => b.value - a.value);
}

function buildHistogramData(transformerDistribution, baselineDistribution) {
  return Object.keys(transformerDistribution ?? {}).map((range, index) => ({
    range,
    transformerCount: transformerDistribution?.[range] ?? 0,
    baselineCount: baselineDistribution?.[range] ?? 0,
    color: HISTOGRAM_COLORS[index % HISTOGRAM_COLORS.length],
  }));
}

function buildTelemetryCards(stats) {
  return [
    {
      label: 'Current Throughput',
      value: `${Number(stats.current_rps_2s ?? 0).toFixed(1)}/s`,
      sub: 'Backend-measured live RPS',
    },
    {
      label: 'Peak Throughput',
      value: `${Number(stats.peak_rps_2s ?? 0).toFixed(1)}/s`,
      sub: 'Peak observed in 2s window',
    },
    {
      label: 'Inference Latency',
      value: `${Number(stats.avg_latency_ms ?? 0).toFixed(1)} ms`,
      sub: `P50 ${Number(stats.p50_latency_ms ?? 0).toFixed(1)} ms · P95 ${Number(stats.p95_latency_ms ?? 0).toFixed(1)} ms`,
    },
    {
      label: 'Recent Block Rate',
      value: formatPct(stats.recent_block_rate_30s),
      sub: `Rolling ${formatInt(stats.recent_window_seconds)}s decision window`,
    },
    {
      label: 'High-Confidence Blocks',
      value: formatInt(stats.high_confidence_blocks),
      sub: `${formatInt(stats.uncertain_scores)} uncertain-score events`,
    },
    {
      label: 'Primary Engine',
      value: stats.engine_name || 'transformer-onnx-primary',
      sub: 'Primary decision path in /predict',
    },
    {
      label: 'Uptime Since Reset',
      value: formatDuration(stats.uptime_since_reset_s),
      sub: 'Elapsed since last stats reset',
    },
    {
      label: 'Confidence Drift',
      value: formatSignedPct(stats.confidence_drift_delta),
      sub: `Last ${formatInt(stats.recent_window_seconds)}s vs previous ${formatInt(stats.recent_window_seconds)}s`,
    },
  ];
}

function buildStatCards(stats) {
  return [
    {
      label: 'Total Requests',
      value: formatInt(stats.total),
      sub: `${formatInt(stats.recent_events?.length ?? 0)} recent entries`,
    },
    {
      label: 'Blocked',
      value: formatInt(stats.blocked),
      sub: `${formatPct(stats.block_rate)} of traffic`,
    },
    {
      label: 'Allowed',
      value: formatInt(stats.allowed),
      sub: `${formatPct(100 - (stats.block_rate ?? 0))} of traffic`,
    },
    {
      label: 'Block Rate',
      value: formatPct(stats.block_rate),
      sub: 'Live decision ratio',
    },
    {
      label: 'Unique Paths',
      value: formatInt(stats.unique_paths_seen),
      sub: 'Distinct routes observed',
    },
    {
      label: 'Attack Diversity',
      value: formatInt(stats.attack_diversity),
      sub: `Unknown blocked: ${formatInt(stats.unknown_blocked)} · Unknown allowed: ${formatInt(stats.unknown_allowed)}`,
    },
  ];
}

function buildComparisonCards(stats) {
  return [
    {
      label: 'Transformer Blocked',
      value: formatInt(stats.transformer_blocked),
      sub: 'Primary engine block decisions',
    },
    {
      label: 'Baseline Blocked',
      value: formatInt(stats.baseline_blocked),
      sub: 'Shadow baseline block decisions',
    },
    {
      label: 'Agreement Rate',
      value: formatPct(stats.comparison_agreement_rate),
      sub: `${formatInt(stats.comparison_agreement_count)} of ${formatInt(stats.comparison_total)} compared requests`,
    },
    {
      label: 'Disagreements',
      value: formatInt(stats.comparison_disagreement_count),
      sub: 'Requests where model decisions diverged',
    },
    {
      label: 'Transformer Latency',
      value: `${Number(stats.transformer_avg_latency_ms ?? 0).toFixed(1)} ms`,
      sub: 'Average inference latency',
    },
    {
      label: 'Baseline Latency',
      value: `${Number(stats.baseline_avg_latency_ms ?? 0).toFixed(1)} ms`,
      sub: 'Average inference latency',
    },
  ];
}

function rowStyleForDecision(decision) {
  if (decision === 'block') {
    return {
      ...styles.logRow,
      backgroundColor: 'rgba(127, 29, 29, 0.14)',
    };
  }

  return {
    ...styles.logRow,
    backgroundColor: 'rgba(30, 64, 175, 0.14)',
  };
}

function decisionTextStyle(decision) {
  return {
    ...styles.decisionCol,
    color: decision === 'block' ? C.red : C.blue,
  };
}

export function StatsPanel({ stats, sparkline, error, showComparison = false }) {
  const [showBaselineDistribution, setShowBaselineDistribution] = useState(false);
  const attackChartData = buildAttackChartData(stats.attack_type_counts);
  const histogramData = buildHistogramData(
    stats.transformer_score_distribution ?? stats.score_distribution,
    stats.baseline_score_distribution,
  );
  const statCards = buildStatCards(stats);
  const telemetryCards = buildTelemetryCards(stats);
  const comparisonCards = buildComparisonCards(stats);
  const recentEvents = (stats.recent_events ?? [])
    .map((event, index, source) => ({
      ...event,
      _key: [
        event.timestamp,
        event.path,
        event.decision,
        event.attack_type,
        event.score,
        event.model,
        source.length - 1 - index,
      ].join('|'),
    }))
    .reverse()
    .slice(0, 20);

  return (
    <aside style={styles.root}>
      <div style={styles.scroll}>
        {error ? (
          <div style={styles.errorBar}>
            Stats polling degraded: {error}
          </div>
        ) : null}

        <section style={styles.section}>
          <div style={styles.sectionTopGrid}>
            <div style={styles.headerCell}>
              <h2 style={styles.sectionTitle}>Live Snapshot</h2>
            </div>
            <div style={styles.telemetryHeaderCell}>
              <div style={styles.dividerLine} />
              <h2 style={styles.sectionTitle}>Model Telemetry</h2>
            </div>
          </div>
          <div style={styles.snapshotSectionBody}>
            <div style={styles.snapshotPane}>
              <div style={styles.paneHeader}>
                <span style={styles.sectionNote}>Current request and decision totals</span>
                <span style={styles.sectionNote}>Polled every 2s</span>
              </div>
              <div style={styles.grid4}>
                {statCards.map((card) => (
                  <div key={card.label} style={styles.statCard}>
                    <div style={styles.statLabel}>{card.label}</div>
                    <div style={styles.statValue}>{card.value}</div>
                    <div style={styles.statSub}>{card.sub}</div>
                  </div>
                ))}
              </div>
            </div>
            <div style={styles.telemetryPane}>
              <div style={styles.dividerLine} />
              <div style={styles.paneHeader}>
                <span style={styles.sectionNote}>Latency and confidence health</span>
                <span style={styles.sectionNote} />
              </div>
              <div style={styles.telemetryGrid}>
                {telemetryCards.map((card) => (
                  <div key={card.label} style={styles.telemetryCard}>
                    <div style={styles.telemetryLabel}>{card.label}</div>
                    <div style={styles.telemetryValue}>{card.value}</div>
                    <div style={styles.telemetrySub}>{card.sub}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </section>

        {showComparison ? (
          <section style={styles.section}>
            <div style={styles.sectionHeader}>
              <h2 style={styles.sectionTitle}>Model Comparison</h2>
              <span style={styles.sectionNote}>Baseline shadow vs transformer-onnx primary</span>
            </div>
            <div style={styles.comparisonGrid}>
              {comparisonCards.map((card) => (
                <div key={card.label} style={styles.comparisonCard}>
                  <div style={styles.telemetryLabel}>{card.label}</div>
                  <div style={styles.telemetryValue}>{card.value}</div>
                  <div style={styles.telemetrySub}>{card.sub}</div>
                </div>
              ))}
            </div>
          </section>
        ) : null}

        <section style={styles.section}>
          <div style={styles.sectionHeader}>
            <h2 style={styles.sectionTitle}>Traffic Throughput</h2>
            <span style={styles.sectionNote}>Requests/sec last 60s</span>
          </div>
          {sparkline.length ? (
            <div style={styles.chartWrap}>
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={sparkline} margin={{ top: 4, right: 12, left: 2, bottom: 0 }}>
                  <defs>
                    <linearGradient id="rpsFill" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor={C.emerald} stopOpacity={0.35} />
                      <stop offset="65%" stopColor={OCEAN} stopOpacity={0.14} />
                      <stop offset="95%" stopColor={OCEAN} stopOpacity={0.03} />
                    </linearGradient>
                    <linearGradient id="rpsStroke" x1="0" y1="0" x2="1" y2="0">
                      <stop offset="0%" stopColor={C.emerald} />
                      <stop offset="100%" stopColor={OCEAN} />
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="t" hide />
                  <YAxis
                    stroke={GOLD}
                    width={32}
                    tickLine={false}
                    axisLine={false}
                    tick={{ fontSize: 11, fill: GOLD }}
                  />
                  <Tooltip
                    formatter={(value) => [`${value}/s`, 'RPS']}
                    labelFormatter={() => 'Traffic rate'}
                    contentStyle={{
                      backgroundColor: C.surface,
                      border: `1px solid ${C.grid}`,
                      borderRadius: '10px',
                      color: C.text,
                    }}
                  />
                  <Area
                    type="monotone"
                    dataKey="rps"
                    stroke="url(#rpsStroke)"
                    strokeWidth={2.5}
                    fill="url(#rpsFill)"
                    isAnimationActive={false}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div style={styles.emptyState}>Waiting for traffic to build the sparkline.</div>
          )}
        </section>

        <div style={styles.split}>
          <section style={styles.section}>
            <div style={styles.sectionHeader}>
              <h2 style={styles.sectionTitle}>Attack Mix</h2>
              <span style={styles.sectionNote}>Blocked events only</span>
            </div>
            {attackChartData.length ? (
              <>
                <div style={styles.chartWrap}>
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={[{ name: 'reactor-shell', value: 1 }]}
                        dataKey="value"
                        innerRadius={74}
                        outerRadius={78}
                        stroke="none"
                        isAnimationActive={false}
                      >
                        <Cell fill="rgba(56, 189, 248, 0.2)" />
                      </Pie>
                      <Pie
                        data={attackChartData}
                        dataKey="value"
                        nameKey="name"
                        innerRadius={48}
                        outerRadius={72}
                        paddingAngle={2}
                        stroke="none"
                        isAnimationActive={false}
                      >
                        {attackChartData.map((entry) => (
                          <Cell key={entry.name} fill={entry.color} />
                        ))}
                      </Pie>
                      <Pie
                        data={[
                          { name: 'core-1', value: 1 },
                          { name: 'core-2', value: 1 },
                          { name: 'core-3', value: 1 },
                          { name: 'core-4', value: 1 },
                          { name: 'core-5', value: 1 },
                          { name: 'core-6', value: 1 },
                        ]}
                        dataKey="value"
                        innerRadius={32}
                        outerRadius={38}
                        paddingAngle={8}
                        stroke="none"
                        isAnimationActive={false}
                      >
                        {Array.from({ length: 6 }).map((_, index) => (
                          <Cell
                            key={`core-${index}`}
                            fill={index % 2 === 0 ? 'rgba(16, 185, 129, 0.45)' : 'rgba(56, 189, 248, 0.35)'}
                          />
                        ))}
                      </Pie>
                      <Pie
                        data={[{ name: 'core-center', value: 1 }]}
                        dataKey="value"
                        innerRadius={0}
                        outerRadius={18}
                        stroke="none"
                        isAnimationActive={false}
                      >
                        <Cell fill="rgba(226, 232, 240, 0.12)" />
                      </Pie>
                      <Tooltip
                        formatter={(value, name) => [value, name]}
                        contentStyle={{
                          backgroundColor: C.surface,
                          border: `1px solid ${C.grid}`,
                          borderRadius: '10px',
                          color: C.text,
                        }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
                <div style={styles.legendWrap}>
                  {attackChartData.map((item) => (
                    <div key={item.name} style={styles.legendItem}>
                      <span style={{ ...styles.swatch, backgroundColor: item.color }} />
                      <span style={styles.legendLabel}>{item.name}</span>
                      <span style={styles.legendValue}>{item.value}</span>
                    </div>
                  ))}
                </div>
              </>
            ) : (
              <div style={styles.emptyState}>No blocked attack classes recorded yet.</div>
            )}
          </section>

        <section style={styles.section}>
          <div style={styles.sectionHeader}>
            <h2 style={styles.sectionTitle}>Score Distribution</h2>
            <div style={styles.sectionActionWrap}>
              <span style={styles.sectionNote}>
                {showBaselineDistribution ? 'Transformer vs baseline confidence distribution' : 'Transformer confidence distribution'}
              </span>
              <button
                type="button"
                style={{
                  ...styles.sectionToggleBtn,
                  ...(showBaselineDistribution ? styles.sectionToggleBtnActive : {}),
                }}
                onClick={() => setShowBaselineDistribution((prev) => !prev)}
              >
                {showBaselineDistribution ? 'Hide Baseline' : 'Show Baseline'}
              </button>
            </div>
          </div>
          {histogramData.length ? (
            <div style={styles.chartWrap}>
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={histogramData} margin={{ top: 4, right: 4, left: -10, bottom: 8 }}>
                    <XAxis
                      dataKey="range"
                      stroke={GOLD}
                      tickLine={false}
                      axisLine={false}
                      tick={{ fontSize: 10, fill: GOLD }}
                      angle={-30}
                      textAnchor="end"
                      height={42}
                    />
                    <YAxis
                      stroke={GOLD}
                      tickLine={false}
                      axisLine={false}
                      width={24}
                      allowDecimals={false}
                      tick={{ fontSize: 11, fill: GOLD }}
                    />
                    <Tooltip
                      formatter={(value, name) => [
                        value,
                        name === 'baselineCount' ? 'Baseline events' : 'Transformer events',
                      ]}
                      contentStyle={{
                        backgroundColor: C.surface,
                        border: `1px solid ${C.grid}`,
                        borderRadius: '10px',
                        color: C.text,
                      }}
                    />
                    <Bar dataKey="transformerCount" name="transformerCount" radius={[6, 6, 0, 0]} isAnimationActive={false}>
                      {histogramData.map((entry) => (
                        <Cell key={entry.range} fill={entry.color} />
                      ))}
                    </Bar>
                    {showBaselineDistribution ? (
                      <Bar
                        dataKey="baselineCount"
                        name="baselineCount"
                        radius={[6, 6, 0, 0]}
                        isAnimationActive={false}
                        fill={BASELINE_BAR}
                      />
                    ) : null}
                  </BarChart>
                </ResponsiveContainer>
              </div>
            ) : (
              <div style={styles.emptyState}>No score distribution data yet.</div>
            )}
          </section>
        </div>

        <section style={styles.section}>
          <div style={styles.sectionHeader}>
            <h2 style={styles.sectionTitle}>Top Targeted Paths</h2>
            <span style={styles.sectionNote}>Most frequently observed routes</span>
          </div>
          {(stats.top_targeted_paths ?? []).length ? (
            <div style={styles.pathList}>
              {stats.top_targeted_paths.map(([path, count]) => (
                <div key={`${path}|${count}`} style={styles.pathRow}>
                  <span style={styles.pathLabel}>{path}</span>
                  <span style={styles.pathValue}>{count}</span>
                </div>
              ))}
            </div>
          ) : (
            <div style={styles.emptyState}>No targeted path data yet.</div>
          )}
        </section>

        <section style={styles.section}>
          <div style={styles.sectionHeader}>
            <h2 style={styles.sectionTitle}>Recent Decisions</h2>
            <span style={styles.sectionNote}>Last 20 decisions</span>
          </div>
          {recentEvents.length ? (
            <div style={styles.logWrap}>
              <div style={styles.logHeader}>
                <span>Time</span>
                <span>Path</span>
                <span>Score</span>
                <span>Decision</span>
                <span>Attack Type</span>
              </div>
              <div style={styles.logList}>
                {recentEvents.map((event) => (
                  <div key={event._key} style={rowStyleForDecision(event.decision)}>
                    <span style={styles.timeCol}>{formatTime(event.timestamp)}</span>
                    <span style={styles.pathCol}>{event.path || '-'}</span>
                    <span style={styles.scoreCol}>{Number(event.score ?? 0).toFixed(4)}</span>
                    <span style={decisionTextStyle(event.decision)}>{event.decision}</span>
                    <span style={styles.typeCol}>{event.attack_type || 'unknown'}</span>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div style={styles.emptyState}>No recent decisions yet.</div>
          )}
        </section>
      </div>
    </aside>
  );
}
