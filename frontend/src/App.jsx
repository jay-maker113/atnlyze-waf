// frontend/src/App.jsx
// Layout shell and top-level state manager.
// Owns: SSE connection, stats polling, alert queue.
// ControlBar owns its own API calls (start/stop/reset) -- no callbacks needed here.

import { useState, useCallback } from 'react';
import { useSSE }   from './hooks/useSSE';
import { useStats } from './hooks/useStats';
import { C } from './theme';
import { resetStats, startAttack, startBenign, stopDemo } from './api';

import { StatsPanel }    from './components/StatsPanel';
import { ArenaPanel }    from './components/ArenaPanel';
import { ControlBar }    from './components/ControlBar';
import { AlertBanner }   from './components/AlertBanner';
import { ConnectionDot } from './components/ConnectionDot';

const styles = {
  app: {
    minHeight:       '100vh',
    backgroundColor: C.bg,
    color:           C.text,
    fontFamily:      "'Inter', 'Segoe UI', system-ui, sans-serif",
    display:         'flex',
    flexDirection:   'column',
    overflow:        'hidden',
  },

  header: {
    display:         'grid',
    gridTemplateColumns: 'minmax(0, 1fr) auto',
    alignItems:      'center',
    gap:             '16px',
    padding:         '12px 24px',
    backgroundColor: C.surface,
    borderBottom:    `1px solid ${C.grid}`,
    flexShrink:      0,
  },
  headerLeft: {
    display:    'flex',
    alignItems: 'center',
    gap:        '10px',
  },
  logoText: {
    fontSize:      '22px',
    fontWeight:    700,
    color:         C.emerald,
    letterSpacing: '0.5px',
  },
  logoWAF: {
    fontSize:   '22px',
    fontWeight: 700,
    color:      C.text,
  },
  subtitle: {
    fontSize:  '12px',
    color:     C.muted,
    marginTop: '2px',
  },
  headerRight: {
    display:    'flex',
    alignItems: 'center',
    gap:        '10px',
    flexWrap:   'wrap',
    justifyContent: 'flex-end',
  },
  connLabel: {
    fontSize: '12px',
    color:    C.muted,
  },
  headerBtn: {
    appearance: 'none',
    border: 'none',
    borderRadius: '10px',
    padding: '8px 12px',
    fontSize: '12px',
    fontWeight: 800,
    letterSpacing: '0.03em',
    cursor: 'pointer',
  },
  benignBtn: {
    backgroundColor: C.blue,
    color: '#0B1630',
  },
  attackBtn: {
    backgroundColor: C.red,
    color: '#2A0B0B',
  },
  stopBtn: {
    backgroundColor: '#334155',
    color: C.text,
  },
  resetBtn: {
    backgroundColor: C.amber,
    color: '#2B1803',
  },
  compareBtn: {
    backgroundColor: 'rgba(30, 45, 61, 0.95)',
    color: C.text,
    border: `1px solid ${C.grid}`,
  },
  compareBtnActive: {
    backgroundColor: 'rgba(16, 185, 129, 0.18)',
    color: C.emerald,
    border: `1px solid rgba(16, 185, 129, 0.45)`,
  },
  headerBtnDisabled: {
    opacity: 0.6,
    cursor: 'not-allowed',
  },

  body: {
    display:   'flex',
    flexDirection: 'column',
    flex:      1,
    overflow:  'hidden',
    minHeight: 0,
  },

  arenaWrapper: {
    flex:          '0 0 240px',
    minHeight:     '240px',
    display:       'flex',
    overflow:      'hidden',
    borderBottom:  `1px solid ${C.grid}`,
  },
  statsWrapper: {
    flex:          1,
    minHeight:     0,
    display:       'flex',
    flexDirection: 'column',
    overflow:      'hidden',
  },

  footer: {
    flexShrink:      0,
    borderTop:       `1px solid ${C.grid}`,
    backgroundColor: C.surface,
  },
};

export default function App() {
  const [arenaEvents, setArenaEvents] = useState([]);
  const [alert, setAlert] = useState(null);
  const [busyAction, setBusyAction] = useState(null);
  const [showComparison, setShowComparison] = useState(false);

  // Stats polling -- sparkline + counters + demo process status
  const { stats, sparkline, demoStatus, error: statsError } = useStats();

  const handleSSEEvent = useCallback((event) => {
    setArenaEvents(prev => {
      const next = [...prev, { ...event, id: `${event.timestamp}-${Math.random()}` }];
      return next.length > 80 ? next.slice(next.length - 80) : next;
    });

    if (event.decision === 'block' && event.score >= 0.9) {
      setAlert({
        attack_type: event.attack_type,
        score: event.score,
        sample: event.path || '-',
      });
    }
  }, []);

  const { connected } = useSSE(handleSSEEvent);

  const dismissAlert = useCallback(() => setAlert(null), []);

  const runHeaderAction = useCallback(async (name, action) => {
    setBusyAction(name);
    try {
      await action();
    } finally {
      setBusyAction(null);
    }
  }, []);

  return (
    <div style={styles.app}>

      <AlertBanner alert={alert} onDismiss={dismissAlert} />

      <header style={styles.header}>
        <div style={styles.headerLeft}>
          <div>
            <div>
              <span style={styles.logoText}>AtnLyze</span>
              <span style={styles.logoWAF}> WAF</span>
            </div>
            <div style={styles.subtitle}>
              DistilBERT Transformer · Live Monitor
            </div>
          </div>
        </div>
        <div style={styles.headerRight}>
          <button
            type="button"
            style={{
              ...styles.headerBtn,
              ...styles.benignBtn,
              ...(busyAction ? styles.headerBtnDisabled : {}),
            }}
            disabled={busyAction !== null}
            onClick={() => runHeaderAction('start-benign', startBenign)}
          >
            {busyAction === 'start-benign' ? 'Starting...' : 'Start Benign'}
          </button>
          <button
            type="button"
            style={{
              ...styles.headerBtn,
              ...styles.attackBtn,
              ...(busyAction ? styles.headerBtnDisabled : {}),
            }}
            disabled={busyAction !== null}
            onClick={() => runHeaderAction('start-attack', startAttack)}
          >
            {busyAction === 'start-attack' ? 'Launching...' : 'Launch Attack'}
          </button>
          <button
            type="button"
            style={{
              ...styles.headerBtn,
              ...styles.stopBtn,
              ...(busyAction ? styles.headerBtnDisabled : {}),
            }}
            disabled={busyAction !== null}
            onClick={() => runHeaderAction('stop', stopDemo)}
          >
            {busyAction === 'stop' ? 'Stopping...' : 'Stop All'}
          </button>
          <button
            type="button"
            style={{
              ...styles.headerBtn,
              ...styles.compareBtn,
              ...(showComparison ? styles.compareBtnActive : {}),
            }}
            onClick={() => setShowComparison((prev) => !prev)}
          >
            {showComparison ? 'Hide Comparison' : 'Show Comparison'}
          </button>
          <button
            type="button"
            style={{
              ...styles.headerBtn,
              ...styles.resetBtn,
              ...(busyAction ? styles.headerBtnDisabled : {}),
            }}
            disabled={busyAction !== null}
            onClick={() => runHeaderAction('reset', resetStats)}
          >
            {busyAction === 'reset' ? 'Resetting...' : 'Reset Stats'}
          </button>
          <span style={styles.connLabel}>
            {connected ? 'Live' : 'Reconnecting...'}
          </span>
          <ConnectionDot connected={connected} />
        </div>
      </header>

      <div style={styles.body}>
        <div style={styles.arenaWrapper}>
          <ArenaPanel events={arenaEvents} />
        </div>
        <div style={styles.statsWrapper}>
          <StatsPanel
            stats={stats}
            sparkline={sparkline}
            error={statsError}
            showComparison={showComparison}
          />
        </div>
      </div>

      <footer style={styles.footer}>
        <ControlBar demoStatus={demoStatus} />
      </footer>

    </div>
  );
}
