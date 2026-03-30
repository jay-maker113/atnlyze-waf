// frontend/src/components/ControlBar.jsx
// Compact footer status strip only.

import { C } from '../theme';

const styles = {
  root: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'flex-start',
    gap: '8px',
    padding: '10px 18px',
    flexWrap: 'wrap',
  },
  pill: {
    display: 'inline-flex',
    alignItems: 'center',
    gap: '8px',
    padding: '6px 10px',
    borderRadius: '999px',
    border: `1px solid ${C.grid}`,
    backgroundColor: 'rgba(15, 25, 35, 0.65)',
    fontSize: '12px',
    color: C.text,
  },
  dot: {
    width: '8px',
    height: '8px',
    borderRadius: '999px',
    flexShrink: 0,
  },
  label: {
    color: C.muted,
    textTransform: 'uppercase',
    letterSpacing: '0.04em',
    fontSize: '11px',
    fontWeight: 700,
  },
};

function processIndicator(status) {
  return status === 'running' ? C.emerald : C.muted;
}

function prettyStatus(status) {
  return status === 'running' ? 'running' : 'stopped';
}

export function ControlBar({ demoStatus }) {
  return (
    <div style={styles.root}>
      {['benign', 'attack', 'feed'].map((name) => (
        <div key={name} style={styles.pill}>
          <span style={styles.label}>{name}</span>
          <span style={{ ...styles.dot, backgroundColor: processIndicator(demoStatus?.[name]) }} />
          <span>{prettyStatus(demoStatus?.[name])}</span>
        </div>
      ))}
    </div>
  );
}
