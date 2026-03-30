// frontend/src/components/AlertBanner.jsx
// Compact bottom-right toast for high-confidence blocks.

import { useEffect } from 'react';

import { C } from '../theme';

const AUTO_DISMISS_MS = 5000;

const styles = {
  root: {
    position: 'fixed',
    right: '18px',
    bottom: '18px',
    width: 'min(340px, calc(100vw - 32px))',
    zIndex: 1000,
    pointerEvents: 'none',
  },
  card: {
    display: 'flex',
    alignItems: 'flex-start',
    gap: '10px',
    padding: '10px 12px',
    borderRadius: '12px',
    border: '1px solid rgba(239, 68, 68, 0.30)',
    background: 'linear-gradient(135deg, rgba(127, 29, 29, 0.96) 0%, rgba(69, 10, 10, 0.96) 100%)',
    boxShadow: '0 12px 24px rgba(0, 0, 0, 0.30)',
    color: C.amber,
    pointerEvents: 'auto',
    animation: 'alert-toast-in 180ms ease-out',
  },
  icon: {
    width: '10px',
    height: '10px',
    borderRadius: '999px',
    backgroundColor: C.red,
    boxShadow: '0 0 10px rgba(239, 68, 68, 0.55)',
    flexShrink: 0,
    marginTop: '5px',
  },
  textWrap: {
    minWidth: 0,
    flex: 1,
  },
  title: {
    fontSize: '11px',
    fontWeight: 900,
    letterSpacing: '0.05em',
    textTransform: 'uppercase',
    marginBottom: '3px',
    color: C.amber,
  },
  meta: {
    display: 'flex',
    gap: '8px',
    flexWrap: 'wrap',
    marginBottom: '4px',
    fontSize: '11px',
    color: '#F8E2A5',
  },
  attackType: {
    fontWeight: 800,
    textTransform: 'uppercase',
    color: C.amber,
  },
  score: {
    fontWeight: 800,
    color: C.amber,
  },
  sample: {
    color: C.text,
    fontFamily: "'Consolas', 'SFMono-Regular', monospace",
    fontSize: '12px',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  closeBtn: {
    appearance: 'none',
    border: 'none',
    backgroundColor: 'rgba(255, 255, 255, 0.10)',
    color: C.amber,
    borderRadius: '8px',
    padding: '5px 7px',
    cursor: 'pointer',
    fontSize: '11px',
    fontWeight: 700,
    flexShrink: 0,
  },
};

function truncateSample(value, max = 42) {
  if (!value) return '-';
  return value.length > max ? `${value.slice(0, max - 3)}...` : value;
}

export function AlertBanner({ alert, onDismiss }) {
  useEffect(() => {
    if (!alert) return undefined;
    const timer = window.setTimeout(() => onDismiss?.(), AUTO_DISMISS_MS);
    return () => window.clearTimeout(timer);
  }, [alert, onDismiss]);

  if (!alert) return null;

  return (
    <>
      <style>
        {`
          @keyframes alert-toast-in {
            from {
              opacity: 0;
              transform: translateY(8px);
            }
            to {
              opacity: 1;
              transform: translateY(0);
            }
          }
        `}
      </style>
      <div style={styles.root}>
        <div style={styles.card} role="alert" aria-live="assertive">
          <span style={styles.icon} />
          <div style={styles.textWrap}>
            <div style={styles.title}>High-Confidence Block</div>
            <div style={styles.meta}>
              <span style={styles.attackType}>{alert.attack_type || 'unknown'}</span>
              <span>score <span style={styles.score}>{Number(alert.score ?? 0).toFixed(4)}</span></span>
            </div>
            <div style={styles.sample}>{truncateSample(alert.sample)}</div>
          </div>
          <button type="button" style={styles.closeBtn} onClick={onDismiss}>
            Dismiss
          </button>
        </div>
      </div>
    </>
  );
}
