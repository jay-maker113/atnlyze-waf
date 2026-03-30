// frontend/src/components/ArenaPanel.jsx
// Horizontal traffic arena with top-to-bottom packet flow.

import { useMemo } from 'react';

import { C } from '../theme';

const COLUMNS = [
  { key: 'scanner', label: 'Scanner' },
  { key: 'injection', label: 'Injection' },
  { key: 'file', label: 'File' },
  { key: 'other', label: 'Other' },
];

const styles = {
  root: {
    position: 'relative',
    width: '100%',
    height: '100%',
    minHeight: '240px',
    display: 'block',
    overflow: 'hidden',
    background:
      'radial-gradient(circle at 20% 20%, rgba(59,130,246,0.07) 0%, rgba(59,130,246,0) 30%), linear-gradient(180deg, #0F1923 0%, #0D1822 100%)',
  },
  gridOverlay: {
    position: 'absolute',
    inset: 0,
    zIndex: 0,
    backgroundImage:
      'linear-gradient(rgba(30,45,61,0.6) 1px, transparent 1px), linear-gradient(90deg, rgba(30,45,61,0.5) 1px, transparent 1px)',
    backgroundSize: '100% 25%, 25% 100%',
    opacity: 0.55,
    pointerEvents: 'none',
  },
  header: {
    position: 'absolute',
    top: '14px',
    left: '18px',
    right: '18px',
    display: 'flex',
    alignItems: 'flex-start',
    justifyContent: 'space-between',
    zIndex: 3,
    pointerEvents: 'none',
  },
  headerLeft: {
    minWidth: 0,
  },
  headerRight: {
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
    flexWrap: 'wrap',
    justifyContent: 'flex-end',
  },
  title: {
    color: C.text,
    fontSize: '18px',
    fontWeight: 800,
    marginBottom: '4px',
  },
  subtitle: {
    color: C.muted,
    fontSize: '12px',
  },
  counter: {
    padding: '8px 10px',
    borderRadius: '12px',
    border: `1px solid ${C.grid}`,
    backgroundColor: 'rgba(22, 32, 48, 0.92)',
    color: C.amber,
    fontSize: '12px',
    fontWeight: 800,
    fontVariantNumeric: 'tabular-nums',
  },
  columnLine: {
    position: 'absolute',
    top: '0',
    bottom: '0',
    width: '1px',
    borderLeft: `1px dashed rgba(100, 116, 139, 0.28)`,
    zIndex: 1,
  },
  columnLabel: {
    position: 'absolute',
    top: '74px',
    transform: 'translateX(-50%)',
    padding: '4px 8px',
    borderRadius: '999px',
    border: `1px solid ${C.grid}`,
    backgroundColor: 'rgba(22, 32, 48, 0.88)',
    color: C.muted,
    fontSize: '11px',
    fontWeight: 700,
    letterSpacing: '0.04em',
    textTransform: 'uppercase',
    zIndex: 2,
  },
  packet: {
    position: 'absolute',
    top: '84px',
    width: '14px',
    height: '14px',
    borderRadius: '999px',
    transform: 'translate(-50%, -50%)',
    willChange: 'transform, opacity',
    zIndex: 4,
  },
  strike: {
    position: 'absolute',
    left: '50%',
    top: '-78px',
    width: '2px',
    height: '72px',
    transform: 'translateX(-50%)',
    borderRadius: '999px',
    background:
      'linear-gradient(180deg, rgba(255,255,255,0.05) 0%, rgba(255,255,255,0.95) 35%, rgba(245,158,11,1) 100%)',
    boxShadow: '0 0 14px rgba(245,158,11,0.85)',
    opacity: 0,
    pointerEvents: 'none',
  },
  packetLabel: {
    position: 'absolute',
    top: '-18px',
    left: '50%',
    transform: 'translateX(-50%)',
    padding: '1px 6px',
    borderRadius: '999px',
    backgroundColor: 'rgba(22, 32, 48, 0.96)',
    border: `1px solid rgba(239, 68, 68, 0.4)`,
    color: C.red,
    fontSize: '9px',
    fontWeight: 800,
    letterSpacing: '0.04em',
    textTransform: 'uppercase',
    whiteSpace: 'nowrap',
    boxShadow: '0 0 10px rgba(0,0,0,0.25)',
  },
  legend: {
    display: 'flex',
    gap: '12px',
    flexWrap: 'wrap',
  },
  legendItem: {
    display: 'inline-flex',
    alignItems: 'center',
    gap: '8px',
    padding: '6px 10px',
    borderRadius: '999px',
    border: '1px solid rgba(100, 116, 139, 0.38)',
    backgroundColor: 'rgba(31, 43, 61, 0.98)',
    color: C.text,
    fontSize: '11px',
    boxShadow: '0 4px 14px rgba(0,0,0,0.18)',
  },
  legendDot: {
    width: '8px',
    height: '8px',
    borderRadius: '999px',
    flexShrink: 0,
  },
  empty: {
    position: 'absolute',
    left: '50%',
    top: '62%',
    transform: 'translate(-50%, -50%)',
    textAlign: 'center',
    color: C.muted,
    fontSize: '13px',
    zIndex: 1,
    padding: '16px 20px',
    borderRadius: '16px',
    border: `1px dashed ${C.grid}`,
    backgroundColor: 'rgba(15, 25, 35, 0.55)',
    minWidth: '280px',
  },
  bottomLine: {
    position: 'absolute',
    left: '0',
    right: '0',
    bottom: '24px',
    borderTop: `1px dashed rgba(245, 158, 11, 0.18)`,
    zIndex: 1,
    pointerEvents: 'none',
  },
};

function groupForAttackType(attackType) {
  if (attackType === 'scanner') return 'scanner';
  if (['sqli', 'xss', 'cmdi', 'php', 'ldap', 'nosql'].includes(attackType)) return 'injection';
  if (['lfi', 'rfi', 'path'].includes(attackType)) return 'file';
  return 'other';
}

function buildPackets(events) {
  const laneCount = {
    scanner: 0,
    injection: 0,
    file: 0,
    other: 0,
  };

  return events.map((event) => {
    const group = groupForAttackType(event.attack_type);
    const index = laneCount[group];
    laneCount[group] += 1;
    const jitter = ((index % 5) - 2) * 10;
    const xMap = {
      scanner: '12.5%',
      injection: '37.5%',
      file: '62.5%',
      other: '87.5%',
    };

    return {
      ...event,
      x: `calc(${xMap[group]} + ${jitter}px)`,
      color: event.decision === 'block' ? C.red : C.blue,
      durationMs: event.decision === 'block' ? 2200 : 3000,
      label: event.decision === 'block' ? (event.attack_type || 'unknown') : '',
    };
  });
}

export function ArenaPanel({ events }) {
  const packets = useMemo(() => buildPackets(events), [events]);

  return (
    <>
      <style>
        {`
          @keyframes packet-fall-benign {
            0% {
              transform: translate(-50%, -50%) translateY(0px) scale(0.85);
              opacity: 0;
            }
            10% {
              opacity: 1;
            }
            100% {
              transform: translate(-50%, -50%) translateY(var(--travel-distance)) scale(1);
              opacity: 0;
            }
          }

          @keyframes packet-fall-blocked {
            0% {
              transform: translate(-50%, -50%) translateY(0px) scale(0.88);
              opacity: 0;
            }
            10% {
              opacity: 1;
            }
            82% {
              transform: translate(-50%, -50%) translateY(calc(var(--travel-distance) - 8px)) scale(1);
              opacity: 1;
            }
            88% {
              transform: translate(-50%, -50%) translateY(var(--travel-distance)) scale(1.45);
              opacity: 1;
              box-shadow: 0 0 22px rgba(245, 158, 11, 0.95);
              background-color: #F59E0B;
            }
            100% {
              transform: translate(-50%, -50%) translateY(var(--travel-distance)) scale(0.4);
              opacity: 0;
            }
          }

          @keyframes strike-flash {
            0%, 75% {
              opacity: 0;
            }
            82% {
              opacity: 0.95;
            }
            90% {
              opacity: 0.25;
            }
            100% {
              opacity: 0;
            }
          }
        `}
      </style>
      <section style={styles.root}>
        <div style={styles.gridOverlay} />
        <div style={styles.bottomLine} />

        <div style={styles.header}>
          <div style={styles.headerLeft}>
            <div style={styles.title}>Traffic Arena</div>
            <div style={styles.subtitle}>Live packet flow, top to bottom</div>
          </div>
          <div style={styles.headerRight}>
            <div style={styles.legend}>
              <div style={styles.legendItem}>
                <span style={{ ...styles.legendDot, backgroundColor: C.blue }} />
                <span>Benign traffic</span>
              </div>
              <div style={styles.legendItem}>
                <span style={{ ...styles.legendDot, backgroundColor: C.red }} />
                <span>Blocked traffic</span>
              </div>
            </div>
            <div style={styles.counter}>{events.length} active traces</div>
          </div>
        </div>

        {COLUMNS.map((column, index) => (
          <div key={column.key}>
            {index > 0 ? <div style={{ ...styles.columnLine, left: `${index * 25}%` }} /> : null}
            <div style={{ ...styles.columnLabel, left: `${12.5 + index * 25}%` }}>{column.label}</div>
          </div>
        ))}

        {packets.map((event) => (
          <div
            key={event.id}
            style={{
              ...styles.packet,
              left: event.x,
              backgroundColor: event.color,
              boxShadow: `0 0 16px ${event.color}`,
              '--travel-distance': '132px',
              animation: event.decision === 'block'
                ? `packet-fall-blocked ${event.durationMs}ms linear forwards`
                : `packet-fall-benign ${event.durationMs}ms linear forwards`,
            }}
            title={`${event.attack_type} | ${event.decision} | ${event.path || '-'}`}
          >
            {event.decision === 'block' ? (
              <span
                style={{
                  ...styles.strike,
                  animation: `strike-flash ${event.durationMs}ms linear forwards`,
                }}
              />
            ) : null}
            {event.label ? <span style={styles.packetLabel}>{event.label}</span> : null}
          </div>
        ))}

        {!events.length ? (
          <div style={styles.empty}>
            Start benign traffic or launch an attack run.
            <br />
            Packets will fall through the arena in real time.
          </div>
        ) : null}
      </section>
    </>
  );
}
