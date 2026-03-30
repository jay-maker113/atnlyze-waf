// frontend/src/components/ConnectionDot.jsx
// Header connection indicator for SSE state.

import { C } from '../theme';

const styles = {
  wrap: {
    position: 'relative',
    width: '12px',
    height: '12px',
    display: 'inline-flex',
    alignItems: 'center',
    justifyContent: 'center',
    flexShrink: 0,
  },
  dot: {
    width: '10px',
    height: '10px',
    borderRadius: '999px',
    position: 'relative',
    zIndex: 2,
  },
  pulse: {
    position: 'absolute',
    inset: '-4px',
    borderRadius: '999px',
    zIndex: 1,
    opacity: 0.45,
    animation: 'connection-pulse 1.8s ease-out infinite',
  },
};

export function ConnectionDot({ connected }) {
  const liveColor = connected ? C.emerald : C.red;

  return (
    <>
      <style>
        {`
          @keyframes connection-pulse {
            0% {
              transform: scale(0.75);
              opacity: 0.55;
            }
            70% {
              transform: scale(1.8);
              opacity: 0;
            }
            100% {
              transform: scale(1.8);
              opacity: 0;
            }
          }
        `}
      </style>

      <span style={styles.wrap} aria-label={connected ? 'connected' : 'reconnecting'}>
        {connected ? (
          <span
            style={{
              ...styles.pulse,
              backgroundColor: liveColor,
            }}
          />
        ) : null}

        <span
          style={{
            ...styles.dot,
            backgroundColor: liveColor,
            boxShadow: connected
              ? `0 0 12px ${C.emerald}`
              : `0 0 10px rgba(239, 68, 68, 0.45)`,
          }}
        />
      </span>
    </>
  );
}
