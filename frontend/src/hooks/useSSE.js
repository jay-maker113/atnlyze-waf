// frontend/src/hooks/useSSE.js
// Manages a single EventSource connection to /stream.
// Reconnects automatically on disconnect with exponential backoff.

import { useState, useEffect, useRef, useCallback } from 'react';
import { getSSEUrl } from '../api';

const RECONNECT_BASE_MS = 1000;
const RECONNECT_MAX_MS = 30000;
const RECONNECT_FACTOR = 2;

export function useSSE(onEvent) {
  const [connected, setConnected] = useState(false);

  const esRef = useRef(null);
  const reconnectDelayRef = useRef(RECONNECT_BASE_MS);
  const reconnectTimerRef = useRef(null);
  const mountedRef = useRef(true);
  const onEventRef = useRef(onEvent);
  const connectRef = useRef(() => {});

  useEffect(() => {
    onEventRef.current = onEvent;
  }, [onEvent]);

  const cleanupConnection = useCallback(() => {
    clearTimeout(reconnectTimerRef.current);
    reconnectTimerRef.current = null;

    if (esRef.current) {
      esRef.current.close();
      esRef.current = null;
    }
  }, []);

  useEffect(() => {
    connectRef.current = () => {
      if (!mountedRef.current) return;

      cleanupConnection();

      const es = new EventSource(getSSEUrl());
      esRef.current = es;

      es.onopen = () => {
        if (!mountedRef.current) return;
        setConnected(true);
        reconnectDelayRef.current = RECONNECT_BASE_MS;
      };

      es.onmessage = (e) => {
        if (!mountedRef.current) return;

        try {
          const data = JSON.parse(e.data);
          if (data.type === 'connected') return;
          onEventRef.current?.(data);
        } catch {
          // Ignore malformed SSE payloads.
        }
      };

      es.onerror = () => {
        if (!mountedRef.current) return;

        setConnected(false);
        cleanupConnection();

        reconnectTimerRef.current = setTimeout(() => {
          if (!mountedRef.current) return;

          reconnectDelayRef.current = Math.min(
            reconnectDelayRef.current * RECONNECT_FACTOR,
            RECONNECT_MAX_MS
          );

          connectRef.current();
        }, reconnectDelayRef.current);
      };
    };
  }, [cleanupConnection]);

  useEffect(() => {
    mountedRef.current = true;
    connectRef.current();

    return () => {
      mountedRef.current = false;
      cleanupConnection();
    };
  }, [cleanupConnection]);

  return { connected };
}
