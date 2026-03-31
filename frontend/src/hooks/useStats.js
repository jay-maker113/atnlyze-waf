// frontend/src/hooks/useStats.js
// Polls /stats every 2 seconds and maintains a 60-point sparkline history.
// Also tracks demo process status via /demo/status.

import { useState, useEffect, useRef, useCallback } from 'react';
import { fetchStats, fetchDemoStatus } from '../api';

const POLL_INTERVAL_MS = 2000;
const SPARKLINE_POINTS = 60; // 60 x 2s = 2-minute rolling window

const EMPTY_STATS = {
  total: 0,
  blocked: 0,
  allowed: 0,
  block_rate: 0,
  avg_latency_ms: 0,
  p50_latency_ms: 0,
  p95_latency_ms: 0,
  current_rps_2s: 0,
  peak_rps_2s: 0,
  recent_block_rate_30s: 0,
  recent_window_seconds: 30,
  recent_events_30s: 0,
  recent_alert_count_30s: 0,
  recent_avg_confidence: 0,
  previous_avg_confidence: 0,
  confidence_drift_delta: 0,
  high_confidence_blocks: 0,
  uncertain_scores: 0,
  engine_name: '',
  uptime_since_reset_s: 0,
  baseline_blocked: 0,
  transformer_blocked: 0,
  baseline_avg_latency_ms: 0,
  transformer_avg_latency_ms: 0,
  comparison_total: 0,
  comparison_agreement_count: 0,
  comparison_agreement_rate: 0,
  comparison_disagreement_count: 0,
  recent_disagreement_events: [],
  unique_paths_seen: 0,
  attack_diversity: 0,
  unknown_blocked: 0,
  unknown_allowed: 0,
  top_targeted_paths: [],
  attack_type_counts: {},
  score_distribution: {},
  baseline_score_distribution: {},
  transformer_score_distribution: {},
  recent_events: [],
};

const EMPTY_DEMO_STATUS = {
  benign: 'stopped',
  attack: 'stopped',
  feed: 'stopped',
};

export function useStats() {
  const [stats, setStats] = useState(EMPTY_STATS);
  const [sparkline, setSparkline] = useState([]);
  const [demoStatus, setDemoStatus] = useState(EMPTY_DEMO_STATUS);
  const [error, setError] = useState(null);
  const mountedRef = useRef(true);

  const poll = useCallback(async () => {
    if (!mountedRef.current) return;

    try {
      const [statsData, demoData] = await Promise.all([
        fetchStats(),
        fetchDemoStatus(),
      ]);

      if (!mountedRef.current) return;

      setStats(statsData);
      setError(null);

      const point = {
        t: Date.now(),
        rps: Number(statsData.current_rps_2s ?? 0),
      };
      setSparkline((prev) => {
        const next = [...prev, point];
        return next.length > SPARKLINE_POINTS
          ? next.slice(next.length - SPARKLINE_POINTS)
          : next;
      });

      setDemoStatus({
        benign: demoData.benign ?? 'stopped',
        attack: demoData.attack ?? 'stopped',
        feed: demoData.feed ?? 'stopped',
      });
    } catch (err) {
      if (!mountedRef.current) return;
      setError(err?.message ?? 'Failed to fetch stats');
    }
  }, []);

  useEffect(() => {
    mountedRef.current = true;

    const initialTimer = setTimeout(() => {
      void poll();
    }, 0);

    const timer = setInterval(() => {
      void poll();
    }, POLL_INTERVAL_MS);

    return () => {
      mountedRef.current = false;
      clearTimeout(initialTimer);
      clearInterval(timer);
    };
  }, [poll]);

  return { stats, sparkline, demoStatus, error };
}
