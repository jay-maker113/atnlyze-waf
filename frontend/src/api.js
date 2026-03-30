// src/atnlyze/frontend/src/api.js
// Single source of all HTTP calls to the FastAPI backend.
// Never call axios directly from components — import from here.

import axios from 'axios';

const BASE = import.meta.env.VITE_API_BASE || 'http://localhost:8001';

const api = axios.create({
  baseURL: BASE,
  timeout: 10000,
});

// ── Stats ─────────────────────────────────────────────────────────────────────

export async function fetchStats() {
  const res = await api.get('/stats');
  return res.data;
}

export async function resetStats() {
  const res = await api.post('/stats/reset');
  return res.data;
}

// ── Demo controls ─────────────────────────────────────────────────────────────

export async function startBenign() {
  const res = await api.post('/demo/start-benign');
  return res.data;
}

export async function startAttack() {
  const res = await api.post('/demo/start-attack');
  return res.data;
}

export async function stopDemo() {
  const res = await api.post('/demo/stop');
  return res.data;
}

export async function fetchDemoStatus() {
  const res = await api.get('/demo/status');
  return res.data;
}

// ── SSE URL (not axios — EventSource handles this natively) ───────────────────
// Components import this to construct the EventSource, not to fetch.

export function getSSEUrl() {
  return `${BASE}/stream`;
}