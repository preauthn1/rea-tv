#!/usr/bin/env node

import http from 'node:http';
import { randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import { access } from 'node:fs/promises';
import { constants } from 'node:fs';
import { resolve } from 'node:path';

const port = Number(process.env.REA_BACKEND_PORT ?? 8787);
const host = process.env.REA_BACKEND_HOST ?? '127.0.0.1';
const bearerToken = process.env.REA_BACKEND_TOKEN;
const mihomoController = process.env.MIHOMO_CONTROLLER_URL?.replace(/\/$/, '') ?? null;
const mihomoSecret = process.env.MIHOMO_SECRET ?? '';
const reaRoot = resolve(process.env.REA_ROOT ?? '../rea');
const dispatcher = resolve(reaRoot, 'scripts/rea.mjs');
const jobs = new Map();
const evidence = [];

const catalog = [
  { id: 'android-apk', name: 'Android APK', operations: ['inspect_android_package', 'search_android_classes', 'inspect_android_class', 'inspect_android_method', 'trace_android_references', 'inspect_android_jni_bindings'] },
  { id: 'flutter', name: 'Flutter AOT', operations: ['identify_flutter_build', 'inspect_dart_aot'] },
  { id: 'native', name: 'Native binary', operations: ['binary_overview', 'inspect_binary_layout', 'inspect_native_exports', 'inspect_binary_hardening', 'search_bytes', 'inspect_native_load_image'] },
  { id: 'javascript', name: 'JavaScript / Electron', operations: ['analyze_javascript_application', 'inspect_electron_fuses', 'trace_application_feature'] },
  { id: 'managed', name: '.NET managed code', operations: ['inspect_managed_artifact', 'inspect_managed_members', 'project_managed_application_graph'] },
  { id: 'firmware', name: 'Firmware', operations: ['inspect_firmware_regions', 'extract_firmware'] },
  { id: 'pcap', name: 'Network capture', operations: ['inspect_pcap_client', 'inspect_pcap_capture', 'inspect_web_network_capture'] },
  { id: 'evidence', name: 'Evidence ledger', operations: ['inspect_evidence_bundle', 'inspect_analysis_view'] },
];

function authorized(req) {
  if (!bearerToken) return true;
  return req.headers.authorization === `Bearer ${bearerToken}`;
}
function safeTarget(target) {
  if (typeof target !== 'string' || target.length === 0 || target.length > 4096) throw new Error('invalid target');
  if (target.includes('\0') || target.startsWith('-')) throw new Error('target must be a path or admitted identifier');
  return target;
}
async function mihomo(path, options = {}) {
  if (!mihomoController) throw new Error('mihomo controller is not configured');
  const headers = { ...(options.body ? {'content-type': 'application/json'} : {}), ...(mihomoSecret ? {authorization: `Bearer ${mihomoSecret}`} : {}) };
  const response = await fetch(`${mihomoController}${path}`, { method: options.method ?? 'GET', headers, body: options.body ? JSON.stringify(options.body) : undefined });
  const text = await response.text();
  if (!response.ok) throw new Error(`mihomo ${response.status}: ${text.slice(0, 1000)}`);
  return text ? JSON.parse(text) : null;
}
function json(res, status, value) {
  const body = JSON.stringify(value);
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
  res.end(body);
}
const cliCommandByOperation = {
  binary_overview: 'analyze',
};
function operationToCommand(operation) { return cliCommandByOperation[operation] ?? operation.replaceAll('_', '-'); }
function readJson(req) {
  return new Promise((resolveBody, reject) => {
    let body = '';
    req.on('data', chunk => { body += chunk; if (body.length > 1024 * 1024) reject(new Error('request too large')); });
    req.on('end', () => { try { resolveBody(body ? JSON.parse(body) : {}); } catch (e) { reject(e); } });
    req.on('error', reject);
  });
}
function cliArgs(operation, target, parameters) {
  const args = [operationToCommand(operation), target];
  if (['inspect_android_package', 'inspect_android_class', 'inspect_android_method', 'trace_android_references', 'inspect_android_jni_bindings', 'inspect_dart_aot', 'inspect_binary_layout', 'inspect_native_exports', 'inspect_binary_hardening', 'inspect_native_load_image', 'inspect_managed_artifact', 'inspect_managed_members', 'inspect_firmware_regions', 'inspect_pcap_capture'].includes(operation)) args.push('--json');
  if (operation === 'search_android_classes' && typeof parameters.query === 'string') args.push(parameters.query);
  if (operation === 'inspect_android_class' && typeof parameters.class_name === 'string') args.push(parameters.class_name);
  if (operation === 'inspect_android_method' && typeof parameters.class_name === 'string' && typeof parameters.method_name === 'string') args.push(parameters.class_name, parameters.method_name);
  if (operation === 'trace_android_references' && typeof parameters.class_name === 'string') args.push(parameters.class_name);
  if (operation === 'inspect_dart_aot' && typeof parameters.abi === 'string') args.push('--abi', parameters.abi);
  if (operation === 'inspect_managed_members' && Array.isArray(parameters.type_names)) for (const type of parameters.type_names) args.push('--type', `${type}`);
  return args;
}
async function runJob(job) {
  job.status = 'running'; job.message = `Running ${job.operation}`;
  try { await access(dispatcher, constants.R_OK); } catch { throw new Error(`REA dispatcher not found: ${dispatcher}`); }
  const parameters = job.parameters ?? {};
  const child = spawn(process.execPath, [dispatcher, ...cliArgs(job.operation, job.target, parameters)], { cwd: reaRoot, env: process.env, stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = ''; let stderr = '';
  child.stdout.on('data', b => { stdout += b.toString(); if (stdout.length > 8 * 1024 * 1024) child.kill(); });
  child.stderr.on('data', b => { stderr += b.toString(); });
  const code = await new Promise(resolveExit => child.on('close', resolveExit));
  if (code !== 0) throw new Error(stderr.trim() || `REA exited with ${code}`);
  let normalized; try { normalized = JSON.parse(stdout); } catch { normalized = { output: stdout.trim() }; }
  const record = { evidence_id: `ev-${randomUUID()}`, operation: job.operation, subject: { name: job.target }, normalized_result: normalized, confidence: 'observed', authority: 'shipped-artifact', limitations: stderr ? [stderr.trim()] : [], locations: [] };
  evidence.unshift(record); evidence.splice(50);
  job.status = 'completed'; job.message = 'Evidence recorded'; job.evidence_id = record.evidence_id;
}
function startJob(operation, target, parameters) {
  const job = { analysis_id: `an-${randomUUID()}`, operation, target, parameters, status: 'queued', created_at: new Date().toISOString() };
  jobs.set(job.analysis_id, job);
  runJob(job).catch(error => { job.status = 'failed'; job.message = error instanceof Error ? error.message : String(error); });
  return job;
}
const server = http.createServer(async (req, res) => {
  if (!authorized(req)) return json(res, 401, { error: 'authentication required' });
  try {
    const url = new URL(req.url, `http://${req.headers.host}`);
    if (req.method === 'GET' && url.pathname === '/api/capabilities') return json(res, 200, { families: catalog });
    if (req.method === 'GET' && url.pathname === '/api/mihomo/status') return json(res, 200, { configured: Boolean(mihomoController), controller: mihomoController ? 'configured' : null, version: await mihomo('/version'), configs: await mihomo('/configs') });
    if (req.method === 'GET' && url.pathname === '/api/mihomo/proxies') return json(res, 200, await mihomo('/proxies'));
    if (req.method === 'GET' && url.pathname === '/api/mihomo/connections') return json(res, 200, await mihomo('/connections'));
    if (req.method === 'GET' && url.pathname === '/api/mihomo/rules') return json(res, 200, await mihomo('/rules'));
    const proxyMatch = url.pathname.match(/^\/api\/mihomo\/proxies\/([^/]+)$/);
    if (req.method === 'PUT' && proxyMatch) { const body = await readJson(req); return json(res, 200, await mihomo(`/proxies/${encodeURIComponent(proxyMatch[1])}`, { method: 'PUT', body })); }
    if (req.method === 'DELETE' && url.pathname === '/api/mihomo/connections') return json(res, 204, await mihomo('/connections', { method: 'DELETE' }));
    if (req.method === 'PATCH' && url.pathname === '/api/mihomo/configs') { const body = await readJson(req); return json(res, 204, await mihomo('/configs', { method: 'PATCH', body })); }
    if (req.method === 'GET' && url.pathname === '/api/evidence') return json(res, 200, evidence.slice(0, Math.min(Number(url.searchParams.get('limit') ?? 50), 50)));
    const jobMatch = url.pathname.match(/^\/api\/analyses\/([^/]+)$/);
    if (req.method === 'GET' && jobMatch) { const job = jobs.get(jobMatch[1]); return job ? json(res, 200, job) : json(res, 404, { error: 'analysis not found' }); }
    if (req.method === 'POST' && url.pathname === '/api/analyses') {
      const body = await readJson(req); if (typeof body.operation !== 'string') return json(res, 400, { error: 'operation and target are required' });
      const target = safeTarget(body.target);
      if (!catalog.some(f => f.operations.includes(body.operation))) return json(res, 400, { error: 'operation is not in catalog' });
      return json(res, 202, startJob(body.operation, target, body.parameters && typeof body.parameters === 'object' ? body.parameters : {}));
    }
    return json(res, 404, { error: 'not found' });
  } catch (error) { return json(res, 400, { error: error instanceof Error ? error.message : String(error) }); }
});
server.listen(port, host, () => console.log(`REA TV backend listening on ${host}:${port}; REA_ROOT=${reaRoot}; auth=${bearerToken ? 'bearer' : 'disabled'}`));
