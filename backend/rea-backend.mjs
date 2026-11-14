#!/usr/bin/env node

import http from 'node:http';
import { randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import { access } from 'node:fs/promises';
import { constants } from 'node:fs';
import { resolve } from 'node:path';

const port = Number(process.env.REA_BACKEND_PORT ?? 8787);
const reaRoot = resolve(process.env.REA_ROOT ?? '../rea');
const dispatcher = resolve(reaRoot, 'scripts/rea.mjs');
const jobs = new Map();
const evidence = [];

const catalog = [
  { id: 'android-apk', name: 'Android APK', operations: ['inspect_android_package', 'search_android_classes', 'inspect_android_class', 'inspect_android_jni_bindings'] },
  { id: 'flutter', name: 'Flutter AOT', operations: ['identify_flutter_build', 'inspect_dart_aot'] },
  { id: 'native', name: 'Native binary', operations: ['inspect_binary_layout', 'inspect_native_exports', 'inspect_binary_hardening'] },
  { id: 'javascript', name: 'JavaScript / Electron', operations: ['analyze_javascript_application', 'inspect_electron_fuses', 'trace_application_feature'] },
  { id: 'managed', name: '.NET managed code', operations: ['inspect_managed_artifact', 'inspect_managed_members', 'project_managed_application_graph'] },
  { id: 'firmware', name: 'Firmware', operations: ['inspect_firmware_regions', 'extract_firmware'] },
  { id: 'pcap', name: 'Network capture', operations: ['inspect_pcap_client', 'inspect_pcap_capture', 'inspect_web_network_capture'] },
  { id: 'evidence', name: 'Evidence ledger', operations: ['inspect_evidence_bundle', 'inspect_analysis_view'] },
];

function json(res, status, value) {
  const body = JSON.stringify(value);
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
  res.end(body);
}
function operationToCommand(operation) { return operation.replaceAll('_', '-'); }
function readJson(req) {
  return new Promise((resolveBody, reject) => {
    let body = '';
    req.on('data', chunk => { body += chunk; if (body.length > 1024 * 1024) reject(new Error('request too large')); });
    req.on('end', () => { try { resolveBody(body ? JSON.parse(body) : {}); } catch (e) { reject(e); } });
    req.on('error', reject);
  });
}
function cliArgs(operation, target, parameters) {
  const args = [operationToCommand(operation), target, '--json'];
  if (operation === 'search_android_classes' && typeof parameters.query === 'string') args.push(parameters.query);
  if (operation === 'inspect_android_class' && typeof parameters.class_name === 'string') args.push(parameters.class_name);
  if (operation === 'inspect_dart_aot' && typeof parameters.abi === 'string') args.push('--abi', parameters.abi);
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
  try {
    const url = new URL(req.url, `http://${req.headers.host}`);
    if (req.method === 'GET' && url.pathname === '/api/capabilities') return json(res, 200, { families: catalog });
    if (req.method === 'GET' && url.pathname === '/api/evidence') return json(res, 200, evidence.slice(0, Math.min(Number(url.searchParams.get('limit') ?? 50), 50)));
    const jobMatch = url.pathname.match(/^\/api\/analyses\/([^/]+)$/);
    if (req.method === 'GET' && jobMatch) { const job = jobs.get(jobMatch[1]); return job ? json(res, 200, job) : json(res, 404, { error: 'analysis not found' }); }
    if (req.method === 'POST' && url.pathname === '/api/analyses') {
      const body = await readJson(req); if (typeof body.operation !== 'string' || typeof body.target !== 'string') return json(res, 400, { error: 'operation and target are required' });
      if (!catalog.some(f => f.operations.includes(body.operation))) return json(res, 400, { error: 'operation is not in catalog' });
      return json(res, 202, startJob(body.operation, body.target, body.parameters && typeof body.parameters === 'object' ? body.parameters : {}));
    }
    return json(res, 404, { error: 'not found' });
  } catch (error) { return json(res, 400, { error: error instanceof Error ? error.message : String(error) }); }
});
server.listen(port, '0.0.0.0', () => console.log(`REA TV backend listening on :${port}; REA_ROOT=${reaRoot}`));
