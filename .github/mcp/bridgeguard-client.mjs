import { spawn } from 'child_process';
import fs from 'fs';
import path from 'path';

const server = spawn('npx', ['-y', 'bridgeguard-mcp'], {
  stdio: ['pipe', 'pipe', 'inherit'],
});

let buffer = '';
let msgId = 1;
const pending = new Map();

server.stdout.on('data', (d) => {
  buffer += d.toString();
  let i;
  while ((i = buffer.indexOf('\n')) !== -1) {
    const line = buffer.slice(0, i).trim();
    buffer = buffer.slice(i + 1);
    if (!line) continue;
    try {
      const m = JSON.parse(line);
      if (m.id && pending.has(m.id)) {
        pending.get(m.id)(m);
        pending.delete(m.id);
      }
    } catch (_) {}
  }
});

function send(method, params = {}) {
  return new Promise((resolve) => {
    const id = msgId++;
    pending.set(id, resolve);
    server.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
  });
}

function notify(method, params = {}) {
  server.stdin.write(JSON.stringify({ jsonrpc: '2.0', method, params }) + '\n');
}

(async () => {
  // ── 1. Handshake ────────────────────────────────────────────────
  const init = await send('initialize', {
    protocolVersion: '2024-11-05',
    capabilities: {},
    clientInfo: { name: 'audit-workflow', version: '1.0.0' },
  });

  if (!init || !init.result) {
    console.error('BRIDGEGUARD_INIT_FAILED — no result from initialize');
    server.kill();
    process.exit(1);
  }

  // MCP requires this one-way notification AFTER the initialize response
  notify('notifications/initialized', {});

  // Give the server a moment to register the initialized state
  await new Promise((r) => setTimeout(r, 500));

  // ── 2. Find a Solidity target ───────────────────────────────────
  const candidates = [];
  for (const dir of ['src/contracts/adapters', 'src', 'contracts']) {
    const abs = path.resolve(dir);
    if (!fs.existsSync(abs)) continue;
    for (const f of fs.readdirSync(abs)) {
      if (f.endsWith('.sol') && !f.endsWith('.t.sol')) {
        candidates.push(path.join(dir, f));
      }
    }
    if (candidates.length) break;
  }

  const targetFile = process.argv[2] || candidates[0];
  if (!targetFile || !fs.existsSync(targetFile)) {
    console.error('No Solidity target found for BridgeGuard');
    server.kill();
    process.exit(1);
  }

  const source = fs.readFileSync(targetFile, 'utf8');
  console.error(`Scanning: ${targetFile}`);

  // ── 3. Call the tool (source first, fallback to contractPath) ───
  let result = await send('tools/call', {
    name: 'bridge_scan_contract',
    arguments: { source },
  });

  if (result.error || (result.result && result.result.isError)) {
    result = await send('tools/call', {
      name: 'bridge_scan_contract',
      arguments: { contractPath: targetFile },
    });
  }

  // ── 4. Write report (absolute path to avoid cwd ambiguity) ──────
  const outPath = path.resolve(process.cwd(), '..', 'bridgeguard-report.json');
  fs.writeFileSync(outPath, JSON.stringify(result, null, 2));
  console.error(`BridgeGuard report saved: ${outPath}`);

  server.kill();
  process.exit(0);
})().catch((e) => {
  console.error('BRIDGEGUARD_CLIENT_FATAL', e);
  server.kill();
  process.exit(1);
});
