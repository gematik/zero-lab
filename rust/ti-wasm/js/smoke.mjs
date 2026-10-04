// The built package in Node on the real TSLs: the expected verdicts, each one
// cross-checked with `ti pki tsl verify` of the same checkout; then certificates checked
// with `TrustContext`, each cross-checked with `ti pki verify --offline` on a cache seeded
// with the same TSL and roots.
//
//   node ti-wasm/js/smoke.mjs <pkg dir> <dir of real TSLs> <ti binary>

import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { performance } from 'node:perf_hooks';
import { pathToFileURL } from 'node:url';

const [pkg, real, ti] = process.argv.slice(2).map((p) => resolve(p));
if (!ti) {
  console.error('usage: smoke.mjs <pkg dir> <dir of real TSLs> <ti binary>');
  process.exit(2);
}

const wasm = await import(pathToFileURL(join(pkg, 'ti_wasm.js')).href);
let started = performance.now();
wasm.initSync({ module: readFileSync(join(pkg, 'ti_wasm_bg.wasm')) });
console.log(`init ${(performance.now() - started).toFixed(0)} ms  ${wasm.version()}`);

// Within the validity of pu-10333, pu-10334 and tu-10713; tu-10687 is long past.
const NOW = '2026-10-02T00:00:00Z';
const cases = [
  { file: 'pu-10334.xml', env: 'prod', result: 'valid' },
  { file: 'pu-10333.xml', env: 'prod', result: 'valid' },
  { file: 'tu-10713.xml', env: 'test', result: 'valid' },
  { file: 'tu-10687.xml', env: 'test', result: 'invalid', code: 'validity_warning_2' },
  { file: 'tu-10713.xml', env: 'prod', result: 'invalid', code: 'certificate_not_valid_math' },
];

const state = mkdtempSync(join(tmpdir(), 'ti-wasm-smoke-'));
const plain = (fp) => fp.replaceAll(':', '').toLowerCase();
let failed = 0;
const expect = (what, actual, expected) => {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    console.error(`  ${what}: ${JSON.stringify(actual)}, expected ${JSON.stringify(expected)}`);
    failed++;
  }
};

for (const c of cases) {
  const xml = readFileSync(join(real, c.file));
  started = performance.now();
  const view = JSON.parse(wasm.verify_tsl(xml, c.env, NOW, undefined, 0));
  const ms = (performance.now() - started).toFixed(0);

  let cli;
  try {
    cli = JSON.parse(
      execFileSync(ti, ['pki', 'tsl', 'verify', join(real, c.file), '--env', c.env, '--at', NOW, '--format', 'json'], {
        env: { ...process.env, XDG_STATE_HOME: state, TI_CACHE_DIR: state },
      }),
    );
  } catch (e) {
    // Exit 1 is an invalid list, still a report.
    cli = JSON.parse(e.stdout);
  }

  const counts = view.counts ? `${view.counts.cas_kept}/${view.counts.cas_listed} CAs, ${view.counts.ocsp} OCSP` : '-';
  const warnings = view.signature?.warnings.map((w) => w.code) ?? [];
  console.log(
    `${c.file} ${c.env.padEnd(4)} ${view.result.padEnd(7)} ${(view.error?.code ?? warnings.join(',')).padEnd(28)} ${counts.padEnd(24)} ${ms} ms`,
  );

  expect('result', view.result, c.result);
  expect('error', view.error?.code ?? null, c.code ?? null);
  expect('cli result', cli.result, view.result);
  expect('cli code', cli.code, view.error?.code ?? null);
  if (view.result === 'valid') {
    expect('sequence number', view.list.sequence_number, cli.sequence_number);
    expect('CAs', view.counts.cas_listed, cli.cas);
    expect('warnings', warnings, cli.warnings.map((w) => w.code));
    expect('signer', view.signature.signer, plain(cli.signer.sha256));
    expect('TSL signer CA', view.signature.tsl_signer_ca, plain(cli.anchor.sha256));

    const pem = view.certificates[view.signature.signer].pem;
    const described = JSON.parse(wasm.describe_certificate(new TextEncoder().encode(pem), NOW));
    expect('signer type', described.certificates[0].certificate_type, 'C.TSL.SIG');
  }
}

for (const call of [
  () => wasm.verify_tsl(new Uint8Array(), 'moon', NOW, undefined, 0),
  () => wasm.verify_tsl(new Uint8Array(), 'prod', 'yesterday', undefined, 0),
  () => wasm.describe_certificate(new Uint8Array([1, 2, 3]), NOW),
]) {
  try {
    call();
    console.error('  a caller mistake did not throw');
    failed++;
  } catch (e) {
    if (!(e instanceof Error)) {
      console.error(`  a caller mistake threw ${e}, not an Error`);
      failed++;
    }
  }
}

// ---- TrustContext ------------------------------------------------------------------

const rust = resolve(new URL('../..', import.meta.url).pathname);
const fixture = (name) => join(rust, 'ti-pki/tests/fixtures', name);

/** A ti cache holding `tsl` and the embedded roots of `env`, as if just downloaded. */
function seededCache(env, tslFile) {
  const dir = mkdtempSync(join(tmpdir(), `ti-wasm-check-${env}-`));
  const urls = JSON.parse(wasm.trust_urls(env));
  const roots = join(rust, 'ti-pki/src', env === 'prod' ? 'roots-prod.json' : 'roots-nonprod.json');
  for (const [kind, url, body] of [
    ['roots', urls.roots_url, roots],
    ['tsl', urls.tsl_url, join(real, tslFile)],
  ]) {
    const id = createHash('sha256').update(url).digest().subarray(0, 8).toString('hex');
    const base = join(dir, 'ti-pki/v1', kind);
    mkdirSync(base, { recursive: true });
    writeFileSync(join(base, `${id}.body`), readFileSync(body));
    const meta = { etag: '"fixture"', last_modified: null, fetched_at: Math.floor(Date.now() / 1000), max_age_secs: null };
    writeFileSync(join(base, `${id}.json`), JSON.stringify(meta));
  }
  return dir;
}

/** A certificate of the production TSL view, as PEM, by its common name. */
function listedPem(cn) {
  const view = JSON.parse(wasm.verify_tsl(readFileSync(join(real, 'pu-10334.xml')), 'prod', NOW, undefined, 0));
  return Object.values(view.certificates).find((c) => c.subject.startsWith(`CN=${cn},`)).pem;
}

const checks = [
  { env: 'ref', tsl: 'tu-10713.xml', file: fixture('smcb-ee-test-only.pem'), result: 'valid' },
  { env: 'ref', tsl: 'tu-10713.xml', file: fixture('admission-2.pem'), result: 'valid' },
  { env: 'prod', tsl: 'pu-10334.xml', file: fixture('tsl-signing-unit-6.pem'), result: 'valid' },
  { env: 'prod', tsl: 'pu-10334.xml', file: fixture('smcb-ee-test-only.pem'), result: 'invalid' },
  { env: 'prod', tsl: 'pu-10334.xml', pem: 'MESIG.SMCB-OCSP2', result: 'invalid' },
];

const contexts = new Map();
const scratch = mkdtempSync(join(tmpdir(), 'ti-wasm-pem-'));
for (const c of checks) {
  let ctx = contexts.get(c.env);
  if (!ctx) {
    started = performance.now();
    ctx = new wasm.TrustContext(readFileSync(join(real, c.tsl)), c.env, NOW, undefined, 0);
    console.log(`TrustContext ${c.env} ${(performance.now() - started).toFixed(0)} ms ${ctx.tsl()}`);
    contexts.set(c.env, ctx);
  }
  let file = c.file;
  if (c.pem) {
    file = join(scratch, `${c.pem}.pem`);
    writeFileSync(file, listedPem(c.pem));
  }
  started = performance.now();
  const report = JSON.parse(ctx.check(readFileSync(file), NOW));
  const ms = (performance.now() - started).toFixed(0);

  const cache = seededCache(c.env, c.tsl);
  let cli;
  try {
    cli = JSON.parse(
      execFileSync(ti, ['pki', 'verify', file, '--env', c.env, '--offline', '--at', NOW, '--format', 'json'], {
        env: { ...process.env, TI_CACHE_DIR: cache, XDG_STATE_HOME: cache },
      }),
    );
  } catch (e) {
    cli = JSON.parse(e.stdout);
  }

  const names = report.tree.filter((n) => n.role !== 'issuer').map((n) => n.name);
  const errors = report.errors.map((e) => e.code);
  console.log(
    `check ${c.env.padEnd(4)} ${report.tree[0].name.padEnd(40)} ${report.result.padEnd(7)} ${(report.certificate_type ?? '-').padEnd(10)} ${(errors.join(',') || '-').padEnd(20)} ${ms} ms`,
  );
  expect('check result', report.result, c.result);
  expect('cli valid', cli.valid, report.result === 'valid');
  expect('cli type', cli.certificate_type, report.certificate_type);
  expect('cli chain', cli.chain.map((link) => link.common_name), names);
  expect('cli errors', cli.errors.map((e) => e.code).sort(), [...errors].sort());
}

if (failed) {
  console.error(`smoke: ${failed} mismatches`);
  process.exit(1);
}
console.log('smoke: ok');
