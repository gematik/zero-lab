// The built package in Node on the real TSLs: the expected verdicts, each one
// cross-checked with `ti pki tsl verify` of the same checkout.
//
//   node ti-wasm/js/smoke.mjs <pkg dir> <dir of real TSLs> <ti binary>

import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
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

if (failed) {
  console.error(`smoke: ${failed} mismatches`);
  process.exit(1);
}
console.log('smoke: ok');
