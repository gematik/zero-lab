# ti-wasm

Built from [zero-lab/rust/ti-wasm](https://github.com/gematik/zero-lab/tree/main/rust/ti-wasm)
by `just wasm-build`; `VERSION.json` names the commit and the module's SHA-256. Do not edit
these files: rebuild and vendor with `just wasm-vendor`.

```js
import { initSync, verify_tsl } from './ti_wasm.js';

// Node: instantiate from the bytes once; a browser can `await init(url)` instead.
initSync({ module: readFileSync(new URL('./ti_wasm_bg.wasm', import.meta.url)) });

/** @type {import('./types').TslView} */
const view = JSON.parse(verify_tsl(xmlBytes, 'prod', new Date().toISOString(), rootsJsonBytes, 7 * 86400));
```

In a browser, load the module from its URL and check certificates locally:

```js
import init, { TrustContext } from './ti_wasm.js';

await init(new URL('./ti_wasm_bg.wasm', import.meta.url));
const now = new Date().toISOString();
const context = new TrustContext(tslBytes, 'prod', now, rootsJsonBytes, 7 * 86400);
/** @type {import('./types').CheckReport} */
const report = JSON.parse(context.check(certificateBytes, now));
```

Every function returns a JSON string, described by `tsl-view.json`, `certificates.json` and `check.json`
and typed in `types.d.ts`. A thrown `Error` is a wrong call, never a verdict. The module
aborts on a panic; instantiate it anew after a trap.
