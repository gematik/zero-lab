(() => {
  'use strict';

  const AUTH_HEADER = document.body.dataset.authHeader || '';

  function esc(value) {
    const div = document.createElement('div');
    div.textContent = String(value);
    return div.innerHTML;
  }

  /* ---- copy buttons ---- */
  document.addEventListener('click', async (ev) => {
    const btn = ev.target.closest('.copy');
    if (!btn) return;
    const code = btn.closest('.code')?.querySelector('pre code');
    if (!code) return;
    try {
      await navigator.clipboard.writeText(code.innerText.replace(/\n$/, ''));
      btn.classList.replace('btn-outline-secondary', 'btn-success');
      btn.textContent = 'Kopiert';
      setTimeout(() => {
        btn.classList.replace('btn-success', 'btn-outline-secondary');
        btn.textContent = 'Copy';
      }, 1500);
    } catch (e) {
      console.error('Copy failed', e);
    }
  });

  /* ---- try blocks ---- */
  const tryBlocks = Array.from(document.querySelectorAll('.try'));

  function buildPath(block) {
    let path = block.dataset.path;
    block.querySelectorAll('[data-var]').forEach((el) => {
      const val = el.value.trim();
      if (val) path = path.replaceAll('{' + el.dataset.var + '}', val);
    });
    return path;
  }

  function collectHeaders(block) {
    const headers = [];
    block.querySelectorAll('[data-header]').forEach((el) => {
      const val = el.value.trim();
      if (val) headers.push([el.dataset.header, val]);
    });
    return headers;
  }

  function buildBody(block) {
    const fields = {};
    let present = false;
    block.querySelectorAll('[data-body]').forEach((el) => {
      const val = el.value.trim();
      if (!val) return;
      fields[el.dataset.body] = /^\d+$/.test(val) ? Number(val) : val;
      present = true;
    });
    return present ? JSON.stringify(fields) : null;
  }

  function shellQuote(s) {
    return '"' + s.replace(/(["\\$`])/g, '\\$1') + '"';
  }

  function buildCurl(block) {
    const method = (block.dataset.method || 'GET').toUpperCase();
    let cmd = 'curl ';
    if (method !== 'GET') cmd += '-X ' + method + ' ';
    cmd += shellQuote(location.origin + buildPath(block));

    const headers = [];
    if (AUTH_HEADER) headers.push(['Authorization', AUTH_HEADER]);
    headers.push(...collectHeaders(block));
    const body = buildBody(block);
    if (body) headers.push(['Content-Type', 'application/json']);
    for (const [name, val] of headers) {
      cmd += ' \\\n  -H ' + shellQuote(name + ': ' + val);
    }
    if (body) cmd += " \\\n  -d '" + body + "'";
    return cmd;
  }

  function updateCurl(block) {
    const code = block.querySelector('.code pre code');
    if (!code) return;
    code.textContent = buildCurl(block);
    if (window.hljs) {
      delete code.dataset.highlighted;
      hljs.highlightElement(code);
    }
  }

  function appendJSONBlock(output, text, isError) {
    const wrap = document.createElement('div');
    wrap.className = 'response' + (isError ? ' response-error' : '');
    const pre = document.createElement('pre');
    const code = document.createElement('code');
    code.className = 'language-json';
    code.textContent = text;
    pre.appendChild(code);
    wrap.appendChild(pre);
    output.appendChild(wrap);
    if (window.hljs) hljs.highlightElement(code);
  }

  function renderInsurantSummary(data) {
    const div = document.createElement('div');
    div.className = 'mb-3';
    const record = data.record || {};
    const entitlement = data.entitlement || {};

    let html = record.found
      ? '<div class="alert alert-success py-2">Akte gefunden bei Provider <strong>' + esc(record.provider) + '</strong></div>'
      : '<div class="alert alert-warning py-2">Keine Akte bei einem der Provider gefunden</div>';

    html += '<table class="table table-sm align-middle mb-2">'
      + '<thead><tr><th>Provider</th><th>Akte</th><th>Consent-Entscheidungen</th></tr></thead><tbody>';
    for (const p of data.providers || []) {
      const consent = (p.consentDecisions || [])
        .map((c) => '<span class="badge ' + (c.decision === 'permit' ? 'text-bg-success' : 'text-bg-danger')
          + ' me-1 mb-1">' + esc(c.functionId) + ': ' + esc(c.decision) + '</span>')
        .join(' ');
      const akte = p.error
        ? '<span class="text-danger" title="' + esc(p.error) + '">Fehler</span>'
        : (p.recordFound
          ? '<span class="badge text-bg-success">vorhanden</span>'
          : '<span class="text-body-secondary">–</span>');
      html += '<tr><td>' + esc(p.number) + '</td><td>' + akte + '</td><td>'
        + (consent || '<span class="text-body-secondary">–</span>') + '</td></tr>';
    }
    html += '</tbody></table>';

    html += entitlement.entitled
      ? '<div class="small text-body-secondary mb-2">Befugnis über diese Middleware erteilt für Provider '
        + esc(entitlement.provider) + (entitlement.entitledAt ? ' am ' + esc(entitlement.entitledAt) : '') + '.</div>'
      : '<div class="small text-body-secondary mb-2">Keine Befugnis über diese Middleware-Instanz erteilt (lokaler Cache, best effort).</div>';

    div.innerHTML = html;
    return div;
  }

  async function execute(block) {
    const btn = block.querySelector('.execute');
    const spinner = btn?.querySelector('.spinner-border');
    const result = block.querySelector('.result');
    const statusEl = result?.querySelector('.status');
    const output = result?.querySelector('.output');
    if (!btn || !result || !statusEl || !output) return;

    btn.disabled = true;
    spinner?.classList.remove('d-none');
    const t0 = performance.now();

    try {
      const options = {
        method: (block.dataset.method || 'GET').toUpperCase(),
        headers: Object.fromEntries(collectHeaders(block)),
      };
      const body = buildBody(block);
      if (body) {
        options.headers['Content-Type'] = 'application/json';
        options.body = body;
      }

      const res = await fetch(buildPath(block), options);
      const ms = Math.round(performance.now() - t0);
      const contentType = (res.headers.get('content-type') || '').split(';')[0].trim().toLowerCase();

      result.classList.remove('d-none');
      statusEl.innerHTML = '<span class="badge ' + (res.ok ? 'text-bg-success' : 'text-bg-danger') + '">'
        + esc(res.status) + '</span> <span class="text-body-secondary">'
        + esc(res.statusText || '') + ' · ' + esc(contentType || '—') + ' · ' + esc(ms) + ' ms</span>';

      if (block._blobUrl) {
        URL.revokeObjectURL(block._blobUrl);
        block._blobUrl = null;
      }
      output.innerHTML = '';

      if (res.status === 204) return;

      if (contentType.includes('json')) {
        const text = await res.text();
        if (!text) return;
        let pretty = text;
        let data = null;
        try {
          data = JSON.parse(text);
          pretty = JSON.stringify(data, null, 2);
        } catch (e) { /* show raw text */ }
        if (data && res.ok && block.dataset.summary === 'insurant-info') {
          output.appendChild(renderInsurantSummary(data));
        }
        appendJSONBlock(output, pretty, !res.ok);
      } else if (contentType.includes('xhtml') || contentType.includes('html')) {
        const blob = await res.blob();
        block._blobUrl = URL.createObjectURL(blob);
        const iframe = document.createElement('iframe');
        iframe.setAttribute('sandbox', '');
        iframe.src = block._blobUrl;
        output.appendChild(iframe);
      } else if (contentType.includes('pdf')) {
        const blob = await res.blob();
        block._blobUrl = URL.createObjectURL(blob);
        const embed = document.createElement('embed');
        embed.type = 'application/pdf';
        embed.src = block._blobUrl;
        output.appendChild(embed);
      } else {
        const text = await res.text();
        if (text) appendJSONBlock(output, text, !res.ok);
      }
    } catch (e) {
      result.classList.remove('d-none');
      statusEl.innerHTML = '<span class="badge text-bg-danger">Fehler</span> <span class="text-body-secondary">'
        + esc(e) + '</span>';
      output.innerHTML = '';
    } finally {
      btn.disabled = false;
      spinner?.classList.add('d-none');
    }
  }

  /* ---- proxy selects ---- */
  async function loadProxies() {
    let proxies = [];
    try {
      const res = await fetch('/api/proxies');
      if (res.ok) proxies = (await res.json()) || [];
    } catch (e) {
      console.error('Laden der Proxies fehlgeschlagen', e);
    }

    document.querySelectorAll('select[data-var="proxy"]').forEach((sel) => {
      sel.innerHTML = '';
      if (!proxies.length) {
        const opt = document.createElement('option');
        opt.value = '';
        opt.textContent = 'Keine Proxies konfiguriert';
        sel.appendChild(opt);
        sel.disabled = true;
        const btn = sel.closest('.try')?.querySelector('.execute');
        if (btn) btn.disabled = true;
        return;
      }
      for (const p of proxies) {
        const opt = document.createElement('option');
        opt.value = p.name;
        opt.textContent = p.name + ' — ' + p.subject + ' (' + p.env + ')';
        sel.appendChild(opt);
      }
    });

    tryBlocks.forEach(updateCurl);
  }

  /* ---- wiring ---- */
  tryBlocks.forEach((block) => {
    block.addEventListener('input', () => updateCurl(block));
    block.addEventListener('change', () => updateCurl(block));
    block.querySelector('.execute')?.addEventListener('click', () => execute(block));
  });

  if (window.hljs) hljs.highlightAll();
  loadProxies();
})();
