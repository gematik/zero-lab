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

  function substituteVars(block, str) {
    block.querySelectorAll('[data-var]').forEach((el) => {
      const val = el.value.trim();
      if (val) str = str.replaceAll('{' + el.dataset.var + '}', val);
    });
    return str;
  }

  function buildQuery(block) {
    const params = new URLSearchParams();
    block.querySelectorAll('[data-param]').forEach((el) => {
      const val = el.dataset.derived
        ? substituteVars(block, el.dataset.derived)
        : el.value.trim();
      if (val) params.append(el.dataset.param, val);
    });
    let query = params.toString();
    const raw = block.querySelector('[data-param-raw]')?.value.trim();
    if (raw) query += (query ? '&' : '') + raw;
    return query;
  }

  function buildPath(block) {
    let path = substituteVars(block, block.dataset.path);
    const query = buildQuery(block);
    if (query) path += (path.includes('?') ? '&' : '?') + query;
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

  function renderProxyStatus(data) {
    const div = document.createElement('div');
    div.className = 'mb-3';

    let html = '<div class="mb-2">';
    if (data.subject) html += '<strong>' + esc(data.subject) + '</strong> ';
    if (data.telematikId) html += '<code>' + esc(data.telematikId) + '</code> ';
    html += '<span class="badge text-bg-info text-uppercase">' + esc(data.env || '') + '</span> '
      + '<span class="badge rounded-pill border text-body-secondary bg-body-tertiary fw-normal">'
      + esc(data.insurantsCached ?? 0) + ' KVNR im Cache</span>';
    if (data.identityError) {
      html += '<div class="text-danger small mt-1">' + esc(data.identityError) + '</div>';
    }
    html += '</div>';

    html += '<div class="table-responsive"><table class="table table-sm align-middle mb-2">'
      + '<thead><tr><th>Provider</th><th>VAU-Version</th><th>User-Authentication</th>'
      + '<th>Connection-Start</th><th>Session geöffnet</th><th>Status</th></tr></thead><tbody>';
    for (const p of data.providers || []) {
      const vau = p.vau || {};
      const state = p.error
        ? '<span class="badge text-bg-danger" title="' + esc(p.error) + '">Fehler</span>'
        : '<span class="badge text-bg-success">OK</span>';
      html += '<tr>'
        + '<td>' + esc(p.number) + (p.baseURL ? '<br><span class="small text-body-secondary">' + esc(p.baseURL) + '</span>' : '') + '</td>'
        + '<td>' + esc(vau['VAU-Version'] || '–') + '</td>'
        + '<td><code>' + esc(vau['User-Authentication'] || '–') + '</code></td>'
        + '<td>' + esc(vau['Connection-Start'] || '–') + '</td>'
        + '<td>' + esc(p.sessionOpenedAt || '–') + '</td>'
        + '<td>' + state + '</td>'
        + '</tr>';
      if (p.error) {
        html += '<tr><td></td><td colspan="5" class="small text-danger">' + esc(p.error) + '</td></tr>';
      }
    }
    html += '</tbody></table></div>';

    div.innerHTML = html;
    return div;
  }

  // escapes, then restores only the <mark> highlighting from full-text snippets
  function escWithMark(value) {
    return esc(value)
      .replaceAll('&lt;mark&gt;', '<mark>')
      .replaceAll('&lt;/mark&gt;', '</mark>');
  }

  function rewriteAttachmentURL(rawUrl, block) {
    let pathname;
    try {
      pathname = new URL(rawUrl, location.origin).pathname;
    } catch (e) {
      return null;
    }
    const proxy = block.querySelector('select[data-var="proxy"]')?.value;
    const kvnr = block.querySelector('[data-var="kvnr"]')?.value.trim();
    if (!proxy || !kvnr) return null;
    return '/api/proxies/' + encodeURIComponent(proxy) + '/insurants/'
      + encodeURIComponent(kvnr) + '/vau' + pathname;
  }

  function documentSnippet(resource) {
    const ext = (resource.extension || []).find((e) =>
      (e.url || '').includes('full-text-search-match-snippet'));
    if (!ext) return '';
    const text = ext.valueString
      || (ext.extension || []).find((e) => e.valueString)?.valueString;
    return text ? '<div class="small text-body-secondary">' + escWithMark(text) + '</div>' : '';
  }

  function renderDocumentList(data, block) {
    const div = document.createElement('div');
    div.className = 'mb-3';
    const entries = (data.entry || []).filter((e) => e.resource?.resourceType === 'DocumentReference');

    if (!entries.length) {
      div.innerHTML = '<div class="alert alert-warning py-2">Keine Dokumente gefunden'
        + (data.total !== undefined ? ' (total: ' + esc(data.total) + ')' : '') + '</div>';
      return div;
    }

    let html = '<div class="small text-body-secondary mb-2">'
      + esc(entries.length) + ' Dokument(e)'
      + (data.total !== undefined ? ' von insgesamt ' + esc(data.total) : '') + '</div>';
    html += '<div class="table-responsive"><table class="table table-sm align-middle mb-2">'
      + '<thead><tr><th>Titel</th><th>Typ</th><th>Datum</th><th>Größe</th><th>Content-Type</th><th></th></tr></thead><tbody>';

    for (const entry of entries) {
      const doc = entry.resource;
      const attachment = doc.content?.[0]?.attachment || {};
      const title = attachment.title || doc.description || doc.id || '–';
      const typeCoding = doc.type?.coding?.[0] || {};
      const type = typeCoding.display || typeCoding.code || '–';
      const date = attachment.creation || doc.date || '–';
      const size = attachment.size ? Math.round(attachment.size / 1024) + ' KB' : '–';
      const href = attachment.url ? rewriteAttachmentURL(attachment.url, block) : null;
      const action = href
        ? '<a class="btn btn-sm btn-outline-primary" href="' + esc(href) + '" target="_blank" rel="noopener">Öffnen</a>'
        : '';
      html += '<tr>'
        + '<td>' + esc(title) + documentSnippet(doc) + '</td>'
        + '<td>' + esc(type) + '</td>'
        + '<td>' + esc(date) + '</td>'
        + '<td>' + esc(size) + '</td>'
        + '<td><code>' + esc(attachment.contentType || '–') + '</code></td>'
        + '<td>' + action + '</td>'
        + '</tr>';
    }
    html += '</tbody></table></div>';

    div.innerHTML = html;
    return div;
  }

  function codeableText(concept) {
    if (!concept) return '';
    if (concept.text) return concept.text;
    const coding = concept.coding?.[0];
    return coding ? (coding.display || coding.code || '') : '';
  }

  function humanName(name) {
    const n = Array.isArray(name) ? name[0] : name;
    if (!n) return '';
    if (n.text) return n.text;
    return [(n.given || []).join(' '), n.family].filter(Boolean).join(' ');
  }

  // one table row per bundle entry; columns chosen per resource type
  function medicationRow(res) {
    const row = {
      type: res.resourceType || '–',
      name: '',
      status: res.status || '',
      date: '',
      details: '',
    };
    switch (res.resourceType) {
      case 'Medication': {
        row.name = codeableText(res.code);
        const pzn = (res.code?.coding || []).find((c) => (c.system || '').includes('/pzn'));
        const form = codeableText(res.form);
        row.details = [pzn ? 'PZN ' + pzn.code : '', form].filter(Boolean).join(' · ');
        break;
      }
      case 'MedicationRequest':
        row.name = codeableText(res.medicationCodeableConcept) || res.medicationReference?.display || res.medicationReference?.reference || '';
        row.date = res.authoredOn || '';
        row.details = res.dosageInstruction?.[0]?.text || '';
        break;
      case 'MedicationDispense':
        row.name = codeableText(res.medicationCodeableConcept) || res.medicationReference?.display || res.medicationReference?.reference || '';
        row.date = res.whenHandedOver || res.whenPrepared || '';
        row.details = res.dosageInstruction?.[0]?.text || '';
        break;
      case 'MedicationStatement':
        row.name = codeableText(res.medicationCodeableConcept) || res.medicationReference?.display || res.medicationReference?.reference || '';
        row.date = res.effectiveDateTime || res.effectivePeriod?.start || '';
        row.details = res.dosage?.[0]?.text || '';
        break;
      case 'Organization':
        row.name = res.name || '';
        row.details = res.identifier?.[0]?.value || '';
        break;
      case 'Practitioner':
        row.name = humanName(res.name);
        row.details = res.identifier?.[0]?.value || '';
        break;
      case 'PractitionerRole':
        row.name = res.practitioner?.display || res.practitioner?.reference || '';
        row.details = res.organization?.display || res.organization?.reference || '';
        break;
      case 'Provenance':
        row.name = res.agent?.[0]?.who?.display || res.agent?.[0]?.who?.reference || '';
        row.date = res.recorded || '';
        row.details = (res.target || []).map((t) => t.reference).join(', ');
        break;
      default:
        row.name = res.id || '';
    }
    return row;
  }

  function renderMedicationBundle(data) {
    const div = document.createElement('div');
    div.className = 'mb-3';

    if (data.resourceType !== 'Bundle') {
      div.innerHTML = '<div class="alert alert-secondary py-2">Keine tabellarische Ansicht für <code>'
        + esc(data.resourceType || 'unbekannt') + '</code> — siehe JSON unten.</div>';
      return div;
    }
    const entries = (data.entry || []).filter((e) => e.resource);
    if (!entries.length) {
      div.innerHTML = '<div class="alert alert-warning py-2">Keine Einträge'
        + (data.total !== undefined ? ' (total: ' + esc(data.total) + ')' : '') + '</div>';
      return div;
    }

    let html = '<div class="small text-body-secondary mb-2">'
      + esc(entries.length) + ' Eintrag/Einträge'
      + (data.total !== undefined ? ' von insgesamt ' + esc(data.total) : '') + '</div>';
    html += '<div class="table-responsive"><table class="table table-sm align-middle mb-2">'
      + '<thead><tr><th>Ressource</th><th>Bezeichnung</th><th>Status</th><th>Datum</th><th>Details</th></tr></thead><tbody>';
    for (const entry of entries) {
      const row = medicationRow(entry.resource);
      const statusBadge = row.status
        ? '<span class="badge ' + (row.status === 'active' || row.status === 'completed' ? 'text-bg-success' : 'text-bg-secondary')
          + '">' + esc(row.status) + '</span>'
        : '–';
      html += '<tr>'
        + '<td><code>' + esc(row.type) + '</code></td>'
        + '<td>' + esc(row.name || '–') + '</td>'
        + '<td>' + statusBadge + '</td>'
        + '<td>' + esc(row.date || '–') + '</td>'
        + '<td class="small text-body-secondary">' + esc(row.details || '–') + '</td>'
        + '</tr>';
    }
    html += '</tbody></table></div>';

    div.innerHTML = html;
    return div;
  }

  function renderSummary(block, data, output) {
    switch (block.dataset.summary) {
      case 'insurant-info':
        output.appendChild(renderInsurantSummary(data));
        break;
      case 'medication-bundle':
        output.appendChild(renderMedicationBundle(data));
        break;
      case 'proxy-status':
        output.appendChild(renderProxyStatus(data));
        break;
      case 'document-list':
        output.appendChild(renderDocumentList(data, block));
        break;
    }
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
        if (data && res.ok) {
          renderSummary(block, data, output);
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

    document.querySelectorAll('.try[data-autoexec]').forEach((block) => {
      const btn = block.querySelector('.execute');
      if (btn && !btn.disabled) execute(block);
    });
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
