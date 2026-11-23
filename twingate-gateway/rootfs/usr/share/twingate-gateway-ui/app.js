// Twingate Gateway add-on: status page.
//
// Polls api/status (a relative URL, so it works under the Home Assistant
// ingress path) and renders it. All values are inserted as text nodes, never
// as HTML: audit data such as paths and user names comes from clients.
'use strict';

(() => {
  const REFRESH_MS = 5000;
  const STATUS_URL = 'api/status';
  const DOCS_HINT = 'the Documentation tab of this add-on';
  const signatures = new Map();
  let failures = 0;
  let timer = null;
  let inFlight = false;

  // --------------------------------------------------------------------------
  // DOM helpers
  // --------------------------------------------------------------------------

  function el(tag, className, ...children) {
    const node = document.createElement(tag);
    if (className) {
      node.className = className;
    }
    for (const child of children.flat(Infinity)) {
      if (child === null || child === undefined || child === false) {
        continue;
      }
      node.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
    return node;
  }

  function code(value) {
    return el('code', 'tg-code', String(value));
  }

  function muted(...children) {
    return el('div', 'tg-muted tg-small', ...children);
  }

  function pill(kind, label) {
    return el('span', `tg-pill tg-pill--${kind}`, label);
  }

  const ICONS = {
    info: 'M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zm-1.25 9h2.5v6.5h-2.5V11zm1.25-4.5a1.4 1.4 0 1 1 0 2.8 1.4 1.4 0 0 1 0-2.8z',
    success: 'M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zm-1.3 13.9-3.9-3.9 1.5-1.5 2.4 2.4 5.1-5.1 1.5 1.5-6.6 6.6z',
    warning: 'M12 2.8 1.8 20.5h20.4L12 2.8zM11 9h2v6h-2V9zm0 7.6h2v2h-2v-2z',
    danger: 'M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zm3.6 5 1.4 1.4-3.6 3.6 3.6 3.6-1.4 1.4-3.6-3.6-3.6 3.6L7 15.6l3.6-3.6L7 8.4 8.4 7l3.6 3.6L15.6 7z',
  };

  function icon(kind) {
    const ns = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(ns, 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('class', 'tg-callout__icon');
    svg.setAttribute('aria-hidden', 'true');
    const path = document.createElementNS(ns, 'path');
    path.setAttribute('d', ICONS[kind] || ICONS.info);
    path.setAttribute('fill', 'currentColor');
    path.setAttribute('fill-rule', 'evenodd');
    svg.append(path);
    return svg;
  }

  function callout(kind, title, ...body) {
    return el('div', `tg-callout tg-callout--${kind}`,
      icon(kind),
      el('div', 'tg-callout__content', title ? el('div', 'tg-callout__title', title) : null, ...body));
  }

  // rows: [label, content] pairs; content may be a node, text or an array.
  function kvTable(rows) {
    const body = el('tbody');
    for (const [label, content] of rows) {
      if (content === null || content === undefined) {
        continue;
      }
      const header = el('th', null, label);
      header.scope = 'row';
      body.append(el('tr', null, header, el('td', null, content)));
    }
    return el('div', 'tg-table-wrap', el('table', 'tg-table tg-table--kv', body));
  }

  function table(columns, rows, extraClass) {
    const headRow = el('tr');
    for (const column of columns) {
      const th = el('th', column.numeric ? 'tg-num' : null, column.label);
      th.scope = 'col';
      headRow.append(th);
    }
    const body = el('tbody');
    for (const row of rows) {
      const tr = el('tr');
      row.forEach((content, index) => {
        const column = columns[index];
        const td = el('td', column.numeric ? 'tg-num' : null, el('span', column.cellClass || null, content));
        td.dataset.label = column.label;
        tr.append(td);
      });
      body.append(tr);
    }
    return el('div', 'tg-table-wrap', el('table', `tg-table ${extraClass || ''}`.trim(), el('thead', null, headRow), body));
  }

  function card(label, value, meta) {
    return el('div', 'tg-card',
      el('div', 'tg-card__label', label),
      el('div', 'tg-card__value', value),
      meta ? el('div', 'tg-card__meta', meta) : null);
  }

  function bar(fraction, kind) {
    const fill = el('span', `tg-bar__fill tg-bar__fill--${kind}`);
    fill.style.width = `${Math.max(0, Math.min(1, fraction)) * 100}%`;
    return el('span', 'tg-bar', fill);
  }

  // Re-renders a section only when its data changed, so that a selection
  // or the copy button's feedback is not reset by every refresh.
  function render(id, key, build) {
    const signature = JSON.stringify(key);
    if (signatures.get(id) === signature) {
      return;
    }
    signatures.set(id, signature);
    const target = document.getElementById(id);
    target.replaceChildren(...[build()].flat().filter(Boolean));
  }

  // --------------------------------------------------------------------------
  // Formatting
  // --------------------------------------------------------------------------

  const numberFormat = new Intl.NumberFormat();

  function num(value) {
    return value === null || value === undefined ? '–' : numberFormat.format(value);
  }

  function dateTime(epoch) {
    if (!epoch) {
      return '–';
    }
    return new Date(epoch * 1000).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
  }

  function clockTime(epoch) {
    const date = new Date(epoch * 1000);
    const today = new Date();
    const time = date.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    if (date.toDateString() === today.toDateString()) {
      return time;
    }
    return `${date.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })} ${time}`;
  }

  function duration(seconds) {
    if (seconds === null || seconds === undefined) {
      return '–';
    }
    const s = Math.max(0, Math.round(seconds));
    const days = Math.floor(s / 86400);
    const hours = Math.floor((s % 86400) / 3600);
    const minutes = Math.floor((s % 3600) / 60);
    if (days > 0) {
      return `${days} d ${hours} h`;
    }
    if (hours > 0) {
      return `${hours} h ${minutes} min`;
    }
    if (minutes > 0) {
      return `${minutes} min`;
    }
    return `${s} s`;
  }

  function relativeDays(epoch) {
    const days = Math.round((epoch * 1000 - Date.now()) / 86400000);
    if (days > 1) {
      return `in ${numberFormat.format(days)} days`;
    }
    if (days === 1) {
      return 'tomorrow';
    }
    if (days === 0) {
      return 'today';
    }
    return `${numberFormat.format(-days)} days ago`;
  }

  // The Gateway logs times in milliseconds, so shorter durations show as < 1 ms.
  function millis(ms) {
    if (ms === null || ms === undefined) {
      return '–';
    }
    if (ms < 1) {
      return '< 1 ms';
    }
    if (ms < 1000) {
      return `${Math.round(ms)} ms`;
    }
    return `${(ms / 1000).toFixed(ms < 10000 ? 2 : 1)} s`;
  }

  // Percentiles are bucket bounds: at most the value, or above the last bound.
  function percentile(value) {
    if (!value) {
      return '–';
    }
    return value.above ? `> ${millis(value.ms)}` : `≤ ${millis(value.ms)}`;
  }

  function bytes(value) {
    if (!value) {
      return '–';
    }
    return `${(value / 1048576).toFixed(1)} MiB`;
  }

  function statusKind(status) {
    if (status >= 500) {
      return 'danger';
    }
    if (status >= 400) {
      return 'warning';
    }
    if (status >= 300) {
      return 'info';
    }
    if (status >= 200) {
      return 'success';
    }
    return 'neutral';
  }

  // --------------------------------------------------------------------------
  // Clipboard
  // --------------------------------------------------------------------------

  async function copyText(textValue) {
    if (navigator.clipboard && window.isSecureContext) {
      try {
        await navigator.clipboard.writeText(textValue);
        return true;
      } catch (error) {
        // Fall through to the selection based copy.
      }
    }
    const area = el('textarea', 'tg-visually-hidden');
    area.value = textValue;
    area.setAttribute('readonly', '');
    document.body.append(area);
    area.select();
    let copied = false;
    try {
      copied = document.execCommand('copy');
    } catch (error) {
      copied = false;
    }
    area.remove();
    return copied;
  }

  function selectContents(node) {
    const range = document.createRange();
    range.selectNodeContents(node);
    const selection = window.getSelection();
    selection.removeAllRanges();
    selection.addRange(range);
  }

  function codeBlock(textValue, copyLabel) {
    const pre = el('pre', 'tg-codeblock__pre', textValue);
    const button = el('button', 'tg-copy', 'Copy');
    button.type = 'button';
    button.setAttribute('aria-label', copyLabel);
    let reset = null;
    button.addEventListener('click', async () => {
      const copied = await copyText(textValue);
      if (!copied) {
        selectContents(pre);
      }
      button.textContent = copied ? 'Copied' : 'Press Ctrl+C';
      clearTimeout(reset);
      reset = setTimeout(() => { button.textContent = 'Copy'; }, 2500);
    });
    return el('div', 'tg-codeblock', button, pre);
  }

  // --------------------------------------------------------------------------
  // Sections
  // --------------------------------------------------------------------------

  const HEALTH = {
    true: ['success', 'Healthy'],
    false: ['danger', 'Not healthy'],
  };

  const SIGNING_KEYS = {
    ok: ['success', 'Working'],
    warning: ['warning', 'Check failed'],
    error: ['danger', 'Network not found'],
    pending: ['neutral', 'Checking'],
    unknown: ['neutral', 'Unknown'],
  };

  function healthPill(health) {
    const [kind, label] = HEALTH[Boolean(health && health.ok)];
    return pill(kind, label);
  }

  function signingKeysPill(keys) {
    const [kind, label] = SIGNING_KEYS[keys.state] || SIGNING_KEYS.unknown;
    return pill(kind, label);
  }

  function healthDetail(health) {
    if (!health) {
      return null;
    }
    if (health.ok) {
      return `GET /healthz answered in ${millis(health.latency_ms)}, checked at ${clockTime(health.checked_at)}.`;
    }
    const reason = health.http_status ? `HTTP ${health.http_status}` : health.error || 'no answer';
    return `GET /healthz on the TLS listener failed (${reason}) at ${clockTime(health.checked_at)}. See the add-on's Log tab.`;
  }

  function renderNotice(data) {
    render('notice', [data.ready], () => {
      if (!data.ready) {
        return callout('warning', 'The Gateway has not finished starting',
          el('p', null, 'The add-on is still starting, or it stopped because of a configuration problem. The add-on\'s Log tab shows why.'));
      }
      return [];
    });
  }

  // The add-on takes the Gateway from a moving image tag when it is built;
  // when that tag now points to a newer release, a rebuild installs it.
  function renderUpdate(data) {
    const update = data.gateway_update || {};
    const slug = data.startup && data.startup.addon_slug;
    render('update', [update.update_available, update.latest, update.running, update.image, slug], () => {
      if (update.update_available !== true) {
        return [];
      }
      const major = String(update.latest).split('.')[0];
      return callout('info', `Gateway ${update.latest} is available`,
        el('p', null, `This add-on is running Gateway ${update.running}. It takes the Gateway from the image tag ${update.image} on Docker Hub when it is built, and that tag now gives ${update.latest}. To update, rebuild the add-on:`),
        el('ol', 'tg-list',
          el('li', null, 'In Home Assistant, open ', el('strong', null, 'Settings > Apps > Twingate Gateway'), '.'),
          el('li', null, 'On the ', el('strong', null, 'Info'), ' tab, open the menu (⋮) of the ', el('strong', null, 'Controls'), ' card and select ', el('strong', null, 'Rebuild'), '.')),
        el('p', null, `Home Assistant builds the add-on again with the newest Gateway ${major}.x and starts it. The configuration, the CA and its certificate are kept; the Gateway accepts no connections until the rebuild is done. From the Home Assistant command line: `,
          code(`ha apps rebuild ${slug || '<slug>'}`)));
    });
  }

  function renderSummary(data) {
    const traffic = data.traffic || {};
    const keys = data.signing_keys;
    render('summary', [data.health && data.health.ok, keys.state, traffic.active_connections, traffic.http && traffic.http.active,
      Math.floor((data.uptime_seconds || 0) / 60), data.gateway_started_at], () => [
      card('Gateway', healthPill(data.health), data.health && data.health.ok ? 'Answering on its TLS listener' : 'Health check failing'),
      card('Signing keys', signingKeysPill(keys), keys.state === 'ok' ? 'Twingate tokens can be verified' : 'See Status below'),
      card('Active connections', num(traffic.available ? traffic.active_connections : null),
        traffic.available ? `${num(traffic.http.active)} requests in progress` : 'Metrics unavailable'),
      card('Uptime', duration(data.uptime_seconds), data.gateway_started_at ? `Since ${dateTime(data.gateway_started_at)}` : null),
    ]);
  }

  function gatewayAddress(data) {
    const startup = data.startup;
    const port = startup.host_port || startup.gateway_port || 8443;
    const items = [];
    if (data.host_hint) {
      items.push(code(`${data.host_hint}:${port}`));
      items.push(muted(`Based on the address you opened Home Assistant with (${data.host_hint}). If Home Assistant runs on another LAN IP address, use that address with port ${port}.`));
    } else {
      items.push(code(`<home-assistant-ip>:${port}`));
      items.push(muted('Replace <home-assistant-ip> with the LAN IP address of the Home Assistant host, shown under Settings > System > Network.'));
    }
    if (startup.host_port_state === 'not_mapped') {
      items.push(callout('warning', 'Port not published',
        el('p', null, `Container port ${startup.gateway_port}/tcp has no host port. Set one in the add-on's Network section, then restart the add-on.`)));
    } else if (startup.host_port_state === 'unknown') {
      items.push(muted('Uses the host port set for 8443/tcp in the add-on\'s Network section (default 8443).'));
    }
    return items;
  }

  function renderSetup(data) {
    render('setup', [data.ready, data.startup && data.startup.ca, data.startup && [data.startup.host_port, data.startup.host_port_state], data.host_hint], () => {
      if (!data.ready) {
        return el('p', 'tg-empty', 'Available when the Gateway has started.');
      }
      const ca = data.startup.ca || {};
      const expiring = ca.not_after_epoch && ca.not_after_epoch * 1000 - Date.now() < 30 * 86400000;
      const nodes = [
        callout('info', 'Next steps',
          el('ol', 'tg-list',
            el('li', null, 'Register the CA certificate below in Twingate as an X.509 certificate authority.'),
            el('li', null, 'Create a Gateway with the Gateway address below, in the Remote Network of the Twingate Connector add-on, using that CA.'),
            el('li', null, 'Create a Web App Resource for the Home Assistant API that uses this Gateway.')),
          el('p', null, `Step-by-step instructions with Terraform and curl are on ${DOCS_HINT}.`)),
        kvTable([
          ['Gateway address', gatewayAddress(data)],
          ['CA subject', ca.subject ? el('span', 'tg-break', ca.subject) : '–'],
          ['SHA-256 fingerprint', ca.fingerprint_sha256 ? el('span', 'tg-mono tg-break', ca.fingerprint_sha256) : '–'],
          ['CA expires', ca.not_after_epoch
            ? [el('span', null, `${dateTime(ca.not_after_epoch)} (${relativeDays(ca.not_after_epoch)})`), expiring ? el('div', null, pill('warning', 'Replace soon')) : null]
            : ca.not_after || '–'],
          ['CA source', ca.source === 'custom'
            ? [el('span', null, 'Your own CA'), muted(code(ca.certificate_file || ''))]
            : 'Created by this add-on'],
        ]),
        el('h3', 'tg-h3', 'CA certificate'),
        el('p', 'tg-muted tg-small', 'The public certificate only. The CA private key never leaves the add-on. If copying does not work, select the text and copy it, or copy it from the add-on\'s Log tab, where it is printed at every start.'),
      ];
      nodes.push(ca.pem ? codeBlock(ca.pem, 'Copy the CA certificate') : el('p', 'tg-empty', 'The CA certificate is not available.'));
      return nodes;
    });
  }

  function signingKeyDetails(keys, network) {
    const lines = [];
    if (keys.authentications_succeeded > 0) {
      const last = keys.last_authentication_at ? `, the latest one by ${clockTime(keys.last_authentication_at)}` : '';
      lines.push(muted(`${num(keys.authentications_succeeded)} client authentications succeeded since the add-on started${last}. The Gateway accepts a Twingate token only after verifying it with the signing keys.`));
    }
    const check = keys.check;
    if (check) {
      if (check.ok) {
        lines.push(muted(`The signing-key URL answered with ${num(check.keys)} ${check.keys === 1 ? 'key' : 'keys'} at ${clockTime(check.checked_at)}.`));
      } else {
        lines.push(muted(`The signing-key URL could not be read at ${clockTime(check.checked_at)}: ${check.error || 'unknown error'}.`));
      }
    } else if (network) {
      lines.push(muted('The signing-key URL is checked shortly after the add-on starts, then every 15 minutes, or every 2 minutes while the check fails.'));
    }
    const startup = keys.startup_check || {};
    const startupText = {
      found: `At startup, Twingate network ${network} was found (HTTP ${startup.http_status}).`,
      unreachable: 'At startup, Twingate could not be reached.',
      http_error: `At startup, the network check answered HTTP ${startup.http_status}.`,
    }[startup.result];
    if (startupText) {
      lines.push(muted(startupText));
    }
    if (network) {
      lines.push(muted(code(`https://${network}.twingate.com/api/v1/jwk/ec`)));
    }
    return lines;
  }

  // The result of the daily release check, next to the Gateway version. A
  // failed check is not a problem of the Gateway: the line then says when
  // the last check succeeded, or that none has yet.
  function updateDetail(data) {
    const update = data.gateway_update || {};
    if (!data.gateway_version) {
      return null;
    }
    if (update.checked_at) {
      const checked = `checked ${dateTime(update.checked_at)}`;
      if (update.update_available === true) {
        return muted(`Gateway ${update.latest} is available (${checked}). See the top of this page.`);
      }
      if (update.update_available === false) {
        return muted(`Up to date (${checked}).`);
      }
      return muted(`${update.image} gives Gateway ${update.latest} (${checked}).`);
    }
    if (update.image) {
      return muted(`The check for a newer Gateway has not succeeded yet. It compares this version with ${update.image} on Docker Hub once a day.`);
    }
    return null;
  }

  function renderStatus(data) {
    const startup = data.startup || {};
    const keys = data.signing_keys;
    const update = data.gateway_update || {};
    render('status', [data.ready, data.health && [data.health.ok, data.health.http_status, data.health.error], Math.floor((data.health && data.health.checked_at || 0) / 60),
      data.gateway_version, [update.update_available, update.latest, update.checked_at, update.image], startup.network, keys,
      startup.static_certificate, startup.certificate_ip_addresses, startup.addon_version, Math.floor((data.uptime_seconds || 0) / 60)], () => {
      if (!data.ready) {
        return el('p', 'tg-empty', 'Available when the Gateway has started.');
      }
      const staticCertificate = startup.static_certificate;
      return kvTable([
        ['Gateway health', [el('div', null, healthPill(data.health)), muted(healthDetail(data.health))]],
        ['Gateway version', data.gateway_version
          ? [el('div', null, data.gateway_version), updateDetail(data)]
          : muted('Reported by the Gateway with the first request it handles.')],
        ['Twingate network', [code(startup.network || '–'), muted(`${startup.network || '<network>'}.twingate.com`)]],
        ['Signing keys', [el('div', null, signingKeysPill(keys)), ...signingKeyDetails(keys, startup.network)]],
        ['Static certificate', staticCertificate
          ? [el('div', null, startup.certificate_ip_addresses.join(', ')),
            muted(staticCertificate.not_after_epoch
              ? `Expires ${dateTime(staticCertificate.not_after_epoch)} (${relativeDays(staticCertificate.not_after_epoch)}); renewed at a start within 30 days of expiry.`
              : 'Expiry unknown.')]
          : muted('None. Only issued for certificate IP addresses.')],
        ['Add-on version', startup.addon_version || '–'],
        ['Gateway uptime', data.uptime_seconds !== null && data.uptime_seconds !== undefined
          ? [el('div', null, duration(data.uptime_seconds)), muted(`Since ${dateTime(data.gateway_started_at)}`)]
          : '–'],
      ]);
    });
  }

  function renderConfiguration(data) {
    const startup = data.startup || {};
    render('configuration', [data.ready, startup.request_header_names, startup.certificate_ip_addresses, startup.audit_log,
      startup.audit_log_file, startup.log_level, startup.ca && startup.ca.source, startup.ca && startup.ca.certificate_file], () => {
      if (!data.ready) {
        return el('p', 'tg-empty', 'Available when the Gateway has started.');
      }
      const names = startup.request_header_names || [];
      const ips = startup.certificate_ip_addresses || [];
      const ca = startup.ca || {};
      return kvTable([
        ['Injected request headers', names.length
          ? [el('div', null, names.map((name, index) => [index ? ' ' : null, code(name)])), muted('Names only. Header values are never shown.')]
          : muted('None.')],
        ['Certificate IP addresses', ips.length ? ips.join(', ') : muted('None.')],
        ['Audit log', startup.audit_log === 'file'
          ? [el('div', null, 'File in the add-on configuration folder'), muted(code(startup.audit_log_file || '/config/audit.log'), ' (rotated at 10 MiB, 3 compressed backups)')]
          : [el('div', null, 'Add-on log'), muted('The add-on\'s Log tab.')]],
        ['Log level', code(startup.log_level || 'info')],
        ['Certificate authority', ca.source === 'custom'
          ? [el('div', null, 'Your own CA'), muted(code(ca.certificate_file || ''))]
          : [el('div', null, 'Created by this add-on'), muted('Kept in the add-on\'s data folder.')]],
      ]);
    });
  }

  const STATUS_CLASSES = [
    ['2xx', 'Success', 'success'],
    ['3xx', 'Redirection', 'info'],
    ['4xx', 'Client error', 'warning'],
    ['5xx', 'Server error', 'danger'],
    ['1xx', 'Informational', 'neutral'],
    ['other', 'Other', 'neutral'],
  ];

  function renderTraffic(data) {
    const traffic = data.traffic || {};
    render('traffic', traffic, () => {
      if (!traffic.available) {
        return callout('warning', 'Metrics are not available',
          el('p', null, `The Gateway's metrics endpoint did not answer (${traffic.error || 'unknown error'}). It starts with the Gateway.`));
      }
      const http = traffic.http;
      const upstream = traffic.upstream;
      const total = Math.max(1, http.total);
      const classRows = STATUS_CLASSES
        .filter(([key]) => key === '2xx' || key === '4xx' || key === '5xx' || http.by_class[key] || upstream.by_class[key])
        .map(([key, label, kind]) => [
          `${key === 'other' ? '' : `${key} `}${label}`,
          num(http.by_class[key]),
          bar(http.by_class[key] / total, kind),
          num(upstream.by_class[key]),
        ]);
      return [
        el('div', 'tg-grid',
          card('Active connections', num(traffic.active_connections), 'Open client connections, including health checks in progress'),
          card('Connections', num(traffic.connections.proxy), 'Closed proxy connections from Twingate Clients since the add-on started'),
          card('Authenticated', num(traffic.authentication.succeeded), 'Connections that presented a valid Twingate token'),
          card('Failed authentication', num(traffic.authentication.failed_at_least), 'At least this many connections did not authenticate'),
          card('Rejected before a request', num(traffic.connections.unknown), 'Connections that never completed TLS and a request, including port probes and handshakes with an unregistered CA'),
          card('HTTP requests', num(http.total), `${num(upstream.total)} answered by the upstream`)),
        el('h3', 'tg-h3', 'Responses'),
        table([
          { label: 'Status' },
          { label: 'To clients', numeric: true },
          { label: 'Share' },
          { label: 'From upstream', numeric: true },
        ], classRows, 'tg-table--stack'),
        el('p', 'tg-muted tg-small', 'Upstream counts only responses received from Home Assistant; when it cannot be reached, the Gateway answers 502 to the client. A WebSocket connection counts as 2xx to clients and as 1xx (101 Switching Protocols) from upstream.'),
        el('h3', 'tg-h3', 'Latency'),
        table([
          { label: 'Requests' },
          { label: 'Count', numeric: true },
          { label: 'Mean', numeric: true },
          { label: 'Median', numeric: true },
          { label: '95th percentile', numeric: true },
        ], [
          ['Client requests', num(http.latency.count), millis(http.latency.mean_ms), percentile(http.latency.p50), percentile(http.latency.p95)],
          ['Upstream requests', num(upstream.latency.count), millis(upstream.latency.mean_ms), percentile(upstream.latency.p50), percentile(upstream.latency.p95)],
        ], 'tg-table--stack'),
        el('p', 'tg-muted tg-small',
          'Percentiles are the bounds of the Gateway\'s histogram buckets, which start at 100 ms for client requests and 5 ms upstream. WebSocket and other long-lived requests count their full duration. ',
          `Counters start at zero when the add-on starts. Gateway memory: ${bytes(traffic.process.resident_memory_bytes)}.`),
      ];
    });
  }

  function auditDescription(audit, startup) {
    if (audit.stream === 'file') {
      return `Summaries of the newest 100 entries of the audit log file ${startup.audit_log_file || '/config/audit.log'}.`;
    }
    return 'Summaries of the newest 100 audit log entries since the add-on started. The full entries are in the add-on\'s Log tab.';
  }

  function renderRequests(data) {
    const audit = data.audit || {};
    const startup = data.startup || {};
    const connected = audit.connected;
    const fileState = audit.relay && audit.relay.file_state;
    // Whether s6-log keeps the copy of the audit log that the relay reads.
    const copy = audit.stream === 'relay' && audit.relay ? audit.relay.copy : null;
    render('requests', [data.ready, audit.stream, connected, audit.relay_silent, fileState, copy, audit.socket_error, audit.records], () => {
      if (!data.ready) {
        return el('p', 'tg-empty', 'Available when the Gateway has started.');
      }
      const nodes = [
        el('p', null, auditDescription(audit, startup),
          ' Kept in memory only. Headers are never shown, paths are shown without their query string (marked ?…), and webhook IDs are masked (/api/webhook/***).'),
      ];
      if (audit.stream === 'none') {
        nodes.push(callout('warning', 'The audit log is not available here',
          el('p', null, 'The Gateway writes its audit log directly to the add-on log, so this page cannot show requests. Restart the add-on.')));
        return nodes;
      }
      const logged = audit.stream === 'file' ? 'to the audit log file' : 'to the add-on\'s Log tab';
      if (audit.socket_error) {
        nodes.push(callout('warning', 'The request list may be out of date',
          el('p', null, `The page cannot receive audit summaries (${audit.socket_error}). The Gateway is not affected, and every request is still logged ${logged}.`)));
      } else if (audit.relay_silent) {
        nodes.push(callout('warning', 'The request list may be out of date',
          el('p', null, `The audit relay has not reported for more than 15 seconds, so requests may be missing here. The Gateway is not affected, and every request is still logged ${logged}. The relay is restarted automatically; if this warning stays, check the add-on's Log tab.`)));
      } else if (!connected) {
        nodes.push(callout('warning', 'Waiting for the audit relay',
          el('p', null, 'The audit relay has not reported yet. Requests appear here once it does.')));
      } else if (copy === 'not kept') {
        nodes.push(callout('warning', 'New requests are not shown here',
          el('p', null, 'The add-on cannot keep the copy of the audit log that this page reads, so requests are missing here from then on. The Gateway is not affected, and every request is still logged to the add-on\'s Log tab, which also says why. Restarting the add-on tries again.')));
      } else if (copy === 'no space') {
        nodes.push(callout('warning', 'The request list may be out of date',
          el('p', null, 'There is no space left in /dev/shm for the copy of the audit log that this page reads, so new requests may be missing here. The Gateway is not affected, and every request is still logged to the add-on\'s Log tab.')));
      } else if (fileState && fileState !== 'reading') {
        const source = audit.stream === 'file' ? 'the audit log file' : 'the copy of the audit log';
        nodes.push(callout('warning', 'The request list may be out of date',
          el('p', null, `The audit relay reports for ${source}: ${fileState}. The Gateway is not affected, and every request is still logged ${logged}.`)));
      }
      const records = audit.records || [];
      if (!records.length) {
        if (copy !== 'not kept') {
          nodes.push(el('p', 'tg-empty', 'No requests yet. Requests appear here after a Twingate client uses a Resource on this Gateway.'));
        }
        return nodes;
      }
      const rows = records.map((record) => [
        clockTime(record.t),
        record.user || '–',
        record.method,
        el('span', 'tg-mono tg-break', record.path || '/', record.pt ? '…' : null, record.q ? el('span', 'tg-muted', '?…') : null),
        pill(record.err ? 'danger' : statusKind(record.status), record.status ? String(record.status) : 'none'),
        millis(record.ms),
      ]);
      nodes.push(table([
        { label: 'Time', cellClass: 'tg-nowrap' },
        { label: 'User', cellClass: 'tg-break' },
        { label: 'Method' },
        { label: 'Path' },
        { label: 'Status' },
        { label: 'Duration', numeric: true },
      ], rows, 'tg-table--stack tg-table--compact'));
      return nodes;
    });
  }

  function renderFooter(data) {
    const startup = data.startup || {};
    render('footer', [startup.addon_version], () => el('p', null,
      `Read-only status page of the Twingate Gateway add-on${startup.addon_version ? ` ${startup.addon_version}` : ''}. Values refresh every 5 seconds.`));
  }

  function renderLive(ok, when) {
    const live = document.getElementById('live');
    if (ok) {
      live.className = 'tg-pill tg-pill--success';
      live.textContent = `Live · ${clockTime(when)}`;
    } else {
      live.className = 'tg-pill tg-pill--danger';
      live.textContent = 'Disconnected';
    }
  }

  // --------------------------------------------------------------------------
  // Polling
  // --------------------------------------------------------------------------

  async function refresh() {
    if (inFlight) {
      return;
    }
    inFlight = true;
    clearTimeout(timer);
    timer = null;
    try {
      const response = await fetch(STATUS_URL, { cache: 'no-store', credentials: 'same-origin', headers: { Accept: 'application/json' } });
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      const data = await response.json();
      failures = 0;
      renderNotice(data);
      renderUpdate(data);
      renderSummary(data);
      renderSetup(data);
      renderStatus(data);
      renderConfiguration(data);
      renderTraffic(data);
      renderRequests(data);
      renderFooter(data);
      renderLive(true, data.updated_at);
    } catch (error) {
      failures += 1;
      if (failures >= 2) {
        renderLive(false);
      }
    } finally {
      inFlight = false;
    }
    schedule();
  }

  function schedule() {
    if (timer === null && !document.hidden) {
      timer = setTimeout(refresh, REFRESH_MS);
    }
  }

  document.addEventListener('visibilitychange', () => {
    if (!document.hidden && timer === null) {
      refresh();
    }
  });

  refresh();
})();
