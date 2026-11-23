// Twingate Gateway add-on: status page.
//
// Polls api/status (a relative URL, so it works under the Home Assistant
// ingress path) and renders it. All values are inserted as text nodes, never
// as HTML: audit data such as paths and user names comes from clients.
//
// The top of the page (summary tiles and notices that need action) is always
// visible; everything else is in collapsible sections (createSections).
'use strict';

(() => {
  const REFRESH_MS = 5000;
  const STATUS_URL = 'api/status';
  const SECTIONS_KEY = 'twingate-gateway:sections';
  // The SHA-256 fingerprint of the CA for which a Twingate client has
  // authenticated (see clientAuthenticated).
  const AUTHENTICATED_KEY = 'twingate-gateway:authenticated';
  const LIST_LIMIT = 10;
  const signatures = new Map();
  let failures = 0;
  let timer = null;
  let inFlight = false;
  let lastData = null;

  // --------------------------------------------------------------------------
  // Collapsible sections. The same helper is used by the Twingate Connector
  // add-on's page; keep the two copies identical.
  //
  // Markup: see "Collapsible sections" in twingate-docs-theme.css. Each
  // <details class="tg-details" data-section="NAME"> is created once, in
  // index.html; the page only updates what is inside it.
  //
  // sections.update(NAME, { digest, level, badge, open }) sets the summary
  // line in place:
  //   digest  one line of text, the section's essential fact
  //   level   0 normal, 1 warning, 2 error
  //   badge   short text for a pill next to the title (warning or danger
  //           colour by level), or '' for none
  //   open    whether the section is open by default, or null while that is
  //           not known yet
  // A section the user has not opened or closed starts as `open`, or open
  // when its level is above 0. The user's choice is kept per section in
  // localStorage (if available) with the level at that moment, and a refresh
  // never changes it, with one exception: a section opens by itself when its
  // level rises above every level it had since the page loaded or since the
  // user's choice. It never closes by itself.
  //
  // sections.rows(NAME, total, limit) returns how many rows of a list to show
  // (limit, or total after the user selected "Show all") and updates the
  // section's tg-showall button. When the user selects it, onChange() is
  // called to render the list again; include the returned number in the
  // list's render key.
  // --------------------------------------------------------------------------

  function createSections(storageKey, onChange) {
    let saved = {};
    try {
      const value = JSON.parse(window.localStorage.getItem(storageKey) || '{}');
      if (value && typeof value === 'object' && !Array.isArray(value)) {
        saved = value;
      }
    } catch (error) {
      saved = {};
    }

    function persist() {
      try {
        window.localStorage.setItem(storageKey, JSON.stringify(saved));
      } catch (error) {
        // Not available (blocked or private browsing): kept until the page reloads.
      }
    }

    function choiceOf(name) {
      const choice = saved[name];
      return choice && typeof choice === 'object' ? choice : {};
    }

    function remember(name, values) {
      saved[name] = Object.assign({}, choiceOf(name), values);
      persist();
    }

    function setText(node, text) {
      if (node && node.textContent !== text) {
        node.textContent = text;
      }
    }

    function setOpen(section, open) {
      section.expected = open;
      if (section.details.open !== open) {
        section.details.open = open;
      }
    }

    const sections = new Map();
    for (const details of document.querySelectorAll('details.tg-details[data-section]')) {
      const name = details.dataset.section;
      const choice = choiceOf(name);
      const section = {
        details,
        badge: details.querySelector('.tg-details__badge'),
        digest: details.querySelector('.tg-details__digest'),
        button: details.querySelector('.tg-showall__button'),
        expected: details.open,
        chosen: typeof choice.open === 'boolean',
        ready: false,
        level: 0,
        seen: 0,
        badgeKey: '',
        all: choice.all === true,
      };
      sections.set(name, section);
      if (section.chosen) {
        setOpen(section, choice.open);
      }
      // The toggle event also follows the page's own changes (setOpen);
      // only a state that differs from the expected one is the user's.
      details.addEventListener('toggle', () => {
        if (details.open === section.expected) {
          return;
        }
        section.expected = details.open;
        section.ready = true;
        section.chosen = true;
        section.seen = Math.max(section.seen, section.level);
        remember(name, { open: details.open, level: section.seen });
      });
      if (section.button) {
        section.button.addEventListener('click', () => {
          section.all = !section.all;
          remember(name, { all: section.all });
          onChange();
          if (!section.all) {
            section.button.scrollIntoView({ block: 'nearest' });
          }
        });
      }
    }

    function update(name, { digest = '', level = 0, badge = '', open = null } = {}) {
      const section = sections.get(name);
      if (!section) {
        return;
      }
      setText(section.digest, digest);
      const badgeKey = badge ? `${level}|${badge}` : '';
      if (badgeKey !== section.badgeKey) {
        section.badgeKey = badgeKey;
        if (badge) {
          const pill = document.createElement('span');
          pill.className = `tg-pill tg-pill--${level >= 2 ? 'danger' : level === 1 ? 'warning' : 'neutral'}`;
          pill.textContent = badge;
          section.badge.replaceChildren(pill);
        } else {
          section.badge.replaceChildren();
        }
      }
      section.level = level;
      if (!section.ready && (section.chosen || open !== null)) {
        section.ready = true;
        const opened = section.chosen
          ? level > (Number(choiceOf(name).level) || 0)
          : open || level > 0;
        setOpen(section, section.details.open || opened);
        section.seen = Math.max(section.seen, level);
      } else if (level > section.seen) {
        section.seen = level;
        setOpen(section, true);
      }
    }

    function rows(name, total, limit) {
      const section = sections.get(name);
      if (!section || !section.button) {
        return total;
      }
      const row = section.button.parentElement;
      if (total <= limit) {
        row.hidden = true;
        return total;
      }
      row.hidden = false;
      setText(section.button, section.all ? `Show newest ${limit}` : `Show all ${total}`);
      section.button.setAttribute('aria-expanded', String(section.all));
      return section.all ? total : limit;
    }

    return { update, rows };
  }

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

  function note(...children) {
    return el('p', 'tg-muted tg-small', ...children);
  }

  function pill(kind, label) {
    return el('span', `tg-pill tg-pill--${kind}`, label);
  }

  function link(href, label) {
    const anchor = el('a', null, label);
    anchor.href = href;
    anchor.target = '_blank';
    anchor.rel = 'noopener noreferrer';
    return anchor;
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

  // Re-renders an element only when its data changed, so that a selection,
  // an open "How to rebuild" or the copy button's feedback is not reset by
  // every refresh.
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

  // "1 user", "3 users"
  function count(value, noun, plural = `${noun}s`) {
    return `${num(value)} ${value === 1 ? noun : plural}`;
  }

  // "a", "a and b", "a, b and c"
  function listing(parts) {
    const items = parts.filter(Boolean);
    return items.length < 2 ? items.join('') : `${items.slice(0, -1).join(', ')} and ${items[items.length - 1]}`;
  }

  function dateTime(epoch) {
    if (!epoch) {
      return '–';
    }
    return new Date(epoch * 1000).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
  }

  function dateOnly(epoch) {
    return new Date(epoch * 1000).toLocaleDateString(undefined, { dateStyle: 'medium' });
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

  function relativeDays(epoch, now) {
    const days = Math.round((epoch - now) / 86400);
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

  // "90:67:D3…B1:57"
  function shortFingerprint(fingerprint) {
    return fingerprint.length > 16 ? `${fingerprint.slice(0, 8)}…${fingerprint.slice(-5)}` : fingerprint;
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
  // Gateway, signing keys, API proxy and audit relay state
  // --------------------------------------------------------------------------

  const NOT_STARTED = 'Available when the Gateway has started';
  const OUT_OF_DATE = 'The Gateway request list may be out of date';

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

  function signingKeyDetail(keys, network) {
    const check = keys.check;
    if (check && check.ok) {
      return `The signing-key URL answered with ${count(check.keys, 'key')} at ${clockTime(check.checked_at)}.`;
    }
    if (check) {
      return `The signing-key URL could not be read at ${clockTime(check.checked_at)}: ${check.error || 'unknown error'}.`;
    }
    const startup = keys.startup_check || {};
    const text = {
      found: `At startup, Twingate network ${network} was found (HTTP ${startup.http_status}); the signing-key URL is checked shortly.`,
      unreachable: 'At startup, Twingate could not be reached.',
      http_error: `At startup, the network check answered HTTP ${startup.http_status}.`,
    }[startup.result];
    return text || 'The signing-key URL is checked shortly after the add-on starts, then every 15 minutes.';
  }

  // The API proxy's state, for its tile and Status details.
  function proxyState(data) {
    const proxy = data.proxy;
    if (!data.ready || !proxy) {
      return { kind: 'neutral', label: 'Unknown', level: 0, meta: 'Not known yet' };
    }
    if (!proxy.seen) {
      return (proxy.silent_seconds || 0) < 15
        ? { kind: 'neutral', label: 'Starting', level: 0, meta: 'Has not reported yet' }
        : { kind: 'danger', label: 'Stopped', level: 2, meta: 'Has not reported' };
    }
    if (!proxy.reporting) {
      return { kind: 'danger', label: 'Stopped', level: 2, meta: 'Not reporting' };
    }
    if (!proxy.token) {
      return { kind: 'danger', label: 'No token', level: 2, meta: 'No Supervisor token' };
    }
    if (proxy.state !== 'running') {
      const state = proxy.state || 'starting';
      return { kind: 'warning', label: `${state.charAt(0).toUpperCase()}${state.slice(1)}`, level: 1, meta: 'Not serving requests' };
    }
    return { kind: 'success', label: 'Running', level: 0, meta: `${count(proxy.websockets || 0, 'WebSocket')} open` };
  }

  // Whether the proxy's signing keys are missing for longer than a start takes.
  function proxyKeysMissing(data, now) {
    const proxy = data.proxy || {};
    return Boolean(proxy.reporting && proxy.keys && !proxy.keys.ok && proxy.started_at && now - proxy.started_at > 30);
  }

  // A problem of the Gateway request list (the audit relay and the copy of
  // the audit log that it reads) as [title, text], or null.
  function auditProblem(data) {
    const audit = data.audit || {};
    if (!data.ready) {
      return null;
    }
    const logged = audit.stream === 'file' ? 'to the audit log file' : 'to the add-on\'s Log tab';
    const fine = ` The Gateway is not affected; every request is still logged ${logged}.`;
    const copy = audit.stream === 'relay' && audit.relay ? audit.relay.copy : null;
    const fileState = audit.relay && audit.relay.file_state;
    if (audit.stream === 'none') {
      return ['Gateway requests are not shown here', 'The Gateway writes its audit log directly to the add-on log. Restart the add-on.'];
    }
    if (audit.socket_error) {
      return [OUT_OF_DATE, `This page cannot receive audit summaries (${audit.socket_error}).${fine}`];
    }
    if (audit.relay_silent) {
      const silent = Math.floor((audit.relay_silent_seconds || 0) / 15) * 15;
      return [OUT_OF_DATE, `The audit relay has not reported for ${duration(silent)}.${fine} Restart the add-on if this stays.`];
    }
    if (!audit.connected) {
      return null;
    }
    if (copy === 'not kept') {
      return ['New Gateway requests are not shown here', `The add-on cannot keep the copy of the audit log that this page reads; the Log tab says why.${fine} Restarting the add-on tries again.`];
    }
    if (copy === 'no space') {
      return [OUT_OF_DATE, `There is no space left in /dev/shm for the copy of the audit log that this page reads.${fine}`];
    }
    if (fileState && fileState !== 'reading') {
      const source = audit.stream === 'file' ? 'the audit log file' : 'the copy of the audit log';
      return [OUT_OF_DATE, `The audit relay reports for ${source}: ${fileState}.${fine}`];
    }
    return null;
  }

  // Whether a Twingate client has authenticated with this Gateway: since the
  // Gateway started (its metrics), or as the user of a listed request. The
  // browser also remembers it for this CA, so that the setup steps do not
  // come back after the add-on restarts; a new CA must be registered again.
  let authenticatedCa = null;
  try {
    authenticatedCa = window.localStorage.getItem(AUTHENTICATED_KEY);
  } catch (error) {
    authenticatedCa = null;
  }

  function clientAuthenticated(data) {
    const ca = (data.startup && data.startup.ca) || {};
    const fingerprint = ca.fingerprint_sha256 || null;
    const keys = data.signing_keys || {};
    const seen = keys.authentications_succeeded > 0
      || ((data.proxy && data.proxy.records) || []).some((record) => record.user)
      || ((data.audit && data.audit.records) || []).some((record) => record.user);
    if (seen && fingerprint && authenticatedCa !== fingerprint) {
      authenticatedCa = fingerprint;
      try {
        window.localStorage.setItem(AUTHENTICATED_KEY, fingerprint);
      } catch (error) {
        // Not available: remembered until the page reloads.
      }
    }
    return seen || (fingerprint !== null && authenticatedCa === fingerprint);
  }

  // The Admin Console address, when the network option is a plain network name.
  function adminConsole(network) {
    const name = String(network || '').toLowerCase();
    if (!/^[a-z0-9][a-z0-9-]{0,62}$/.test(name)) {
      return null;
    }
    return `https://${name}.twingate.com/`;
  }

  // The Gateway address for the Twingate Connector add-on on this Home
  // Assistant: the add-on's host name, as in the API proxy's Resource address,
  // and the Gateway's own port.
  function gatewayAddress(data) {
    const startup = data.startup || {};
    const settings = startup.proxy || {};
    return `${settings.dns_name || '<add-on host name>.local.hass.io'}:${startup.gateway_port || 8443}`;
  }

  // --------------------------------------------------------------------------
  // Top of the page: lead, notices that need action, summary tiles
  // --------------------------------------------------------------------------

  function renderLead(data) {
    const startup = data.startup || {};
    render('lead', [startup.network], () => {
      const url = adminConsole(startup.network);
      return ['The Gateway and its Home Assistant API proxy as the add-on sees them. Twingate\'s view is in the ',
        url ? link(url, 'Admin Console') : 'Admin Console', '.'];
    });
  }

  function renderNotice(data) {
    const problem = auditProblem(data);
    render('notice', [data.ready, problem], () => {
      if (!data.ready) {
        return callout('warning', 'The Gateway has not finished starting',
          el('p', null, 'The add-on is still starting, or it stopped because of a configuration problem. The add-on\'s Log tab shows why.'));
      }
      return problem ? callout('warning', problem[0], el('p', null, problem[1])) : [];
    });
  }

  // Shown until the first Twingate client has authenticated.
  function renderNextSteps(data, authenticated) {
    const address = gatewayAddress(data);
    render('next-steps', [data.ready && !authenticated, address], () => {
      if (!data.ready || authenticated) {
        return [];
      }
      return callout('info', 'Next steps',
        el('ol', 'tg-list',
          el('li', null, 'Register the CA certificate (under Setup) in Twingate as an X.509 certificate authority.'),
          el('li', null, 'Create a Gateway with the Gateway address ', code(address), ' (see Setup), in the Remote Network of your Connector, using that CA.'),
          el('li', null, 'Create a Web App Resource on that Gateway with the API proxy address and upstream port.')),
        el('p', null, 'Step by step, with Terraform or curl: the add-on\'s Documentation tab.'));
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
        el('p', null, `This add-on runs Gateway ${update.running}. Rebuild the add-on to install ${update.latest}; the configuration and the CA are kept.`),
        el('details', null,
          el('summary', 'tg-showall__button', 'How to rebuild'),
          el('ol', 'tg-list',
            el('li', null, 'In Home Assistant, open ', el('strong', null, 'Settings > Apps > Twingate Gateway'), '.'),
            el('li', null, 'On the ', el('strong', null, 'Info'), ' tab, open the menu (⋮) of the ', el('strong', null, 'Controls'), ' card and select ', el('strong', null, 'Rebuild'), '.')),
          el('p', null, 'Or on the Home Assistant command line: ', code(`ha apps rebuild ${slug || '<slug>'}`),
            `. The rebuild takes the newest Gateway ${major}.x from the image tag ${update.image} on Docker Hub; the Gateway accepts no connections until it is done.`)));
    });
  }

  function renderSummary(data) {
    const traffic = data.traffic || {};
    const keys = data.signing_keys || {};
    const health = data.health || {};
    const proxy = proxyState(data);
    // Four tiles fill a row of the page; the Gateway's uptime is part of its
    // tile (and a row of Status details). It has a line of its own, so that a
    // longer or shorter uptime never changes the tile's height, and it is in
    // minutes, so that the tiles are not rendered again at every refresh.
    let uptime = 'Uptime not known yet';
    if (data.uptime_seconds !== null && data.uptime_seconds !== undefined) {
      uptime = `Up ${data.uptime_seconds < 60 ? '< 1 min' : duration(data.uptime_seconds)}`;
    }
    render('summary', [health.ok, data.gateway_version, keys.state, traffic.available, traffic.active_connections, traffic.http && traffic.http.active,
      proxy, uptime], () => [
      card('Gateway', healthPill(health), [
        el('div', null, health.ok ? (data.gateway_version ? `Version ${data.gateway_version}` : 'Answering') : 'Health check failing'),
        el('div', null, uptime)]),
      card('Signing keys', signingKeysPill(keys), keys.state === 'ok' ? 'Twingate tokens can be verified' : 'See Status details'),
      card('API proxy', pill(proxy.kind, proxy.label), proxy.meta),
      card('Active connections', num(traffic.available ? traffic.active_connections : null),
        traffic.available ? `${count(traffic.http.active, 'request')} in progress` : 'Metrics unavailable'),
    ]);
  }

  // --------------------------------------------------------------------------
  // Sections
  // --------------------------------------------------------------------------

  const DECISIONS = {
    read: ['success', 'Allowed (Read)'],
    mcp: ['success', 'Allowed (MCP)'],
    full: ['success', 'Allowed (Full)'],
    denied: ['warning', 'Denied'],
    blocked: ['danger', 'Blocked'],
    invalid: ['warning', 'Refused'],
    unauthenticated: ['neutral', 'No valid token'],
    limited: ['warning', 'Too many at once'],
    error: ['danger', 'Failed'],
    closed: ['neutral', 'Closed'],
  };

  function proxyRequestText(record) {
    if (record.kind === 'ws-cmd') {
      return ['WebSocket ', el('span', 'tg-mono tg-break', record.path || '?'), record.detail ? el('span', 'tg-muted', ` (${record.detail})`) : null];
    }
    if (record.kind === 'ws') {
      return ['WebSocket closed', record.detail ? el('span', 'tg-muted', ` (${record.detail})`) : null];
    }
    return [`${record.method} `, el('span', 'tg-mono tg-break', record.path || '/', record.q ? el('span', 'tg-muted', '?…') : null)];
  }

  function usersOf(records) {
    return new Set(records.map((record) => record.user).filter(Boolean)).size;
  }

  function renderProxyRequests(data) {
    const settings = data.startup && data.startup.proxy;
    const proxy = data.proxy || {};
    const counts = proxy.counts || {};
    const records = proxy.records || [];

    let digest;
    if (!data.ready) {
      digest = NOT_STARTED;
    } else if (!settings) {
      digest = 'Not available';
    } else if (!proxy.seen) {
      digest = 'The proxy has not reported yet';
    } else if (!counts.requests) {
      digest = 'None since the proxy started';
    } else {
      digest = [count(counts.requests, 'request'), counts.denied ? `${num(counts.denied)} denied` : null,
        counts.blocked ? `${num(counts.blocked)} blocked` : null,
        counts.unauthenticated ? `${num(counts.unauthenticated)} without a valid token` : null,
        count(usersOf(records), 'user')].filter(Boolean).join(', ');
    }
    sections.update('proxy-requests', { digest, open: data.ready ? true : null });

    const shown = sections.rows('proxy-requests', data.ready && settings ? records.length : 0, LIST_LIMIT);
    render('proxy-requests', [data.ready, Boolean(settings), proxy.seen, counts, records, shown], () => {
      if (!data.ready) {
        return el('p', 'tg-empty', `${NOT_STARTED}.`);
      }
      if (!settings) {
        return el('p', 'tg-empty', 'The API proxy configuration is not available. The add-on\'s Log tab shows why.');
      }
      if (!records.length) {
        return el('p', 'tg-empty', proxy.seen
          ? 'No requests yet. They appear when a Twingate client uses the API proxy Resource.'
          : 'The proxy has not reported yet.');
      }
      const totals = listing([`${num(counts.allowed)} allowed`, counts.denied ? `${num(counts.denied)} denied` : null,
        counts.blocked ? `${num(counts.blocked)} blocked for every caller` : null,
        counts.unauthenticated ? `${num(counts.unauthenticated)} without a valid token` : null,
        counts.invalid ? `${num(counts.invalid)} refused as invalid` : null,
        counts.limited ? `${num(counts.limited)} too many at once` : null,
        counts.errors ? `${num(counts.errors)} failed` : null]);
      const rows = records.slice(0, shown).map((record) => {
        const [kind, label] = DECISIONS[record.decision] || DECISIONS.error;
        return [
          clockTime(record.t),
          record.user || '–',
          record.grant || '–',
          el('span', null, proxyRequestText(record)),
          pill(kind, label),
          record.status ? String(record.status) : '–',
          millis(record.ms),
        ];
      });
      return [
        note(`Since the proxy started: ${totals}. Newest first, with WebSocket commands.`),
        table([
          { label: 'Time', cellClass: 'tg-nowrap' },
          { label: 'User', cellClass: 'tg-break' },
          { label: 'Grant' },
          { label: 'Request' },
          { label: 'Decision' },
          { label: 'Status' },
          { label: 'Duration', numeric: true },
        ], rows, 'tg-table--stack tg-table--compact'),
      ];
    });
  }

  function renderRequests(data) {
    const audit = data.audit || {};
    const startup = data.startup || {};
    const records = audit.records || [];
    const copy = audit.stream === 'relay' && audit.relay ? audit.relay.copy : null;
    const listed = data.ready && audit.stream !== 'none';

    let digest;
    if (!data.ready) {
      digest = NOT_STARTED;
    } else if (audit.stream === 'none') {
      digest = 'Not available: the audit log goes directly to the add-on log';
    } else if (!records.length) {
      digest = copy === 'not kept' ? 'Not shown: see the notice at the top' : audit.connected ? 'None yet' : 'Waiting for the audit relay';
    } else {
      const client = records.filter((record) => !record.err && record.status >= 400 && record.status < 500).length;
      const server = records.filter((record) => record.err || record.status >= 500).length;
      digest = [count(records.length, 'request'), client ? `${num(client)} × 4xx` : null, server ? `${num(server)} × 5xx or failed` : null,
        count(usersOf(records), 'user')].filter(Boolean).join(', ');
    }
    // Open by default for the request_headers setup, whose requests are
    // listed here only; proxied requests are also in the section above.
    sections.update('requests', { digest, open: data.ready ? (startup.request_header_names || []).length > 0 : null });

    const shown = sections.rows('requests', listed ? records.length : 0, LIST_LIMIT);
    render('requests', [data.ready, audit.stream, audit.connected, copy, startup.audit_log_file, records, shown], () => {
      if (!data.ready) {
        return el('p', 'tg-empty', `${NOT_STARTED}.`);
      }
      if (audit.stream === 'none') {
        return el('p', 'tg-empty', 'Not available: the Gateway writes its audit log directly to the add-on log.');
      }
      if (!records.length) {
        if (copy === 'not kept') {
          return el('p', 'tg-empty', 'None to show: see the notice at the top of the page.');
        }
        return el('p', 'tg-empty', audit.connected
          ? 'No requests yet. They appear when a Twingate client uses a Resource on this Gateway.'
          : 'Waiting for the audit relay. Requests appear here once it reports.');
      }
      const rows = records.slice(0, shown).map((record) => [
        clockTime(record.t),
        record.user || '–',
        record.method,
        el('span', 'tg-mono tg-break', record.path || '/', record.pt ? '…' : null, record.q ? el('span', 'tg-muted', '?…') : null),
        pill(record.err ? 'danger' : statusKind(record.status), record.status ? String(record.status) : 'none'),
        millis(record.ms),
      ]);
      return [
        note(audit.stream === 'file'
          ? `The newest 100 entries of the audit log file ${startup.audit_log_file || '/config/audit.log'}, newest first.`
          : 'The newest 100 audit log entries since the add-on started, newest first. The add-on\'s Log tab has the full entries.'),
        table([
          { label: 'Time', cellClass: 'tg-nowrap' },
          { label: 'User', cellClass: 'tg-break' },
          { label: 'Method' },
          { label: 'Path' },
          { label: 'Status' },
          { label: 'Duration', numeric: true },
        ], rows, 'tg-table--stack tg-table--compact'),
      ];
    });
  }

  const GRANTS = [
    ['read', 'Read', 'Reads over REST and WebSocket; no actions and no templates.', 'Everyone with access to the Resource', 'everyone'],
    ['mcp', 'MCP', 'The Model Context Protocol endpoint /api/mcp.', 'Nobody', 'nobody'],
    ['full', 'Full', 'Everything that is not always blocked; includes Read and MCP.', 'Nobody', 'nobody'],
  ];

  function groupList(names, empty) {
    if (!names || !names.length) {
      return el('span', 'tg-muted', empty);
    }
    return el('div', null, names.map((name, index) => [index ? ' ' : null, code(name)]));
  }

  function renderAccess(data) {
    const settings = data.startup && data.startup.proxy;
    const groups = (settings && settings.groups) || {};
    let digest;
    if (!data.ready) {
      digest = NOT_STARTED;
    } else if (!settings) {
      digest = 'Not available';
    } else {
      digest = GRANTS.map(([key, label, , , none]) => `${label}: ${groups[key] && groups[key].length ? groups[key].join(', ') : none}`).join(' · ');
    }
    sections.update('access', { digest, open: data.ready ? false : null });

    render('access', [data.ready, Boolean(settings), groups], () => {
      if (!data.ready) {
        return el('p', 'tg-empty', `${NOT_STARTED}.`);
      }
      if (!settings) {
        return el('p', 'tg-empty', 'The API proxy configuration is not available. The add-on\'s Log tab shows why.');
      }
      return [
        table([
          { label: 'Grant' },
          { label: 'Who' },
          { label: 'Allows' },
        ], GRANTS.map(([key, label, allows, empty]) => [el('strong', null, label), groupList(groups[key], empty), allows]), 'tg-table--stack'),
        note('Full is a block-list, not a security boundary. What MCP can do is set in Home Assistant\'s MCP Server settings; by default any action on any entity.'),
      ];
    });
  }

  function renderSetup(data, now, authenticated) {
    const startup = data.startup || {};
    const ca = startup.ca || {};
    const settings = startup.proxy;
    const address = gatewayAddress(data);
    const left = ca.not_after_epoch ? ca.not_after_epoch - now : null;
    const expiring = left !== null && left < 30 * 86400;

    let digest = NOT_STARTED;
    let level = 0;
    let badge = '';
    if (data.ready) {
      if (startup.host_port_state === 'not_mapped') {
        level = 2;
        badge = 'Port not published';
      } else if (left !== null && left <= 0) {
        level = 2;
        badge = 'CA expired';
      } else if (expiring) {
        level = 1;
        badge = 'CA expires soon';
      }
      let caText = 'CA not available';
      if (expiring) {
        caText = `CA ${left <= 0 ? 'expired' : 'expires'} ${dateOnly(ca.not_after_epoch)}`;
      } else if (ca.fingerprint_sha256) {
        caText = `CA ${shortFingerprint(ca.fingerprint_sha256)}`;
      } else if (ca.not_after_epoch) {
        caText = `CA ${ca.source === 'custom' ? 'of your own' : 'created by this add-on'}, expires ${dateOnly(ca.not_after_epoch)}`;
      }
      digest = `Gateway address ${address}, ${caText}`;
    }
    sections.update('setup', { digest, level, badge, open: data.ready ? !authenticated : null });

    render('setup', [data.ready, ca, startup.host_port, startup.host_port_state, startup.gateway_port, data.host_hint, settings,
      Math.floor(now / 3600)], () => {
      if (!data.ready) {
        return el('p', 'tg-empty', `${NOT_STARTED}.`);
      }
      // A Connector that does not run on this Home Assistant cannot resolve
      // the add-on's host name; it needs the host's LAN IP address and the
      // host port, which the add-on cannot see (host_hint is only a hint).
      const port = startup.host_port || startup.gateway_port || 8443;
      const lanAddress = code(`${data.host_hint || '<home-assistant-ip>'}:${port}`);
      const sameHost = 'With the Twingate Connector add-on on this Home Assistant. For a Connector elsewhere, use ';
      let addressHelp;
      if (startup.host_port_state === 'not_mapped') {
        addressHelp = callout('warning', 'Port not published',
          el('p', null, `Container port ${startup.gateway_port}/tcp has no host port. Set one in the add-on's Network section, then restart the add-on.`));
      } else if (data.host_hint) {
        addressHelp = muted(sameHost, 'the host\'s LAN IP address, for example ', lanAddress, ' (the address you opened Home Assistant with).');
      } else {
        addressHelp = muted(sameHost, lanAddress, ' with the host\'s LAN IP address (Settings > System > Network).',
          startup.host_port_state === 'unknown' ? ' The port is the host port set for 8443/tcp in the Network section.' : null);
      }
      let resource = muted('Not available. The add-on\'s Log tab shows why.');
      if (settings) {
        resource = [
          el('div', null, 'Address ', code(settings.dns_name || '<add-on host name>.local.hass.io'), ', upstream port ', code(String(settings.port))),
          settings.host_port_state === 'mapped' && settings.host_port
            ? muted('Or address ', code(data.host_hint || '<home-assistant-ip>'), ' with upstream port ', code(String(settings.host_port)), ': published on your LAN.')
            : muted('The Gateway reaches the proxy inside the add-on; no port needs to be published.'),
        ];
      }
      return [
        kvTable([
          ['Gateway address', [code(address), addressHelp]],
          ['API proxy Resource', resource],
          ['CA subject', ca.subject ? el('span', 'tg-break', ca.subject) : '–'],
          ['SHA-256 fingerprint', ca.fingerprint_sha256 ? el('span', 'tg-mono tg-break', ca.fingerprint_sha256) : '–'],
          ['CA expires', ca.not_after_epoch
            ? [el('div', null, `${dateTime(ca.not_after_epoch)} (${relativeDays(ca.not_after_epoch, now)})`), expiring ? el('div', null, pill('warning', 'Replace soon')) : null]
            : ca.not_after || '–'],
          ['CA source', ca.source === 'custom'
            ? [el('div', null, 'Your own CA'), muted(code(ca.certificate_file || ''))]
            : [el('div', null, 'Created by this add-on'), muted('Kept in the add-on\'s data folder.')]],
        ]),
        el('h3', 'tg-h3', 'CA certificate'),
        note('Register it in Twingate as an X.509 certificate authority. This is the public certificate; the CA private key never leaves the add-on.'),
        ca.pem ? codeBlock(ca.pem, 'Copy the CA certificate') : el('p', 'tg-empty', 'The CA certificate is not available.'),
      ];
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

  function renderTraffic(data, now) {
    const traffic = data.traffic || {};
    const startup = data.startup || {};
    const keys = data.signing_keys || {};
    // Shortly after the start the metrics endpoint may not answer yet.
    const missing = Boolean(data.ready && !traffic.available && startup.started_at && now - startup.started_at > 30);

    let digest;
    let level = 0;
    let badge = '';
    if (traffic.available) {
      const classes = STATUS_CLASSES.filter(([key]) => traffic.http.by_class[key]).map(([key]) => `${num(traffic.http.by_class[key])} × ${key}`);
      digest = `${count(traffic.connections.proxy, 'connection')}, ${num(traffic.authentication.succeeded)} authenticated, ${num(traffic.authentication.failed_at_least)} failed; ${classes.length ? classes.join(', ') : 'no HTTP requests'}`;
    } else if (missing) {
      digest = 'The Gateway\'s metrics endpoint does not answer';
      level = 1;
      badge = 'No metrics';
    } else {
      digest = 'Metrics not available yet';
    }
    sections.update('traffic', { digest, level, badge, open: false });

    const memory = traffic.available ? bytes(traffic.process.resident_memory_bytes) : null;
    render('traffic', traffic.available
      ? [traffic.connections, traffic.authentication, traffic.http.total, traffic.http.by_class, traffic.http.latency, traffic.upstream.total,
        traffic.upstream.by_class, traffic.upstream.latency, memory, keys.last_authentication_at]
      : [traffic.error, missing], () => {
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
          card('Connections', num(traffic.connections.proxy), 'Closed connections from Twingate Clients'),
          card('Authenticated', num(traffic.authentication.succeeded),
            keys.last_authentication_at ? `Last one by ${clockTime(keys.last_authentication_at)}` : 'With a valid Twingate token'),
          card('Failed authentication', num(traffic.authentication.failed_at_least), 'At least this many connections'),
          card('Rejected before a request', num(traffic.connections.unknown), 'Port probes, handshakes with an unregistered CA')),
        el('h3', 'tg-h3', 'Responses'),
        table([
          { label: 'Status' },
          { label: 'To clients', numeric: true },
          { label: 'Share' },
          { label: 'From upstream', numeric: true },
        ], classRows, 'tg-table--stack'),
        note(`${count(http.total, 'HTTP request')}, ${num(upstream.total)} answered by the upstream (Home Assistant). A WebSocket counts as 2xx to clients and 1xx from upstream.`),
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
        note(`Percentiles are the bounds of the Gateway's histogram buckets. Counters start at zero when the add-on starts. Gateway memory: ${memory}.`),
      ];
    });
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

  // The first problem of the Gateway, the signing keys, the API proxy and
  // the request list, as [level, badge], or null.
  function statusProblem(data, now) {
    const health = data.health || {};
    const keys = data.signing_keys || {};
    const proxy = proxyState(data);
    const problems = [
      [!health.ok, 2, 'Not healthy'],
      [keys.state === 'error', 2, 'Network not found'],
      [proxy.level === 2, 2, proxy.label === 'No token' ? 'No Supervisor token' : 'Proxy stopped'],
      [keys.state === 'warning', 1, 'Key check failed'],
      [proxy.level === 1, 1, `Proxy ${proxy.label.toLowerCase()}`],
      [proxyKeysMissing(data, now), 1, 'Proxy keys not loaded'],
      [Boolean(auditProblem(data)), 1, 'Requests out of date'],
    ].filter(([found]) => found);
    return problems.length ? problems[0].slice(1) : null;
  }

  function keysText(data) {
    const keys = data.signing_keys || {};
    const proxy = data.proxy || {};
    if (keys.state === 'ok') {
      return proxy.seen && proxy.keys && !proxy.keys.ok ? 'proxy keys not loaded' : 'keys loaded';
    }
    return {
      warning: 'signing-key check failed',
      error: 'Twingate network not found',
      pending: 'signing keys being checked',
    }[keys.state] || 'signing keys unknown';
  }

  function auditRelayRow(data, problem) {
    const audit = data.audit || {};
    const relay = audit.relay || {};
    if (audit.stream === 'none') {
      return [el('div', null, pill('neutral', 'Not available')), muted('The Gateway writes its audit log directly to the add-on log.')];
    }
    if (problem) {
      return [el('div', null, pill('warning', 'May be out of date')), muted('See the notice at the top of this page.')];
    }
    if (!audit.connected) {
      return [el('div', null, pill('neutral', 'Waiting')), muted('The audit relay has not reported yet.')];
    }
    return [el('div', null, pill('success', 'Up to date')),
      muted(`The audit relay reads ${relay.source === 'file' ? 'the audit log file' : 'the copy of the add-on log'}: ${count(relay.entries || 0, 'entry', 'entries')} since it started.`)];
  }

  function renderStatus(data, now) {
    const startup = data.startup || {};
    const keys = data.signing_keys || {};
    const health = data.health || {};
    const proxy = data.proxy || {};
    const proxyKeys = proxy.keys || {};
    const state = proxyState(data);
    const problem = auditProblem(data);

    let digest = NOT_STARTED;
    let level = 0;
    let badge = '';
    if (data.ready) {
      const found = statusProblem(data, now);
      if (found) {
        [level, badge] = found;
      }
      const parts = [`Gateway${data.gateway_version ? ` ${data.gateway_version}` : ''} ${health.ok ? 'healthy' : 'not healthy'}`,
        `proxy ${state.label.toLowerCase()}`, keysText(data)];
      if (problem) {
        parts.push('request list may be out of date');
      }
      digest = parts.join(', ');
    }
    sections.update('status', { digest, level, badge, open: data.ready ? false : null });

    const update = data.gateway_update || {};
    const relay = data.audit && data.audit.relay;
    render('status', [data.ready, [health.ok, health.http_status, health.error], Math.floor((health.checked_at || 0) / 60),
      data.gateway_version, [update.update_available, update.latest, update.checked_at, update.image], startup.network,
      [keys.state, keys.check, keys.startup_check], state, proxy.started_at, proxy.websockets, proxyKeys,
      [data.audit && data.audit.stream, data.audit && data.audit.connected, relay && relay.source, relay && relay.entries, problem],
      startup.static_certificate, startup.certificate_ip_addresses, startup.addon_version, Math.floor((data.uptime_seconds || 0) / 60),
      data.gateway_started_at, Math.floor(now / 3600)], () => {
      if (!data.ready) {
        return el('p', 'tg-empty', `${NOT_STARTED}.`);
      }
      const nodes = [];
      if (state.level === 2 && state.label === 'No token') {
        nodes.push(callout('danger', 'The API proxy has no Supervisor token',
          el('p', null, 'It cannot reach Home Assistant. Restart the add-on.')));
      } else if (state.level === 2) {
        nodes.push(callout('danger', 'The API proxy is not reporting',
          el('p', null, 'It has not reported for more than 15 seconds; s6 restarts it when it stops. The Gateway and the request_headers setup are not affected. If this stays, check the add-on\'s Log tab.')));
      }
      let proxyDetail = 'Has not reported yet.';
      if (state.label === 'Running') {
        proxyDetail = `Since ${dateTime(proxy.started_at)}; ${count(proxy.websockets || 0, 'WebSocket connection')} open.`;
      } else if (state.level === 2) {
        proxyDetail = state.label === 'No token' ? 'No Supervisor token: it cannot reach Home Assistant.' : 'Has not reported for more than 15 seconds.';
      } else if (state.level === 1) {
        proxyDetail = `Reports the state "${proxy.state}".`;
      }
      const staticCertificate = startup.static_certificate;
      nodes.push(kvTable([
        ['Gateway health', [el('div', null, healthPill(health)), muted(healthDetail(health))]],
        ['Gateway version', data.gateway_version
          ? [el('div', null, data.gateway_version), updateDetail(data)]
          : muted('Reported by the Gateway with the first request it handles.')],
        ['Signing keys', [el('div', null, signingKeysPill(keys)), muted(signingKeyDetail(keys, startup.network))]],
        ['API proxy', [el('div', null, pill(state.kind, state.label)), muted(proxyDetail)]],
        ['Proxy signing keys', proxy.seen
          ? [el('div', null, pill(proxyKeys.ok ? 'success' : 'warning', proxyKeys.ok ? 'Loaded' : 'Not loaded')),
            muted(proxyKeys.ok
              ? `${count(proxyKeys.keys, 'key')}, read ${clockTime(proxyKeys.checked_at)}. The proxy verifies callers' Twingate tokens with them.`
              : `Requests are refused until the keys can be read (${proxyKeys.error || 'not read yet'}).`)]
          : muted('Not reported yet.')],
        ['Gateway request list', auditRelayRow(data, problem)],
        ['Gateway uptime', data.uptime_seconds !== null && data.uptime_seconds !== undefined
          ? [el('div', null, duration(data.uptime_seconds)), muted(`Since ${dateTime(data.gateway_started_at)}`)]
          : '–'],
        ['Static certificate', staticCertificate
          ? [el('div', null, (startup.certificate_ip_addresses || []).join(', ')),
            muted(staticCertificate.not_after_epoch
              ? `Expires ${dateTime(staticCertificate.not_after_epoch)} (${relativeDays(staticCertificate.not_after_epoch, now)}); renewed at a start within 30 days of expiry.`
              : 'Expiry unknown.')]
          : muted('None. Only issued for certificate IP addresses.')],
        ['Add-on version', startup.addon_version || '–'],
      ]));
      return nodes;
    });
  }

  function renderConfiguration(data) {
    const startup = data.startup || {};
    const names = startup.request_header_names || [];
    sections.update('configuration', {
      digest: data.ready
        ? `Network ${startup.network || '–'}, log level ${startup.log_level || 'info'}, audit log: ${startup.audit_log === 'file' ? 'file' : 'add-on log'}, ${count(names.length, 'injected header')}`
        : NOT_STARTED,
      open: data.ready ? false : null,
    });
    const tokenHeader = startup.proxy && startup.proxy.token_header;
    render('configuration', [data.ready, startup.network, names, startup.certificate_ip_addresses, startup.audit_log,
      startup.audit_log_file, startup.log_level, tokenHeader], () => {
      if (!data.ready) {
        return el('p', 'tg-empty', `${NOT_STARTED}.`);
      }
      const ips = startup.certificate_ip_addresses || [];
      const tokenNote = tokenHeader ? ['The add-on also adds ', code(tokenHeader), ' (the client\'s Twingate token) for the API proxy.'] : null;
      return kvTable([
        ['Twingate network', [code(startup.network || '–'),
          startup.network ? muted(`Signing keys from https://${startup.network}.twingate.com/api/v1/jwk/ec`) : null]],
        ['Log level', code(startup.log_level || 'info')],
        ['Audit log', startup.audit_log === 'file'
          ? [el('div', null, 'File in the add-on configuration folder'), muted(code(startup.audit_log_file || '/config/audit.log'), ' (rotated at 10 MiB, 3 compressed backups)')]
          : [el('div', null, 'Add-on log'), muted('The add-on\'s Log tab.')]],
        ['Injected request headers', names.length
          ? [el('div', null, names.map((name, index) => [index ? ' ' : null, code(name)])), muted('Names only; values are never shown. ', tokenNote)]
          : [el('div', null, 'None configured'), tokenNote ? muted(tokenNote) : null]],
        ['Certificate IP addresses', ips.length ? ips.join(', ') : muted('None.')],
      ]);
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

  function renderAll(data) {
    // Times are compared with the add-on's clock, not the browser's.
    const now = data.updated_at;
    const authenticated = clientAuthenticated(data);
    renderLead(data);
    renderNotice(data);
    renderNextSteps(data, authenticated);
    renderUpdate(data);
    renderSummary(data);
    renderProxyRequests(data);
    renderRequests(data);
    renderAccess(data);
    renderSetup(data, now, authenticated);
    renderTraffic(data, now);
    renderStatus(data, now);
    renderConfiguration(data);
    renderFooter(data);
  }

  const sections = createSections(SECTIONS_KEY, () => {
    if (lastData) {
      renderAll(lastData);
    }
  });

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
      lastData = data;
      renderAll(data);
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
