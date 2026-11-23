// Twingate Connector add-on: status page.
//
// Polls api/status (a relative URL, so it works under the Home Assistant
// ingress path) and renders it. All values are inserted as text nodes, never
// as HTML: log lines, user names and Resource addresses come from outside.
//
// The top of the page (summary tiles and notices that need action) is always
// visible; everything else is in collapsible sections (createSections).
'use strict';

(() => {
  const REFRESH_MS = 5000;
  const STATUS_URL = 'api/status';
  // The add-on's name and slug from its config.yml, which connector_ui.py
  // puts into index.html (data-addon-name, data-addon-slug). The slug keeps
  // the section choices of this add-on apart from those of the Twingate
  // Connector (Exit) add-on: both pages share the browser's storage.
  const ADDON = document.documentElement.dataset;
  const SECTIONS_KEY = `${ADDON.addonSlug}:sections`;
  const LIST_LIMIT = 10;
  const signatures = new Map();
  let failures = 0;
  let timer = null;
  let inFlight = false;
  let lastData = null;

  // --------------------------------------------------------------------------
  // Collapsible sections. The same helper is used by the Twingate Gateway
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

  // Re-renders an element only when its data changed, so that a text
  // selection is not reset by every refresh.
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
  function count(value, noun) {
    return `${num(value)} ${noun}${value === 1 ? '' : 's'}`;
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

  function millis(ms) {
    if (ms === null || ms === undefined) {
      return '–';
    }
    if (ms < 1000) {
      return `${Math.round(ms)} ms`;
    }
    if (ms < 60000) {
      return `${(ms / 1000).toFixed(1)} s`;
    }
    return duration(ms / 1000);
  }

  function since(epoch, now) {
    if (!epoch) {
      return null;
    }
    return `${dateTime(epoch)} (${duration(now - epoch)} ago)`;
  }

  const UNITS = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];

  function bytes(value) {
    if (value === null || value === undefined) {
      return '–';
    }
    let amount = value;
    let unit = 0;
    while (amount >= 1024 && unit < UNITS.length - 1) {
      amount /= 1024;
      unit += 1;
    }
    return unit === 0 ? `${numberFormat.format(amount)} B` : `${amount.toFixed(amount < 10 ? 2 : 1)} ${UNITS[unit]}`;
  }

  function rate(value) {
    return `${bytes(value)}/s`;
  }

  // --------------------------------------------------------------------------
  // Connector state
  // --------------------------------------------------------------------------

  const STATE_KINDS = {
    Online: 'success',
    Authentication: 'info',
    Offline: 'warning',
    Error: 'danger',
  };

  function statePill(state) {
    if (!state) {
      return pill('neutral', 'Unknown');
    }
    return pill(STATE_KINDS[state] || 'neutral', state);
  }

  const PROCESS = {
    running: ['success', 'Running'],
    starting: ['neutral', 'Starting'],
    stopped: ['danger', 'Not running'],
    unknown: ['neutral', 'Unknown'],
  };

  function processPill(process) {
    const [kind, label] = PROCESS[process && process.state] || PROCESS.unknown;
    return pill(kind, label);
  }

  // The add-on writes "unknown" when the Connector did not report its version.
  function knownVersion(version) {
    return version && version !== 'unknown' ? version : null;
  }

  // The Admin Console address, when the network option is a plain network name.
  function adminConsole(network) {
    const name = String(network || '').toLowerCase();
    if (!/^[a-z0-9][a-z0-9-]{0,62}$/.test(name)) {
      return null;
    }
    return `https://${name}.twingate.com/`;
  }

  // In Error, or cycling through the other states without ever having been
  // online: the tokens or the network name are usually the cause.
  function notOnline(state) {
    if (!state.current || state.current === 'Online') {
      return false;
    }
    return state.current === 'Error' || (!state.last_online_at && state.changes >= 6);
  }

  // --------------------------------------------------------------------------
  // Top of the page: lead, notices that need action, summary tiles
  // --------------------------------------------------------------------------

  function renderLead(data) {
    const startup = data.startup || {};
    render('lead', [startup.network], () => {
      const url = adminConsole(startup.network);
      return ['The Connector\'s own view. Twingate\'s view is in the ', url ? link(url, 'Admin Console') : 'Admin Console', '.'];
    });
  }

  function renderNotice(data) {
    const relay = data.relay || {};
    const process = data.process || {};
    const state = data.state || {};
    const startup = data.startup || {};
    const silent = data.ready && relay.expected && !relay.connected && !relay.pending;
    const offline = data.ready && process.state !== 'stopped' && notOnline(state);
    render('notice', [data.ready, process.state, relay.expected, silent, silent ? Math.floor((relay.age_seconds || 0) / 15) : 0,
      relay.socket_error, relay.source_error, offline, offline && !!state.last_online_at, startup.network], () => {
      if (!data.ready) {
        return callout('warning', 'The Connector has not been started yet',
          el('p', null, 'The add-on installs it at every start. If this stays, the add-on\'s Log tab shows why.'));
      }
      const nodes = [];
      if (process.state === 'starting') {
        nodes.push(callout('info', 'Starting the Connector'));
      } else if (process.state === 'stopped') {
        nodes.push(callout('danger', 'The Connector is not running',
          el('p', null, 'Its process has exited and the add-on stops with it. The add-on\'s Log tab shows why.')));
      }
      if (offline) {
        const url = adminConsole(startup.network);
        nodes.push(callout('warning', state.last_online_at ? 'The Connector is not online' : 'The Connector has not come online since the add-on started',
          el('p', null, 'If it keeps cycling through Offline, Authentication and Error, the tokens or the network name are wrong or the tokens were revoked: generate new tokens in the ',
            url ? link(url, 'Admin Console') : 'Admin Console', ', enter them in the add-on\'s Configuration tab and restart the add-on.')));
      }
      if (!relay.expected) {
        nodes.push(callout('warning', 'The Connector log is not available here',
          el('p', null, 'This page cannot show its state, warnings or connections. Restart the add-on.')));
      } else if (relay.source_error) {
        nodes.push(callout('warning', 'State, warnings and connections may be out of date',
          el('p', null, `The log relay cannot read the copy of the Connector's log (${relay.source_error}). The Connector is not affected; restart the add-on if this stays.`)));
      } else if (silent) {
        const age = relay.age_seconds === null || relay.age_seconds === undefined
          ? 'has not reported since this page\'s server started'
          : `has not reported for ${duration(relay.age_seconds)}`;
        nodes.push(callout('danger', 'State, warnings and connections may be out of date',
          el('p', null, `The log relay ${age}${relay.socket_error ? ` (${relay.socket_error})` : ''}. The Connector is not affected; restart the add-on if this stays.`)));
      }
      return nodes;
    });
  }

  function renderSummary(data, now) {
    const state = data.state || {};
    const metrics = data.metrics || {};
    const process = data.process || {};
    const startup = data.startup || {};
    const uptime = metrics.available && metrics.uptime_seconds !== null ? metrics.uptime_seconds
      : process.started_at ? now - process.started_at : null;
    render('summary', [state.current, state.since, process.state, startup.connector_version, metrics.available,
      metrics.resources, metrics.relay_regions, Math.floor((uptime || 0) / 60), Math.floor(now / 60)], () => [
      card('Connector state', statePill(state.current),
        state.since ? `Since ${clockTime(state.since)} (${duration(now - state.since)})` : 'No state reported yet'),
      card('Process', processPill(process),
        knownVersion(startup.connector_version) ? `Connector ${startup.connector_version}`
          : startup.connector_version ? 'Version unknown' : 'Version not known yet'),
      card('Resources', num(metrics.available ? metrics.resources : null),
        metrics.available ? `${count(metrics.relay_regions, 'relay region')} connected` : 'Metrics unavailable'),
      card('Uptime', duration(uptime), uptime !== null ? `Since ${dateTime(now - uptime)}` : null),
    ]);
  }

  // --------------------------------------------------------------------------
  // Sections
  // --------------------------------------------------------------------------

  const NOT_STARTED = 'Available when the Connector has started';
  const NO_RELAY = 'Not available: the Connector writes its log directly to the add-on log.';

  const RESULTS = {
    open: ['info', 'Open'],
    closed: ['success', 'Closed'],
    failed: ['danger', 'Failed'],
    denied: ['warning', 'Denied'],
    other: ['neutral', 'Other'],
  };

  function pathLabel(item) {
    const path = item.path === 'direct' ? 'Direct' : item.path ? `${item.path.charAt(0).toUpperCase()}${item.path.slice(1)}` : '–';
    return item.proto ? [el('div', null, path), muted(item.proto)] : path;
  }

  function resourceLabel(item) {
    const address = item.resource || item.resource_ip || '–';
    const target = item.port ? `${address}:${item.port}` : address;
    const details = [item.protocol ? item.protocol.toUpperCase() : null,
      item.resource_ip && item.resource_ip !== item.resource ? item.resource_ip : null].filter(Boolean).join(' · ');
    return [el('span', 'tg-mono tg-break', target), details ? muted(details) : null];
  }

  function resultLabel(item) {
    const [kind, label] = RESULTS[item.result] || RESULTS.other;
    const nodes = [el('div', null, pill(kind, label))];
    if (item.error) {
      nodes.push(muted(el('span', 'tg-break', item.error)));
    }
    return nodes;
  }

  function connectionDuration(item, now) {
    if (item.result === 'open') {
      return `${duration(now - item.t)} so far`;
    }
    return millis(item.ms);
  }

  function renderConnections(data, now) {
    const connections = data.connections || {};
    const startup = data.startup || {};
    const relay = data.relay || {};
    const totals = connections.totals || {};
    const items = connections.items || [];
    const listed = data.ready && connections.enabled && relay.expected;

    let digest;
    let level = 0;
    let badge = '';
    if (!data.ready) {
      digest = NOT_STARTED;
    } else if (!connections.enabled) {
      digest = 'Off: turn on the connection_logs option to list them';
    } else if (connections.unsupported) {
      digest = 'Your Twingate plan does not include connection logs';
      level = 1;
      badge = 'Not in your plan';
    } else if (!relay.expected) {
      digest = 'Not available';
    } else if (!items.length) {
      digest = 'None since the add-on started';
    } else {
      digest = [count(totals.shown, 'connection'), totals.open ? `${num(totals.open)} open` : null,
        totals.failed ? `${num(totals.failed)} failed or denied` : null, count(totals.users, 'user')].filter(Boolean).join(', ');
    }
    sections.update('connections', { digest, level, badge, open: data.ready ? Boolean(connections.enabled) : null });

    const shown = sections.rows('connections', listed ? items.length : 0, LIST_LIMIT);
    const open = items.some((item) => item.result === 'open');
    render('connections', [data.ready, relay.expected, connections, startup.log_level, open ? Math.floor(now / 10) : 0, shown], () => {
      if (!data.ready) {
        return el('p', 'tg-empty', `${NOT_STARTED}.`);
      }
      if (!connections.enabled) {
        return callout('info', 'Connection logs are off',
          el('p', null, 'Turn on connection_logs in the add-on\'s Configuration tab and restart the add-on to list each connection here: user, Resource, path, bytes, duration, location and result.'),
          el('p', null, 'Connection logs contain personal data: the email address of every user, the Resources they use and their device\'s public IP address and location. The add-on log keeps them.'));
      }
      const nodes = [];
      if (connections.unsupported) {
        nodes.push(callout('warning', 'Your Twingate plan does not include connection logs',
          el('p', null, 'The Connector ignores the connection_logs option and reports no connections.')));
      }
      if (!relay.expected) {
        nodes.push(el('p', 'tg-empty', NO_RELAY));
        return nodes;
      }
      if (!items.length) {
        nodes.push(el('p', 'tg-empty', 'No connections yet. They appear when someone uses a Resource through this Connector.'));
        if (startup.log_level === 'error' && !connections.unsupported) {
          nodes.push(note('With log level error, the Connector does not log that your Twingate plan lacks connection logs. If none appear, choose warn or info and check Warnings and errors.'));
        }
        return nodes;
      }
      nodes.push(note(`Newest first, from ${count(connections.events, 'connection log line')} since the add-on started. Kept in memory only, without the device's IP address and ID.`));
      const rows = items.slice(0, shown).map((item) => [
        clockTime(item.t),
        item.user || '–',
        resourceLabel(item),
        pathLabel(item),
        bytes(item.rx),
        bytes(item.tx),
        connectionDuration(item, now),
        item.location || '–',
        resultLabel(item),
      ]);
      nodes.push(table([
        { label: 'Started', cellClass: 'tg-nowrap' },
        { label: 'User', cellClass: 'tg-break' },
        { label: 'Resource' },
        { label: 'Path' },
        { label: 'Received', numeric: true },
        { label: 'Sent', numeric: true },
        { label: 'Duration', numeric: true },
        { label: 'Location' },
        { label: 'Result' },
      ], rows, 'tg-table--stack tg-table--compact'));
      return nodes;
    });
  }

  function renderProblems(data) {
    const problems = data.problems || { items: [], counts: {} };
    const counts = problems.counts || {};
    // Errors first, so that the shortened list shows them; then newest first.
    const items = (problems.items || []).slice().sort((a, b) =>
      ((b.level === 'error') - (a.level === 'error')) || ((b.last || 0) - (a.last || 0)));
    const startup = data.startup || {};
    const relay = data.relay || {};
    const listed = data.ready && relay.expected;

    let digest;
    let level = 0;
    let badge = '';
    if (!data.ready) {
      digest = NOT_STARTED;
    } else if (!relay.expected) {
      digest = 'Not available';
    } else if (!items.length) {
      digest = startup.log_level === 'error' ? 'No errors since the add-on started (log level error: no warnings)' : 'None since the add-on started';
    } else {
      const errors = counts.error || 0;
      const warnings = counts.warning || 0;
      level = errors ? 2 : 1;
      badge = errors ? count(errors, 'error') : count(warnings, 'warning');
      const latest = Math.max(...items.map((item) => item.last || 0));
      digest = `${listing([errors ? count(errors, 'error') : null, warnings ? count(warnings, 'warning') : null])} since the add-on started, latest at ${clockTime(latest)}`;
    }
    sections.update('problems', { digest, level, badge, open: data.ready ? false : null });

    const shown = sections.rows('problems', listed ? items.length : 0, LIST_LIMIT);
    render('problems', [data.ready, relay.expected, problems, startup.log_level, shown], () => {
      if (!data.ready) {
        return el('p', 'tg-empty', `${NOT_STARTED}.`);
      }
      if (!relay.expected) {
        return el('p', 'tg-empty', NO_RELAY);
      }
      const nodes = [];
      if (startup.log_level === 'error') {
        nodes.push(note('With log level error, the Connector logs errors only. Choose warn or info to see its warnings here.'));
      }
      if (!items.length) {
        nodes.push(el('p', 'tg-empty', 'No warnings or errors since the add-on started.'));
        return nodes;
      }
      nodes.push(note('Grouped by message, errors first, newest first. IP and email addresses are shown as [IP] and [email]; the add-on\'s Log tab has the full log.'));
      const rows = items.slice(0, shown).map((item) => [
        clockTime(item.last),
        pill(item.level === 'error' ? 'danger' : 'warning', item.level === 'error' ? 'Error' : 'Warning'),
        [item.source ? el('div', 'tg-muted tg-small', item.source) : null, el('span', 'tg-mono tg-break', item.message)],
        num(item.count),
      ]);
      nodes.push(table([
        { label: 'Last seen', cellClass: 'tg-nowrap' },
        { label: 'Level' },
        { label: 'Message' },
        { label: 'Count', numeric: true },
      ], rows, 'tg-table--stack tg-table--compact'));
      return nodes;
    });
  }

  const PATHS = [
    ['direct', 'Direct', 'success'],
    ['relay_quic', 'Relay (QUIC)', 'info'],
    ['relay_tcp', 'Relay (TCP)', 'warning'],
    ['relay_other', 'Relay', 'warning'],
    ['other', 'Other', 'neutral'],
  ];

  function renderTraffic(data, now) {
    const metrics = data.metrics || {};
    const process = data.process || {};
    // Shortly after the start the metrics endpoint may not answer yet.
    const missing = !metrics.available && process.state === 'running' && process.started_at && now - process.started_at > 30;

    let digest;
    let level = 0;
    let badge = '';
    if (metrics.available) {
      const inbound = metrics.inbound;
      const outbound = metrics.outbound;
      const total = inbound.total + outbound.total;
      const parts = [`${bytes(inbound.total)} received`, `${bytes(outbound.total)} sent`];
      if (total > 0) {
        parts.push(`${Math.round(((inbound.direct + outbound.direct) / total) * 100)}% direct`);
      }
      if (metrics.rate) {
        parts.push(`${rate(metrics.rate.inbound_bps + metrics.rate.outbound_bps)} now`);
      }
      digest = parts.join(', ');
    } else if (missing) {
      digest = 'The Connector\'s metrics endpoint does not answer';
      level = 1;
      badge = 'No metrics';
    } else {
      digest = process.state === 'running' ? 'Metrics not available yet' : 'Available when the Connector runs';
    }
    sections.update('traffic', { digest, level, badge, open: false });

    render('traffic', [metrics, process.state, missing], () => {
      if (!metrics.available) {
        if (process.state !== 'running') {
          return el('p', 'tg-empty', 'Available when the Connector runs.');
        }
        return callout('warning', 'Metrics are not available',
          el('p', null, `The Connector's metrics endpoint did not answer (${metrics.error || 'unknown error'}). It starts with the Connector.`));
      }
      const inbound = metrics.inbound;
      const outbound = metrics.outbound;
      const total = Math.max(1, inbound.total + outbound.total);
      const rows = PATHS
        .filter(([key]) => key === 'direct' || key === 'relay_quic' || key === 'relay_tcp' || inbound[key] || outbound[key])
        .map(([key, label, kind]) => [
          label,
          bytes(inbound[key]),
          bytes(outbound[key]),
          bar((inbound[key] + outbound[key]) / total, kind),
        ]);
      const current = metrics.rate;
      return [
        el('div', 'tg-grid',
          card('Received from Resources', bytes(inbound.total), `${bytes(inbound.relay)} of it through relays`),
          card('Sent to Resources', bytes(outbound.total), `${bytes(outbound.relay)} of it through relays`),
          card('Current rate', current ? rate(current.inbound_bps + current.outbound_bps) : '–',
            current ? `${rate(current.inbound_bps)} received, ${rate(current.outbound_bps)} sent` : 'Shown after about 10 seconds')),
        table([
          { label: 'Path' },
          { label: 'Received from Resources', numeric: true },
          { label: 'Sent to Resources', numeric: true },
          { label: 'Share' },
        ], rows, 'tg-table--stack'),
        note('Direct traffic flows peer-to-peer between a Twingate Client and the Connector; relayed traffic passes through a Twingate Relay. Counters start when the Connector starts.'),
      ];
    });
  }

  function historyTable(history) {
    const rows = history.slice(-10).reverse().map((entry) => [clockTime(entry.t), statePill(entry.state)]);
    return table([{ label: 'Time', cellClass: 'tg-nowrap' }, { label: 'State' }], rows, 'tg-table--compact');
  }

  function renderStatus(data, now) {
    const startup = data.startup || {};
    const state = data.state || {};
    const process = data.process || {};

    let digest;
    let level = 0;
    let badge = '';
    if (!data.ready) {
      digest = NOT_STARTED;
    } else {
      if (process.state === 'stopped') {
        level = 2;
        badge = 'Not running';
      } else if (notOnline(state)) {
        level = state.current === 'Error' ? 2 : 1;
        badge = state.current;
      }
      const parts = [!state.current ? 'No state reported yet'
        : state.since ? `${state.current} since ${clockTime(state.since)}` : state.current];
      if (state.current && state.current !== 'Online') {
        parts.push(state.last_online_at ? `last online ${clockTime(state.last_online_at)}` : 'not online since the add-on started');
      }
      if (state.changes) {
        parts.push(count(state.changes, 'state change'));
      }
      digest = parts.join(', ');
    }
    sections.update('status', { digest, level, badge, open: data.ready ? false : null });

    render('status', [data.ready, state, process.state, process.started_at, startup.connector_version, startup.addon_version,
      Math.floor(now / 60)], () => {
      if (!data.ready) {
        return el('p', 'tg-empty', `${NOT_STARTED}.`);
      }
      let lastOnline = '–';
      if (state.current === 'Online') {
        lastOnline = state.online_since ? `Now, without interruption since ${clockTime(state.online_since)}` : 'Now';
      } else if (state.last_online_at) {
        lastOnline = since(state.last_online_at, now);
      } else if (state.current) {
        lastOnline = 'Not since the add-on started';
      }
      const nodes = [
        kvTable([
          ['Connector state', [el('div', null, statePill(state.current)),
            muted(state.since ? `Since ${since(state.since, now)}` : 'Not reported yet')]],
          ['Last online', lastOnline],
          ['State changes', `${num(state.changes || 0)} since the add-on started`],
          ['Process', [el('div', null, processPill(process)),
            process.started_at ? muted(`Started ${since(process.started_at, now)}`) : null]],
          ['Connector version', knownVersion(startup.connector_version)
            ? [el('div', null, startup.connector_version), muted('Installed from Twingate\'s repository when the add-on starts')]
            : muted(startup.connector_version ? 'Unknown: the Connector did not report its version' : 'Not known yet')],
          ['Add-on version', startup.addon_version || '–'],
        ]),
      ];
      if (state.history && state.history.length) {
        nodes.push(el('h3', 'tg-h3', 'Recent state changes'));
        nodes.push(historyTable(state.history));
      }
      return nodes;
    });
  }

  const LEVEL_TEXT = {
    error: 'Level 3: errors only',
    warn: 'Level 4: errors and warnings',
    info: 'Level 5: errors, warnings and information',
    debug: 'Level 7: everything, very verbose',
  };

  function renderConfiguration(data) {
    const startup = data.startup || {};
    sections.update('configuration', {
      digest: data.ready
        ? `Network ${startup.network || '–'}, log level ${startup.log_level || 'info'}, connection logs ${startup.connection_logs ? 'on' : 'off'}`
        : NOT_STARTED,
      open: data.ready ? false : null,
    });
    render('configuration', [data.ready, startup.network, startup.log_level, startup.hostname_label, startup.deployed_by_label,
      startup.connection_logs, startup.metrics_port], () => {
      if (!data.ready) {
        return el('p', 'tg-empty', `${NOT_STARTED}.`);
      }
      const url = adminConsole(startup.network);
      return kvTable([
        ['Twingate network', [code(startup.network || '–'), url ? muted('Admin Console: ', link(url, url.slice(8, -1))) : null]],
        ['Log level', [code(startup.log_level || 'info'), LEVEL_TEXT[startup.log_level] ? muted(LEVEL_TEXT[startup.log_level]) : null]],
        ['Hostname label', startup.hostname_label
          ? [code(startup.hostname_label), muted('Shown in the Connector\'s details in the Admin Console')]
          : muted('None')],
        ['Deployed by label', startup.deployed_by_label ? code(startup.deployed_by_label) : muted('None')],
        ['Connection logs', startup.connection_logs
          ? [el('div', null, 'On'), muted('One log line per connection, with the user\'s email address')]
          : 'Off'],
        ['Metrics', startup.metrics_port
          ? [el('div', null, 'Port ', code(startup.metrics_port), ' inside the add-on container'),
            muted('Prometheus format at /metrics, on the internal add-on network only')]
          : muted('Off')],
        ['Tokens', muted('Set in the add-on\'s Configuration tab; never shown here')],
      ]);
    });
  }

  function renderFooter(data) {
    const startup = data.startup || {};
    render('footer', [startup.addon_version], () => el('p', null,
      `Read-only status page of the ${ADDON.addonName} add-on${startup.addon_version ? ` ${startup.addon_version}` : ''}. Values refresh every 5 seconds.`));
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
    renderLead(data);
    renderNotice(data);
    renderSummary(data, now);
    renderConnections(data, now);
    renderProblems(data);
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
