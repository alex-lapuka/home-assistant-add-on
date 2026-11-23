// Twingate Connector add-on: status page.
//
// Polls api/status (a relative URL, so it works under the Home Assistant
// ingress path) and renders it. All values are inserted as text nodes, never
// as HTML: log lines, user names and Resource addresses come from outside.
'use strict';

(() => {
  const REFRESH_MS = 5000;
  const STATUS_URL = 'api/status';
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

  // Re-renders a section only when its data changed, so that a text
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

  const STATES = {
    Online: ['success', 'The Connector reports that it is connected to Twingate.'],
    Authentication: ['info', 'The Connector is signing in to Twingate with its access and refresh tokens.'],
    Offline: ['warning', 'The Connector is not connected to Twingate. It retries on its own.'],
    Error: ['danger', 'The Connector ran into an error, for example with its tokens, the network name or the connection to Twingate. It retries on its own.'],
  };

  function statePill(state) {
    if (!state) {
      return pill('neutral', 'Unknown');
    }
    return pill((STATES[state] || ['neutral'])[0], state);
  }

  function stateText(state) {
    if (!state) {
      return 'The Connector has not reported a state yet. It prints its state when it starts and whenever the state changes.';
    }
    return (STATES[state] || [null, `The Connector reports the state ${state}.`])[1];
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

  function notOnlineHelp(state) {
    if (!state.current || state.current === 'Online') {
      return null;
    }
    if (state.current !== 'Error' && (state.last_online_at || state.changes < 6)) {
      return null;
    }
    return callout('warning', state.last_online_at ? 'The Connector is not online' : 'The Connector has not come online since the add-on started',
      el('p', null, 'If it keeps cycling through Offline, Authentication and Error, the tokens or the network name are usually wrong, or the tokens were revoked. Generate new tokens for this Connector in the Admin Console, enter them in the add-on\'s Configuration tab and restart the add-on.'),
      el('p', null, 'The warnings below and the add-on\'s Log tab show the Connector\'s own reason.'));
  }

  // --------------------------------------------------------------------------
  // Sections
  // --------------------------------------------------------------------------

  function renderNotice(data) {
    const relay = data.relay || {};
    const process = data.process || {};
    const silent = data.ready && relay.expected && !relay.connected && !relay.pending;
    render('notice', [data.ready, process.state, relay.expected, silent, silent ? Math.floor((relay.age_seconds || 0) / 15) : 0,
      relay.socket_error, relay.source_error], () => {
      if (!data.ready) {
        return callout('warning', 'The Connector has not been started yet',
          el('p', null, 'The add-on installs the Connector from Twingate\'s package repository at every start, which takes a moment. If this does not change, the add-on stopped because of a configuration problem; the add-on\'s Log tab shows why.'));
      }
      const nodes = [];
      if (process.state === 'starting') {
        nodes.push(callout('info', 'Starting', el('p', null, 'The add-on is installing and starting the Connector.')));
      } else if (process.state === 'stopped') {
        nodes.push(callout('danger', 'The Connector is not running',
          el('p', null, 'The Connector process has exited. The add-on stops with it; the add-on\'s Log tab shows why.')));
      }
      if (!relay.expected) {
        nodes.push(callout('warning', 'The Connector log is not available here',
          el('p', null, 'The Connector writes its log directly to the add-on log, so this page cannot show its state, warnings or connections. Restart the add-on.')));
      } else if (relay.source_error) {
        nodes.push(callout('warning', 'The state, warnings and connections below may be out of date',
          el('p', null, `The log relay cannot read the copy of the Connector's log that the add-on keeps for this page (${relay.source_error}).`),
          el('p', null, 'The Connector keeps running and its log still reaches the add-on\'s Log tab. If this stays, restart the add-on.')));
      } else if (silent) {
        const age = relay.age_seconds === null || relay.age_seconds === undefined
          ? 'has not reported since this page\'s server started'
          : `has not reported for ${duration(relay.age_seconds)}`;
        nodes.push(callout('danger', 'The state, warnings and connections below may be out of date',
          el('p', null, `The log relay, which reads the Connector's log for this page, ${age}.`,
            relay.socket_error ? ` The page cannot receive its summaries (${relay.socket_error}).` : ' It is restarted automatically.'),
          el('p', null, 'The Connector keeps running and its log still reaches the add-on\'s Log tab. If this stays, restart the add-on.')));
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
        metrics.available ? `${num(metrics.relay_regions)} relay ${metrics.relay_regions === 1 ? 'region' : 'regions'} connected` : 'Metrics unavailable'),
      card('Uptime', duration(uptime), uptime !== null ? `Since ${dateTime(now - uptime)}` : null),
    ]);
  }

  function renderScope(data) {
    const startup = data.startup || {};
    render('scope', [startup.network], () => {
      const url = adminConsole(startup.network);
      return callout('info', 'This page shows the Connector\'s own view',
        el('p', null, 'Whether Twingate sees this Connector as online, and which Resources and users it serves, is shown in the Twingate Admin Console, in the Remote Network this Connector belongs to.'),
        url ? el('p', null, link(url, `Open the Admin Console (${url.slice(8, -1)})`)) : null);
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
    render('status', [data.ready, state, process.state, process.started_at, startup.connector_version, startup.addon_version,
      Math.floor(now / 60)], () => {
      if (!data.ready) {
        return el('p', 'tg-empty', 'Available when the Connector has started.');
      }
      const stateDetails = [el('div', null, statePill(state.current)), muted(stateText(state.current))];
      if (state.since) {
        stateDetails.push(muted(`Since ${since(state.since, now)}.`));
      }
      if (state.current === 'Online' && state.online_since) {
        stateDetails.push(muted(`Online without interruption since ${clockTime(state.online_since)}.`));
      } else if (state.last_online_at) {
        stateDetails.push(muted(`Last online at ${dateTime(state.last_online_at)}.`));
      } else if (state.current) {
        stateDetails.push(muted('Not online since the add-on started.'));
      }
      if (state.changes) {
        stateDetails.push(muted(`${num(state.changes)} state ${state.changes === 1 ? 'change' : 'changes'} since the add-on started.`));
      }
      const nodes = [
        notOnlineHelp(state),
        kvTable([
          ['Connector state', stateDetails],
          ['Process', [el('div', null, processPill(process)),
            process.started_at ? muted(`Started ${since(process.started_at, now)}.`) : null]],
          ['Connector version', knownVersion(startup.connector_version)
            ? [el('div', null, startup.connector_version), muted('Installed from Twingate\'s package repository when the add-on starts.')]
            : muted(startup.connector_version ? 'Unknown: the Connector did not report its version.' : 'Not known yet.')],
          ['Add-on version', startup.addon_version || '–'],
        ]),
      ];
      if (state.history && state.history.length) {
        nodes.push(el('h3', 'tg-h3', 'Recent state changes'));
        nodes.push(el('p', 'tg-muted tg-small', 'As printed by the Connector in its log, newest first.'));
        nodes.push(historyTable(state.history));
      }
      return nodes;
    });
  }

  const LEVEL_TEXT = {
    error: 'level 3: errors only',
    warn: 'level 4: errors and warnings',
    info: 'level 5: errors, warnings and information',
    debug: 'level 7: everything, very verbose',
  };

  function renderConfiguration(data) {
    const startup = data.startup || {};
    render('configuration', [data.ready, startup.network, startup.log_level, startup.hostname_label, startup.deployed_by_label,
      startup.connection_logs, startup.metrics_port], () => {
      if (!data.ready) {
        return el('p', 'tg-empty', 'Available when the Connector has started.');
      }
      const url = adminConsole(startup.network);
      return kvTable([
        ['Twingate network', [code(startup.network || '–'), url ? muted(link(url, url.slice(8, -1))) : null]],
        ['Log level', [code(startup.log_level || 'info'), muted(`Connector log ${LEVEL_TEXT[startup.log_level] || ''}.`)]],
        ['Hostname label', startup.hostname_label
          ? [code(startup.hostname_label), muted('Sent to Twingate as the Connector\'s hostname, shown in its details in the Admin Console.')]
          : muted('None.')],
        ['Deployed by label', startup.deployed_by_label ? code(startup.deployed_by_label) : muted('None.')],
        ['Connection logs', startup.connection_logs
          ? [el('div', null, 'On'), muted('The Connector writes a log line for every connection, including the user\'s email address.')]
          : [el('div', null, 'Off'), muted('See Recent connections below.')]],
        ['Metrics', startup.metrics_port
          ? [el('div', null, 'Port ', code(startup.metrics_port), ' inside the add-on container'),
            muted('Prometheus format at /metrics. Reachable from Home Assistant and other add-ons on the internal add-on network, not published on the host or your LAN.')]
          : muted('Off.')],
        ['Tokens', muted('The access and refresh tokens are set in the add-on\'s Configuration tab and are never shown here.')],
      ]);
    });
  }

  const PATHS = [
    ['direct', 'Direct', 'success'],
    ['relay_quic', 'Relay (QUIC)', 'info'],
    ['relay_tcp', 'Relay (TCP)', 'warning'],
    ['relay_other', 'Relay', 'warning'],
    ['other', 'Other', 'neutral'],
  ];

  function renderTraffic(data) {
    const metrics = data.metrics || {};
    const process = data.process || {};
    render('traffic', [metrics, process.state], () => {
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
            current ? `${rate(current.inbound_bps)} received, ${rate(current.outbound_bps)} sent (last ${current.window_seconds} s)` : 'Measuring, shown after about 10 seconds'),
          card('Resources', num(metrics.resources), 'Available to this Connector'),
          card('Relay regions', num(metrics.relay_regions), 'Regions with Twingate Relays this Connector is connected to'),
          card('Connector uptime', duration(metrics.uptime_seconds), 'Reported by the Connector')),
        el('h3', 'tg-h3', 'By path'),
        table([
          { label: 'Path' },
          { label: 'Received from Resources', numeric: true },
          { label: 'Sent to Resources', numeric: true },
          { label: 'Share' },
        ], rows, 'tg-table--stack'),
        el('p', 'tg-muted tg-small',
          'Direct traffic flows peer-to-peer between a Twingate Client and the Connector; relayed traffic passes through a Twingate Relay. ',
          'Counters start at zero when the Connector starts.'),
      ];
    });
  }

  function renderProblems(data) {
    const problems = data.problems || { items: [], counts: {} };
    const startup = data.startup || {};
    const relay = data.relay || {};
    render('problems', [data.ready, relay.expected, problems, startup.log_level], () => {
      if (!data.ready) {
        return el('p', 'tg-empty', 'Available when the Connector has started.');
      }
      if (!relay.expected) {
        return el('p', 'tg-empty', 'Not available: the Connector writes its log directly to the add-on log.');
      }
      const nodes = [
        el('p', null, 'Warnings and errors from the Connector\'s log since the add-on started, grouped by message (numbers ignored), most recent first. IP addresses and email addresses are shown as [IP] and [email]. Kept in memory only. The full log is in the add-on\'s Log tab.'),
      ];
      if (startup.log_level === 'error') {
        nodes.push(muted('With log level error, the Connector logs errors only. Choose warn or info to see its warnings here.'));
      }
      const items = problems.items || [];
      if (!items.length) {
        nodes.push(el('p', 'tg-empty', 'No warnings or errors since the add-on started.'));
        return nodes;
      }
      const rows = items.map((item) => [
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
    const open = (connections.items || []).some((item) => item.result === 'open');
    render('connections', [data.ready, relay.expected, connections, startup.log_level, open ? Math.floor(now / 10) : 0], () => {
      if (!data.ready) {
        return el('p', 'tg-empty', 'Available when the Connector has started.');
      }
      if (!connections.enabled) {
        return callout('info', 'Connection logs are off',
          el('p', null, 'To see recent connections here, turn on the option connection_logs in the add-on\'s Configuration tab and restart the add-on. The page then lists when each connection started, which user made it, the Resource and port, whether it went direct or through a relay, the bytes received and sent, the duration, the approximate location and the result.'),
          el('p', null, 'Connection logs contain personal data: the email address of every user, the Resources they use, and their device\'s public IP address and approximate location. The Connector writes one line per connection to the add-on log, which Home Assistant keeps with its other logs. This page keeps its summaries in memory only and does not show the IP address.'));
      }
      const nodes = [];
      if (connections.unsupported) {
        nodes.push(callout('warning', 'Your Twingate plan does not include connection logs',
          el('p', null, 'The Connector logged that network analytics is not supported in your Twingate product tier, so it ignores the connection_logs option and reports no connections.')));
      }
      if (!relay.expected) {
        nodes.push(el('p', 'tg-empty', 'Not available: the Connector writes its log directly to the add-on log.'));
        return nodes;
      }
      nodes.push(el('p', null, 'The newest 100 connections since the add-on started, from the Connector\'s connection logs, newest first. Kept in memory only. The client\'s public IP address and device ID are not shown here; the full lines are in the add-on\'s Log tab.'));
      const totals = connections.totals || {};
      const items = connections.items || [];
      if (!items.length) {
        nodes.push(el('p', 'tg-empty', 'No connections yet. They appear here when someone uses a Resource through this Connector.'));
        if (startup.log_level === 'error' && !connections.unsupported) {
          nodes.push(muted('With log level error, the Connector does not log the warning it gives when your Twingate plan does not include connection logs. If no connections appear although Resources are used through this Connector, choose the log level warn or info, restart the add-on and check Recent warnings and errors.'));
        }
        return nodes;
      }
      nodes.push(el('div', 'tg-grid',
        card('Connections', num(totals.shown), `${num(connections.events)} connection log lines since the add-on started`),
        card('Open', num(totals.open), 'Established and not closed yet'),
        card('Failed or denied', num(totals.failed), 'Could not connect, or not allowed'),
        card('Users', num(totals.users), 'Distinct users in the list')));
      const rows = items.map((item) => [
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
      nodes.push(el('p', 'tg-muted tg-small', 'Received and sent are the bytes the Connector counted on the connection. The location is derived by Twingate from the public IP address of the user\'s device.'));
      return nodes;
    });
  }

  function renderFooter(data) {
    const startup = data.startup || {};
    render('footer', [startup.addon_version], () => el('p', null,
      `Read-only status page of the Twingate Connector add-on${startup.addon_version ? ` ${startup.addon_version}` : ''}. Values refresh every 5 seconds.`));
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
      // Times are compared with the add-on's clock, not the browser's.
      const now = data.updated_at;
      failures = 0;
      renderNotice(data);
      renderSummary(data, now);
      renderScope(data);
      renderStatus(data, now);
      renderConfiguration(data);
      renderTraffic(data);
      renderProblems(data);
      renderConnections(data, now);
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
