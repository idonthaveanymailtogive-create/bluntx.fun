/* BluntX site UI. Data gathering and scoring live in core.js (shared byte-for-byte with the BluntX extension).
   Every call goes straight from the browser to free, keyless public APIs; nothing is stored. */
(function (root) {
  'use strict';

  // ---------- core (core.js) ----------
  function C() { return root.BluntXCore; }
  function chainName(c) { return C().chainName(c); }
  function usd(n) { return C().usd(n); }
  function ago(h) { return C().ago(h); }
  function pct(x) { return C().pct(x); }
  function flag(v) { return C().flag(v); }
  function detect(a) { return C().detect(a); }
  function extract(t) { return C().extract(t); }
  function getJSON(u, ms) { return C().getJSON(u, ms); }
  function gather(a, c) { return C().gather(a, c, { rpcMode: 'always' }); }
  function score(d) { return C().score(d); }
  var CHAINS = {}, GOPLUS_IDS = {}, HONEYPOT_IDS = {};
  if (root.BluntXCore) { CHAINS = root.BluntXCore.CHAINS; GOPLUS_IDS = root.BluntXCore.GOPLUS_IDS; HONEYPOT_IDS = root.BluntXCore.HONEYPOT_IDS; }

  // DexScreener links usually point at a pair (pool) address, not the token. Resolve them to the token.
  async function resolveDexLink(raw) {
    var m = String(raw || '').match(/dexscreener\.com\/([a-z0-9-]+)\/([A-Za-z0-9]{20,70})/i);
    if (!m) return null;
    try {
      var j = await getJSON('https://api.dexscreener.com/latest/dex/pairs/' + m[1].toLowerCase() + '/' + m[2], 10000);
      var p = (j && j.pairs && j.pairs[0]) || (j && j.pair);
      if (p && p.baseToken && p.baseToken.address) return { addr: p.baseToken.address, chain: p.chainId };
    } catch (e) { /* fall back to the raw address */ }
    return null;
  }

  // ---------- UI (DOM only: API data is always inserted as text, never as HTML) ----------
  function el(tag, attrs, kids) {
    var n = document.createElement(tag);
    if (attrs) Object.keys(attrs).forEach(function (k) {
      if (k === 'class') n.className = attrs[k]; else if (k === 'text') n.textContent = attrs[k]; else n.setAttribute(k, attrs[k]);
    });
    (kids || []).forEach(function (c) { if (c != null) n.appendChild(typeof c === 'string' ? document.createTextNode(c) : c); });
    return n;
  }
  function svgEl(name, attrs) {
    var n = document.createElementNS('http://www.w3.org/2000/svg', name);
    if (attrs) Object.keys(attrs).forEach(function (k) {
      if (k === 'text') n.textContent = attrs[k]; else n.setAttribute(k, attrs[k]);
    });
    return n;
  }
  // Only http(s) links to known hosts; anything else is dropped.
  var LINK_HOSTS = /^(dexscreener\.com|rugcheck\.xyz|pump\.fun|gopluslabs\.io|honeypot\.is|solscan\.io|etherscan\.io|bscscan\.com|basescan\.org|arbiscan\.io|polygonscan\.com|optimistic\.etherscan\.io|snowtrace\.io|sonicscan\.org|blastscan\.io|lineascan\.build|tronscan\.org|suiscan\.xyz|tonviewer\.com|explorer\.aptoslabs\.com)$/;
  function safeUrl(u) {
    try { var x = new URL(u); return x.protocol === 'https:' && LINK_HOSTS.test(x.hostname.replace(/^www\./, '')) ? x.href : null; } catch (e) { return null; }
  }
  function safeImg(u) {
    try { var x = new URL(u); return x.protocol === 'https:' && /^(cdn|dd)\.dexscreener\.com$/.test(x.hostname) ? x.href : null; } catch (e) { return null; }
  }
  function ext(href, label) {
    var h = safeUrl(href);
    return h ? el('a', { href: h, target: '_blank', rel: 'noopener noreferrer', text: label + ' ↗' }) : null;
  }
  function msg(out, cls, text, spin) {
    out.replaceChildren(el('div', { class: cls }, [spin ? el('div', { class: 'spin' }) : null, text]));
  }
  // ---------- report v3 (SVG attributes only, never element.style, so it stays within style-src 'self') ----------
  var GA = { cx: 100, cy: 100, r: 80 };
  function gPoint(v) { var a = Math.PI * Math.max(0, Math.min(100, v)) / 100; return [GA.cx - GA.r * Math.cos(a), GA.cy - GA.r * Math.sin(a)]; }
  function gArc(v0, v1) {
    var p0 = gPoint(v0), p1 = gPoint(v1);
    return 'M' + p0[0].toFixed(2) + ' ' + p0[1].toFixed(2) + ' A80 80 0 0 1 ' + p1[0].toFixed(2) + ' ' + p1[1].toFixed(2);
  }
  function buildGauge(points, rating) {
    var pts = Math.max(0, Number(points) || 0), v = Math.min(100, pts);
    var label = pts + ' risk points: ' + rating + '. Under 25 is Low risk, 25 to 54 is Caution, 55 or more is High risk.';
    var svg = svgEl('svg', { viewBox: '0 0 200 122', role: 'img', 'aria-label': label });
    svg.appendChild(svgEl('title', { text: label }));
    svg.appendChild(svgEl('path', { class: 'g-zone ok', d: gArc(0, 25) }));
    svg.appendChild(svgEl('path', { class: 'g-zone warn', d: gArc(25, 55) }));
    svg.appendChild(svgEl('path', { class: 'g-zone bad', d: gArc(55, 100) }));
    if (v > 0.5) svg.appendChild(svgEl('path', { class: 'g-val', d: gArc(0, v) }));
    var dot = gPoint(v);
    svg.appendChild(svgEl('circle', { class: 'g-dot', cx: dot[0].toFixed(2), cy: dot[1].toFixed(2), r: '7' }));
    [['0', 20, 118], ['25', 27, 36], ['55', 124, 11], ['100+', 180, 118]].forEach(function (t) {
      svg.appendChild(svgEl('text', { class: 'g-tick', x: String(t[1]), y: String(t[2]), 'text-anchor': 'middle', text: t[0] }));
    });
    svg.appendChild(svgEl('text', { class: 'g-num', x: '100', y: '96', 'text-anchor': 'middle', text: String(pts) }));
    svg.appendChild(svgEl('text', { class: 'g-of', x: '100', y: '116', 'text-anchor': 'middle', text: 'RISK POINTS' }));
    return el('div', { class: 'rp-gauge' }, [svg]);
  }
  function bar(cls, frac) {
    var f = Math.max(0, Math.min(1, frac || 0));
    var svg = svgEl('svg', { viewBox: '0 0 100 6', preserveAspectRatio: 'none', 'aria-hidden': 'true' });
    svg.appendChild(svgEl('rect', { x: '0', y: '0', width: '100', height: '6' }));
    if (f > 0) svg.appendChild(svgEl('rect', { class: 'fill', x: '0', y: '0', width: (100 * f).toFixed(1), height: '6' }));
    return el('span', { class: cls }, [svg]);
  }
  var LEVEL_WORD = { ok: 'Clear', warn: 'Caution', bad: 'High risk' };
  var IC = { good: '✓', warn: '!', bad: '✕', info: 'i' };
  function finding(r) {
    var txt = el('span', null, [r.text, r.force ? el('span', { class: 'rp-crit', text: 'Critical' }) : null]);
    var pts = r.pts || r.capped ? el('span', { class: 'rp-pts' + (r.level === 'bad' ? ' bad' : ''), title: r.capped ? 'Category limit reached' : '' },
      ['+' + r.pts, r.capped ? el('small', { text: ' (limit)' }) : null]) : el('span');
    return el('li', null, [el('span', { class: 'rp-ic ' + r.level, 'aria-hidden': 'true', text: IC[r.level] || 'i' }), txt, pts]);
  }
  function categoryCard(g) {
    var scored = g.reasons.filter(function (r) { return r.pts || r.force || r.level === 'bad' || r.level === 'warn' || r.level === 'info'; });
    var good = g.reasons.filter(function (r) { return scored.indexOf(r) < 0; });
    var shown = scored.concat(good.slice(0, Math.max(0, 2 - scored.length)));
    var more = good.filter(function (r) { return shown.indexOf(r) < 0; });
    var sub = g.cap ? '+' + g.pts + ' of ' + g.cap + ' max' : (g.pts ? '+' + g.pts + ' points' : '0 points');
    var kids = [
      el('div', { class: 'rp-card-head' }, [el('h3', { text: g.title }), el('span', { class: 'rp-badge ' + g.level, text: LEVEL_WORD[g.level] })]),
      el('div', { class: 'rp-card-sub' }, [el('span', { text: sub }), bar('rp-cap', g.cap ? g.pts / g.cap : g.pts / 55)]),
      el('ul', { class: 'rp-f' }, shown.map(finding))
    ];
    if (more.length) kids.push(el('details', { class: 'rp-more' }, [el('summary', { text: more.length + ' more check' + (more.length === 1 ? '' : 's') + ' passed' }), el('ul', { class: 'rp-f' }, more.map(finding))]));
    return el('article', { class: 'rp-card ' + g.level, 'aria-label': g.title + ': ' + LEVEL_WORD[g.level] }, kids);
  }
  function confBars(cf) {
    return el('span', { class: 'rp-bars', 'aria-hidden': 'true' }, cf.areas.filter(function (a) { return a.state !== 'na'; }).map(function (a) {
      return el('i', { class: a.state === 'checked' ? 'on' : a.state === 'partial' ? 'half' : '' });
    }));
  }
  function stat(k, v) { return el('div', { class: 'rp-stat' }, [el('small', { text: k }), el('span', { text: String(v) })]); }

  function render(out, d, s) {
    if (s.verdict === 'error') { msg(out, 'err', s.message); return; }
    var t = C().title(s), m = s.market || {}, main = s.main;
    var bt = main ? (String(main.baseToken && main.baseToken.address).toLowerCase() === d.addr.toLowerCase() ? main.baseToken : main.quoteToken || main.baseToken)
      : d.gp ? { name: d.gp.token_name || d.gp.name, symbol: d.gp.token_symbol || d.gp.symbol }
      : (d.rug && d.rug.tokenMeta ? { name: d.rug.tokenMeta.name, symbol: d.rug.tokenMeta.symbol } : {});
    bt = bt || {};
    var img = safeImg(main && main.info && main.info.imageUrl);
    var frag = document.createDocumentFragment();

    // token header
    var others = (d.chainsSeen || []).filter(function (c) { return c !== d.chain; });
    var sym = bt.symbol ? String(bt.symbol).trim() : '';
    var media;
    if (img) { media = el('img', { alt: '', width: '42', height: '42', referrerpolicy: 'no-referrer', loading: 'lazy' }); media.src = img; }
    else media = el('span', { class: 'rp-ph', 'aria-hidden': 'true', text: (sym || '?').slice(0, 2).toUpperCase() });
    frag.appendChild(el('div', { class: 'rp-tok' }, [media, el('div', null, [
      el('p', { class: 'rp-eyebrow', text: 'Token risk report' }),
      el('h3', { class: 'rp-name' }, [(bt.name || 'Unknown token').trim(), sym ? el('span', { class: 'mut', text: ' ($' + sym + ')' }) : null]),
      el('span', { class: 'chip', text: chainName(d.chain) }), main ? el('span', { class: 'chip', text: s.pool ? s.pool.dex : main.dexId }) : null,
      s.limited ? el('span', { class: 'chip', text: 'Market data only' }) : null,
      el('code', { text: d.addr }),
      others.length ? el('small', { class: 'mut also', text: 'Also trades on: ' + others.map(chainName).join(', ') + ' (select a chain above to check it there)' }) : null
    ])]));

    // summary: gauge, verdict, main reasons, confidence
    var cf = s.confidence;
    var range = s.verdict === 'green' ? ['ok', 'Under 25'] : s.verdict === 'yellow' ? ['warn', '25–54'] : ['bad', s.forced && s.points < 55 ? 'Critical finding' : '55 or more'];
    var why = (s.top && s.top.length ? s.top : []).map(function (r, i) {
      return el('li', null, [el('span', { class: 'rp-n ' + (r.level === 'bad' ? 'bad' : 'warn'), text: String(i + 1) }), el('span', { text: r.text })]);
    });
    if (!why.length) why = [el('li', null, [el('span', { class: 'rp-n ok', text: '✓' }), el('span', { text: 'No risk signals added points to this report.' })])];
    var confKids = cf ? [confBars(cf), el('span', null, [el('b', { text: 'Data confidence: ' + cf.level }), ' · ' + cf.pct + '% of checks completed'])] : [];
    frag.appendChild(el('section', { class: 'rp-sum ' + s.verdict, 'aria-label': 'Overall rating' }, [
      buildGauge(s.points, t[0]),
      el('div', null, [
        el('p', { class: 'rp-verdict' }, [t[0], el('span', { class: 'rp-badge ' + range[0], text: range[1] })]),
        el('p', { class: 'rp-lede', text: t[1] }),
        el('ol', { class: 'rp-why', 'aria-label': 'Main reasons' }, why),
        el('div', { class: 'rp-confline' }, confKids)
      ])
    ]));

    // key numbers
    var safety;
    if (d.engine === 'solana') safety = stat('Mint / Freeze', d.authoritiesKnown ? (d.mintAuthority ? 'Active' : 'Revoked') + ' / ' + (d.freezeAuthority ? 'Active' : 'Revoked') : '—');
    else if (d.taxes && d.taxes.buy != null) safety = stat('Buy / sell tax', pct(d.taxes.buy) + ' / ' + pct(d.taxes.sell));
    else safety = stat('Market cap', usd(m.mcap));
    frag.appendChild(el('div', { class: 'rp-stats', 'aria-label': 'Key numbers' }, [
      stat('Price', m.price ? '$' + Number(m.price).toPrecision(4) : '—'),
      stat(m.onCurve ? 'Market cap' : 'Liquidity', m.onCurve ? usd(m.mcap) : usd(m.liq)),
      stat('24h volume', usd(m.vol24)),
      stat('Age', isFinite(m.created) ? ago((Date.now() - m.created) / 36e5) : '—'),
      stat('Top 10 holders', s.holders ? s.holders.top10.toFixed(1) + '%' : '—'),
      safety
    ]));

    // category cards, most points first
    var order = { bad: 0, warn: 1, ok: 2 };
    var groups = (s.groups || []).slice().sort(function (a, b) { return (order[a.level] - order[b.level]) || (b.pts - a.pts); });
    frag.appendChild(el('h3', { class: 'rp-h', text: 'Findings by category' }));
    frag.appendChild(el('div', { class: 'rp-cards' }, groups.map(categoryCard)));

    // data confidence
    if (cf) {
      var head = el('p', null, [el('b', { text: cf.level + ' · ' + cf.pct + '%. ' }),
        cf.fresh ? 'Very new token: some checks may not have caught up yet. ' : '',
        !cf.missing.length && !cf.partial.length ? 'All checks completed.' : (cf.missing.length ? 'Not available: ' + cf.missing.join(', ') + '. ' : '') + (cf.partial.length ? 'Partly checked: ' + cf.partial.join(', ') + '.' : '')]);
      var areas = el('div', { class: 'rp-areas' }, cf.areas.map(function (a) {
        return el('div', { class: 'rp-area ' + a.state }, [el('span', { text: a.label }), el('span', { class: 'st ' + a.state, text: a.stateText }),
          bar('bar', a.state === 'checked' ? 1 : a.state === 'partial' ? 0.5 : 0), a.why ? el('span', { class: 'why', text: cap(a.why) + '.' }) : null]);
      }));
      var ck = [head, areas, el('div', { class: 'rp-legend' }, [el('span', null, [el('i', { class: 'l-ok' }), 'Low risk: under 25']), el('span', null, [el('i', { class: 'l-warn' }), 'Caution: 25–54']), el('span', null, [el('i', { class: 'l-bad' }), 'High risk: 55 or more, or any critical finding'])])];
      if (cf.retry) {
        var rb = el('button', { type: 'button', class: 'btn-secondary rp-retry', text: 'Try again' });
        rb.addEventListener('click', function () { C().resetNet(); var sel = document.getElementById('chain'); check(d.addr, sel ? sel.value : 'auto'); });
        ck.push(rb);
      }
      frag.appendChild(el('h3', { class: 'rp-h', text: 'Data confidence' }));
      frag.appendChild(el('section', { class: 'rp-conf', 'aria-label': 'Data confidence' }, ck));
    }

    var a = encodeURIComponent(d.addr), ex = CHAINS[d.chain] && CHAINS[d.chain][1];
    var links = [main ? ext(main.url, 'DexScreener') : null];
    if (d.chain === 'solana') { links.push(ext('https://rugcheck.xyz/tokens/' + a, 'RugCheck')); if (/pump$/.test(d.addr)) links.push(ext('https://pump.fun/coin/' + a, 'pump.fun')); }
    if (GOPLUS_IDS[d.chain] && d.chain !== 'tron') links.push(ext('https://gopluslabs.io/token-security/' + GOPLUS_IDS[d.chain] + '/' + a, 'GoPlus'));
    if (HONEYPOT_IDS[d.chain]) links.push(ext('https://honeypot.is/' + (d.chain === 'ethereum' ? 'ethereum' : d.chain === 'bsc' ? 'bsc' : 'base') + '?address=' + a, 'honeypot.is'));
    if (ex) links.push(ext(ex + a, 'Explorer'));
    frag.appendChild(el('div', { class: 'links' }, links));

    var NAMES = { dexscreener: 'DexScreener', goplus: 'GoPlus', honeypot: 'honeypot.is', rugcheck: 'RugCheck', rpcAccount: 'Solana RPC', rpcSupply: 'Solana RPC (supply)', rpcHolders: 'Solana RPC (holder lookup)', goplusCreator: 'GoPlus (creator wallet)', evmRpc: 'public RPC', rugGraph: 'RugCheck (wallet graph)', dexSearch: 'DexScreener (name search)' };
    var used = Object.keys(d.sources).map(function (k) { return { dexscreener: 'DexScreener', goplus: 'GoPlus', honeypot: 'honeypot.is', rugcheck: d.rugSummary ? 'RugCheck (summary)' : 'RugCheck', rpcAccount: 'Solana RPC', evmRpc: 'public RPC' }[k]; }).filter(function (v, i, arr) { return v && arr.indexOf(v) === i; });
    var errs = Object.keys(d.errors).map(function (k) { return NAMES[k] || k; });
    frag.appendChild(el('p', { class: 'src', text: 'Chain: ' + chainName(d.chain) + (d.chainGuessed ? ' (guessed from address format)' : '') + '. Data: ' + used.join(', ') +
      (s.holders ? '. Holders via ' + s.holders.via : '') + '. ' + (errs.length ? 'Unavailable: ' + errs.join(', ') + '. ' : '') + 'Checked ' + new Date().toLocaleString() + '.' }));
    out.replaceChildren(frag);
  }
  function cap(x) { return x.charAt(0).toUpperCase() + x.slice(1); }

  var MAX_INPUT = 300;
  async function check(raw, chainChoice) {
    var out = document.getElementById('out'), btn = document.getElementById('go');
    raw = String(raw || '').trim();
    if (CHAIN_OPTS.indexOf(chainChoice) < 0) chainChoice = 'auto';
    if (!raw || raw.length > MAX_INPUT) { msg(out, 'err', 'Enter a token address or a token page link.'); return; }
    var addr = extract(raw);
    var dl = await resolveDexLink(raw);
    if (dl && detect(dl.addr)) {
      addr = dl.addr;
      if (chainChoice === 'auto' && CHAIN_OPTS.indexOf(dl.chain) >= 0) { chainChoice = dl.chain; document.getElementById('chain').value = dl.chain; }
      document.getElementById('mint').value = addr;
    }
    if (!detect(addr)) { msg(out, 'err', 'This does not appear to be a valid token address. Enter a contract or mint address (Solana, 0x…, T…, EQ…, or 0x…::module::COIN), or a token page link.'); return; }
    btn.disabled = true;
    out.closest('.result').hidden = false;
    msg(out, 'loading', 'Analyzing token… detecting the chain and retrieving public data.', true);
    out.closest('.result').scrollIntoView({ behavior: 'smooth', block: 'start' });
    try {
      var d = await gather(addr, chainChoice);
      render(out, d, score(d));
      try { history.replaceState(null, '', '#' + (chainChoice && chainChoice !== 'auto' ? chainChoice + ':' : '') + addr); } catch (e) {}
    } catch (e) {
      msg(out, 'err', 'Data sources are currently unreachable. Please check your connection and try again.');
    } finally { btn.disabled = false; }
  }

  function fromHash() {
    var h;
    try { h = decodeURIComponent(location.hash.slice(1)); } catch (e) { return null; }
    if (!h || h.length > MAX_INPUT) return null;
    var chain = 'auto', m = h.match(/^([a-z]+):(.+)$/);
    if (m && !/^0x/.test(h) && CHAIN_OPTS.indexOf(m[1]) >= 0) { chain = m[1]; h = m[2]; }
    return detect(h) ? { addr: h, chain: chain } : null;
  }
  var CHAIN_OPTS = [];


  function initDrawer() {
    var btn = document.getElementById('menu-btn');
    var drawer = document.getElementById('drawer');
    var backdrop = document.getElementById('backdrop');
    var closeBtn = document.getElementById('drawer-close');
    if (!btn || !drawer || !backdrop || !closeBtn) return;
    var lastFocus = null;
    var open = false;

    function focusables() {
      return Array.prototype.slice.call(drawer.querySelectorAll('a[href], button:not([disabled])'));
    }
    function setOpen(next) {
      if (next === open) return;
      open = next;
      drawer.classList.toggle('is-open', open);
      backdrop.classList.toggle('is-open', open);
      document.documentElement.classList.toggle('drawer-open', open);
      btn.setAttribute('aria-expanded', open ? 'true' : 'false');
      btn.setAttribute('aria-label', open ? 'Close menu' : 'Open menu');
      drawer.setAttribute('aria-hidden', open ? 'false' : 'true');
      backdrop.setAttribute('aria-hidden', open ? 'false' : 'true');
      if (open) {
        lastFocus = document.activeElement;
        document.addEventListener('keydown', onKey);
        requestAnimationFrame(function () {
          requestAnimationFrame(function () { closeBtn.focus(); });
        });
      } else {
        document.removeEventListener('keydown', onKey);
        if (lastFocus && typeof lastFocus.focus === 'function') lastFocus.focus();
      }
    }
    function onKey(e) {
      if (e.key === 'Escape') { e.preventDefault(); setOpen(false); return; }
      if (e.key !== 'Tab') return;
      var list = focusables();
      if (!list.length) return;
      var first = list[0], last = list[list.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    }

    btn.addEventListener('click', function () { setOpen(!open); });
    closeBtn.addEventListener('click', function () { setOpen(false); });
    backdrop.addEventListener('click', function () { setOpen(false); });
    drawer.addEventListener('click', function (e) {
      var a = e.target.closest && e.target.closest('a');
      if (a) setOpen(false);
    });
    window.addEventListener('resize', function () {
      if (open && window.matchMedia('(min-width: 760px)').matches) setOpen(false);
    });

    markCurrentNav();
  }

  function markCurrentNav() {
    var path = location.pathname;
    if (!path || path === '/index.html') path = '/';
    var links = document.querySelectorAll('.links-nav a, .drawer-nav a');
    Array.prototype.forEach.call(links, function (a) {
      var href = a.getAttribute('href') || '';
      a.classList.remove('is-current');
      a.removeAttribute('aria-current');
      if (!href || href.charAt(0) === '#' || /^(https?:)?\/\//i.test(href)) return;
      var linkPath;
      try { linkPath = new URL(href, location.origin).pathname; } catch (e) { return; }
      if (linkPath === '/index.html') linkPath = '/';
      if (linkPath === path) {
        a.classList.add('is-current');
        a.setAttribute('aria-current', 'page');
      }
    });
  }

  var SECTION_PAGES = {
    'how-it-works': '/how.html',
    'checks': '/how.html',
    'how': '/how.html#scoring',
    'extension': '/extension.html',
    'faq': '/faq.html'
  };

  function redirectLegacyHash() {
    var raw;
    try { raw = decodeURIComponent(location.hash.slice(1)); } catch (e) { return false; }
    var dest = SECTION_PAGES[raw];
    if (!dest) return false;
    location.replace(dest);
    return true;
  }

  if (typeof document !== 'undefined') {
    // Frame-buster: frame-ancestors cannot be set from a meta tag on GitHub Pages.
    if (window.top !== window.self) {
      document.documentElement.classList.add('framed');
      try { window.top.location = window.self.location.href; } catch (e) {}
    }
    if ('serviceWorker' in navigator) window.addEventListener('load', function () { navigator.serviceWorker.register('/sw.js').catch(function () {}); });
    document.addEventListener('DOMContentLoaded', function () {
      var yr = document.getElementById('yr'); if (yr) yr.textContent = String(new Date().getFullYear());
      initDrawer();
      if (redirectLegacyHash()) return;
      var input = document.getElementById('mint'), sel = document.getElementById('chain');
      if (!input || !sel) return;
      CHAIN_OPTS = Array.prototype.map.call(sel.options, function (o) { return o.value; });
      document.getElementById('form').addEventListener('submit', function (e) { e.preventDefault(); check(input.value, sel.value); });
      Array.prototype.forEach.call(document.querySelectorAll('.ex'), function (b) {
        b.addEventListener('click', function () { input.value = b.dataset.mint; sel.value = 'auto'; check(b.dataset.mint, 'auto'); });
      });
      var h = fromHash();
      if (h) { input.value = h.addr; sel.value = h.chain; check(h.addr, h.chain); }
      window.addEventListener('hashchange', function () {
        var x = fromHash();
        if (x && (x.addr !== input.value.trim() || x.chain !== sel.value)) { input.value = x.addr; sel.value = x.chain; check(x.addr, x.chain); }
      });
    });
  }

  root.BluntX = { gather: gather, score: score, detect: detect, extract: extract, resolveDexLink: resolveDexLink };
  if (typeof module !== 'undefined') module.exports = root.BluntX;
})(typeof window !== 'undefined' ? window : globalThis);
