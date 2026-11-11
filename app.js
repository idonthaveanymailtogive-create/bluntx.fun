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
  // Risk rail: SVG attributes only (no element.style), so it stays compatible with style-src 'self'.
  function buildMeter(points, rating) {
    var pts = Math.max(0, Number(points) || 0);
    var visual = Math.min(100, pts);
    var W = 284, X = 8, Y = 26, H = 6;
    var nx = X + (visual / 100) * W;
    var gW = (24.5 / 100) * W, yW = (30 / 100) * W, rW = W - gW - yW;
    var clipId = 'meter-clip-' + Math.random().toString(36).slice(2, 9);
    var svg = svgEl('svg', { class: 'meter', viewBox: '0 0 300 40', role: 'img', 'aria-label': pts + ' risk points, ' + rating });
    svg.appendChild(svgEl('title', { text: pts + ' risk points, ' + rating }));
    var defs = svgEl('defs');
    var clip = svgEl('clipPath', { id: clipId });
    clip.appendChild(svgEl('rect', { x: String(X), y: String(Y), width: String(W), height: String(H), rx: '3' }));
    defs.appendChild(clip);
    svg.appendChild(defs);
    svg.appendChild(svgEl('rect', { class: 'meter-bed', x: String(X), y: String(Y), width: String(W), height: String(H), rx: '3' }));
    var zones = svgEl('g', { 'clip-path': 'url(#' + clipId + ')' });
    zones.appendChild(svgEl('rect', { class: 'meter-zone-g', x: String(X), y: String(Y), width: String(gW), height: String(H) }));
    zones.appendChild(svgEl('rect', { class: 'meter-zone-y', x: String(X + gW), y: String(Y), width: String(yW), height: String(H) }));
    zones.appendChild(svgEl('rect', { class: 'meter-zone-r', x: String(X + gW + yW), y: String(Y), width: String(rW), height: String(H) }));
    svg.appendChild(zones);
    var needle = svgEl('g', { transform: 'translate(' + nx.toFixed(1) + ',0)' });
    needle.appendChild(svgEl('path', { class: 'meter-needle', d: 'M0 16 L4 26 L0 23.5 L-4 26 Z' }));
    svg.appendChild(needle);
    svg.appendChild(svgEl('text', { class: 'meter-lab', x: String(X), y: '12', text: 'Low' }));
    svg.appendChild(svgEl('text', { class: 'meter-lab', x: String(X + gW), y: '12', text: 'Caution' }));
    svg.appendChild(svgEl('text', { class: 'meter-lab', x: String(X + gW + yW), y: '12', text: 'High' }));
    return el('div', { class: 'meter-wrap' }, [svg]);
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
  var ICON = { good: '✓', warn: '!', bad: '✕', info: 'i' };
  function stat(k, v) { return el('div', { class: 'stat' }, [el('small', { text: k }), el('span', { text: String(v) })]); }

  function render(out, d, s) {
    if (s.verdict === 'error') { msg(out, 'err', s.message); return; }
    var t = C().title(s), m = s.market || {}, main = s.main;
    var bt = main ? main.baseToken : d.gp ? { name: d.gp.token_name || d.gp.name, symbol: d.gp.token_symbol || d.gp.symbol }
      : (d.rug && d.rug.tokenMeta ? { name: d.rug.tokenMeta.name, symbol: d.rug.tokenMeta.symbol } : {});
    var img = safeImg(main && main.info && main.info.imageUrl);
    var frag = document.createDocumentFragment();

    frag.appendChild(el('div', { class: 'verdict ' + s.verdict }, [
      el('div', { class: 'score' }, [el('b', { text: String(s.points) }), el('small', { text: 'risk pts' })]),
      el('div', null, [
        el('h3', null, [t[0], s.limited ? el('small', { class: 'lim', text: 'market data only' }) : null]),
        el('p', { text: t[1] })
      ])
    ]));
    frag.appendChild(buildMeter(s.points, t[0]));

    var cf = s.confidence;
    if (cf) {
      var cfKids = [el('div', { class: 'conf-head' }, [el('b', { text: 'Data confidence: ' + cf.level }), el('span', { class: 'mut', text: ' ' + cf.pct + '% of checks completed' })])];
      if (cf.missing.length) cfKids.push(el('p', { text: 'Could not be checked: ' + cf.missing.join(', ') + '.' }));
      if (cf.partial.length) cfKids.push(el('p', { text: 'Partly checked: ' + cf.partial.join(', ') + '.' }));
      if (!cf.missing.length && !cf.partial.length) cfKids.push(el('p', { text: 'All checks completed.' }));
      if (cf.retry) {
        var rb = el('button', { type: 'button', class: 'retry', text: 'Try again' });
        rb.addEventListener('click', function () { C().resetNet(); var sel = document.getElementById('chain'); check(d.addr, sel ? sel.value : 'auto'); });
        cfKids.push(rb);
      }
      frag.appendChild(el('div', { class: 'conf conf-' + cf.level.toLowerCase() }, cfKids));
    }
    var pl = s.pool;
    if (pl) {
      var plText = pl.kind === 'curve' ? 'Bonding curve (no DEX pool yet)'
        : pl.dex + ' · ' + usd(pl.liq) + ' · ' + Math.round(pl.share * 100) + '% of liquidity · ' +
          (pl.kind === 'lp' ? pct(pl.lockPct) + ' locked or burned' : 'lock not verifiable');
      frag.appendChild(el('div', { class: 'pool' }, [el('small', { text: 'Main pool' }), el('span', { text: plText })]));
    }

    var others = (d.chainsSeen || []).filter(function (c) { return c !== d.chain; });
    var tokKids = [];
    if (img) { var im = el('img', { alt: '', width: '36', height: '36', referrerpolicy: 'no-referrer', loading: 'lazy' }); im.src = img; tokKids.push(im); }
    tokKids.push(el('div', null, [
      el('b', { text: (bt.name || 'Unknown token').trim() + (bt.symbol ? ' ($' + String(bt.symbol).trim() + ')' : '') }), ' ',
      el('span', { class: 'chip', text: chainName(d.chain) }), el('br'),
      el('code', { text: d.addr }),
      others.length ? el('small', { class: 'mut also', text: 'Also trades on: ' + others.map(chainName).join(', ') + ' (select a chain above to check it there)' }) : null
    ]));
    frag.appendChild(el('div', { class: 'tok' }, tokKids));

    var safety;
    if (d.engine === 'solana') safety = stat('Mint / Freeze', d.authoritiesKnown ? (d.mintAuthority ? 'ACTIVE' : 'revoked') + ' / ' + (d.freezeAuthority ? 'ACTIVE' : 'revoked') : '—');
    else if (d.engine === 'goplus' && d.gp) safety = stat('Honeypot · Buy/Sell tax', (d.honeypot ? 'YES' : 'No') + ' · ' + (d.taxes && d.taxes.buy != null ? pct(d.taxes.buy) + '/' + pct(d.taxes.sell) : '—'));
    else if (d.engine === 'goplus-sui' && d.gp) safety = stat('Mintable', d.gp.mintable && flag(d.gp.mintable.value) ? 'YES' : 'No');
    else safety = stat('Contract scan', 'not available');
    frag.appendChild(el('div', { class: 'stats' }, [
      stat('Price', m.price ? '$' + Number(m.price).toPrecision(4) : '—'),
      stat(m.onCurve ? 'Market cap' : 'Liquidity', m.onCurve ? usd(m.mcap) : usd(m.liq)),
      stat('FDV', usd(m.fdv)), stat('24h volume', usd(m.vol24)),
      stat('24h buys / sells', main ? m.buys + ' / ' + m.sells : '—'),
      stat('Age', isFinite(m.created) ? ago((Date.now() - m.created) / 36e5) : '—'),
      stat('Top 10 holders', s.holders ? s.holders.top10.toFixed(1) + '%' : '—'), safety
    ]));

    frag.appendChild(el('ul', { class: 'reasons' }, s.reasons.map(function (r) {
      return el('li', { class: r.level }, [el('span', { class: 'ic', 'aria-hidden': 'true', text: ICON[r.level] }), el('span', { text: r.text }),
        (r.pts || r.capped) ? el('span', { class: 'pts', title: r.capped ? 'Category limit reached' : '', text: '+' + r.pts + (r.capped ? ' (limit)' : '') }) : null]);
    })));

    var a = encodeURIComponent(d.addr), ex = CHAINS[d.chain] && CHAINS[d.chain][1];
    var links = [main ? ext(main.url, 'DexScreener') : null];
    if (d.chain === 'solana') { links.push(ext('https://rugcheck.xyz/tokens/' + a, 'RugCheck')); if (/pump$/.test(d.addr)) links.push(ext('https://pump.fun/coin/' + a, 'pump.fun')); }
    if (GOPLUS_IDS[d.chain] && d.chain !== 'tron') links.push(ext('https://gopluslabs.io/token-security/' + GOPLUS_IDS[d.chain] + '/' + a, 'GoPlus'));
    if (HONEYPOT_IDS[d.chain]) links.push(ext('https://honeypot.is/' + (d.chain === 'ethereum' ? 'ethereum' : d.chain === 'bsc' ? 'bsc' : 'base') + '?address=' + a, 'honeypot.is'));
    if (ex) links.push(ext(ex + a, 'Explorer'));
    frag.appendChild(el('div', { class: 'links' }, links));

    var NAMES = { dexscreener: 'DexScreener', goplus: 'GoPlus', honeypot: 'honeypot.is', rugcheck: 'RugCheck', rpcAccount: 'Solana RPC', rpcSupply: 'Solana RPC (supply)', rpcHolders: 'Solana RPC (holder lookup)', goplusCreator: 'GoPlus (creator wallet)', evmRpc: 'public RPC' };
    var used = Object.keys(d.sources).map(function (k) { return { dexscreener: 'DexScreener', goplus: 'GoPlus', honeypot: 'honeypot.is', rugcheck: d.rugSummary ? 'RugCheck (summary)' : 'RugCheck', rpcAccount: 'Solana RPC', evmRpc: 'public RPC' }[k]; }).filter(function (v, i, a) { return v && a.indexOf(v) === i; });
    var errs = Object.keys(d.errors).map(function (k) { return NAMES[k] || k; });
    frag.appendChild(el('p', { class: 'src', text: 'Chain: ' + chainName(d.chain) + (d.chainGuessed ? ' (guessed from address format)' : '') + '. Data: ' + used.join(', ') +
      (s.holders ? '. Holders via ' + s.holders.via : '') + '. ' + (errs.length ? 'Unavailable: ' + errs.join(', ') + '. ' : '') + 'Checked ' + new Date().toLocaleString() + '.' }));
    out.replaceChildren(frag);
  }

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
