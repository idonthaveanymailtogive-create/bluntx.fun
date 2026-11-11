/* BluntX token risk checker — static, no build step. Every call goes straight from the browser to free, keyless public APIs:
   DexScreener (all chains, market data), Solana RPC + RugCheck (Solana), GoPlus (EVM, Tron, Sui), honeypot.is (ETH/BSC/Base). */
(function (root) {
  'use strict';

  // ---------- config ----------
  var RPCS = [
    'https://public.rpc.solanavibestation.com',   // free, CORS *, supports getTokenLargestAccounts
    'https://solana.api.pocket.network',          // free, CORS ok (no holder lookups for big SPL tokens)
    'https://solana-rpc.publicnode.com',          // free, CORS ok (getAccountInfo only)
    'https://api.mainnet-beta.solana.com'         // official; often 403s browser origins / 429s, so tried last
  ];
  var DEX = 'https://api.dexscreener.com/latest/dex/tokens/';
  var RUG = 'https://api.rugcheck.xyz/v1/tokens/';
  var GOPLUS = 'https://api.gopluslabs.io/api/v1/';
  var HONEYPOT = 'https://api.honeypot.is/v2/IsHoneypot';

  var SOL_RE = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
  var EVM_RE = /^0x[0-9a-fA-F]{40}$/;
  var TRON_RE = /^T[1-9A-HJ-NP-Za-km-z]{33}$/;
  var SUI_RE = /^0x[0-9a-fA-F]{1,64}::\w+::\w+$/;
  var TON_RE = /^(?:[EU]Q[A-Za-z0-9_-]{46}|-?\d:[0-9a-fA-F]{64})$/;

  // DexScreener chainId -> GoPlus chain id (EVM + Tron use /token_security/<id>; Sui has its own endpoint)
  var GOPLUS_IDS = {
    ethereum: '1', bsc: '56', arbitrum: '42161', polygon: '137', base: '8453', optimism: '10', avalanche: '43114',
    cronos: '25', gnosischain: '100', linea: '59144', zksync: '324', scroll: '534352', mantle: '5000', blast: '81457',
    opbnb: '204', sonic: '146', berachain: '80094', abstract: '2741', unichain: '130', worldchain: '480', monad: '143',
    soneium: '1868', xlayer: '196', manta: '169', merlin: '4200', kcc: '321', bitlayer: '200901', zircuit: '48900',
    morph: '2818', story: '1514', hashkey: '177', plasma: '9745', tron: 'tron'
  };
  var HONEYPOT_IDS = { ethereum: '1', bsc: '56', base: '8453' };

  var CHAINS = { // label + explorer token URL
    solana: ['Solana', 'https://solscan.io/token/'],
    ethereum: ['Ethereum', 'https://etherscan.io/token/'],
    bsc: ['BNB Chain', 'https://bscscan.com/token/'],
    base: ['Base', 'https://basescan.org/token/'],
    arbitrum: ['Arbitrum', 'https://arbiscan.io/token/'],
    polygon: ['Polygon', 'https://polygonscan.com/token/'],
    optimism: ['Optimism', 'https://optimistic.etherscan.io/token/'],
    avalanche: ['Avalanche', 'https://snowtrace.io/token/'],
    sonic: ['Sonic', 'https://sonicscan.org/token/'],
    blast: ['Blast', 'https://blastscan.io/token/'],
    linea: ['Linea', 'https://lineascan.build/token/'],
    tron: ['Tron', 'https://tronscan.org/#/token20/'],
    sui: ['Sui', 'https://suiscan.xyz/mainnet/coin/'],
    ton: ['TON', 'https://tonviewer.com/'],
    hyperliquid: ['Hyperliquid', null], abstract: ['Abstract', null], berachain: ['Berachain', null],
    aptos: ['Aptos', 'https://explorer.aptoslabs.com/coin/'], near: ['NEAR', null], pulsechain: ['PulseChain', null]
  };
  function chainName(c) { return (CHAINS[c] && CHAINS[c][0]) || (c ? c.charAt(0).toUpperCase() + c.slice(1) : 'Unknown'); }

  // ---------- helpers ----------
  function timeoutFetch(url, opts, ms) {
    var ctl = typeof AbortController !== 'undefined' ? new AbortController() : null;
    var t = ctl ? setTimeout(function () { ctl.abort(); }, ms || 12000) : null;
    opts = opts || {};
    if (ctl) opts.signal = ctl.signal;
    return fetch(url, opts).finally(function () { if (t) clearTimeout(t); });
  }
  async function getJSON(url, ms) {
    var r = await timeoutFetch(url, {}, ms);
    if (!r.ok) throw new Error('HTTP ' + r.status);
    return r.json();
  }
  async function rpc(method, params) {
    var lastErr;
    for (var i = 0; i < RPCS.length; i++) {
      try {
        var r = await timeoutFetch(RPCS[i], {
          method: 'POST', headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: method, params: params })
        }, 12000);
        var j = await r.json().catch(function () { return null; });
        if (j && j.result !== undefined && !j.error) return { result: j.result, via: RPCS[i] };
        lastErr = new Error((j && j.error && j.error.message) || ('HTTP ' + r.status));
      } catch (e) { lastErr = e; }
    }
    throw lastErr || new Error('RPC failed');
  }
  function host(u) { try { return new URL(u).host; } catch (e) { return u; } }
  function liqOf(p) { return (p.liquidity && p.liquidity.usd) || 0; }
  var DEAD = /^0x0{40}$|^0x0{36}dead$|^0x000000000000000000000000000000000000dead$/i;

  // ---------- address detection ----------
  function detect(addr) {
    if (EVM_RE.test(addr)) return 'evm';
    if (SUI_RE.test(addr)) return 'sui';
    if (TON_RE.test(addr)) return 'ton';
    if (TRON_RE.test(addr)) return 'tron';
    if (SOL_RE.test(addr)) return 'solana';
    if (/^[A-Za-z0-9_:.\-]{20,140}$/.test(addr)) return 'other';
    return null;
  }
  // Pull an address out of whatever was pasted (a raw address, or a DexScreener / explorer / pump.fun link).
  function extract(text) {
    text = (text || '').trim();
    var m = text.match(/0x[0-9a-fA-F]{1,64}::\w+::\w+/) || text.match(/0x[0-9a-fA-F]{40}(?![0-9a-fA-F])/) ||
      text.match(/[EU]Q[A-Za-z0-9_-]{46}/) || text.match(/(?:^|[^1-9A-HJ-NP-Za-km-z])(T[1-9A-HJ-NP-Za-km-z]{33})(?![1-9A-HJ-NP-Za-km-z])/) ||
      text.match(/[1-9A-HJ-NP-Za-km-z]{32,44}/);
    if (!m) return text;
    return m[1] || m[0];
  }

  // ---------- data gathering ----------
  async function gather(addr, chainChoice, log) {
    chainChoice = chainChoice || 'auto';
    var d = { addr: addr, mint: addr, kind: detect(addr), sources: {}, errors: {} };

    // 1) DexScreener (every chain): decides the chain in Auto mode.
    try {
      var j = await getJSON(DEX + encodeURIComponent(addr));
      d.allPairs = (j && j.pairs) || [];
      d.sources.dexscreener = 'ok (' + d.allPairs.length + ' pairs)';
    } catch (e) { d.allPairs = []; d.errors.dexscreener = e.message; }

    var chainsSeen = {};
    d.allPairs.forEach(function (p) { chainsSeen[p.chainId] = (chainsSeen[p.chainId] || 0) + liqOf(p) + 1e-9; });
    d.chainsSeen = Object.keys(chainsSeen);

    if (chainChoice !== 'auto') d.chain = chainChoice;
    else if (d.allPairs.length) {
      var best = d.allPairs.slice().sort(function (a, b) { return liqOf(b) - liqOf(a); })[0];
      d.chain = best.chainId;
      // pump.fun-style curves report null liquidity; prefer the chain with the most total liquidity anyway
      var top = d.chainsSeen.sort(function (a, b) { return chainsSeen[b] - chainsSeen[a]; })[0];
      if (top) d.chain = top;
    } else {
      d.chain = { evm: 'ethereum', solana: 'solana', tron: 'tron', sui: 'sui', ton: 'ton' }[d.kind] || null;
      d.chainGuessed = true;
    }
    d.pairs = d.allPairs.filter(function (p) { return p.chainId === d.chain; });

    // 2) Chain-specific safety data
    if (d.chain === 'solana') {
      d.engine = 'solana';
      await gatherSolana(d);
    } else if (d.chain === 'sui') {
      d.engine = 'goplus-sui';
      await gatherGoPlus(d, GOPLUS + 'sui/token_security?contract_addresses=' + encodeURIComponent(addr));
    } else if (GOPLUS_IDS[d.chain] && (EVM_RE.test(addr) || d.chain === 'tron')) {
      d.engine = 'goplus';
      var tasks = [gatherGoPlus(d, GOPLUS + 'token_security/' + GOPLUS_IDS[d.chain] + '?contract_addresses=' + addr)];
      if (HONEYPOT_IDS[d.chain]) tasks.push(
        getJSON(HONEYPOT + '?address=' + addr + '&chainID=' + HONEYPOT_IDS[d.chain], 15000)
          .then(function (h) { d.hp = h; d.sources.honeypot = 'ok'; })
          .catch(function (e) { d.errors.honeypot = e.message; }));
      await Promise.all(tasks);
    } else {
      d.engine = 'market';
    }
    return d;
  }

  async function gatherGoPlus(d, url) {
    try {
      var j = await getJSON(url, 15000);
      var res = j && j.result;
      var v = res && (res[d.addr] || res[d.addr.toLowerCase()] || res[Object.keys(res)[0]]);
      if (j && j.code === 1 && v && Object.keys(v).length) { d.gp = v; d.sources.goplus = 'ok'; }
      else d.errors.goplus = (j && j.message && j.code !== 1) ? j.message : 'token not indexed';
    } catch (e) { d.errors.goplus = e.message; }
  }

  async function gatherSolana(d) {
    var mint = d.addr;
    await Promise.all([
      rpc('getAccountInfo', [mint, { encoding: 'jsonParsed' }]).then(function (r) {
        var v = r.result && r.result.value;
        if (!v) { d.notMint = true; d.sources.rpcAccount = 'no account'; return; }
        var info = v.data && v.data.parsed && v.data.parsed.info;
        if (!info || (v.data.parsed.type !== 'mint')) { d.notMint = true; d.sources.rpcAccount = 'not a token mint'; return; }
        d.mintAuthority = info.mintAuthority || null;
        d.freezeAuthority = info.freezeAuthority || null;
        d.decimals = info.decimals;
        d.supplyRaw = info.supply;
        d.authoritiesKnown = true;
        d.sources.rpcAccount = 'ok via ' + host(r.via);
      }).catch(function (e) { d.errors.rpcAccount = e.message; }),

      rpc('getTokenSupply', [mint]).then(function (r) {
        d.supply = r.result.value; d.sources.rpcSupply = 'ok via ' + host(r.via);
      }).catch(function (e) { d.errors.rpcSupply = e.message; }),

      rpc('getTokenLargestAccounts', [mint]).then(async function (r) {
        var accs = r.result.value || [];
        d.largest = accs; d.sources.rpcHolders = 'ok via ' + host(r.via);
        try {
          var m = await rpc('getMultipleAccounts', [accs.map(function (a) { return a.address; }), { encoding: 'jsonParsed' }]);
          (m.result.value || []).forEach(function (acc, i) {
            var o = acc && acc.data && acc.data.parsed && acc.data.parsed.info && acc.data.parsed.info.owner;
            if (o) accs[i].owner = o;
          });
        } catch (e) { /* owners optional */ }
      }).catch(function (e) { d.errors.rpcHolders = e.message; }),

      getJSON(RUG + mint + '/report', 15000).then(function (j) {
        if (j && !j.error) { d.rug = j; d.sources.rugcheck = 'ok'; } else d.errors.rugcheck = (j && j.error) || 'no report';
      }).catch(function (e) { d.errors.rugcheck = e.message; })
    ]);
    if (!d.authoritiesKnown && d.rug && 'mintAuthority' in d.rug) {
      d.mintAuthority = d.rug.mintAuthority || null;
      d.freezeAuthority = d.rug.freezeAuthority || null;
      d.authoritiesKnown = true; d.sources.authorities = 'from RugCheck (RPC unavailable)';
    }
  }

  // ---------- holders ----------
  function solanaHolders(d) {
    var supplyUi = d.supply ? Number(d.supply.uiAmountString || d.supply.uiAmount) :
      (d.supplyRaw && d.decimals != null ? Number(d.supplyRaw) / Math.pow(10, d.decimals) : null);
    if (!supplyUi && d.rug && d.rug.token) supplyUi = Number(d.rug.token.supply) / Math.pow(10, d.rug.token.decimals || 0);
    var skip = {};
    (d.pairs || []).forEach(function (p) { skip[p.pairAddress] = 1; });
    if (d.rug) {
      var ka = d.rug.knownAccounts || {};
      Object.keys(ka).forEach(function (k) { if (/AMM|LOCKER/i.test(ka[k].type)) skip[k] = 1; });
      (d.rug.markets || []).forEach(function (m) { if (m.pubkey) skip[m.pubkey] = 1; });
    }
    var list = null, via = null;
    if (d.largest && d.largest.length && supplyUi) {
      list = d.largest.map(function (a) { return { addr: a.address, owner: a.owner, pct: 100 * Number(a.uiAmountString || a.uiAmount || 0) / supplyUi }; });
      via = 'Solana RPC';
    } else if (d.rug && d.rug.topHolders && d.rug.topHolders.length) {
      list = d.rug.topHolders.map(function (h) { return { addr: h.address, owner: h.owner, pct: Number(h.pct) || 0 }; });
      via = 'RugCheck (RPC holder lookup was rate-limited)';
    }
    if (!list) return null;
    return summarize(list, function (h) { return skip[h.owner] || skip[h.addr]; }, via, list.some(function (h) { return !!h.owner; }));
  }

  function goplusHolders(d) {
    var hs = d.gp && d.gp.holders;
    if (!hs || !hs.length) return null;
    var skip = {};
    (d.pairs || []).forEach(function (p) { skip[String(p.pairAddress).toLowerCase()] = 1; });
    (d.gp.dex || []).forEach(function (x) { if (x.pair) skip[String(x.pair).toLowerCase()] = 1; });
    var list = hs.map(function (h) {
      return { addr: h.address, tag: h.tag, locked: Number(h.is_locked) === 1, pct: 100 * Number(h.percent || 0) };
    });
    return summarize(list, function (h) {
      return skip[String(h.addr).toLowerCase()] || h.locked || DEAD.test(h.addr) ||
        /pool|pair|lp\b|uniswap|pancake|sushi|aerodrome|burn|dead|lock|null/i.test(h.tag || '');
    }, 'GoPlus', true);
  }

  function summarize(list, isPool, via, ownersKnown) {
    var poolPct = 0, users = [];
    list.forEach(function (h) { if (isPool(h)) poolPct += h.pct; else users.push(h); });
    users = users.slice(0, 10);
    return {
      top10: users.reduce(function (s, h) { return s + h.pct; }, 0),
      top1: users.length ? users[0].pct : 0, poolPct: poolPct, via: via, ownersKnown: ownersKnown
    };
  }

  // ---------- scoring ----------
  function usd(n) {
    if (n == null || !isFinite(n)) return '—';
    if (n >= 1e9) return '$' + (n / 1e9).toFixed(2) + 'B';
    if (n >= 1e6) return '$' + (n / 1e6).toFixed(2) + 'M';
    if (n >= 1e3) return '$' + (n / 1e3).toFixed(1) + 'K';
    return '$' + Number(n).toFixed(n < 1 ? 6 : 0);
  }
  function ago(h) { return h < 1 ? Math.round(h * 60) + ' min' : h < 48 ? Math.round(h) + 'h' : Math.round(h / 24) + ' days'; }
  function pct(x) { return (Math.round(x * 10) / 10) + '%'; }
  function flag(v) { return v === '1' || v === 1 || v === true; }

  function score(d, now) {
    now = now || Date.now();
    var reasons = [], pts = 0, forceRed = false, limited = false;
    function add(level, text, p) { reasons.push({ level: level, text: text, pts: p || 0 }); pts += p || 0; }
    function red(text) { add('bad', text, 50); forceRed = true; }

    var pairs = (d.pairs || []).slice().sort(function (a, b) { return liqOf(b) - liqOf(a); });
    if (d.engine === 'solana' && d.notMint && !pairs.length)
      return { verdict: 'error', message: 'This address is not a Solana token mint. Please verify it is the token mint address, not a wallet or pair address.' };
    if (!pairs.length && !d.gp && !(d.engine === 'solana' && d.authoritiesKnown))
      return { verdict: 'error', message: d.chain ? 'Token not found on ' + chainName(d.chain) + '. Please verify the address or select a different chain.' : 'No market found for this address on any supported chain. Please verify the address.' };

    // ----- contract / authority checks -----
    var h = null;
    if (d.engine === 'solana') {
      if (d.authoritiesKnown) {
        if (d.mintAuthority) add('bad', 'Mint authority is active: additional tokens can be minted, diluting existing holders.', 35);
        else add('good', 'Mint authority revoked: supply is fixed.');
        if (d.freezeAuthority) { add('bad', 'Freeze authority is active: holder balances can be frozen, preventing transfers or sales.', 40); forceRed = true; }
        else add('good', 'Freeze authority revoked: holder balances cannot be frozen.');
      } else add('warn', 'Mint and freeze authority could not be verified (RPC unavailable).', 10);
      h = solanaHolders(d);
    } else if (d.engine === 'goplus' && d.gp) {
      scoreGoPlus(d, add, red);
      h = goplusHolders(d);
    } else if (d.engine === 'goplus-sui' && d.gp) {
      var g = d.gp;
      function capVal(x) { return x && flag(x.value); }
      if (flag(g.trusted_token)) add('good', 'GoPlus lists this as a trusted token.');
      if (capVal(g.mintable)) add('bad', 'Supply is mintable: the capability holder can issue additional tokens.', 35); else add('good', 'Supply cannot be minted further.');
      if (capVal(g.blacklist)) add('bad', 'Blacklist enabled: specific wallets can be blocked from selling.', 25);
      if (capVal(g.contract_upgradeable)) add('warn', 'Contract is upgradeable: its logic can be changed later.', 10);
      if (capVal(g.metadata_modifiable)) add('info', 'Token metadata (name, logo) can be modified.');
      h = goplusHolders(d);
    } else {
      limited = true;
      add('warn', d.engine === 'market'
        ? 'Limited check: no free contract scanner covers ' + chainName(d.chain) + ', so this rating uses market data only. Honeypot and owner-permission checks were not performed.'
        : 'No contract scan data is available for this token, so this rating uses market data only.', 10);
    }

    // ----- market -----
    var main = pairs[0], m = {};
    if (!pairs.length) add('bad', 'No trading market found on DexScreener. Selling may not be possible.', 25);
    else {
      m.liq = pairs.reduce(function (s, p) { return s + liqOf(p); }, 0);
      m.fdv = main.fdv || main.marketCap; m.mcap = main.marketCap || main.fdv; m.price = main.priceUsd;
      m.created = Math.min.apply(null, pairs.map(function (p) { return p.pairCreatedAt || Infinity; }));
      m.vol24 = pairs.reduce(function (s, p) { return s + ((p.volume && p.volume.h24) || 0); }, 0);
      m.buys = pairs.reduce(function (s, p) { return s + ((p.txns && p.txns.h24 && p.txns.h24.buys) || 0); }, 0);
      m.sells = pairs.reduce(function (s, p) { return s + ((p.txns && p.txns.h24 && p.txns.h24.sells) || 0); }, 0);
      m.onCurve = !m.liq;
      if (m.onCurve) {
        add('info', main.dexId === 'pumpfun' ? 'Still on the pump.fun bonding curve (not yet migrated to a DEX pool).'
          : 'No liquidity pool reported (likely still on a launchpad bonding curve).');
        if ((m.mcap || 0) < 10000) add('bad', 'Very low market cap (' + usd(m.mcap) + '): price is highly sensitive to individual trades.', 20);
        else if ((m.mcap || 0) < 50000) add('warn', 'Low market cap (' + usd(m.mcap) + '): expect high volatility.', 10);
      } else if (m.liq < 5000) add('bad', 'Very low liquidity (' + usd(m.liq) + '): sales may have significant price impact.', 30);
      else if (m.liq < 25000) add('warn', 'Low liquidity (' + usd(m.liq) + ').', 15);
      else add('good', 'Adequate liquidity (' + usd(m.liq) + ').');
      if (isFinite(m.created)) {
        var ageH = (now - m.created) / 36e5;
        if (ageH < 24) add('bad', 'Recently launched: trading started ' + ago(ageH) + ' ago. New tokens carry elevated risk.', 15);
        else if (ageH < 168) add('warn', 'Early-stage token: trading started ' + ago(ageH) + ' ago.', 8);
        else add('good', 'Trading history: ' + ago(ageH) + '.');
      }
      var tx = m.buys + m.sells;
      if (tx >= 20 && m.sells / tx > 0.7) add('warn', 'Elevated sell pressure: ' + m.sells + ' sells vs ' + m.buys + ' buys in 24h.', 10);
      else if (tx > 0) add('info', '24h trades: ' + m.buys + ' buys / ' + m.sells + ' sells.');
      if (m.vol24 < 1000) add('warn', 'Very low trading volume (' + usd(m.vol24) + ' in 24h).', 10);
    }

    // ----- holders -----
    if (h) {
      var note = h.poolPct > 0.5 ? ' (excluding ' + h.poolPct.toFixed(1) + '% held in pools, bonding curves or burn addresses)' : '';
      if (h.top10 > 50) add('bad', 'Top 10 wallets hold ' + h.top10.toFixed(1) + '% of supply' + note + '. High concentration increases sell-off risk.', 30);
      else if (h.top10 > 30) add('warn', 'Top 10 wallets hold ' + h.top10.toFixed(1) + '% of supply' + note + '. This may include exchange wallets.', 15);
      else add('good', 'Top 10 wallets hold ' + h.top10.toFixed(1) + '% of supply' + note + ': broadly distributed.');
      if (h.top1 > 15) add('warn', 'A single wallet holds ' + h.top1.toFixed(1) + '%.', 15);
      if (!h.ownersKnown) add('info', 'Pool wallets could not be identified, so holder figures may include liquidity pools.');
    } else if (!limited) add('warn', 'Holder data is temporarily unavailable. Please try again shortly.', 5);

    // ----- RugCheck (Solana) -----
    var rc = d.rug;
    if (d.engine === 'solana' && rc) {
      if (rc.rugged) red('RugCheck reports this token as rugged.');
      (rc.risks || []).filter(function (r) { return r.level === 'danger'; }).slice(0, 3)
        .forEach(function (r) { add('bad', 'RugCheck: ' + r.name + (r.description ? ' (' + r.description + ')' : ''), 15); });
      (rc.risks || []).filter(function (r) { return r.level === 'warn'; }).slice(0, 3)
        .forEach(function (r) { add('info', 'RugCheck note: ' + r.name + (r.description ? ' (' + r.description + ')' : '')); });
    }

    var verdict = forceRed || pts >= 55 ? 'red' : pts >= 25 ? 'yellow' : 'green';
    return { verdict: verdict, points: pts, reasons: reasons, market: m, main: main, holders: h, limited: limited };
  }

  // GoPlus EVM / Tron contract checks (+ honeypot.is second opinion)
  function scoreGoPlus(d, add, red) {
    var g = d.gp, hp = d.hp;
    var owner = (g.owner_address || '').trim();
    var ownerState = !('owner_address' in g) ? 'unknown' : (!owner || DEAD.test(owner) || /^T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb$/.test(owner)) ? 'renounced' : 'active';
    // A power that only the owner can use is a big deal if there is an owner, low-impact if ownership is renounced.
    var trusted = flag(g.trust_list);
    function ownerPower(isOn, text, p) {
      if (!flag(isOn)) return;
      if (trusted && ownerState !== 'renounced') { add('warn', text + ' (GoPlus-trusted token; likely by design, e.g. staking emissions).', Math.round(p / 3)); return; }
      if (ownerState === 'renounced') add('info', text + ', but ownership is renounced, so it cannot be used.');
      else add(ownerState === 'active' ? 'bad' : 'warn', text + (ownerState === 'unknown' ? ' (owner status unknown).' : '.'), ownerState === 'active' ? p : Math.round(p / 2));
    }

    var sellTax = g.sell_tax !== '' && g.sell_tax != null ? Number(g.sell_tax) * 100 : null;
    var buyTax = g.buy_tax !== '' && g.buy_tax != null ? Number(g.buy_tax) * 100 : null;
    var hpIs = hp && hp.honeypotResult && hp.honeypotResult.isHoneypot === true;
    var hpSell = hp && hp.simulationResult && hp.simulationResult.sellTax;
    var hpBuy = hp && hp.simulationResult && hp.simulationResult.buyTax;
    if (hpSell != null && (sellTax == null || hpSell > sellTax)) sellTax = hpSell;
    if (hpBuy != null && (buyTax == null || hpBuy > buyTax)) buyTax = hpBuy;
    d.taxes = { buy: buyTax, sell: sellTax };
    d.honeypot = flag(g.is_honeypot) || hpIs;

    if (flag(g.trust_list)) add('good', 'GoPlus lists this as a trusted token.');
    if (g.is_in_cex && flag(g.is_in_cex.listed)) add('good', 'Listed on centralized exchanges' + (g.is_in_cex.cex_list && g.is_in_cex.cex_list.length ? ' (' + g.is_in_cex.cex_list.slice(0, 4).join(', ') + ')' : '') + '.');

    if (d.honeypot) red('Honeypot detected: buys succeed but sells are blocked' + (hpIs ? ' (confirmed by honeypot.is simulation)' : '') + '.');
    else if (hp && hp.simulationSuccess) add('good', 'No honeypot detected: honeypot.is simulated a buy and a sell successfully.');
    else if (hp && hp.simulationSuccess === false) add('warn', 'honeypot.is could not simulate a sale.', 10);
    else add('good', 'GoPlus reports no honeypot behaviour.');

    if (flag(g.cannot_sell_all)) add('bad', 'Full balance cannot be sold in a single transaction.', 25);
    if (flag(g.cannot_buy)) add('warn', 'Buying is currently restricted.', 10);

    if (sellTax != null) {
      if (sellTax > 50) red('Sell tax is ' + pct(sellTax) + ': more than half of the sale value is taxed.');
      else if (sellTax > 10) add('bad', 'High sell tax: ' + pct(sellTax) + '.', 25);
      else if (sellTax > 5) add('warn', 'Sell tax: ' + pct(sellTax) + '.', 10);
    }
    if (buyTax != null) {
      if (buyTax > 10) add('bad', 'High buy tax: ' + pct(buyTax) + '.', 15);
      else if (buyTax > 5) add('warn', 'Buy tax: ' + pct(buyTax) + '.', 5);
    }
    if (sellTax != null && buyTax != null && sellTax <= 5 && buyTax <= 5) add('good', 'Low taxes: buy ' + pct(buyTax) + ', sell ' + pct(sellTax) + '.');

    if (ownerState === 'renounced') add('good', 'Ownership renounced: contract settings cannot be changed.');
    else if (ownerState === 'active') add('info', 'Contract has an active owner (' + owner.slice(0, 6) + '…' + owner.slice(-4) + ').');

    if (flag(g.owner_change_balance)) { add('bad', 'Owner can modify wallet balances.', 40); }
    if (flag(g.hidden_owner)) add('bad', 'Hidden owner detected with control over the contract.', 25);
    if (flag(g.can_take_back_ownership)) add('bad', 'Ownership can be reclaimed after being renounced.', 25);
    if (flag(g.honeypot_with_same_creator)) add('bad', 'The creator is linked to previous honeypot contracts.', 25);
    if (g.is_open_source === '0') add('bad', 'Contract source code is not verified.', 20);
    else if (flag(g.is_open_source)) add('good', 'Contract source code is verified.');
    if (flag(g.is_proxy)) add('warn', 'Proxy (upgradeable) contract: its logic can be changed later.', 10);
    if (flag(g.selfdestruct)) add('bad', 'Contract includes a self-destruct function.', 15);
    ownerPower(g.is_mintable, 'Owner can mint new tokens', 35);
    ownerPower(g.is_blacklisted, 'Blacklist function can block wallets from selling', 15);
    ownerPower(g.transfer_pausable, 'Trading can be paused', 15);
    ownerPower(g.slippage_modifiable, 'Taxes can be changed by the owner', 15);
    ownerPower(g.personal_slippage_modifiable, 'Taxes can be set per wallet', 15);
    if (flag(g.trading_cooldown)) add('info', 'Trading cooldown between transactions is enabled.');

    // LP lock (Uniswap-v2 style pools only)
    var lps = g.lp_holders || [];
    if (lps.length) {
      var locked = lps.reduce(function (s, x) { return s + ((Number(x.is_locked) === 1 || DEAD.test(x.address) || String(x.address).toLowerCase() === d.addr.toLowerCase() || /burn|dead|lock/i.test(x.tag || '')) ? Number(x.percent || 0) : 0); }, 0) * 100;
      d.lpLocked = locked;
      var liq = (d.pairs || []).reduce(function (s, p) { return s + liqOf(p); }, 0);
      if (locked >= 90) add('good', pct(locked) + ' of LP tokens are locked or burned.');
      else if (liq < 500000) add('warn', 'Only ' + pct(locked) + ' of LP tokens are locked or burned: liquidity could be withdrawn.', 15);
      else add('info', pct(locked) + ' of LP tokens are locked or burned.');
    }
  }

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
  var TITLES = {
    green: ['Low risk', 'Few risk signals found. This is not a guarantee.'],
    yellow: ['Caution', 'Some risk signals found. Review the findings below.'],
    red: ['High risk', 'Significant risk signals found.']
  };
  var ICON = { good: '✓', warn: '!', bad: '✕', info: 'i' };
  function stat(k, v) { return el('div', { class: 'stat' }, [el('small', { text: k }), el('span', { text: String(v) })]); }

  function render(out, d, s) {
    if (s.verdict === 'error') { msg(out, 'err', s.message); return; }
    var t = TITLES[s.verdict], m = s.market || {}, main = s.main;
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
        r.pts ? el('span', { class: 'pts', text: '+' + r.pts }) : null]);
    })));

    var a = encodeURIComponent(d.addr), ex = CHAINS[d.chain] && CHAINS[d.chain][1];
    var links = [main ? ext(main.url, 'DexScreener') : null];
    if (d.chain === 'solana') { links.push(ext('https://rugcheck.xyz/tokens/' + a, 'RugCheck')); if (/pump$/.test(d.addr)) links.push(ext('https://pump.fun/coin/' + a, 'pump.fun')); }
    if (GOPLUS_IDS[d.chain] && d.chain !== 'tron') links.push(ext('https://gopluslabs.io/token-security/' + GOPLUS_IDS[d.chain] + '/' + a, 'GoPlus'));
    if (HONEYPOT_IDS[d.chain]) links.push(ext('https://honeypot.is/' + (d.chain === 'ethereum' ? 'ethereum' : d.chain === 'bsc' ? 'bsc' : 'base') + '?address=' + a, 'honeypot.is'));
    if (ex) links.push(ext(ex + a, 'Explorer'));
    frag.appendChild(el('div', { class: 'links' }, links));

    var NAMES = { dexscreener: 'DexScreener', goplus: 'GoPlus', honeypot: 'honeypot.is', rugcheck: 'RugCheck', rpcAccount: 'Solana RPC', rpcSupply: 'Solana RPC (supply)', rpcHolders: 'Solana RPC (holder lookup)' };
    var used = Object.keys(d.sources).map(function (k) { return { dexscreener: 'DexScreener', goplus: 'GoPlus', honeypot: 'honeypot.is', rugcheck: 'RugCheck', rpcAccount: 'Solana RPC' }[k]; }).filter(Boolean);
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
