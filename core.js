/* BluntX checker core v3: data gathering + scoring, shared byte-for-byte by bluntx.fun and the BluntX extension.
   No DOM access. Every call goes straight to free, keyless public APIs:
   DexScreener (all chains), Solana RPC + RugCheck (Solana), GoPlus (EVM, Tron, Sui), honeypot.is (ETH/BSC/Base),
   public EVM RPC (proxy-slot fallback). Points: under 25 = Low risk, 25–54 = Caution, 55+ = High risk. */
(function (root) {
  'use strict';
  var VERSION = '3.0.0';

  // ---------- config ----------
  var RPCS = [
    'https://public.rpc.solanavibestation.com',   // free, CORS *, supports getTokenLargestAccounts
    'https://solana-rpc.publicnode.com',          // free, CORS ok
    'https://solana.api.pocket.network',          // free, CORS ok (no holder lookups for big SPL tokens)
    'https://api.mainnet-beta.solana.com'         // official; often 403s browser origins / 429s, so tried last
  ];
  var EVM_RPCS = {
    ethereum: 'https://ethereum-rpc.publicnode.com', bsc: 'https://bsc-rpc.publicnode.com', base: 'https://base-rpc.publicnode.com',
    arbitrum: 'https://arbitrum-one-rpc.publicnode.com', polygon: 'https://polygon-bor-rpc.publicnode.com',
    optimism: 'https://optimism-rpc.publicnode.com', avalanche: 'https://avalanche-c-chain-rpc.publicnode.com'
  };
  var DEX = 'https://api.dexscreener.com/latest/dex/tokens/';
  var RUG = 'https://api.rugcheck.xyz/v1/tokens/';
  var GOPLUS = 'https://api.gopluslabs.io/api/v1/';
  var HONEYPOT = 'https://api.honeypot.is/v2/IsHoneypot';
  var DEX_SEARCH = 'https://api.dexscreener.com/latest/dex/search?q=';
  var DEX_PAIRS = 'https://api.dexscreener.com/token-pairs/v1/';

  var SOL_RE = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
  var EVM_RE = /^0x[0-9a-fA-F]{40}$/;
  var TRON_RE = /^T[1-9A-HJ-NP-Za-km-z]{33}$/;
  var SUI_RE = /^0x[0-9a-fA-F]{1,64}::\w+::\w+$/;
  var TON_RE = /^(?:[EU]Q[A-Za-z0-9_-]{46}|-?\d:[0-9a-fA-F]{64})$/;

  var GOPLUS_IDS = {
    ethereum: '1', bsc: '56', arbitrum: '42161', polygon: '137', base: '8453', optimism: '10', avalanche: '43114',
    cronos: '25', gnosischain: '100', linea: '59144', zksync: '324', scroll: '534352', mantle: '5000', blast: '81457',
    opbnb: '204', sonic: '146', berachain: '80094', abstract: '2741', unichain: '130', worldchain: '480', monad: '143',
    soneium: '1868', xlayer: '196', manta: '169', merlin: '4200', kcc: '321', bitlayer: '200901', zircuit: '48900',
    morph: '2818', story: '1514', hashkey: '177', plasma: '9745', tron: 'tron'
  };
  var HONEYPOT_IDS = { ethereum: '1', bsc: '56', base: '8453' };
  var CHAINS = {
    solana: ['Solana', 'https://solscan.io/token/'], ethereum: ['Ethereum', 'https://etherscan.io/token/'],
    bsc: ['BNB Chain', 'https://bscscan.com/token/'], base: ['Base', 'https://basescan.org/token/'],
    arbitrum: ['Arbitrum', 'https://arbiscan.io/token/'], polygon: ['Polygon', 'https://polygonscan.com/token/'],
    optimism: ['Optimism', 'https://optimistic.etherscan.io/token/'], avalanche: ['Avalanche', 'https://snowtrace.io/token/'],
    sonic: ['Sonic', 'https://sonicscan.org/token/'], blast: ['Blast', 'https://blastscan.io/token/'],
    linea: ['Linea', 'https://lineascan.build/token/'], tron: ['Tron', 'https://tronscan.org/#/token20/'],
    sui: ['Sui', 'https://suiscan.xyz/mainnet/coin/'], ton: ['TON', 'https://tonviewer.com/'],
    hyperliquid: ['Hyperliquid', null], abstract: ['Abstract', null], berachain: ['Berachain', null],
    aptos: ['Aptos', 'https://explorer.aptoslabs.com/coin/'], near: ['NEAR', null], pulsechain: ['PulseChain', null]
  };
  function chainName(c) { return (CHAINS[c] && CHAINS[c][0]) || (c ? c.charAt(0).toUpperCase() + c.slice(1) : 'Unknown'); }

  // Scoring constants (see bluntx-docs/checker-v2-proposal.md)
  var LOW_MAX = 25, HIGH_MIN = 55;
  var CAPS = { creator: 40, cluster: 35, liquidity: 30 };
  var MAJORS = /^(W?SOL|USDC(\.e)?|USDT|USDbC|USD1|USDe|USDS|DAI|PYUSD|FDUSD|USDG|W?ETH|stETH|wstETH|cbETH|W?BNB|BTCB|W?BTC|cbBTC|W?AVAX|W?POL|MATIC|WMATIC|W?S|W?TRX|SUI|TON|W?HYPE|W?BERA|W?MON|W?CRO|W?MNT)$/i;
  var AUTO_LAUNCHERS = /uxento|j7tracker|rapidlaunch/i;
  var NATIVE_RC = /creator history|lp unlocked|unlocked lp|insider|permanent delegate|transfer hook|default account state|non.?transferable|transfer fee/i;
  var MAJOR_QUOTE = /^(W?SOL|USDC(\.e)?|USDT|USDbC|USD1|DAI|PYUSD|FDUSD|W?ETH|W?BNB|W?AVAX|W?POL|WMATIC|W?S|W?TRX|SUI|TON|W?HYPE|W?BERA|W?CRO|W?MNT)$/i;
  var NET_MIN = 2, NET_MAX = 50;          // F1: only small linked-wallet networks are scored
  var LP_LOCKER = /raydium|flux|meteora|lp/i; // F4: these Solana locker types hold LP; others (Jupiter, Streamflow…) are token vesting
  var SYS_PROGRAM = '11111111111111111111111111111111';
  var STRONG_CREATOR = ['phishing_activities', 'stealing_attack', 'sanctioned', 'cybercrime', 'money_laundering', 'financial_crime', 'blackmail_activities'];

  // ---------- network: per-host pacing, short cache, injectable fetch ----------
  var NET = { fetch: null, rpcs: null, ttl: 120000, maxCache: 300, gaps: { 'api.gopluslabs.io': 2100, 'api.rugcheck.xyz': 1100, 'api.honeypot.is': 400, 'api.dexscreener.com': 250 }, retryWait: 1500, gpRetryWait: 2500, search: true };
  var cache = new Map(), nextAt = {};
  function configure(o) { Object.keys(o || {}).forEach(function (k) { if (k === 'gaps') Object.assign(NET.gaps, o.gaps); else NET[k] = o[k]; }); }
  function resetNet() { cache.clear(); nextAt = {}; }
  function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }
  function host(u) { try { return new URL(u).host; } catch (e) { return String(u); } }
  async function pace(h) {
    var gap = NET.gaps[h] || 0; if (!gap) return;
    var now = Date.now(), at = Math.max(now, nextAt[h] || 0);
    nextAt[h] = at + gap;
    if (at > now) await sleep(at - now);
  }
  async function rawFetch(url, opts, ms) {
    var f = NET.fetch || (typeof fetch !== 'undefined' ? fetch : null);
    if (!f) throw new Error('fetch unavailable');
    var ctl = typeof AbortController !== 'undefined' ? new AbortController() : null;
    var t = ctl ? setTimeout(function () { ctl.abort(); }, ms || 12000) : null;
    opts = Object.assign({}, opts || {});
    if (ctl) opts.signal = ctl.signal;
    try { return await f(url, opts); } finally { if (t) clearTimeout(t); }
  }
  function httpError(status, msg) { var e = new Error(msg || ('HTTP ' + status)); e.status = status; return e; }
  // GET JSON with pacing + cache. Rejects with err.status on HTTP errors.
  async function getJSON(url, ms) {
    var c = cache.get(url);
    if (c && Date.now() - c.at < NET.ttl) return c.data;
    await pace(host(url));
    var r = await rawFetch(url, { headers: { accept: 'application/json' } }, ms);
    if (!r.ok) throw httpError(r.status, r.status === 429 ? 'rate-limited (HTTP 429)' : 'HTTP ' + r.status);
    var data = await r.json();
    if (cache.size > NET.maxCache) cache.delete(cache.keys().next().value);
    cache.set(url, { at: Date.now(), data: data });
    return data;
  }
  async function rpcCall(endpoints, method, params) {
    var lastErr;
    for (var i = 0; i < endpoints.length; i++) {
      try {
        var r = await rawFetch(endpoints[i], {
          method: 'POST', headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: method, params: params })
        }, 12000);
        var j = await r.json().catch(function () { return null; });
        if (j && j.result !== undefined && !j.error) return { result: j.result, via: endpoints[i] };
        lastErr = httpError(r.status, (j && j.error && j.error.message) || ('HTTP ' + r.status));
      } catch (e) { lastErr = e; }
    }
    throw lastErr || new Error('RPC failed');
  }
  function liqOf(p) { return (p && p.liquidity && p.liquidity.usd) || 0; }
  var DEAD = /^0x0{40}$|^0x0{36}dead$/i;

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
  function extract(text) {
    text = (text || '').trim();
    var m = text.match(/0x[0-9a-fA-F]{1,64}::\w+::\w+/) || text.match(/0x[0-9a-fA-F]{40}(?![0-9a-fA-F])/) ||
      text.match(/[EU]Q[A-Za-z0-9_-]{46}/) || text.match(/(?:^|[^1-9A-HJ-NP-Za-km-z])(T[1-9A-HJ-NP-Za-km-z]{33})(?![1-9A-HJ-NP-Za-km-z])/) ||
      text.match(/[1-9A-HJ-NP-Za-km-z]{32,44}/);
    if (!m) return text;
    return m[1] || m[0];
  }

  // ---------- data gathering ----------
  // opts: { pairs: prefetched DexScreener pairs for this token, dexError, rpcMode: 'always' (site) | 'fallback' (extension) }
  async function gather(addr, chainChoice, opts) {
    opts = opts || {};
    chainChoice = chainChoice || 'auto';
    var d = { addr: addr, mint: addr, kind: detect(addr), sources: {}, errors: {}, coreVersion: VERSION };

    if (opts.pairs) { d.allPairs = opts.pairs; d.sources.dexscreener = 'ok (' + d.allPairs.length + ' pairs)'; if (opts.dexError) d.errors.dexscreener = opts.dexError; }
    else {
      try {
        var j = await getJSON(DEX + encodeURIComponent(addr));
        d.allPairs = (j && j.pairs) || [];
        d.sources.dexscreener = 'ok (' + d.allPairs.length + ' pairs)';
      } catch (e) { d.allPairs = []; d.errors.dexscreener = e.message; }
    }
    // Fallback: the per-chain pairs endpoint sometimes lists tokens the search endpoint misses.
    if (!d.allPairs.length && chainChoice !== 'auto') {
      try {
        var tp = await getJSON(DEX_PAIRS + encodeURIComponent(chainChoice) + '/' + encodeURIComponent(addr));
        if (Array.isArray(tp) && tp.length) { d.allPairs = tp; d.sources.dexscreener = 'ok (' + tp.length + ' pairs, per-chain)'; }
      } catch (e) { /* keep the first result */ }
    }

    var chainsSeen = {};
    d.allPairs.forEach(function (p) { chainsSeen[p.chainId] = (chainsSeen[p.chainId] || 0) + liqOf(p) + 1e-9; });
    d.chainsSeen = Object.keys(chainsSeen);
    if (chainChoice !== 'auto') d.chain = chainChoice;
    else if (d.allPairs.length) {
      var top = d.chainsSeen.slice().sort(function (a, b) { return chainsSeen[b] - chainsSeen[a]; })[0];
      d.chain = top;
    } else {
      d.chain = { evm: 'ethereum', solana: 'solana', tron: 'tron', sui: 'sui', ton: 'ton' }[d.kind] || null;
      d.chainGuessed = true;
    }
    d.pairs = d.allPairs.filter(function (p) { return p.chainId === d.chain; });

    if (d.chain === 'solana') { d.engine = 'solana'; await gatherSolana(d, opts.rpcMode || 'always'); }
    else if (d.chain === 'sui') { d.engine = 'goplus-sui'; await gatherGoPlus(d, GOPLUS + 'sui/token_security?contract_addresses=' + encodeURIComponent(addr)); }
    else if (GOPLUS_IDS[d.chain] && (EVM_RE.test(addr) || d.chain === 'tron')) {
      d.engine = 'goplus';
      var tasks = [gatherGoPlus(d, GOPLUS + 'token_security/' + GOPLUS_IDS[d.chain] + '?contract_addresses=' + addr)];
      if (HONEYPOT_IDS[d.chain]) tasks.push(
        getJSON(HONEYPOT + '?address=' + addr + '&chainID=' + HONEYPOT_IDS[d.chain], 15000)
          .then(function (h) { d.hp = h; d.sources.honeypot = 'ok'; })
          .catch(function (e) { d.errors.honeypot = e.message; }));
      await Promise.all(tasks);
      var creator = d.gp && String(d.gp.creator_address || '').trim();
      if (creator && EVM_RE.test(creator) && d.chain !== 'tron') {
        try {
          var a = await getJSON(GOPLUS + 'address_security/' + creator + '?chain_id=' + GOPLUS_IDS[d.chain], 15000);
          if (a && a.code === 1 && a.result) { d.creatorSec = a.result; d.sources.goplusCreator = 'ok'; }
          else d.errors.goplusCreator = (a && a.message) || 'no result';
        } catch (e) { d.errors.goplusCreator = e.message; }
      }
      if (!d.gp && EVM_RPCS[d.chain] && EVM_RE.test(addr)) await gatherProxySlots(d);
    } else d.engine = 'market';
    if (NET.search) await gatherLookalikes(d);
    return d;
  }

  // N9: other tokens with the same symbol on the same chain (one DexScreener search).
  async function gatherLookalikes(d) {
    var pairs = d.pairs || [];
    if (!pairs.length) return;
    var me = d.addr.toLowerCase(), mine = pairs[0].baseToken && String(pairs[0].baseToken.address).toLowerCase() === me ? pairs[0].baseToken : pairs[0].quoteToken;
    var sym = mine && String(mine.symbol || '').trim();
    var liq = pairs.reduce(function (s, p) { return s + liqOf(p); }, 0);
    if (!sym || sym.length < 2 || sym.length > 20 || MAJORS.test(sym) || liq >= 1e6) return;
    try {
      var j = await getJSON(DEX_SEARCH + encodeURIComponent(sym), 10000);
      d.lookalikes = ((j && j.pairs) || []).filter(function (p) {
        return p.chainId === d.chain && p.baseToken && String(p.baseToken.symbol || '').trim().toLowerCase() === sym.toLowerCase() &&
          String(p.baseToken.address).toLowerCase() !== me;
      });
      d.sources.dexSearch = 'ok';
    } catch (e) { d.errors.dexSearch = e.message; }
  }

  // GoPlus, with one retry after a rate limit (code 4029 or HTTP 429).
  async function gatherGoPlus(d, url) {
    for (var attempt = 0; attempt < 2; attempt++) {
      var limited = false;
      try {
        var j = await getJSON(url, 15000);
        var res = j && j.result;
        var v = res && (res[d.addr] || res[d.addr.toLowerCase()] || res[Object.keys(res)[0]]);
        if (j && j.code === 1 && v && Object.keys(v).length) { d.gp = v; d.sources.goplus = attempt ? 'ok (after retry)' : 'ok'; delete d.errors.goplus; return; }
        limited = !!(j && j.code === 4029);
        d.errors.goplus = limited ? 'rate-limited (HTTP 429)' : (j && j.message && j.code !== 1) ? j.message : 'token not indexed';
        if (limited) cache.delete(url);
      } catch (e) { d.errors.goplus = e.message; limited = e.status === 429; }
      if (!limited) return;
      await sleep(NET.gpRetryWait);
    }
  }

  // EIP-1967 implementation/admin slots + the older OpenZeppelin slot.
  var PROXY_SLOTS = ['0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc',
    '0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103',
    '0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3'];
  // Fallback when GoPlus has nothing: proxy slots and owner() read straight from a public RPC.
  async function gatherProxySlots(d) {
    try {
      var rs = await Promise.all(PROXY_SLOTS.map(function (s) { return rpcCall([EVM_RPCS[d.chain]], 'eth_getStorageAt', [d.addr, s, 'latest']); }));
      d.proxySlot = rs.some(function (r) { return /[1-9a-f]/i.test(String(r.result).slice(2)); });
      d.sources.evmRpc = 'ok';
    } catch (e) { d.errors.evmRpc = e.message; }
    try {
      var o = await rpcCall([EVM_RPCS[d.chain]], 'eth_call', [{ to: d.addr, data: '0x8da5cb5b' }, 'latest']);
      var hex = String(o.result || '');
      if (/^0x[0-9a-f]{64}$/i.test(hex)) d.rpcOwner = '0x' + hex.slice(26);
    } catch (e) { /* no owner() function: nothing to report */ }
  }

  async function fetchRug(d) {
    var url = RUG + d.addr + '/report';
    try {
      var j;
      try { j = await getJSON(url, 15000); }
      catch (e) {
        if (e.status !== 429) throw e;
        await sleep(NET.retryWait);
        try { j = await getJSON(url, 15000); }
        catch (e2) {
          if (e2.status !== 429) throw e2;
          var s = await getJSON(RUG + d.addr + '/report/summary', 15000);
          d.rug = s; d.rugSummary = true; d.sources.rugcheck = 'summary only (full report rate-limited)';
          return;
        }
      }
      if (j && !j.error) { d.rug = j; d.sources.rugcheck = 'ok'; } else d.errors.rugcheck = (j && j.error) || 'no report';
    } catch (e) { d.errors.rugcheck = e.message; }
  }

  function readExtensions(list) {
    var x = {};
    (list || []).forEach(function (e) {
      var st = e && e.state || {};
      if (e.extension === 'permanentDelegate' && st.delegate) x.permanentDelegate = st.delegate;
      if (e.extension === 'transferHook' && st.programId) x.transferHook = st.programId;
      if (e.extension === 'defaultAccountState' && /frozen/i.test(String(st.accountState))) x.defaultFrozen = true;
      if (e.extension === 'nonTransferable') x.nonTransferable = true;
    });
    return x;
  }
  function rugExtensions(te) {
    if (!te || typeof te !== 'object') return null;
    var x = {};
    if (te.permanentDelegate && te.permanentDelegate.delegate) x.permanentDelegate = te.permanentDelegate.delegate;
    if (te.transferHook && (te.transferHook.programId || te.transferHook.programID)) x.transferHook = te.transferHook.programId || te.transferHook.programID;
    if (te.defaultAccountState && /frozen|2/i.test(String(te.defaultAccountState.state || te.defaultAccountState.accountState || ''))) x.defaultFrozen = true;
    if (te.nonTransferable === true) x.nonTransferable = true;
    return x;
  }

  async function gatherSolana(d, rpcMode) {
    var mint = d.addr;
    function account() {
      return rpcCall(NET.rpcs || RPCS, 'getAccountInfo', [mint, { encoding: 'jsonParsed' }]).then(function (r) {
        var v = r.result && r.result.value;
        if (!v) { d.notMint = true; d.sources.rpcAccount = 'no account'; return; }
        var info = v.data && v.data.parsed && v.data.parsed.info;
        if (!info || (v.data.parsed.type !== 'mint')) { d.notMint = true; d.sources.rpcAccount = 'not a token mint'; return; }
        d.mintAuthority = info.mintAuthority || null;
        d.freezeAuthority = info.freezeAuthority || null;
        d.decimals = info.decimals; d.supplyRaw = info.supply;
        d.authoritiesKnown = true;
        d.ext = readExtensions(info.extensions);
        d.sources.rpcAccount = 'ok via ' + host(r.via);
      }).catch(function (e) { d.errors.rpcAccount = e.message; });
    }
    function holders() {
      return Promise.all([
        rpcCall(NET.rpcs || RPCS, 'getTokenSupply', [mint]).then(function (r) { d.supply = r.result.value; d.sources.rpcSupply = 'ok via ' + host(r.via); })
          .catch(function (e) { d.errors.rpcSupply = e.message; }),
        rpcCall(NET.rpcs || RPCS, 'getTokenLargestAccounts', [mint]).then(async function (r) {
          var accs = r.result.value || [];
          d.largest = accs; d.sources.rpcHolders = 'ok via ' + host(r.via);
          try {
            var m = await rpcCall(NET.rpcs || RPCS, 'getMultipleAccounts', [accs.map(function (a) { return a.address; }), { encoding: 'jsonParsed' }]);
            (m.result.value || []).forEach(function (acc, i) {
              var o = acc && acc.data && acc.data.parsed && acc.data.parsed.info && acc.data.parsed.info.owner;
              if (o) accs[i].owner = o;
            });
          } catch (e) { /* owners optional */ }
        }).catch(function (e) { d.errors.rpcHolders = e.message; })
      ]);
    }
    if (rpcMode === 'always') await Promise.all([account(), holders(), fetchRug(d)]);
    else {
      await Promise.all([account(), fetchRug(d)]);
      if (!d.rug || !d.rug.topHolders || !d.rug.topHolders.length) await holders();
    }
    if (!d.authoritiesKnown && d.rug && 'mintAuthority' in d.rug) {
      d.mintAuthority = d.rug.mintAuthority || null;
      d.freezeAuthority = d.rug.freezeAuthority || null;
      d.authoritiesKnown = true; d.sources.authorities = 'from RugCheck (RPC unavailable)';
    }
    if (!d.ext && d.rug) d.ext = rugExtensions(d.rug.token_extensions);
    // N2: wallet graph (who sent to whom), only when RugCheck found small linked-wallet networks.
    if (d.rug && !d.rugSummary && smallNetworks(d.rug).length) {
      try {
        var g = await getJSON(RUG + d.addr + '/insiders/graph', 15000);
        if (Array.isArray(g)) { d.graph = g; d.sources.rugGraph = 'ok'; }
      } catch (e) { d.errors.rugGraph = e.message; }
    }
  }
  function netSize(n) { return Number(n.activeAccounts || n.numActiveAccounts || n.size || 0); }
  function smallNetworks(rc) { return (rc.insiderNetworks || []).filter(function (n) { var z = netSize(n); return z >= NET_MIN && z <= NET_MAX; }); }

  // ---------- holders ----------
  function solanaHolders(d) {
    var supplyUi = d.supply ? Number(d.supply.uiAmountString || d.supply.uiAmount) :
      (d.supplyRaw && d.decimals != null ? Number(d.supplyRaw) / Math.pow(10, d.decimals) : null);
    if (!supplyUi && d.rug && d.rug.token) supplyUi = Number(d.rug.token.supply) / Math.pow(10, d.rug.token.decimals || 0);
    var skip = {}, insider = {};
    (d.pairs || []).forEach(function (p) { skip[p.pairAddress] = 1; });
    if (d.rug) {
      var ka = d.rug.knownAccounts || {};
      Object.keys(ka).forEach(function (k) { if (/AMM|LOCKER/i.test(ka[k].type)) skip[k] = 1; });
      (d.rug.markets || []).forEach(function (m) { if (m.pubkey) skip[m.pubkey] = 1; if (typeof m.liquidityAAccount === 'string') skip[m.liquidityAAccount] = 1; if (typeof m.liquidityBAccount === 'string') skip[m.liquidityBAccount] = 1; });
      (d.rug.topHolders || []).forEach(function (h) { if (h.insider) { insider[h.address] = 1; if (h.owner) insider[h.owner] = 1; } });
    }
    var list = null, via = null;
    if (d.largest && d.largest.length && supplyUi) {
      list = d.largest.map(function (a) { return { addr: a.address, owner: a.owner, pct: 100 * Number(a.uiAmountString || a.uiAmount || 0) / supplyUi }; });
      via = 'Solana RPC';
    } else if (d.rug && d.rug.topHolders && d.rug.topHolders.length) {
      list = d.rug.topHolders.map(function (h) { return { addr: h.address, owner: h.owner, pct: Number(h.pct) || 0 }; });
      via = 'RugCheck';
    }
    if (!list) return null;
    list.forEach(function (h) { h.insider = !!(insider[h.addr] || (h.owner && insider[h.owner])); });
    return summarize(list, function (h) { return skip[h.owner] || skip[h.addr]; }, via, list.some(function (h) { return !!h.owner; }));
  }
  function goplusHolders(d) {
    var hs = d.gp && d.gp.holders;
    if (!hs || !hs.length) return null;
    var skip = {};
    (d.pairs || []).forEach(function (p) { skip[String(p.pairAddress).toLowerCase()] = 1; });
    (d.gp.dex || []).forEach(function (x) { if (x.pair) skip[String(x.pair).toLowerCase()] = 1; });
    var list = hs.map(function (h) { return { addr: h.address, tag: h.tag, locked: Number(h.is_locked) === 1, pct: 100 * Number(h.percent || 0) }; });
    return summarize(list, function (h) {
      return skip[String(h.addr).toLowerCase()] || h.locked || DEAD.test(h.addr) ||
        /pool|pair|lp\b|uniswap|pancake|sushi|aerodrome|burn|dead|lock|null/i.test(h.tag || '');
    }, 'GoPlus', true);
  }
  function summarize(list, isPool, via, ownersKnown) {
    var poolPct = 0, users = [];
    list.forEach(function (h) { if (isPool(h)) poolPct += h.pct; else users.push(h); });
    users.sort(function (a, b) { return b.pct - a.pct; });
    var top = users.slice(0, 10);
    return {
      top10: top.reduce(function (s, h) { return s + h.pct; }, 0),
      top1: top.length ? top[0].pct : 0, poolPct: poolPct, via: via, ownersKnown: ownersKnown,
      sameSize: sameSize(users.slice(0, 20))
    };
  }
  // N1: the largest group of holders (≥0.3% each, top 20) whose balances sit within 1% of each other.
  function sameSize(users) {
    var p = users.map(function (h) { return h.pct; }).filter(function (x) { return x >= 0.3; });
    var best = { n: 0, pct: 0, lo: 0 };
    p.forEach(function (a) {
      var grp = p.filter(function (b) { return b >= a && b <= a * 1.01; });
      if (grp.length > best.n) best = { n: grp.length, pct: grp.reduce(function (s, x) { return s + x; }, 0), lo: a };
    });
    best.of = p.length;
    return best;
  }

  // ---------- formatting ----------
  function usd(n) {
    if (n == null || !isFinite(n)) return '—';
    if (n >= 1e9) return '$' + (n / 1e9).toFixed(2) + 'B';
    if (n >= 1e6) return '$' + (n / 1e6).toFixed(2) + 'M';
    if (n >= 1e3) return '$' + (n / 1e3).toFixed(1) + 'K';
    return '$' + Number(n).toFixed(n < 1 ? 6 : 0);
  }
  function ago(h) { return h < 1 ? Math.round(h * 60) + ' min' : h < 48 ? Math.round(h) + 'h' : Math.round(h / 24) + ' days'; }
  function pct(x) { return x > 0 && x < 0.1 ? 'under 0.1%' : (Math.round(x * 10) / 10) + '%'; }
  function flag(v) { return v === '1' || v === 1 || v === true; }
  var MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  function dateStr(ms) { var t = new Date(ms); return t.getUTCDate() + ' ' + MONTHS[t.getUTCMonth()] + ' ' + t.getUTCFullYear(); }
  var DEX_NAMES = { raydium: 'Raydium', pumpswap: 'PumpSwap', pumpfun: 'pump.fun', meteora: 'Meteora', orca: 'Orca', uniswap: 'Uniswap',
    pancakeswap: 'PancakeSwap', aerodrome: 'Aerodrome', sushiswap: 'SushiSwap', camelot: 'Camelot', traderjoe: 'Trader Joe',
    velodrome: 'Velodrome', quickswap: 'QuickSwap', fluxbeam: 'FluxBeam', launchlab: 'LaunchLab', moonshot: 'Moonshot', fourmeme: 'Four.meme' };
  function dexName(p) {
    var n = DEX_NAMES[p.dexId] || (p.dexId ? p.dexId.charAt(0).toUpperCase() + p.dexId.slice(1) : 'Unknown DEX');
    var lab = (p.labels || []).filter(function (l) { return /^(v\d|clmm|dlmm|cpmm|dyn2?|amm)$/i.test(l); });
    return n + (lab.length ? ' ' + lab[0].toUpperCase() : '');
  }

  // ---------- scoring ----------
  // Display groups (category cards). Caps apply to the cat field (creator, cluster, liquidity) only.
  var GROUPS = [['contract', 'Contract & token'], ['liquidity', 'Liquidity & lock'], ['holders', 'Holders'],
    ['creator', 'Creator history'], ['cluster', 'Linked wallets & snipers'], ['activity', 'Trading activity']];
  function quoteOf(p, addr) {
    var me = String(addr).toLowerCase();
    var other = p.baseToken && String(p.baseToken.address).toLowerCase() === me ? p.quoteToken : p.baseToken;
    return other && String(other.symbol || '').trim();
  }
  // F8: prefer the largest pool paired with a major token when it has at least half the top pool's liquidity.
  function pickMain(pairs, addr) {
    if (!pairs.length) return null;
    var top = pairs[0];
    if (MAJOR_QUOTE.test(quoteOf(top, addr) || '')) return top;
    for (var i = 1; i < pairs.length; i++) {
      if (liqOf(pairs[i]) < 0.5 * liqOf(top)) break;
      if (MAJOR_QUOTE.test(quoteOf(pairs[i], addr) || '')) return pairs[i];
    }
    return top;
  }

  function score(d, now) {
    now = now || Date.now();
    var reasons = [], limited = false, G = 'contract';
    function add(level, text, p, o) {
      var r = { level: level, text: text, pts: p || 0, grp: (o && (o.grp || o.cat)) || G };
      if (o) { if (o.cat) r.cat = o.cat; if (o.force) r.force = true; if (o.data) r.data = true; }
      reasons.push(r); return r;
    }
    function red(text, cat) { return add('bad', text, 50, { force: true, cat: cat }); }

    var pairs = (d.pairs || []).slice().sort(function (a, b) { return liqOf(b) - liqOf(a); });
    var main = pickMain(pairs, d.addr);
    if (main && main !== pairs[0]) pairs = [main].concat(pairs.filter(function (p) { return p !== main; }));
    if (d.engine === 'solana' && d.notMint && !pairs.length)
      return { verdict: 'error', message: 'This address is not a Solana token mint. Please verify it is the token mint address, not a wallet or pair address.' };
    if (!pairs.length && !d.gp && !(d.engine === 'solana' && d.authoritiesKnown)) {
      // F7: say plainly when nothing is known, instead of naming a guessed chain.
      if (d.chainGuessed) return { verdict: 'error', message: 'No market or contract data was found for this address. The token may be on a chain BluntX does not cover yet (for example Robinhood Chain), or the address may be wrong. Please check the address.' };
      return { verdict: 'error', message: 'Token not found on ' + chainName(d.chain) + '. Please verify the address or select a different chain.' };
    }

    var rc = d.engine === 'solana' ? d.rug : null;
    var fullRug = !!(rc && !d.rugSummary && ('creatorTokens' in rc || 'graphInsidersDetected' in rc || 'markets' in rc));
    var m = {};
    var totalLiq = pairs.reduce(function (s, p) { return s + liqOf(p); }, 0);
    var created = Math.min.apply(null, pairs.length ? pairs.map(function (p) { return p.pairCreatedAt || Infinity; }) : [Infinity]);
    var ageH = isFinite(created) ? (now - created) / 36e5 : null;
    var fresh = ageH != null && ageH < 1;

    // ----- contract / authority -----
    var h = null;
    if (d.engine === 'solana') {
      if (d.authoritiesKnown) {
        if (d.mintAuthority) add('bad', 'Mint authority is active: additional tokens can be minted, diluting existing holders.', 35);
        else add('good', 'Mint authority revoked: supply is fixed.');
        if (d.freezeAuthority) add('bad', 'Freeze authority is active: holder balances can be frozen, preventing transfers or sales.', 40, { force: true });
        else add('good', 'Freeze authority revoked: holder balances cannot be frozen.');
      } else add('warn', 'Mint and freeze authority could not be verified (RPC unavailable).', 10, { data: true });
      var x = d.ext || {};
      if (x.permanentDelegate) add('bad', 'The issuer can move or burn tokens in any wallet (permanent delegate).', 40, { force: true });
      if (x.defaultFrozen) add('bad', 'New wallets start frozen: the issuer must approve each wallet before it can trade.', 40, { force: true });
      if (x.nonTransferable) add('bad', 'This token cannot be transferred or sold.', 40, { force: true });
      if (x.transferHook) add('warn', 'Every transfer runs extra code chosen by the issuer (transfer hook).', 15);
      if (rc) scoreTransferFee(rc, add);
      if (rc && rc.verification) {
        if (rc.verification.jup_strict) add('good', 'Verified on Jupiter\'s strict token list.');
        else if (rc.verification.jup_verified) add('good', 'Listed as verified on Jupiter.');
      }
      h = solanaHolders(d);
    } else if (d.engine === 'goplus' && d.gp) {
      scoreGoPlus(d, add, red, pairs, ageH);
      h = goplusHolders(d);
    } else if (d.engine === 'goplus-sui' && d.gp) {
      var g = d.gp;
      var capVal = function (v) { return v && flag(v.value); };
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
        : 'No contract scan data is available for this token, so this rating uses market data and a few direct contract reads only.', 10, { data: true });
      if (d.hp) scoreHoneypotOnly(d, add, red);
      if (d.rpcOwner) {
        if (DEAD.test(d.rpcOwner)) add('good', 'Ownership renounced (read directly from the contract).');
        else add('info', 'Contract has an active owner (' + d.rpcOwner.slice(0, 6) + '…' + d.rpcOwner.slice(-4) + '), read directly from the contract.');
      }
      if (d.proxySlot) add('warn', 'Proxy (upgradeable) contract: its logic can be changed later.', 10);
    }

    // ----- market -----
    if (!pairs.length) add('bad', 'No trading market found on DexScreener. Selling may not be possible.', 25, { grp: 'liquidity' });
    else {
      m.liq = totalLiq;
      m.fdv = main.fdv || main.marketCap; m.mcap = main.marketCap || main.fdv; m.price = main.priceUsd;
      m.created = created;
      m.vol24 = pairs.reduce(function (s, p) { return s + ((p.volume && p.volume.h24) || 0); }, 0);
      var sumTx = function (win, side) { return pairs.reduce(function (s, p) { return s + ((p.txns && p.txns[win] && p.txns[win][side]) || 0); }, 0); };
      m.buys = sumTx('h24', 'buys'); m.sells = sumTx('h24', 'sells');
      m.buys1 = sumTx('h1', 'buys'); m.sells1 = sumTx('h1', 'sells');
      m.change1 = main.priceChange ? Number(main.priceChange.h1) : null;
      m.change6 = main.priceChange ? Number(main.priceChange.h6) : null;
      m.onCurve = !m.liq;
      G = 'liquidity';
      if (m.onCurve) {
        add('info', main.dexId === 'pumpfun' ? 'Still on the pump.fun bonding curve (not yet migrated to a DEX pool).'
          : 'No liquidity pool reported (likely still on a launchpad bonding curve).');
        if ((m.mcap || 0) < 10000) add('bad', 'Very low market cap (' + usd(m.mcap) + '): price is highly sensitive to individual trades.', 20);
        else if ((m.mcap || 0) < 50000) add('warn', 'Low market cap (' + usd(m.mcap) + '): expect high volatility.', 10);
      } else if (m.liq < 5000) add('bad', 'Very low liquidity (' + usd(m.liq) + '): sales may have significant price impact.', 30);
      else if (m.liq < 25000) add('warn', 'Low liquidity (' + usd(m.liq) + '): larger sales will move the price noticeably.', 15);
      else add('good', 'Adequate liquidity (' + usd(m.liq) + ').');
      G = 'activity';
      if (ageH != null) {
        if (ageH < 24) add('bad', 'Recently launched: trading started ' + ago(ageH) + ' ago. New tokens carry elevated risk.', 15);
        else if (ageH < 168) add('warn', 'Early-stage token: trading started ' + ago(ageH) + ' ago.', 8);
        else add('good', 'Trading history: ' + ago(ageH) + '.');
      }
      // N6: price crash (liquidity pulled or a dump).
      var drop = m.change1 != null && m.change1 <= -80 ? [m.change1, 'in the last hour'] : m.change6 != null && m.change6 <= -90 ? [m.change6, 'in the last 6 hours'] : null;
      if (drop) {
        var pulled = !m.onCurve && m.liq < 1000;
        add('bad', 'Price fell ' + Math.round(-drop[0]) + '% ' + drop[1] + (m.onCurve ? ', a common sign that the creator or early buyers sold out.' : '; liquidity may have been removed.'), 25, { force: pulled });
      }
      // Sell pressure: last hour when there is enough activity, otherwise 24 hours.
      var tx1 = m.buys1 + m.sells1, tx = m.buys + m.sells;
      if (tx1 >= 50) {
        if (m.sells1 > 2 * m.buys1) add('warn', 'Heavy selling in the last hour: ' + m.sells1 + ' sells vs ' + m.buys1 + ' buys.', 10);
        else add('info', 'Last hour: ' + m.buys1 + ' buys / ' + m.sells1 + ' sells' + (m.change1 != null && isFinite(m.change1) ? '. Price change: ' + (m.change1 > 0 ? '+' : '') + Math.round(m.change1 * 10) / 10 + '%.' : '.'));
      } else if (tx >= 20 && m.sells / tx > 0.7) add('warn', 'Elevated sell pressure: ' + m.sells + ' sells vs ' + m.buys + ' buys in 24h.', 10);
      else if (tx > 0) add('info', '24h trades: ' + m.buys + ' buys / ' + m.sells + ' sells.');
      if (m.vol24 < 1000) add('warn', 'Very low trading volume (' + usd(m.vol24) + ' in 24h).', 10);
      // N9: lookalike token with far more liquidity.
      G = 'contract';
      var trustedTok = (d.gp && flag(d.gp.trust_list)) || (rc && rc.verification && rc.verification.jup_strict);
      if (d.lookalikes && d.lookalikes.length && !trustedTok) {
        var big = d.lookalikes.filter(function (p) { return liqOf(p) >= 10 * Math.max(totalLiq, 1) && (p.pairCreatedAt || Infinity) < created; })
          .sort(function (a, b) { return liqOf(b) - liqOf(a); })[0];
        if (big) add('warn', 'Another token named $' + String(big.baseToken.symbol).trim() + ' on ' + chainName(d.chain) + ' has far more liquidity (' + usd(liqOf(big)) + '). Check you have the right address.', 10);
      }
    }

    // ----- holders -----
    G = 'holders';
    if (h) {
      var note = h.poolPct > 0.5 ? ' (excluding ' + h.poolPct.toFixed(1) + '% held in pools, bonding curves or burn addresses)' : '';
      var lead = 'Top 10 wallets hold ' + h.top10.toFixed(1) + '% of supply' + note;
      if (h.poolPct > 50) lead = pct(h.poolPct) + ' of supply is in pools, locked or burn addresses. The 10 largest other wallets hold ' + h.top10.toFixed(1) + '%';  // F6
      if (h.top10 > 50) add('bad', lead + '. High concentration increases sell-off risk.', 30);
      else if (h.top10 > 30) add('warn', lead + '. This may include exchange wallets.', 15);
      else add('good', lead + (h.poolPct > 50 ? '.' : ': broadly distributed.'));
      if (h.top1 > 15) add('warn', 'A single wallet holds ' + h.top1.toFixed(1) + '%.', 15);
      else if (h.top1 > 0) add('good', 'Largest single wallet holds ' + h.top1.toFixed(1) + '%.');
      if (!h.ownersKnown) add('info', 'Pool wallets could not be identified, so holder figures may include liquidity pools.');
    } else if (!limited) add('warn', 'Holder data is temporarily unavailable. Please try again shortly.', 5, { data: true });

    // ----- A. creator history -----
    G = 'creator';
    if (rc) scoreSolanaCreator(d, rc, add, fullRug);
    // ----- B. linked wallets, snipers, bundles -----
    G = 'cluster';
    if (rc && fullRug) scoreSolanaClusters(d, rc, add, fresh);
    if (h && h.sameSize && h.sameSize.n >= 5) {
      var ss = h.sameSize;
      add(ss.n >= 8 ? 'bad' : 'warn', ss.n + ' of the 20 largest wallets hold almost identical amounts (about ' + pct(ss.lo) + ' each), a common sign of a bundled launch.', ss.n >= 8 ? 20 : 10, { cat: 'cluster' });
    }
    var ha = d.hp && d.hp.holderAnalysis;
    if (ha) {
      var sip = Number(ha.siphoned) || 0, tot = Number(ha.holders) || 0;
      if (sip >= 5 || (sip > 0 && tot && sip / tot >= 0.01))   // F2
        add('bad', 'Tokens have been taken out of ' + sip + ' holders\' wallets without their action.', 50, { cat: 'cluster', force: true });
      else if (sip > 0) add('info', 'honeypot.is saw ' + sip + ' wallet' + (sip === 1 ? '' : 's') + ' lose tokens without a transfer. With so few cases this is usually a contract quirk, so it is not scored.');
      var sn = Number(ha.snipersSuccess) || 0;   // N3 (info until validated)
      if (sn >= 5) add('info', 'honeypot.is saw ' + sn + ' wallets buy in the first blocks after launch.');
    }

    // ----- C. liquidity -----
    G = 'liquidity';
    var pool = poolInfo(d, pairs, totalLiq, rc, now);
    if (pool) scoreLiquidity(d, pool, add, now);
    scoreUnlocks(d, rc, m, add, now);

    // ----- RugCheck findings (Solana) -----
    G = 'contract';
    if (rc) {
      if (rc.rugged) red('RugCheck reports this token as rugged.');
      (rc.risks || []).filter(function (r) { return r.level === 'danger' && !NATIVE_RC.test(r.name || ''); }).slice(0, 3)
        .forEach(function (r) { add('bad', 'RugCheck: ' + r.name + (r.description ? ' (' + r.description + ')' : ''), 15); });
      (rc.risks || []).filter(function (r) { return r.level === 'warn' && !NATIVE_RC.test(r.name || ''); }).slice(0, 3)
        .forEach(function (r) { add('info', 'RugCheck note: ' + r.name + (r.description ? ' (' + r.description + ')' : '')); });
    }

    // ----- category caps, total, verdict -----
    Object.keys(CAPS).forEach(function (cat) {
      var rs = reasons.filter(function (r) { return r.cat === cat && r.pts; });
      if (rs.some(function (r) { return r.force; })) return;
      var left = CAPS[cat];
      rs.forEach(function (r) {
        var p = Math.min(r.pts, left);
        if (p < r.pts) { r.capped = r.pts; r.pts = p; }
        left -= p;
      });
    });
    var pts = reasons.reduce(function (s, r) { return s + (r.pts || 0); }, 0);
    var forceRed = reasons.some(function (r) { return r.force; });
    var verdict = forceRed || pts >= HIGH_MIN ? 'red' : pts >= LOW_MAX ? 'yellow' : 'green';
    var conf = confidence(d, { pairs: pairs, holders: h, pool: pool, limited: limited, fullRug: fullRug, fresh: fresh });
    var lowData = false;
    if (verdict === 'green' && conf.level === 'Low') { verdict = 'yellow'; lowData = true; }
    var top = reasons.filter(function (r) { return r.pts > 0 || r.force; })
      .sort(function (a, b) { return (b.force ? 1000 : 0) + b.pts - ((a.force ? 1000 : 0) + a.pts); }).slice(0, 3);
    return { verdict: verdict, points: pts, reasons: reasons, market: m, main: main, holders: h, limited: limited,
      pool: pool, confidence: conf, lowData: lowData, forced: forceRed, top: top, groups: groupSummary(reasons), fresh: fresh };
  }

  // Per-card totals for the report.
  function groupSummary(reasons) {
    return GROUPS.map(function (g) {
      var rs = reasons.filter(function (r) { return r.grp === g[0]; });
      var pts = rs.reduce(function (s, r) { return s + (r.pts || 0); }, 0);
      var level = rs.some(function (r) { return r.force; }) || pts >= 25 || rs.some(function (r) { return r.level === 'bad' && r.pts; }) ? 'bad'
        : pts > 0 || rs.some(function (r) { return r.level === 'warn'; }) ? 'warn' : 'ok';
      return { key: g[0], title: g[1], pts: pts, cap: CAPS[g[0]] || null, level: level, reasons: rs };
    }).filter(function (g) { return g.reasons.length; });
  }

  // N7: Token-2022 transfer fee.
  function scoreTransferFee(rc, add) {
    var tf = rc.transferFee;
    if (!tf || typeof tf !== 'object') return;
    var fee = Number(tf.pct) || 0;
    var changeable = !!(tf.authority && tf.authority !== SYS_PROGRAM);
    var tail = changeable ? ', and the issuer can change it.' : '.';
    if (fee > 10) add('bad', 'Every transfer is charged a ' + pct(fee) + ' fee' + tail, 20);
    else if (fee > 5) add('warn', 'Every transfer is charged a ' + pct(fee) + ' fee' + tail, 10);
    else if (fee > 0) add('info', 'Every transfer is charged a ' + pct(fee) + ' fee' + tail);
    if (changeable) add('warn', fee > 0 ? 'The issuer can raise the transfer fee at any time.' : 'The issuer can switch on a transfer fee later.', 5);
  }

  // When GoPlus is unavailable but honeypot.is answered (ETH, BSC, Base).
  function scoreHoneypotOnly(d, add, red) {
    var hp = d.hp, sim = hp.simulationResult || {};
    if (hp.honeypotResult && hp.honeypotResult.isHoneypot === true) red('Honeypot detected: buys succeed but sells are blocked (honeypot.is simulation).');
    else if (hp.simulationSuccess) add('good', 'No honeypot detected: honeypot.is simulated a buy and a sell successfully.');
    else if (hp.simulationSuccess === false) add('warn', 'honeypot.is could not simulate a sale.', 10);
    var st = sim.sellTax, bt = sim.buyTax;
    d.taxes = { buy: bt != null ? bt : null, sell: st != null ? st : null };
    if (st != null) {
      if (st > 50) red('Sell tax is ' + pct(st) + ': more than half of the sale value is taxed.');
      else if (st > 10) add('bad', 'High sell tax: ' + pct(st) + '.', 25);
      else if (st > 5) add('warn', 'Sell tax: ' + pct(st) + '.', 10);
    }
    if (bt != null && bt > 10) add('bad', 'High buy tax: ' + pct(bt) + '.', 15);
    var cc = hp.contractCode;
    if (cc && cc.rootOpenSource === false) add('bad', 'Contract source code is not verified.', 20);
    else if (cc && cc.rootOpenSource) add('good', 'Contract source code is verified.');
    if (cc && (cc.isProxy || cc.hasProxyCalls) && !d.proxySlot) d.proxySlot = true;
  }

  function scoreSolanaCreator(d, rc, add, fullRug) {
    var rugHist = (rc.risks || []).some(function (r) { return /creator history of rugged/i.test(r.name || ''); });
    if (rugHist) add('bad', 'This creator\'s wallet has launched tokens that were later rugged.', 40, { cat: 'creator', force: true });
    if (d.rugSummary) return;
    var others = (rc.creatorTokens || []).filter(function (t) { return t && t.mint !== d.addr; });
    var n = others.length;
    if (n >= 10) add('bad', 'The creator has launched ' + n + ' other tokens. Serial launchers often abandon tokens.', 15, { cat: 'creator' });
    else if (n >= 3) add('warn', 'The creator has launched ' + n + ' other tokens. Serial launchers often abandon tokens.', 8, { cat: 'creator' });
    else if (n > 0) add('info', 'The creator has launched ' + n + ' other token' + (n === 1 ? '' : 's') + '.');
    else if (fullRug && rc.creator) add('good', 'No other launches found from the creator\'s wallet.');
    if (n >= 3) {
      var dead = others.filter(function (t) { return Number(t.marketCap || 0) < 5000; }).length;
      if (dead / n >= 0.8) add('bad', 'Most of this creator\'s other tokens are now nearly worthless.', 10, { cat: 'creator' });
    }
    var cp = creatorPctSolana(d, rc);
    if (cp != null) creatorHolding(add, cp);
  }
  function creatorPctSolana(d, rc) {
    if (!rc.creator) return null;
    var th = (rc.topHolders || []).filter(function (x) { return x.owner === rc.creator || x.address === rc.creator; });
    if (th.length) return th.reduce(function (s, x) { return s + (Number(x.pct) || 0); }, 0);
    var sup = rc.token && Number(rc.token.supply);
    if (sup && rc.creatorBalance != null) return 100 * Number(rc.creatorBalance) / sup;
    return null;
  }
  function creatorHolding(add, cp) {
    if (cp > 20) add('bad', 'The creator still holds ' + pct(cp) + ' of the supply and could sell it at any time.', 20, { cat: 'creator' });
    else if (cp > 5) add('warn', 'The creator still holds ' + pct(cp) + ' of the supply and could sell it at any time.', 10, { cat: 'creator' });
    else add('good', 'The creator holds ' + pct(cp) + ' of the supply.', 0, { grp: 'creator' });
  }

  function scoreSolanaClusters(d, rc, add, fresh) {
    var sup = (rc.token && Number(rc.token.supply)) || Number(d.supplyRaw) || 0;
    var small = smallNetworks(rc);
    var large = (rc.insiderNetworks || []).filter(function (n) { return netSize(n) > NET_MAX; });
    var held = small.reduce(function (s, n) { return s + (Number(n.currentHolding) || 0); }, 0);
    var share = sup ? 100 * held / sup : 0;
    var best = null;
    if (share >= 30) best = ['bad', 'Linked wallets control ' + pct(share) + ' of the supply, a strong sign of coordinated dump risk.', 30, true];
    else if (share >= 10) best = ['bad', 'A group of linked wallets holds ' + pct(share) + ' of the supply.', 25];
    else if (share >= 3) best = ['warn', 'A group of linked wallets holds ' + pct(share) + ' of the supply.', 12];
    if (best) add(best[0], best[1], best[2], { cat: 'cluster', force: !!best[3] });
    else if (share > 0) add('info', 'Small linked-wallet groups detected, holding ' + pct(share) + ' of the supply.');
    else if (!large.length) add(fresh ? 'info' : 'good', fresh ? 'Linked-wallet data is not available yet for a token this new.' : 'No linked-wallet groups detected among holders.');
    if (large.length) {   // F1
      var biggest = Math.max.apply(null, large.map(netSize));
      add('info', 'A large transfer network of ' + biggest.toLocaleString('en-US') + ' wallets was found. Networks this large usually include exchanges and pools, so it is not scored.');
    }
    // N2: one wallet that sent funds or tokens to several current holders.
    if (d.graph && sup) {
      var hub = null;
      d.graph.forEach(function (net) {
        var hold = {};
        (net.nodes || []).forEach(function (n) { hold[n.id] = Number(n.holdings) || 0; });
        var out = {};
        (net.links || []).forEach(function (l) {
          if (!l || l.source === l.target || !(hold[l.target] > 0)) return;
          (out[l.source] = out[l.source] || {})[l.target] = 1;
        });
        Object.keys(out).forEach(function (src) {
          var ts = Object.keys(out[src]), amt = ts.reduce(function (s, t) { return s + hold[t]; }, 0);
          if (!hub || ts.length > hub.n || (ts.length === hub.n && amt > hub.amt)) hub = { n: ts.length, amt: amt };
        });
      });
      var hs = hub ? 100 * hub.amt / sup : 0;
      if (hub && hub.n >= 3 && hs < 1)
        add('info', hub.n + ' small holders (together ' + pct(hs) + ' of the supply) were sent funds or tokens by the same wallet. Too small to score.');
      else if (hub && ((hub.n >= 5 && hs >= 3) || (hub.n >= 3 && hs >= 10)))
        add('bad', hub.n + ' wallets holding ' + pct(hs) + ' of the supply were all sent funds or tokens by the same wallet, which suggests one person controls them.', 30, { cat: 'cluster' });
      else if (hub && hub.n >= 3)
        add('warn', hub.n + ' wallets holding ' + pct(hs) + ' of the supply were all sent funds or tokens by the same wallet, which suggests one person controls them.', 20, { cat: 'cluster' });
      else add('info', 'No shared funding wallet found among the linked holders.');
    }
    if (rc.deployPlatform && AUTO_LAUNCHERS.test(rc.deployPlatform))
      add('warn', 'Launched with an automated launch tool often used for bundled launches.', 10, { cat: 'cluster' });
  }

  // Main pool, its share of liquidity, LP lock status and soonest unlock.
  function poolInfo(d, pairs, totalLiq, rc, now) {
    var main = pairs[0];
    if (!main) return null;
    var p = { dex: dexName(main), pair: main.pairAddress, liq: liqOf(main), share: totalLiq ? liqOf(main) / totalLiq : 1, kind: 'unknown', lockPct: null, unlockAt: null };
    p.quote = quoteOf(main, d.addr);
    var labels = (main.labels || []).join(' ');
    var concentrated = /\b(v3|v4|clmm|dlmm|wp|dyn2)\b/i.test(labels);
    if (!totalLiq) { p.kind = 'curve'; return p; }
    if (d.engine === 'solana') {
      var mk = rc && (rc.markets || []);
      var mm = mk && (mk.filter(function (x) { return x.pubkey === main.pairAddress; })[0] ||
        mk.slice().sort(function (a, b) { return ((b.lp && (b.lp.quoteUSD + b.lp.baseUSD)) || 0) - ((a.lp && (a.lp.quoteUSD + a.lp.baseUSD)) || 0); })[0]);
      if (mm && /clmm|dlmm|whirlpool|orca|damm_v2/i.test(mm.marketType || '')) concentrated = true;
      var lk = mm && mm.lp && mm.lp.lpLockedPct;
      if (mm && lk != null && (!concentrated || lk > 0)) { p.kind = 'lp'; p.lockPct = Number(lk); }
      else if (concentrated) p.kind = 'concentrated';
      if (rc && rc.lockers) {
        Object.keys(rc.lockers).forEach(function (k) {
          var L = rc.lockers[k], t = Number(L.unlockDate) * 1000;
          if (L.type && !LP_LOCKER.test(L.type)) return;   // F4: vesting lockers are not LP locks
          if (t > now && Number(L.usdcLocked || 0) >= 0.1 * (p.liq || 0) && (!p.unlockAt || t < p.unlockAt)) p.unlockAt = t;
        });
      }
    } else if (d.engine === 'goplus' && d.gp) {
      var gd = (d.gp.dex || []).filter(function (x) { return String(x.pair || '').toLowerCase() === String(main.pairAddress || '').toLowerCase(); })[0];
      if (gd && /v3|v4|cl/i.test(gd.liquidity_type || '')) concentrated = true;
      var lps = d.gp.lp_holders || [];
      if (concentrated) p.kind = 'concentrated';
      else if (lps.length) {
        p.kind = 'lp';
        p.lockPct = lps.reduce(function (s, x) { return s + (lpLocked(x, d) ? Number(x.percent || 0) : 0); }, 0) * 100;
        lps.forEach(function (x) {
          if (Number(x.is_locked) !== 1 || Number(x.percent || 0) < 0.1) return;
          (x.locked_detail || []).forEach(function (ld) {
            var t = Date.parse(ld.end_time);
            if (isFinite(t) && t > now && (!p.unlockAt || t < p.unlockAt)) p.unlockAt = t;
          });
        });
      }
    } else if (concentrated) p.kind = 'concentrated';
    return p;
  }
  function lpLocked(x, d) {
    return Number(x.is_locked) === 1 || DEAD.test(x.address) || String(x.address).toLowerCase() === d.addr.toLowerCase() || /burn|dead|lock/i.test(x.tag || '');
  }

  function scoreLiquidity(d, pool, add, now) {
    var lockTxt = pool.kind === 'curve' ? 'bonding curve, no pool yet' : pool.kind === 'lp' ? pct(pool.lockPct) + ' of LP locked or burned'
      : pool.kind === 'concentrated' ? 'lock status not available for this pool type' : 'lock status not available';
    if (pool.kind === 'curve') return;
    add(pool.kind === 'lp' && pool.lockPct >= 90 ? 'good' : 'info', 'Main pool: ' + pool.dex + ', ' + usd(pool.liq) + ' (' + Math.round(pool.share * 100) + '% of all liquidity), ' + lockTxt + '.');
    var g = d.gp, ownerLp = 0, eoaLp = 0;
    if (d.engine === 'solana' && pool.kind === 'lp' && pool.liq >= 1000) {
      if (pool.lockPct < 50) add('bad', 'Most of the liquidity in the main pool can be withdrawn by its owner.', 25, { cat: 'liquidity' });
      else if (pool.lockPct < 90) add('warn', 'Only ' + pct(pool.lockPct) + ' of the main pool\'s liquidity is locked.', 10, { cat: 'liquidity' });
    }
    if (d.engine === 'goplus' && g && pool.kind === 'lp') {
      var who = [g.creator_address, g.owner_address].filter(Boolean).map(function (a) { return String(a).toLowerCase(); });
      (g.lp_holders || []).forEach(function (x) {
        if (lpLocked(x, d)) return;
        var share = Number(x.percent || 0) * 100;
        if (who.indexOf(String(x.address).toLowerCase()) >= 0) ownerLp += share;
        else if (String(x.is_contract) === '0') eoaLp += share;   // N5
      });
      if (ownerLp >= 50) add('bad', 'The creator controls ' + pct(ownerLp) + ' of the liquidity and can remove it.', 25, { cat: 'liquidity' });
      else if (eoaLp >= 50) add('bad', 'Most of the pool\'s LP tokens (' + pct(eoaLp) + ') sit in an ordinary wallet that can withdraw them at any time.', 20, { cat: 'liquidity' });
      else if (pool.lockPct >= 90) add('good', pct(pool.lockPct) + ' of LP tokens are locked or burned.');
      else if ((d.pairs || []).reduce(function (s, p) { return s + liqOf(p); }, 0) < 500000) add('warn', 'Only ' + pct(pool.lockPct) + ' of LP tokens are locked or burned: liquidity could be withdrawn.', 15, { cat: 'liquidity' });
      else add('info', pct(pool.lockPct) + ' of LP tokens are locked or burned.');
    }
    if (pool.unlockAt) {
      var days = (pool.unlockAt - now) / 864e5, dd = Math.max(1, Math.ceil(days));
      var t = 'The liquidity lock ends in ' + dd + ' day' + (dd === 1 ? '' : 's') + ' (' + dateStr(pool.unlockAt) + '). After that it can be withdrawn.';
      if (days < 7) add('bad', t, 20, { cat: 'liquidity' });
      else if (days < 30) add('warn', t, 10, { cat: 'liquidity' });
      else add('info', 'Liquidity lock ends ' + dateStr(pool.unlockAt) + '.');
    }
    if (pool.share > 0.8 && pool.quote && !MAJORS.test(String(pool.quote).trim()))
      add('warn', 'Most liquidity is paired with ' + String(pool.quote).trim() + ', a less common token; its value moves with that token.', 10, { cat: 'liquidity' });
    else if (pool.quote && MAJORS.test(String(pool.quote).trim())) add('good', 'Main pool is paired with ' + String(pool.quote).trim() + ', a major token.');
    if (pool.kind === 'concentrated') add('info', 'Liquidity lock can\'t be verified for this pool type.');
    else if (pool.kind === 'unknown' && pool.liq < 100000) add('warn', 'Liquidity lock status could not be verified.', 5, { data: true });
  }

  // N4: token vesting or team locks that end soon (Solana lockers that are not LP; GoPlus locked holders).
  function scoreUnlocks(d, rc, m, add, now) {
    var cands = [], mcap = m.mcap || 0, liq = m.liq || 0;
    if (rc && rc.lockers) Object.keys(rc.lockers).forEach(function (k) {
      var L = rc.lockers[k], t = Number(L.unlockDate) * 1000;
      if (!L.type || LP_LOCKER.test(L.type) || !(t > now)) return;
      var u = Number(L.usdcLocked) || 0;
      cands.push({ t: t, usd: u, pct: mcap ? 100 * u / mcap : null });
    });
    if (d.engine === 'goplus' && d.gp) (d.gp.holders || []).forEach(function (x) {
      if (Number(x.is_locked) !== 1 || DEAD.test(x.address) || /pool|pair|lp\b|burn|dead|null/i.test(x.tag || '')) return;
      var p = Number(x.percent || 0) * 100;
      (x.locked_detail || []).forEach(function (ld) {
        var t = Date.parse(ld.end_time);
        if (isFinite(t) && t > now) cands.push({ t: t, pct: p, usd: mcap ? p / 100 * mcap : null });
      });
    });
    var sig = cands.filter(function (c) { return (c.pct != null && c.pct >= 5) || (c.usd != null && c.usd >= 1000 && c.usd >= 0.1 * liq); })
      .sort(function (a, b) { return a.t - b.t; })[0];
    if (!sig) return;
    var days = (sig.t - now) / 864e5, dd = Math.max(1, Math.ceil(days));
    var what = 'Tokens worth ' + (sig.usd != null ? usd(sig.usd) : 'an unknown amount') + (sig.pct != null ? ' (' + pct(sig.pct) + ' of supply)' : '');
    if (days < 7) add('bad', what + ' unlock on ' + dateStr(sig.t) + ' (in ' + dd + ' day' + (dd === 1 ? '' : 's') + ') and could then be sold.', 15, { cat: 'liquidity' });
    else if (days < 30) add('warn', what + ' unlock on ' + dateStr(sig.t) + ' (in ' + dd + ' days) and could then be sold.', 8, { cat: 'liquidity' });
    else add('info', what + ' are locked until ' + dateStr(sig.t) + '.');
  }

  // GoPlus EVM / Tron contract checks (+ honeypot.is second opinion)
  function scoreGoPlus(d, add, red, pairs, ageH) {
    var g = d.gp, hp = d.hp;
    var owner = (g.owner_address || '').trim();
    var ownerState = !('owner_address' in g) ? 'unknown' : (!owner || DEAD.test(owner) || /^T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb$/.test(owner)) ? 'renounced' : 'active';
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

    if (trusted) add('good', 'GoPlus lists this as a trusted token.');
    if (g.is_in_cex && flag(g.is_in_cex.listed)) add('good', 'Listed on centralized exchanges' + (g.is_in_cex.cex_list && g.is_in_cex.cex_list.length ? ' (' + g.is_in_cex.cex_list.slice(0, 4).join(', ') + ')' : '') + '.');
    // N8: copy of another token, or an airdrop scam (only some tokens carry these fields).
    if ((g.fake_token && flag(g.fake_token.value)) || flag(g.is_airdrop_scam))
      red(flag(g.is_airdrop_scam) ? 'GoPlus flags this as an airdrop scam token.' : 'GoPlus flags this as a copy of another token.');
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
    var tt = g.transfer_tax !== '' && g.transfer_tax != null ? Number(g.transfer_tax) * 100 : null;
    if (tt != null && tt > 10) add('warn', 'Wallet-to-wallet transfers are taxed ' + pct(tt) + '.', 10);

    if (ownerState === 'renounced') add('good', 'Ownership renounced: contract settings cannot be changed.');
    else if (ownerState === 'active') add('info', 'Contract has an active owner (' + owner.slice(0, 6) + '…' + owner.slice(-4) + ').');

    if (flag(g.owner_change_balance)) add('bad', 'Owner can modify wallet balances.', 40, { force: ownerState !== 'renounced' });
    if (flag(g.hidden_owner)) add('bad', 'Hidden owner detected with control over the contract.', 25);
    if (flag(g.can_take_back_ownership)) add('bad', 'Ownership can be reclaimed after being renounced.', 25);

    // D3/D4: proxy and source code
    var cc = hp && hp.contractCode;
    var isProxy = flag(g.is_proxy) || !!(cc && (cc.isProxy || cc.hasProxyCalls));
    var hidden = g.is_open_source === '0' || !!(cc && cc.rootOpenSource === false);
    if (isProxy && hidden) add('bad', 'The contract code is hidden and can be swapped at any time.', 30, { force: true });
    else {
      if (hidden) add('bad', 'Contract source code is not verified.', 20);
      else if (flag(g.is_open_source)) add('good', 'Contract source code is verified.');
      if (isProxy) {
        if (ownerState === 'active') add('bad', 'The owner can change how this contract works at any time (upgradeable proxy).', 20);
        else add('warn', 'Proxy (upgradeable) contract: its logic can be changed later.', 10);
      }
    }
    if (flag(g.selfdestruct)) {
      if (ownerState === 'active') add('bad', 'The owner can delete the contract (self-destruct).', 25);
      else add('bad', 'Contract includes a self-destruct function.', 15);
    }
    if (flag(g.external_call)) add('warn', 'The contract calls other contracts during transfers, which can hide extra rules.', 10);
    // D1: hidden mint
    if (flag(g.is_mintable) && (flag(g.hidden_owner) || flag(g.can_take_back_ownership)) && !trusted)
      add('bad', 'Supply can still be increased through a hidden or reclaimable owner.', 35);
    else ownerPower(g.is_mintable, 'Owner can mint new tokens', 35);
    ownerPower(g.is_blacklisted, 'Blacklist function can block wallets from selling', 15);
    ownerPower(g.transfer_pausable, 'Trading can be paused', 15);
    ownerPower(g.slippage_modifiable, 'Taxes can be changed by the owner', 15);
    ownerPower(g.personal_slippage_modifiable, 'Taxes can be set per wallet', 15);
    ownerPower(g.anti_whale_modifiable, 'Owner can change the max wallet or transaction limit, which can block selling', 10);
    if (flag(g.trading_cooldown)) add('info', 'Trading cooldown between transactions is enabled.');
    if (flag(g.is_whitelisted)) add('info', 'Some wallets are exempt from the contract\'s rules (whitelist).');

    // A. creator history (EVM)
    var sameCreator = flag(g.honeypot_with_same_creator);
    if (sameCreator) add('bad', 'The creator is linked to previous honeypot contracts.', 40, { cat: 'creator', force: true });
    var cs = d.creatorSec;
    if (cs) {
      // F3: strong flags force High risk; weaker ones (honeypot-related, malicious-contract count) add points only.
      var strong = STRONG_CREATOR.filter(function (k) { return flag(cs[k]); });
      var nMal = Number(cs.number_of_malicious_contracts_created) || 0;
      var weak = nMal > 0 || flag(cs.honeypot_related_address);
      if (strong.length) add('bad', 'The creator\'s wallet is linked to scams, theft or sanctioned activity.', 40, { cat: 'creator', force: true });
      else if (weak && !sameCreator) add('bad', 'GoPlus links the creator\'s wallet to ' + (nMal > 0 ? nMal + ' contract' + (nMal === 1 ? '' : 's') + ' it flags as malicious.' : 'honeypot contracts.'),
        ageH != null && ageH < 720 ? 30 : 20, { cat: 'creator' });
      else if (!sameCreator) add('good', 'No scam or honeypot links found for the creator\'s wallet.', 0, { grp: 'creator' });
    }
    var skip = {};
    (pairs || []).forEach(function (p) { skip[String(p.pairAddress).toLowerCase()] = 1; });
    skip[d.addr.toLowerCase()] = 1;
    var cp = 0;
    [['creator_address', 'creator_percent'], ['owner_address', 'owner_percent']].forEach(function (k) {
      var a = String(g[k[0]] || '').toLowerCase();
      if (!a || DEAD.test(a) || skip[a]) return;
      var v = Number(g[k[1]] || 0) * 100;
      if (v > cp) cp = v;
    });
    if (cp && !trusted) creatorHolding(add, cp);
  }

  // ---------- data confidence ----------
  // Each area is Checked (full credit), Partly checked (half), Not available (none) or Not applicable (left out).
  var AREAS = [
    ['contract', 3, 'contract permissions'], ['market', 2, 'trading market data'], ['holders', 2, 'holder breakdown'],
    ['lock', 2, 'liquidity lock'], ['creator', 1, 'creator history'], ['cluster', 1, 'linked-wallet check']
  ];
  var STATE_TEXT = { checked: 'Checked', partial: 'Partly checked', missing: 'Not available', na: 'Not applicable' };
  function confidence(d, c) {
    var st = {}, why = {};
    var evm = d.engine === 'goplus', sol = d.engine === 'solana';
    var rateLimited = function (k) { return /429|rate/i.test(String(d.errors[k] || '')); };
    // contract
    if (sol) { st.contract = d.authoritiesKnown ? 1 : 0; if (!d.authoritiesKnown) why.contract = 'the Solana RPC and RugCheck did not answer'; }
    else if ((evm || d.engine === 'goplus-sui') && d.gp) st.contract = 1;
    else if (d.hp || d.rpcOwner || d.proxySlot != null) { st.contract = 0.5; why.contract = 'GoPlus had no data' + (rateLimited('goplus') ? ' (rate-limited)' : '') + ', so only basic contract reads were made'; }
    else { st.contract = 0; why.contract = d.engine === 'market' ? 'no free contract scanner covers ' + chainName(d.chain) : 'GoPlus had no data for this token' + (rateLimited('goplus') ? ' (rate-limited)' : ''); }
    // market
    st.market = d.errors.dexscreener && !c.pairs.length ? 0 : 1;
    if (!st.market) why.market = 'DexScreener did not answer';
    // holders
    st.holders = c.holders ? (c.holders.ownersKnown ? 1 : 0.5) : 0;
    if (!c.holders) why.holders = c.limited ? 'no holder source covers this chain' : 'holder lookups failed';
    else if (!c.holders.ownersKnown) why.holders = 'pool wallets could not be separated from holders';
    // liquidity lock
    if (!c.pool) { st.lock = c.pairs.length || d.errors.dexscreener ? 0 : 'na'; if (st.lock === 'na') why.lock = 'no trading pool'; }
    else if (c.pool.kind === 'curve') { st.lock = 'na'; why.lock = 'still on a bonding curve, so there is no pool to lock'; }
    else if (c.pool.kind === 'lp') st.lock = 1;
    else if (c.pool.kind === 'concentrated') { st.lock = 0.5; why.lock = 'lock data does not exist for this pool type'; }
    else { st.lock = 0; why.lock = 'no lock data for this pool'; }
    // creator and linked wallets
    st.creator = sol ? (c.fullRug ? 1 : 0) : evm && d.gp ? (d.creatorSec ? 1 : 0.5) : 0;
    st.cluster = sol ? (c.fullRug ? 1 : 0) : evm && d.gp ? 0.5 : 0;
    if (sol && !c.fullRug) why.creator = why.cluster = d.rugSummary ? 'RugCheck only returned a summary (rate-limited)' : 'RugCheck did not answer';
    if (evm && d.gp && !d.creatorSec) why.creator = 'the creator wallet lookup did not answer';
    if (evm && d.gp) why.cluster = 'wallet-link data is only available for Solana tokens';
    if (!sol && !(evm && d.gp)) { why.creator = why.creator || 'no creator data source covers this token'; why.cluster = why.cluster || 'no wallet-link data source covers this token'; }
    if (c.fresh) ['creator', 'cluster'].forEach(function (k) {   // F5
      if (st[k] > 0.5) { st[k] = 0.5; why[k] = 'the token is under 1 hour old, so this data may not have caught up yet'; }
    });
    var credit = 0, total = 0, missing = [], partial = [], areas = [];
    AREAS.forEach(function (a) {
      var v = st[a[0]], state = v === 'na' ? 'na' : v >= 1 ? 'checked' : v > 0 ? 'partial' : 'missing';
      if (v !== 'na') { total += a[1]; credit += a[1] * v; }
      if (state === 'missing') missing.push(a[2]); else if (state === 'partial') partial.push(a[2]);
      areas.push({ key: a[0], label: cap1(a[2]), state: state, stateText: STATE_TEXT[state], why: why[a[0]] || '' });
    });
    var p = total ? Math.round(100 * credit / total) : 0;
    var level = p >= 85 ? 'High' : p >= 60 ? 'Medium' : 'Low';
    if (c.fresh && level === 'High') level = 'Medium';
    var errs = Object.keys(d.errors).map(function (k) { return String(d.errors[k]); });
    return { level: level, pct: p, missing: missing, partial: partial, areas: areas, fresh: !!c.fresh,
      retry: !!c.fresh || errs.some(function (e) { return /429|rate|timeout|abort|HTTP 5|fetch|network/i.test(e); }),
      text: confidenceText(level, missing, partial, c.fresh) };
  }
  function cap1(s) { return s.charAt(0).toUpperCase() + s.slice(1); }
  function joinList(a) { return a.length < 2 ? a.join('') : a.slice(0, -1).join(', ') + ' and ' + a[a.length - 1]; }
  function confidenceText(level, missing, partial, fresh) {
    var t = 'Data confidence: ' + level + '.';
    if (fresh) t += ' Very new token: some checks may not have caught up yet.';
    if (missing.length) t += ' ' + cap1(joinList(missing)) + ' could not be checked.';
    if (partial.length) t += ' Partly checked: ' + joinList(partial) + '.';
    return t;
  }

  var TITLES = {
    green: ['Low risk', 'Few risk signals found. This is not a guarantee.'],
    yellow: ['Caution', 'Some risk signals found. Review the findings below before you buy.'],
    red: ['High risk', 'Significant risk signals found.']
  };
  function title(s) {
    if (s.lowData) return ['Caution: not enough data', 'Too little data could be checked to call this Low risk.'];
    if (s.verdict === 'red' && s.forced && s.points < HIGH_MIN) return ['High risk', 'A critical finding forces this rating, whatever the point total.'];
    return TITLES[s.verdict] || ['Unknown', ''];
  }

  var API = {
    VERSION: VERSION, RPCS: RPCS, EVM_RPCS: EVM_RPCS, GOPLUS_IDS: GOPLUS_IDS, HONEYPOT_IDS: HONEYPOT_IDS, CHAINS: CHAINS, CAPS: CAPS, GROUPS: GROUPS,
    LOW_MAX: LOW_MAX, HIGH_MIN: HIGH_MIN,
    chainName: chainName, configure: configure, resetNet: resetNet, getJSON: getJSON,
    detect: detect, extract: extract, gather: gather, score: score, title: title,
    usd: usd, ago: ago, pct: pct, flag: flag, liqOf: liqOf
  };
  root.BluntXCore = API;
  if (typeof module !== 'undefined' && module.exports) module.exports = API;
})(typeof self !== 'undefined' ? self : typeof window !== 'undefined' ? window : globalThis);
