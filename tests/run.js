/* Score saved gather() fixtures and check the rating band.
   Live inputs live in tests/fixtures/*.json (see tests/gather.js). This file does not call the network
   except for nothing: the chain-probe case uses a fake fetch.
   Run: node tests/run.js
*/
'use strict';
const fs = require('fs');
const path = require('path');
const core = require('../core.js');

const tokens = JSON.parse(fs.readFileSync(path.join(__dirname, 'tokens.json'), 'utf8'));
const dir = path.join(__dirname, 'fixtures');

function bandOf(s) {
  if (!s || s.verdict === 'error') return 'error';
  if (s.verdict === 'green') return 'Low';
  if (s.verdict === 'yellow') return 'Caution';
  if (s.verdict === 'red') return 'High';
  return s.verdict;
}
function okBand(expect, got) {
  if (expect === 'Caution+') return got === 'Caution' || got === 'High';
  return got === expect;
}

let failed = 0;
function check(name, cond, detail) {
  if (cond) { console.log('  ok  ' + name); return; }
  failed++;
  console.log('  FAIL ' + name + (detail ? ' — ' + detail : ''));
}

console.log('core ' + core.VERSION);
console.log('— saved fixtures —');
tokens.forEach(function (t) {
  const file = path.join(dir, t.id + '.json');
  if (!fs.existsSync(file)) { check(t.name, false, 'missing fixture ' + file); return; }
  const fx = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (!fx.data || fx.data.coreVersion !== '4.0.0') { check(t.name, false, 'fixture was not gathered by core 4.0.0'); return; }
  const s = core.score(fx.data, fx.gatheredAt);
  const got = bandOf(s);
  const POINTS = { bonk: 5, jup: 10, wif: 10, usdc: 5, ray: 10, fartcoin: 5, pepe: 5, brett: 5, anusha: 28, rizzmass3: 138, bip: 58, hawk: 95, squid: 145, notsafemoon: 78 };
  check(t.name + ' ' + got + ' ' + s.points + (s.forced ? ' forced' : ''), okBand(t.band, got), 'expected ' + t.band);
  check(t.name + ' score unchanged', s.points === POINTS[t.id], 'got ' + s.points);
  var allFindings = (s.reasons || []).concat((s.groups || []).reduce(function (a, g) { return a.concat(g.reasons || []); }, []));
  if (s.verdict === 'red' || s.verdict === 'yellow') {
    var goods = allFindings.filter(function (r) { return r.level === 'good'; });
    check(t.name + ' has no green findings', !goods.length, goods.map(function (r) { return r.level + ': ' + r.text; }).slice(0, 2).join(' | '));
  }
  if (s.verdict === 'red') {
    var bare = (s.reasons || []).filter(function (r) {
      return (/^No honeypot detected\b|^Low taxes:/.test(r.text) || /of LP (tokens )?(are )?locked or burned\.?$/.test(r.text)) && !/does not make (it|the token) safe/i.test(r.text);
    });
    check(t.name + ' positive lines do not read as safety', !bare.length, bare.map(function (r) { return r.text; }).join(' | '));
  }
  if (s.verdict === 'green' && t.id !== 'usdc') check(t.name + ' keeps a green finding on Low', (s.reasons || []).some(function (r) { return r.level === 'good'; }));
  const text = (s.reasons || []).map(function (r) { return r.text; }).join('\n');
  if (t.id === 'hawk' || t.id === 'squid') check(t.name + ' names the incident', /Known incident:/.test(text));
  if (t.id === 'usdc') check('USDC is not a forced High', s.verdict === 'green' && !s.forced);
  if (t.id === 'notsafemoon') check('NotSafeMoon says ownership can be reclaimed', /can be reclaimed/i.test(text) && !/so it cannot be used/.test(text));
  if (t.id === 'hawk') check('HAWK does not show Jupiter as a pass', !(s.reasons || []).some(function (r) { return r.jup && r.level === 'good'; }));
});

console.log('— chain probe (fake fetch, not live data) —');
(async function () {
  const nsm = '0x337e35ed5b38d5c7ec9f8d7cf78fe7f43d7dec6f';
  const calls = [];
  function json(obj, status) {
    status = status || 200;
    return { ok: status >= 200 && status < 300, status: status, json: async function () { return obj; } };
  }
  core.resetNet();
  core.configure({
    search: false,
    gaps: { 'api.gopluslabs.io': 0, 'api.dexscreener.com': 0, 'api.honeypot.is': 0, 'api.rugcheck.xyz': 0 },
    fetch: async function (url) {
      const u = String(url);
      calls.push(u);
      if (u.indexOf('/latest/dex/tokens/') >= 0) return json({ pairs: null });
      if (u.indexOf('token-pairs/v1/') >= 0) return json([]);
      if (u.indexOf('/token_security/1') >= 0) return json({ code: 1, message: 'OK', result: {} });
      if (u.indexOf('/token_security/56') >= 0) return json({ code: 1, message: 'OK', result: { [nsm]: {
        token_name: 'NotSafeMoon', token_symbol: 'NOTSAFEMOON', total_supply: '1',
        buy_tax: '0.08', sell_tax: '0.08', is_open_source: '1', is_honeypot: '0',
        can_take_back_ownership: '1', owner_address: '0x0000000000000000000000000000000000000000',
        dex: [{ liquidity: '17700', pair: '0x357f9cd8f2749a31119c3e32729965ca56f4cbd8', name: 'PancakeV2' }]
      } } });
      if (u.indexOf('/token_security/8453') >= 0) return json({ code: 1, message: 'OK', result: {} });
      if (u.indexOf('honeypot.is') >= 0) return json({ simulationSuccess: true, honeypotResult: { isHoneypot: false } });
      return json({ code: 0, message: 'unexpected ' + u }, 404);
    }
  });
  try {
    const d = await core.gather(nsm, 'auto', { rpcMode: 'always' });
    check('no-pairs 0x scans BSC and Base, not Ethereum only', d.chain === 'bsc'
      && calls.some(function (u) { return u.indexOf('/token_security/56') >= 0 || u.indexOf('token-pairs/v1/bsc/') >= 0; })
      && calls.some(function (u) { return u.indexOf('/token_security/8453') >= 0 || u.indexOf('token-pairs/v1/base/') >= 0; }),
      'chain=' + d.chain);
    check('matched chain is not labelled a guess', d.chain === 'bsc' && !d.chainGuessed);
  } catch (e) {
    check('chain probe ran', false, e && e.message);
  }
  core.configure({
    fetch: null, search: true,
    gaps: { 'api.gopluslabs.io': 2100, 'api.rugcheck.xyz': 1100, 'api.honeypot.is': 400, 'api.dexscreener.com': 250 }
  });
  core.resetNet();

  console.log('— reclaimable owner (synthetic contract, not a live token) —');
  const addr = '0x' + 'ab'.repeat(20);
  const now = Date.now();
  const synthetic = {
    addr: addr, chain: 'bsc', engine: 'goplus', kind: 'evm', sources: {}, errors: {},
    pairs: [{
      chainId: 'bsc', dexId: 'pancakeswap', pairAddress: '0x' + '11'.repeat(20), labels: [],
      baseToken: { address: addr, symbol: 'TEST', name: 'Test' },
      quoteToken: { address: '0x' + '22'.repeat(20), symbol: 'WBNB', name: 'WBNB' },
      liquidity: { usd: 20000 }, fdv: 100000, marketCap: 100000, priceUsd: '1',
      pairCreatedAt: now - 10 * 864e5, volume: { h24: 5000 },
      txns: { h24: { buys: 30, sells: 10 }, h1: { buys: 2, sells: 1 } }, priceChange: { h1: 0, h6: 0 }
    }],
    gp: {
      token_name: 'Test', token_symbol: 'TEST', is_open_source: '1', is_honeypot: '0',
      owner_address: '0x0000000000000000000000000000000000000000', can_take_back_ownership: '1',
      buy_tax: '0', sell_tax: '0', slippage_modifiable: '1', is_mintable: '0', hidden_owner: '0', owner_change_balance: '0'
    }
  };
  const s = core.score(synthetic, now);
  const text = (s.reasons || []).map(function (r) { return r.text; }).join('\n');
  check('reclaimable power is not described as renounced-and-unusable', /ownership can be reclaimed, so this power can come back/.test(text) && !/so it cannot be used/.test(text));

  if (failed) { console.log('\n' + failed + ' failed'); process.exit(1); }
  console.log('\nall checks passed');
})();
