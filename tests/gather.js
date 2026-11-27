/* Capture live gather() output for the checker fixtures.
   Uses the same keyless APIs as the site (rpcMode: 'always'). Does not invent data:
   a failed source is stored on the fixture as an error and the file is still written
   only when gather() itself returns. Re-run: node tests/gather.js
*/
'use strict';
const fs = require('fs');
const path = require('path');
const core = require('../core.js');

const tokens = JSON.parse(fs.readFileSync(path.join(__dirname, 'tokens.json'), 'utf8'));
const outDir = path.join(__dirname, 'fixtures');
fs.mkdirSync(outDir, { recursive: true });

// RugCheck market entries include full token-account objects the scorer never reads.
// Keep the fields score() uses so a fixture stays small and still reproduces the rating.
function slimMarkets(data) {
  var mk = data && data.rug && data.rug.markets;
  if (!Array.isArray(mk)) return;
  data.rug.markets = mk.map(function (m) {
    if (!m || typeof m !== 'object') return m;
    var out = { pubkey: m.pubkey, marketType: m.marketType };
    if (m.lp) out.lp = { quoteUSD: m.lp.quoteUSD, baseUSD: m.lp.baseUSD, lpLockedPct: m.lp.lpLockedPct, lpLockedUSD: m.lp.lpLockedUSD };
    if (typeof m.liquidityAAccount === 'string') out.liquidityAAccount = m.liquidityAAccount;
    if (typeof m.liquidityBAccount === 'string') out.liquidityBAccount = m.liquidityBAccount;
    return out;
  });
}

function failed(errors) {
  return Object.keys(errors || {}).filter(function (k) { return /timeout|abort|429|400|HTTP 5|fetch|network|unavailable/i.test(String(errors[k])); });
}

async function one(t) {
  core.resetNet();
  let data = await core.gather(t.addr, 'auto', { rpcMode: 'always' });
  if (failed(data.errors).length) {
    core.resetNet();
    data = await core.gather(t.addr, 'auto', { rpcMode: 'always' });
  }
  slimMarkets(data);
  const gatheredAt = Date.now();
  const fx = {
    id: t.id, name: t.name, addr: t.addr, band: t.band,
    gatheredAt: gatheredAt, coreVersion: data.coreVersion,
    chain: data.chain, chainGuessed: !!data.chainGuessed, engine: data.engine,
    sources: data.sources, errors: data.errors, data: data
  };
  fs.writeFileSync(path.join(outDir, t.id + '.json'), JSON.stringify(fx));
  const s = core.score(data, gatheredAt);
  const sym = (data.pairs && data.pairs[0] && data.pairs[0].baseToken && data.pairs[0].baseToken.symbol)
    || (data.gp && (data.gp.token_symbol || data.gp.symbol))
    || (data.rug && data.rug.tokenMeta && data.rug.tokenMeta.symbol) || '';
  console.log([t.name, 'chain=' + data.chain, 'engine=' + data.engine, 'pairs=' + ((data.pairs || []).length),
    'sym=' + sym, 'score=' + s.points, s.verdict, s.forced ? 'forced' : '',
    'err=' + JSON.stringify(data.errors || {})].join(' | '));
}

(async function () {
  for (const t of tokens) {
    try { await one(t); }
    catch (e) { console.log(t.name + ' GATHER FAILED: ' + (e && e.message)); process.exitCode = 1; }
  }
})();
