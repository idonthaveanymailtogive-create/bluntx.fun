# BluntX — Token risk checker for any chain

Source for https://bluntx.fun. Static site, no build step, hosted on GitHub Pages.

- Paste a contract or mint address (or a DexScreener / pump.fun link) and get a **Low risk**, **Caution** or **High risk** rating, a points-based risk score and plain-English findings.
- No wallet connection, no account, no data stored. Every check runs in the browser against free public APIs (DexScreener, GoPlus, honeypot.is, Solana RPC, RugCheck).
- Installable as a web app (`manifest.webmanifest`, `sw.js`); the service worker caches only the site's own files.
- Browser extension (beta): `bluntx-extension.zip`, Chrome load-unpacked. Rates coins on pump.fun with the same labels and points model.
- Whitepaper: `whitepaper.html` / `whitepaper.pdf`.

Run locally: `python3 -m http.server 8765`, then open http://localhost:8765
Deep link: `https://bluntx.fun/#<address>` or `#<chain>:<address>` (e.g. `#base:0x…`).

X: [@BluntXfun](https://x.com/BluntXfun)
