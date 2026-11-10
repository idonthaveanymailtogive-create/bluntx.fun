# Security

BluntX (https://bluntx.fun) is a static, client-side token risk checker with an optional browser extension.

## What BluntX will never do

- Ask you to connect a wallet, sign a transaction, or share a seed phrase or private key.
- Ask for an account, a password or payment.
- Send your searches to a BluntX server. There is no BluntX server; checks run in your browser against public APIs.

If something claiming to be BluntX asks for any of the above, it is not BluntX.

## How the site is hardened

- Strict Content-Security-Policy: scripts and styles load only from bluntx.fun (no inline code, no `eval`); network requests are limited to the public data APIs the checker uses; `object-src 'none'`, `base-uri 'self'`, `form-action 'none'`.
- No third-party scripts, fonts, analytics, trackers or CDNs. Everything is self-hosted.
- `Referrer-Policy: no-referrer`; external links use `rel="noopener noreferrer"`.
- API data is inserted into the page as text only, never as HTML. Links and images from API data are allowed only for known hosts over HTTPS.
- Address input is length-limited and validated against strict per-chain formats before any request is made.
- Frame-busting script to prevent clickjacking (GitHub Pages cannot send a `frame-ancestors` header).
- The service worker caches only the site's own files and never intercepts API requests.
- HTTPS: enforcement will be switched on as soon as GitHub Pages issues the certificate for bluntx.fun.

## Browser extension

- Manifest V3, no remote code, extension-page CSP `script-src 'self'; object-src 'none'`.
- Permissions: `storage`, `scripting`, `sidePanel` only. Host access is limited to pump.fun, api.dexscreener.com and api.rugcheck.xyz.
- It reads coin links on a pump.fun tab you switch on, and never touches wallets or transactions.

## Reporting a vulnerability

Please report privately by direct message to [@BluntXfun](https://x.com/BluntXfun). Please do not open a public issue for security reports. See also `/.well-known/security.txt`.
