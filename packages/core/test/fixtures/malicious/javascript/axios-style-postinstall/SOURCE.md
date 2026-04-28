# axios-style postinstall

Defanged reproduction of the install-script vector used in:

- axios npm package compromise (April 2026): https://www.trendmicro.com/en_us/research/26/c/axios-npm-package-compromised.html, https://www.microsoft.com/en-us/security/blog/2026/04/01/mitigating-the-axios-npm-supply-chain-compromise/
- chalk/debug compromise (September 2025)

The real attacks placed the actual loader in `scripts/setup.js`. We only
reproduce the package.json hook here — the loader itself is covered by
`malicious/javascript/eval-fetch/`.

This fixture must NOT be renamed to look like an `input.js` because the
detector keys off the file *path* `package.json`.
