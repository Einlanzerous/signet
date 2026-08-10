# Changelog

## [1.6.0](https://github.com/Einlanzerous/signet/compare/v1.5.1...v1.6.0) (2026-08-10)


### Features

* **derive:** compose a secret's value from other secrets (SGNT-18) ([#23](https://github.com/Einlanzerous/signet/issues/23)) ([70afeae](https://github.com/Einlanzerous/signet/commit/70afeae685a87dc6b7a7839ca3487122e3e3a4ff))

## [1.5.1](https://github.com/Einlanzerous/signet/compare/v1.5.0...v1.5.1) (2026-08-09)


### Bug Fixes

* **serve:** say which signal stopped the daemon, and that it stopped (SGNT-19) ([#21](https://github.com/Einlanzerous/signet/issues/21)) ([3fc341f](https://github.com/Einlanzerous/signet/commit/3fc341fc268d01e28d3a7e4723f5f7be6cae7d09))

## [1.5.0](https://github.com/Einlanzerous/signet/compare/v1.4.1...v1.5.0) (2026-08-04)


### Features

* **sync:** preflight the PAT's repo grant (SGNT-10) ([#18](https://github.com/Einlanzerous/signet/issues/18)) ([6e33f81](https://github.com/Einlanzerous/signet/commit/6e33f8128ea4f87a27f1ebad5163b3fa9b8a7402))


### Bug Fixes

* **sync:** name every credential lookup path when none resolves (SGNT-9) ([#20](https://github.com/Einlanzerous/signet/issues/20)) ([508e1b9](https://github.com/Einlanzerous/signet/commit/508e1b9d504b878e997514fc422d7a4b6eb9cbd8))

## [1.4.1](https://github.com/Einlanzerous/signet/compare/v1.4.0...v1.4.1) (2026-08-02)


### Bug Fixes

* **api:** serve every address in SIGNET_ADDR (SGNT-17) ([#16](https://github.com/Einlanzerous/signet/issues/16)) ([a5818d9](https://github.com/Einlanzerous/signet/commit/a5818d93f2c48820a58574810dcfa10a83a75b8f))

## [1.4.0](https://github.com/Einlanzerous/signet/compare/v1.3.0...v1.4.0) (2026-08-02)


### Features

* **sync:** fall back to the vault's SIGNET_PAT (SGNT-16) ([#15](https://github.com/Einlanzerous/signet/issues/15)) ([0d2eae1](https://github.com/Einlanzerous/signet/commit/0d2eae124b84b5c43de80bc06d37850fc34e12ee))


### Bug Fixes

* **render:** merge into env files instead of rewriting them (SGNT-15) ([#13](https://github.com/Einlanzerous/signet/issues/13)) ([e8c212d](https://github.com/Einlanzerous/signet/commit/e8c212db737b93a83850b62f94472918a810ce44))

## [1.3.0](https://github.com/Einlanzerous/signet/compare/v1.2.0...v1.3.0) (2026-08-01)


### Features

* **release:** dispatch to construct-server on release (SGNT-12) ([8cf201d](https://github.com/Einlanzerous/signet/commit/8cf201da1ce62aea4d8e45d302be794c081a67d9))
* **target:** add target list and target rm (SGNT-11) ([4d1d42b](https://github.com/Einlanzerous/signet/commit/4d1d42b6c6b8f3ccd60a467c2ff26bd2a93f19c0))


### Bug Fixes

* **store:** make mutation and audit append atomic (SGNT-14) ([#12](https://github.com/Einlanzerous/signet/issues/12)) ([e66319e](https://github.com/Einlanzerous/signet/commit/e66319e90998fd1f5bcc55bdeeaa9703f79e92ec))

## [1.2.0](https://github.com/Einlanzerous/signet/compare/v1.1.0...v1.2.0) (2026-07-31)


### Features

* **audit:** structured ledger — typed event kinds, actor roles, status (SGNT-13) ([ac1e6a5](https://github.com/Einlanzerous/signet/commit/ac1e6a56a638fab104e1b1b3a3a598935a2b69cb))


### Bug Fixes

* **audit:** close chain-fork race, role forgery, and status encoding gaps ([39b2ec0](https://github.com/Einlanzerous/signet/commit/39b2ec08b2219a16ed7f4bbff5d81c188213f11f))

## [1.1.0](https://github.com/Einlanzerous/signet/compare/v1.0.0...v1.1.0) (2026-07-24)


### Features

* **config:** accept SIGNET_PAT as fallback for SIGNET_GITHUB_TOKEN (SGNT-5) ([3080a13](https://github.com/Einlanzerous/signet/commit/3080a136765f60ccecf04262b38024892603c17d))

## 1.0.0 (2026-07-23)


### Features

* **api:** add add-target and set-expiry command endpoints (SGNT-3) ([c72c0d2](https://github.com/Einlanzerous/signet/commit/c72c0d26641014a744bc4d72891d784f37476f16))
* initial Signet scaffold — vault, env registry, GitHub Actions sync (IDEA-13) ([a07f216](https://github.com/Einlanzerous/signet/commit/a07f2167f59dfe25bb4bc69ae6cebe0a51a52850))


### Bug Fixes

* **envfile:** parse multi-line quoted and PEM values on import ([bad3dcc](https://github.com/Einlanzerous/signet/commit/bad3dccb7060a85dbc9156540ec8ec2916e60039))
