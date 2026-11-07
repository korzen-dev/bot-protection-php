# Changelog

## [2.0.1](https://github.com/korzen-dev/korzen/compare/php/v2.0.0...php/v2.0.1) (2026-11-07)


### Fixes

* **sdks:** Go's lint passes revive's unhandled-error, and Composer runs as the one on PATH ([#2471](https://github.com/korzen-dev/korzen/issues/2471)) ([12409cd](https://github.com/korzen-dev/korzen/commit/12409cdc4c5c5abfe45c7e574d409fd6625fb303))
* **sdks:** xn--zz.com is no email domain in any SDK, the same on every Node ([#2475](https://github.com/korzen-dev/korzen/issues/2475)) ([422d95c](https://github.com/korzen-dev/korzen/commit/422d95c50846874eee6162fceee55aac403a930d))
* **wordpress:** the plugin's zip passes Plugin Check ([#2541](https://github.com/korzen-dev/korzen/issues/2541)) ([02846c1](https://github.com/korzen-dev/korzen/commit/02846c1b69e9ad37715929d66ea1f7fdbe733d6e))

## [2.0.0](https://github.com/korzen-dev/korzen/compare/php/v1.0.0...php/v2.0.0) (2026-11-03)


### ⚠ BREAKING CHANGES

* **sdks:** the removed members leave each SDK's public `Decision` type (Go's `Crawler`, Python's `Crawler`, PHP's `Crawler`, Java's `Decision.Crawler`, .NET's `DecisionCrawler`, Node's `Reason` and `CrawlerKind` types go with them).

### Features

* **sdks:** every SDK reads the decide answer's eight members alone ([#2015](https://github.com/korzen-dev/korzen/issues/2015)) ([0e7dd3e](https://github.com/korzen-dev/korzen/commit/0e7dd3ecba21fd36557ed5dbb9cdfae5bb1221b4)), refs [#1965](https://github.com/korzen-dev/korzen/issues/1965)

## 1.0.0 (2026-11-01)


### ⚠ BREAKING CHANGES

* for a tenant with the decoy on and no onDecoy handler, a decoyed refusal of an action (POST, PUT, PATCH or DELETE) is now answered 202 with {} (application/json) instead of 403. A page load (GET, HEAD) is refused or sent to the challenge as before; a handler that is set still wins; decoy false is a 403; Korzen down lets the request through.

### Features

* **79:** every SDK sends the scheme the request came on, read where the IP is ([#104](https://github.com/korzen-dev/bot-protection-sdks/issues/104)) ([d3959d4](https://github.com/korzen-dev/bot-protection-sdks/commit/d3959d48acf8233c6874906f377401380273be9a)), refs [#79](https://github.com/korzen-dev/bot-protection-sdks/issues/79)
* **conformance:** the runner in Rust, the same 126 cases; WordPress joins the suite ([#74](https://github.com/korzen-dev/bot-protection-sdks/issues/74)) ([28cd277](https://github.com/korzen-dev/bot-protection-sdks/commit/28cd2779200661cb5f8e347f2c2ff39173be180a))
* decide's context in every SDK (korzen-dev/korzen[#716](https://github.com/korzen-dev/bot-protection-sdks/issues/716)) ([#66](https://github.com/korzen-dev/bot-protection-sdks/issues/66)) ([2ab65be](https://github.com/korzen-dev/bot-protection-sdks/commit/2ab65be8e01b5932dc6810dec4be9b3d9e0d3f83))
* every SDK names itself in Korzen-Sdk ([#64](https://github.com/korzen-dev/bot-protection-sdks/issues/64)) ([88803d9](https://github.com/korzen-dev/bot-protection-sdks/commit/88803d936ce1b166cb0006fad5080c661a0f5f92))
* every SDK reads decoy and answers a decoyed refusal with the customer's decoy ([#47](https://github.com/korzen-dev/bot-protection-sdks/issues/47)) ([15846a8](https://github.com/korzen-dev/bot-protection-sdks/commit/15846a8425a1665401a039f71522a5f6bda39f40))
* every SDK reads the JA4, header order and HTTP version a named CDN forwards (korzen [#1400](https://github.com/korzen-dev/bot-protection-sdks/issues/1400)) ([#124](https://github.com/korzen-dev/bot-protection-sdks/issues/124)) ([0dd4888](https://github.com/korzen-dev/bot-protection-sdks/commit/0dd4888e2c42180f1417a9c8f7200b565a590171))
* every SDK reads the token from x-korzen-token before the _kz cookie (korzen-dev/korzen[#795](https://github.com/korzen-dev/bot-protection-sdks/issues/795)) ([#71](https://github.com/korzen-dev/bot-protection-sdks/issues/71)) ([0edabfa](https://github.com/korzen-dev/bot-protection-sdks/commit/0edabfa9b878e28d5dab951810db821dfc813126))
* every SDK says where it read the visitor's IP ([#155](https://github.com/korzen-dev/bot-protection-sdks/issues/155)) ([eaf0995](https://github.com/korzen-dev/bot-protection-sdks/commit/eaf09952208328b89c24a3cb716c773bf9a8b639))
* every SDK sends the request's Host with every decision, and a signed agent's headers ([#137](https://github.com/korzen-dev/bot-protection-sdks/issues/137)) ([eac1e4c](https://github.com/korzen-dev/bot-protection-sdks/commit/eac1e4c65f3f5791f4b3e122b30b866d6db8cf6f))
* first-party mode in the Python, PHP, Java and .NET SDKs ([#107](https://github.com/korzen-dev/bot-protection-sdks/issues/107)) ([#118](https://github.com/korzen-dev/bot-protection-sdks/issues/118)) ([bda62b8](https://github.com/korzen-dev/bot-protection-sdks/commit/bda62b86b1f69ac372568ff2838b53b60c0363fb))
* **node:** the crawler kinds assistant and scan in every SDK ([47ecef9](https://github.com/korzen-dev/bot-protection-sdks/commit/47ecef91bfdbb7e064a2973d15b267c9bb4c8d95))
* one place per identity, context.identity_hash and places_per_identity in every SDK (korzen-dev/korzen[#388](https://github.com/korzen-dev/bot-protection-sdks/issues/388)) ([#69](https://github.com/korzen-dev/bot-protection-sdks/issues/69)) ([c39f4d0](https://github.com/korzen-dev/bot-protection-sdks/commit/c39f4d0d4f33872105b721568488b29b2dfc8ba2))
* **php:** curl, when it is loaded, to ask Bot Protection ([#22](https://github.com/korzen-dev/bot-protection-sdks/issues/22)) ([ca708d5](https://github.com/korzen-dev/bot-protection-sdks/commit/ca708d52587f3dc4015af0a698e2fda40e764179))
* **php:** the PHP SDK, korzen/bot-protection ([#7](https://github.com/korzen-dev/bot-protection-sdks/issues/7)) ([1c91494](https://github.com/korzen-dev/bot-protection-sdks/commit/1c91494b9547669537250c06bd477f10992da860))
* **php:** the PHP style guide, its strictest lints, and the SDK reviewed against it ([#59](https://github.com/korzen-dev/bot-protection-sdks/issues/59)) ([ce00e10](https://github.com/korzen-dev/bot-protection-sdks/commit/ce00e10cca7abedfec65e019ad5459ccef2b95af))
* **python, php:** WSGI and PHP send header_order, as the server's measured order allows ([#46](https://github.com/korzen-dev/bot-protection-sdks/issues/46)) ([595726d](https://github.com/korzen-dev/bot-protection-sdks/commit/595726d497fc0b8bc6f45112e917932190559eb4))
* the default decoy, 202 with {} on a decoyed action with no onDecoy (korzen-dev/korzen[#157](https://github.com/korzen-dev/bot-protection-sdks/issues/157)) ([#68](https://github.com/korzen-dev/bot-protection-sdks/issues/68)) ([fe250e3](https://github.com/korzen-dev/bot-protection-sdks/commit/fe250e31313099ae2f929679cffdb8b558e31694))
* the six SDKs and the conformance suite on API v1 ([#13](https://github.com/korzen-dev/bot-protection-sdks/issues/13)) ([eed5acf](https://github.com/korzen-dev/bot-protection-sdks/commit/eed5acff933a126036ef886749f9f1b4ba4bb5d4))
* the unavailable problem and item code (API v1.0.1) ([#14](https://github.com/korzen-dev/bot-protection-sdks/issues/14)) ([64f8df5](https://github.com/korzen-dev/bot-protection-sdks/commit/64f8df5d4d19be3055299f8269a4b9f40e8f00d5))
* the way back keeps its query byte for byte, the first _kz cookie, the edge's fields on events (korzen [#1136](https://github.com/korzen-dev/bot-protection-sdks/issues/1136)) ([#15](https://github.com/korzen-dev/bot-protection-sdks/issues/15)) ([1d9a9bf](https://github.com/korzen-dev/bot-protection-sdks/commit/1d9a9bf7d9fdad175ae2aa3ce892a9fba37c2da2))


### Fixes

* **88:** a header sent twice goes as one, an empty one as none ([#101](https://github.com/korzen-dev/bot-protection-sdks/issues/101)) ([3d3afbc](https://github.com/korzen-dev/bot-protection-sdks/commit/3d3afbcc56ad5fe3e07d33331670125e96285916)), refs [#88](https://github.com/korzen-dev/bot-protection-sdks/issues/88)
* a country longer than 2 bytes is sent as none, never cut ([#144](https://github.com/korzen-dev/bot-protection-sdks/issues/144)) ([e85d0f6](https://github.com/korzen-dev/bot-protection-sdks/commit/e85d0f60a8efcb856d1e5d6abecff93cdd74bb72))
* a decision's lists are never null in any SDK (korzen [#1166](https://github.com/korzen-dev/bot-protection-sdks/issues/1166)) ([16a7eb9](https://github.com/korzen-dev/bot-protection-sdks/commit/16a7eb98d9902646b8391a6f6014d4ea30dddd4d))
* a decision's lists are never null in any SDK (korzen [#1166](https://github.com/korzen-dev/bot-protection-sdks/issues/1166)) ([9d601d7](https://github.com/korzen-dev/bot-protection-sdks/commit/9d601d78b0d9d6ec8561d210b1db74d998161299))
* a name past the 64th of a CDN's header order voids nothing ([#139](https://github.com/korzen-dev/bot-protection-sdks/issues/139)) ([8aefc52](https://github.com/korzen-dev/bot-protection-sdks/commit/8aefc52ea32ca34ee27f2439f479d6d1e7056e01))
* account_age_days is sent as max(0, floor(x)) by every SDK ([#145](https://github.com/korzen-dev/bot-protection-sdks/issues/145)) ([ac6a129](https://github.com/korzen-dev/bot-protection-sdks/commit/ac6a129de08bc4956e8e18193f40680485b87e29))
* account_age_days past u32 is sent as u32's largest by every SDK ([#151](https://github.com/korzen-dev/bot-protection-sdks/issues/151)) ([99916f6](https://github.com/korzen-dev/bot-protection-sdks/commit/99916f63e3bc89e9f6d4011862d35fae2e78a180))
* **conformance:** no case leaves the machine, and the refused port is held for the run ([#99](https://github.com/korzen-dev/bot-protection-sdks/issues/99), [#92](https://github.com/korzen-dev/bot-protection-sdks/issues/92)) ([#103](https://github.com/korzen-dev/bot-protection-sdks/issues/103)) ([0df7805](https://github.com/korzen-dev/bot-protection-sdks/commit/0df7805c80d10cb06ef56c29c17503df0da3a171))
* every SDK checks its settings once: an http URL off loopback never gets the key ([#86](https://github.com/korzen-dev/bot-protection-sdks/issues/86)) ([#98](https://github.com/korzen-dev/bot-protection-sdks/issues/98)) ([0664d07](https://github.com/korzen-dev/bot-protection-sdks/commit/0664d078070bf13294f977670df782fcfa317150))
* every SDK sends an account_age_days of 0 ([#152](https://github.com/korzen-dev/bot-protection-sdks/issues/152)) ([7a385f4](https://github.com/korzen-dev/bot-protection-sdks/commit/7a385f4ba3e46c72e3aa62501f4543f89a9817a6))
* every SDK's budget bounds its call, the name's lookup included, and the backoff stays within the batch ([#87](https://github.com/korzen-dev/bot-protection-sdks/issues/87)) ([#97](https://github.com/korzen-dev/bot-protection-sdks/issues/97)) ([7a7573d](https://github.com/korzen-dev/bot-protection-sdks/commit/7a7573d2a24a1c363f0f0c725b5512aa28fc7d5a))
* hooks, the challenge's answer and onAnswer fail open in Node, Go and Python ([#82](https://github.com/korzen-dev/bot-protection-sdks/issues/82), [#83](https://github.com/korzen-dev/bot-protection-sdks/issues/83)) ([#90](https://github.com/korzen-dev/bot-protection-sdks/issues/90)) ([21051a0](https://github.com/korzen-dev/bot-protection-sdks/commit/21051a0fb43df54eee8af87c5dc3fd30d5d26f97))
* **php, go:** the API key never in an error's trace or a printed Go Client ([#48](https://github.com/korzen-dev/bot-protection-sdks/issues/48)) ([7bcca0f](https://github.com/korzen-dev/bot-protection-sdks/commit/7bcca0fe0ac260f5254c0fc85f5905c95b4f1e38))
* **php:** curl's headers cut halfway are no answer ([#51](https://github.com/korzen-dev/bot-protection-sdks/issues/51)) ([831c3d6](https://github.com/korzen-dev/bot-protection-sdks/commit/831c3d6df98903711591605ba08cb6fee556e3bb))
* **php:** hooks, the challenge's answer and onAnswer fail open ([#82](https://github.com/korzen-dev/bot-protection-sdks/issues/82), [#83](https://github.com/korzen-dev/bot-protection-sdks/issues/83)) ([#93](https://github.com/korzen-dev/bot-protection-sdks/issues/93)) ([119ff91](https://github.com/korzen-dev/bot-protection-sdks/commit/119ff91d845f8b56591d88e84132301143bf881f))
* **php:** the Makefile names Composer COMPOSER_BIN, not COMPOSER ([#10](https://github.com/korzen-dev/bot-protection-sdks/issues/10)) ([d574187](https://github.com/korzen-dev/bot-protection-sdks/commit/d5741873703a4e4611916392ee00b9036f343662))
* **php:** the stream transport bounds the headers by the call's timeout ([#45](https://github.com/korzen-dev/bot-protection-sdks/issues/45)) ([189e81c](https://github.com/korzen-dev/bot-protection-sdks/commit/189e81ce3dc331a8c09af9bb33340b29ad6af4b7))
* the review's small fixes: WordPress's way back over https, Node's patched engines, docs ([#43](https://github.com/korzen-dev/bot-protection-sdks/issues/43)) ([8f69c83](https://github.com/korzen-dev/bot-protection-sdks/commit/8f69c835d40ad6cbb96b57d2637bf2fa99cf4f72))
* the way back from the challenge page is a relative path, never a host a request wrote ([#85](https://github.com/korzen-dev/bot-protection-sdks/issues/85)) ([#100](https://github.com/korzen-dev/bot-protection-sdks/issues/100)) ([5b16c91](https://github.com/korzen-dev/bot-protection-sdks/commit/5b16c91eb2636232a79b1b626ce8d98f4107bd08))


### Documentation

* a crawler's kind may be assistant or scan, in every SDK (korzen [#1168](https://github.com/korzen-dev/bot-protection-sdks/issues/1168), [#1164](https://github.com/korzen-dev/bot-protection-sdks/issues/1164)) ([d3fc742](https://github.com/korzen-dev/bot-protection-sdks/commit/d3fc7422fa7dc5be100ee716a3b9611fcba4f62f))
* **php:** the README in prettier's shape ([#23](https://github.com/korzen-dev/bot-protection-sdks/issues/23)) ([b67538e](https://github.com/korzen-dev/bot-protection-sdks/commit/b67538e0d6509aa1b165843a8ca1cb565828b696))
* refuse a challenge as a block on sign-in, sign-up and checkout, never let it through ([#117](https://github.com/korzen-dev/bot-protection-sdks/issues/117)) ([37a3b9d](https://github.com/korzen-dev/bot-protection-sdks/commit/37a3b9d4167fdf5becaa48334eeb6527cfe0d7e4))
* requireToken on payment, login and sign-up routes, in every SDK's README ([#67](https://github.com/korzen-dev/bot-protection-sdks/issues/67)) ([f318acc](https://github.com/korzen-dev/bot-protection-sdks/commit/f318accd9d994a16f08b0c4aba0e1f63bd0d3aaf))
* the licence linked absolute, decoy among a decision's members, Next.js's proxy.js ([#49](https://github.com/korzen-dev/bot-protection-sdks/issues/49)) ([94f46b4](https://github.com/korzen-dev/bot-protection-sdks/commit/94f46b4b7ba6f67cafd8b7f41590ff5953f59589))
* the licence made precise: modification as 3(b) allows, copies from registries, governing law ([#11](https://github.com/korzen-dev/bot-protection-sdks/issues/11)) ([ca4f2b6](https://github.com/korzen-dev/bot-protection-sdks/commit/ca4f2b6e9fac0cb53a2a779632b0b847fc0a70a5))
* the SDKs say what they send, never how Bot Protection detects (korzen-dev/korzen[#779](https://github.com/korzen-dev/bot-protection-sdks/issues/779)) ([#70](https://github.com/korzen-dev/bot-protection-sdks/issues/70)) ([b414e75](https://github.com/korzen-dev/bot-protection-sdks/commit/b414e7520fc6e7b0692cdfb6ddcc1772a8adf53d))

## Changelog
