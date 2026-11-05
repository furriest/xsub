# xsub

[Русский](README.md) · News: [t.me/xsuby](https://t.me/xsuby) · Chat: [t.me/xsuby_chat](https://t.me/xsuby_chat)

Subscription manager, domain lists and a node watchdog for **XKeen + Xray** on Keenetic / Netcraze routers. A server mode (Docker, x86_64/arm64) is available.

XKeen intercepts traffic and runs Xray. xsub manages the contents.

## Features

- **Subscriptions:** `vless://`, `vmess://`, `trojan://`, `ss://`, `hysteria2://` (`hy2://`), `wireguard://` (`wg://`), `socks://`, `http(s)://` links (plain or base64); **Clash/mihomo YAML**, **sing-box JSON**, **Xray JSON** (full configs as served by Remnawave/Marzban). Transports: TCP (incl. HTTP header), WebSocket, gRPC, HTTPUpgrade, XHTTP, mKCP; TLS and Reality; Hysteria2 salamander, certificate pinning, port hopping. Name filters, multiple subscriptions. If a panel with a device limit (Remnawave) serves stubs without HWID, the request is retried with a persistent `x-hwid` — file `/opt/etc/xsub/hwid` is created automatically.
- Enable **Always send HWID** per subscription to include the device ID in the first request. It is disabled by default; the automatic HWID retry when a response has no suitable nodes remains enabled. The provider may count the router against its device limit.
- **Balancer** `leastPing` + observatory, written to `07_xsub.json`.
- **Watchdog** checks the active node every minute with a **real download** (32 KB by default — above the block threshold where `generate_204` still passes; configurable). Custom addresses: `watchdog.check_urls`. Switching goes through the Xray API, no core restart.
- **Reliability:** spare nodes are download-checked in the background every 30 minutes; 24-hour history; on failure proven nodes are tried first, not the lowest ping.
- **Switch to a faster node:** when a spare node is no less reliable and faster than the current one by `switch_faster_ms` (default 200; 0 — off), the watchdog switches without waiting for a failure. Both nodes are re-measured back-to-back before switching, so shared channel/CPU noise does not fake the gap. At most once per background cycle.
- **Fallback nodes:** by link or moved from the XKeen configs; also a fallback via a router interface (`nwg0`, `ovpn_br0` — traffic goes through the Keenetic OS tunnel, bypassing Xray). When the whole subscription fails, the watchdog switches to a fallback and tries to switch back every 10 minutes.
- **Groups:** a list through a subset of nodes (name filter regex). Each group has its own balancer and watchdog.
- **"Direct" and "Via VPN" lists** on the web page, remote lists by URL in any popular format (plain, dnsmasq, surge/clash, egern, sing-box; updated daily). Before applying, the config is checked with `xray -test`; on error nothing changes.
- **"Where will this site go?"** — a domain, link or IP shows the matching rule, list and node (including `.dat` categories).
- **Self-healing:** replaced `05_routing.json`/`07_xsub.json` are restored; if the core is gone for 3 minutes, XKeen is restarted (mihomo is left alone).
- **Telegram notifications:** switches, down/recovery, subscription or traffic expiry, self-healing, new versions. When Telegram is blocked, messages go via VPN. Messages are prefixed with the device hostname.
- **History** of switches and 24-hour availability per node and group; one-file backup and restore; one-click update; RU/EN interface.
- **Geo files:** daily update of [itdoginfo/allow-domains](https://github.com/itdoginfo/allow-domains) (`geosite_itdog.dat`).

A single static binary with no dependencies; the web UI is built in.

## Requirements

- Keenetic / Netcraze with Entware and [XKeen](https://github.com/jameszeroX/XKeen) with the **Xray** core (`xkeen -xray`).
- Architecture: aarch64, armv7, mipsel, mips. **At least 100 MB free** — in practice a USB drive.
- Space: Xray core ~32 MB, `geoip.dat` + `geosite.dat` ~6 MB, xsub ~8 MB, XKeen with dependencies 3–5 MB. About 50 MB plus headroom for opkg temp files, cache and logs. Built-in storage (usually a 55 MB partition) is not enough.
- Throughput is CPU-bound (encryption on the router CPU, no acceleration): mips/mipsel — well below line rate, armv7 — in between, aarch64 — the fastest option.
- Watchdog traffic: 32 KB per check; 30 nodes every 30 minutes ≈ 45 MB/day.

Your router's architecture:

```sh
uname -m                  # aarch64, armv7l, mips…
opkg print-architecture   # tells mipsel from mips on MIPS
```

## Install

Over SSH on the router (Entware shell):

```sh
curl -fsSL https://raw.githubusercontent.com/furriest/xsub/main/install.sh | sh
```

The installer detects the architecture, checks free space, installs the package, creates the config and prints the page address, login and password. It offers to install XKeen if missing (`XSUB_YES=1` — no questions). Until a subscription is added, the Xray configs are untouched.

The opkg feed for `opkg upgrade` (it knows nothing about VPN and may not reach GitHub on a blocked network):

```sh
curl -fsSL https://raw.githubusercontent.com/furriest/xsub/main/install.sh | XSUB_FEED=1 sh
```

Manual install (get your own architecture — the packages are declared `Architecture: all`, opkg will not reject a foreign build):

```sh
case "$(uname -m)" in
  aarch64|arm64) A=aarch64 ;;
  armv*)         A=armv7 ;;
  mips*)         opkg print-architecture | grep -q mipsel && A=mipsel || A=mips ;;
esac
opkg install "https://github.com/furriest/xsub/releases/latest/download/xsub_$A.ipk"
```

Update: the "Update" button in Settings (downloads via VPN, verifies SHA256, log at `/tmp/xsub-update.log`) or the same install.sh again.

Nothing in the Xray configs needs hand-editing: `04_outbounds.json` can stay empty, `05_routing.json` is written by xsub. Settings → Environment shows problems and the command to fix them. Optional on the Keenetic/XKeen side: encrypted DNS (DoT/DoH), an `xkeen` policy in connection priorities, IPv6 (`xkeen -ipv6`), excluding Russian IPs (`xkeen -gips`/`xkeen -dgips` — such addresses go direct even if listed).

## Docker (server)

The same xsub in a container: Xray core, subscriptions, watchdog; all traffic of the built-in SOCKS5 proxy goes through a working node.

```sh
curl -fsSL -o docker-compose.yml https://raw.githubusercontent.com/furriest/xsub/main/docker-compose.yml
docker compose up -d
```

The web UI credentials (`http://<server>:8099/`) are printed to the first-start log: `docker compose logs`. The `ghcr.io/furriest/xsub` image is built from the release tag; update with `docker compose pull && docker compose up -d` (or watchtower via the label in the compose file). The in-app Update button is hidden in containers.

Server mode differences (auto-detected via `/.dockerenv` or `XSUB_SERVER=1`):

- The entrypoint builds a SOCKS5 inbound on first start from `SOCKS_PORT` (1080), `SOCKS_USER`, `SOCKS_PASSWORD` → `01_inbounds.json` in the confdir. Without credentials the inbound has no auth — do not expose it to the internet. To rebuild, delete the file and restart the container.
- Traffic outside the lists follows the **"Default"** toggle (Lists and groups tab): "Via VPN" in server mode, "Direct" on routers.
- Logging goes to stdout; check history lives in the `xsub-data` volume.
- The page is reachable from private addresses only (LAN, SSH tunnel) unless "Access from the internet" is enabled in Settings (password mandatory).
- Defaults: `/usr/local/bin/xray`, confdir `/data/xray`, `xsub-xray-restart` instead of `xkeen -restart`.

Without Docker, use the `xsub-<version>-x86_64` binary from the release: install Xray separately, set paths and `restart_cmd` in `config.json`, run with `XSUB_SERVER=1`.

## What changes in the Xray configs

xsub writes two files into the XKeen config folder (`/opt/etc/xray/configs`):

| File | Contents |
|---|---|
| `05_routing.json` | rules from the lists, the `force-proxy-*` rule, balancers |
| `07_xsub.json` | nodes, observatory, API (`127.0.0.1:10085`), local check inbounds (`10990+` targets, `11000+` nodes) |

`05_routing.json` belongs to xsub entirely — move your rules into the lists instead of editing the file.

Originals are saved to `/opt/etc/xsub/backup/original/`. Roll back:

```sh
/opt/etc/init.d/S99xsub stop
xsub -restore
```

`opkg remove xsub` rolls back automatically. If your files already contain `api`/`observatory` sections or a `routing` section in a file read after `05_routing.json`, xsub refuses to apply and explains what to fix.

## Lists

One entry per line, comments after `#`:

```
example.com                    # domain with all subdomains
=example.com                   # this exact domain only
ext:geosite_itdog.dat:youtube  # category from a file in the geo folder
geosite:telegram               # category from geosite.dat
1.2.3.0/24                     # IP or subnet
regexp:^ads\.                  # regular expression
https://…/list.txt             # remote list
```

Rule order: "Direct" → groups (page order) → "Via VPN". Traffic outside lists follows the **"Default"** toggle.

Remote lists are fetched on save and updated daily; written to disk only when changed. The format is detected automatically and parsed in full:

- bare domains and subnets, `=domain`, dnsmasq lines (`server=/domain/…`);
- classical client rules (surge, shadowrocket, loon, stash, quantumult-x, Clash payload): `DOMAIN`, `DOMAIN-SUFFIX`, `DOMAIN-KEYWORD`, `IP-CIDR`, `GEOIP` and the `HOST-*` variants; the third field (`all`, `no-resolve`) is ignored;
- typed egern YAML blocks: `domain_set`, `domain_suffix_set`, `domain_keyword_set`, `domain_regex_set`, `ip_cidr_set`;
- sing-box JSON rule-sets: `domain`, `domain_suffix`, `domain_keyword`, `domain_regex`, `ip_cidr`.

Entries with no equivalent in Xray rules (process_name, ports, ASN) are skipped. Example: `https://raw.githubusercontent.com/VPSDance/ai-proxy-rules/main/rules/surge/all.list`.

Groups: a name and a node filter (name regex, e.g. `(?i)netherlands|NL`). Each group gets its own list; with no matching nodes its traffic goes through the main target.

## Settings

Most settings are on the page (Settings tab); they are stored in `/opt/etc/xsub/settings.json` over `config.json`, xsub restarts itself. The rest is in `config.json` (after editing: `/opt/etc/init.d/S99xsub restart`).

| Parameter | Default | Purpose |
|---|---|---|
| `listen` | `0.0.0.0:8099` | page address |
| `user`, `password` | `admin`, random | login |
| `log_file`, `log_max_kb` | `/tmp/xsub.log`, `256` | log: `""` — page only; `/tmp` — RAM; a path on storage writes to flash |
| `sub_interval_hours` | `6` | subscription refresh (retry in 10 minutes after a failure) |
| `user_agent` | `v2rayN/7.0` | panel response format; per-subscription override possible |
| `max_nodes` | `60` | max nodes from one subscription |
| `ui_allow_wan` | `false` | access from the internet. Unencrypted HTTP — enable only with a strong password |
| `ui_allow_hosts` | — | allowed Host header names (DNS rebinding protection) |
| `xray.restart_cmd` | `xkeen -restart` | core restart |
| `xray.template_tag` | — | outbound to copy sockopt (mark) from |
| `xray.manage_api` | `true` | `false` if you configured the Xray API yourself (`RoutingService` at `xray.api_listen`) |
| `xray.fallback_tag` | — | legacy: fallback outbound from the XKeen configs; prefer "Fallback nodes" in the UI |
| `watchdog.interval_sec` | `60` | watchdog tick |
| `watchdog.fails_to_switch` | `2` | consecutive failures before switching |
| `watchdog.test_url`, `test_bytes` | Cloudflare, `32768` | what to download for checks (`{bytes}` is substituted) |
| `watchdog.check_urls` | — | addresses that must also open through the node |
| `watchdog.latency_url` | `gstatic.com/generate_204` | latency probe; falls back to `test_url` when unreachable |
| `watchdog.switch_faster_ms` | `200` | switch to a faster spare at a ≥ N ms gap (0 — off; once per cycle; both nodes re-measured before switching) |
| `watchdog.background_cycle_min` | `30` | background check period for spare nodes (0 — off) |
| `watchdog.stats_file` | `/tmp/xsub-stats.json` | check history across xsub restarts |
| `watchdog.restart_delay_sec` | `7` | pause after core start before pinning nodes |
| `watchdog.restart_xray` | `true` | restart XKeen when the core is gone for 3 minutes |
| `telegram.*` | — | `token`, `chat_id`, `expire_days` (3), `traffic_pct` (90), `on_switch`, `on_update` |
| `update_repo` | `furriest/xsub` | update source |
| `geo.files` | itdoginfo | geo files to download into `xray.assetdir` |

Subscriptions, groups, fallbacks and lists are files next to `config.json` (`subscriptions.json`, `groups.json`, `fallbacks.json`, `vpn.txt`, `direct.txt`, `group-*.txt`), exported and imported by the Backup buttons. Subscription links are secrets: mode `0600`, never logged.

Storage is written only on changes: a new subscription body, list edits, geo files, Xray config changes. The log (`/tmp` by default) rotates at `log_max_kb` (current + `.old`); the last 80 lines are on the page.

## Security

- Password-protected; home network only by default; 10 wrong passwords lock the address out for 10 minutes.
- Changes require a special request header — a foreign website cannot forge them.
- Plain HTTP: do not expose port 8099 to the internet.
- Self-healing restores the configs if an XKeen update replaces them.

## Limitations

Skipped with a warning (not supported by Xray): TUIC, Hysteria v1, AnyTLS, NaiveProxy, ShadowsocksR, SSH, Mieru; Shadowsocks plugins; VMess with `alterId > 0`; h2 and QUIC transports; `dialerProxy` chains in JSON subscriptions.

- Disabling certificate verification (`allowInsecure`) is not supported by recent Xray: such nodes are added with normal verification — they work with a valid certificate or `pinSHA256`/`pcs` in the link.
- A node rejected by the installed core: xsub tries a simplified variant (pre-26.10 Xray — no Hysteria2 port hopping, legacy mKCP format); otherwise only that node is dropped, with the reason on the page.
- WireGuard runs in userspace (`noKernelTun`), without a system interface.
- Xray core only; mihomo has its own subscription machinery.

## Build and release

```sh
go vet ./... && go test -race ./...
scripts/build.sh                 # version from git describe → dist/
VERSION=1.2.3 scripts/build.sh   # or set explicitly
```

The YAML library is vendored in `third_party/` (go-yaml v3.0.1, MIT/Apache-2.0). GitHub Actions builds a release on `v*` tags: packages on the release page, opkg feed on GitHub Pages, image on ghcr.

The page interface is RU/EN; messages produced by xsub itself (log, history, notifications) are in Russian.

## Contacts and license

- Channel: [t.me/xsuby](https://t.me/xsuby) · Chat: [t.me/xsuby_chat](https://t.me/xsuby_chat)
- License: MIT
