# xsub

[Русский](README.md) · News: [t.me/xsuby](https://t.me/xsuby) · Chat: [t.me/xsuby_chat](https://t.me/xsuby_chat)

Subscriptions, domain lists and a node watchdog for **XKeen + Xray** on Keenetic / Netcraze routers.

XKeen intercepts traffic and runs Xray. xsub takes care of the contents:

- **Subscriptions.** Understands nearly everything the Xray core supports:
  - `vless://`, `vmess://`, `trojan://`, `ss://`, `hysteria2://` (`hy2://`), `wireguard://` (`wg://`), `socks://`, `http(s)://` links — plain or base64;
  - **Clash / mihomo YAML**, **sing-box JSON** and **Xray JSON** subscriptions (full configs as served by Remnawave/Marzban for Happ and v2rayN);
  - TCP (including the HTTP header), WebSocket, gRPC, HTTPUpgrade, XHTTP and mKCP transports; TLS and Reality; for Hysteria2 — salamander obfuscation, certificate pinning and port hopping.

  Nodes can be filtered by name; informational entries from panels ("10 GB left" etc.) are skipped. Traffic usage and expiry are shown when the panel provides them. Multiple subscriptions are supported.
- **Watchdog.** Every minute the active node is checked with a **real download** (32 KB by default — above the 16–20 KB threshold of a common block; configurable). This catches blocking where short probes such as `generate_204` pass but real traffic is cut. You can add your own addresses that must also open through the node. Switching goes through the Xray API, without restarting the core.
- **Node reliability.** Every spare node is download-checked in the background once per 30 minutes (configurable), spread evenly over time. Each node keeps a 24-hour history, and on failure reliable nodes are tried first, not just the fastest ones by ping.
- **Fallback nodes.** Your own servers for when no subscription node works: added as a link (`vless://`, `socks://`, `http://` and anything else xsub understands) or moved from the XKeen configs (e.g. `04_outbounds.json`) with one click. The watchdog checks them like regular nodes, switches to a fallback when the whole subscription is down and tries to switch back every 10 minutes.
- **Groups.** Send a list through its own subset of nodes, e.g. "YouTube via Netherlands" or "ChatGPT via US only". Each group has its own balancer and watchdog.
- **"Via VPN" and "Direct" lists** are edited on the web page; remote lists can be added by URL (updated daily). Everything is checked with `xray -test` on a copy of the configs before it is applied; on error nothing changes.
- **"Where will this site go?"** — enter a domain, link or IP and see which rule matches and which node the traffic will use (including categories from `.dat` files).
- **Self-healing.** If `05_routing.json` or `07_xsub.json` gets replaced (an XKeen update, another panel), xsub restores them. If the Xray core is gone for 3 minutes, xsub restarts XKeen (but leaves it alone if you switched to mihomo).
- **Telegram notifications:** node switches, all nodes down and recovery, subscription or traffic running out, self-healing actions, new xsub versions. If Telegram is blocked, messages go through the VPN. Every message starts with the router hostname, so several devices can be told apart in one chat — rename the router if that name should not be visible there.
- **History** of switches and a 24-hour availability strip for every node and group.
- **Settings on the page**, a one-file backup of everything and restore from it, one-click xsub update, Russian and English interface.
- **Geo files.** [itdoginfo/allow-domains](https://github.com/itdoginfo/allow-domains) (`geosite_itdog.dat`) is updated daily: `russia-inside`, `youtube`, `telegram` and other categories.

A single static binary with no dependencies (no Python). The web page is built in.

## Requirements

- Keenetic / Netcraze with Entware ("Open Package support");
- [XKeen](https://github.com/jameszeroX/XKeen) with the **Xray** core (`xkeen -xray`);
- aarch64, mipsel, mips or armv7;
- **at least 100 MB free** for Entware — in practice that means a USB drive.

### How much space

Most of it goes to the Xray core, not to xsub. Unpacked sizes, Xray v26.10.21:

| What | Space |
| --- | --- |
| Xray binary, mips/mipsel | 32.7 MB |
| Xray binary, aarch64 / armv7 | ~31 MB |
| `geoip.dat` + `geosite.dat` | 6 MB |
| xsub | 7.9 MB |
| XKeen with its scripts and dependencies (iptables, ipset, curl, ca-bundle, coreutils) | 3–5 MB |
| **Total** | **≈ 50 MB** |

On top of that you need headroom: opkg unpacks packages into a temporary directory, geo files
are updated through a copy kept next to them, and the log and subscription cache live somewhere
too. Hence the 100 MB figure.

RAM is used as well: the core keeps the geo databases in memory, and the more categories and
nodes are in play, the more it holds. No per-model threshold is given here — it depends too
much on list sizes — but on routers with the smallest amount of memory the headroom is thin.

**Keenetic's built-in storage is not enough.** On models that have it, the OPKG partition is
usually 55 MB with part of it already in use — the Xray binary alone does not fit. A USB drive
is required; any flash drive will do, and Keenetic moves Entware onto it with its own tools.
If no USB port is free — the only one taken by a modem, say — XKeen with Xray cannot be
installed on that router at all: that is a limit of the Xray core's size, not of xsub.

### What to expect from the CPU

Xray encrypts traffic on the router's CPU; there is no hardware acceleration for VLESS/Reality.
The CPU, not your ISP plan, sets the speed ceiling:

- **mips / mipsel** — the slowest option: it works, but VPN throughput will be noticeably
  below the line rate.
- **armv7** — in between.
- **aarch64** — the fastest option available.

To find out your architecture:

```sh
uname -m                  # aarch64, armv7l, mips…
opkg print-architecture   # tells mipsel from mips on MIPS
```

If speed matters, measure it right after installing by picking a node by hand on the Nodes tab.
Latency is shown there too, but it tells you about the route, not about throughput: the CPU can
be the bottleneck even when latency looks fine.

The watchdog adds a little subscription traffic: each node check downloads 32 KB (configurable).
Thirty nodes checked once every 30 minutes is about 45 MB a day.

## Install

Over SSH on the router (Entware shell):

```sh
curl -fsSL https://raw.githubusercontent.com/furriest/xsub/main/install.sh | sh
```

The installer detects the architecture, checks there is enough free space, installs the package, creates the config and prints the page address, login and password. Open `http://<router-IP>:8099/` and add your subscription link. If XKeen is not installed, the installer offers to install it (choose the Xray core there); if XKeen has no Xray core or runs mihomo, it offers `xkeen -ux` / `xkeen -xray`. Without a terminal it installs nothing unasked; `XSUB_YES=1` answers yes to everything.

Until a subscription is added, xsub does not touch the Xray configs.

Nothing has to be edited in the Xray configs by hand: after installing XKeen (Xray core) and xsub, everything is set up on the web page. Settings → Environment shows whether XKeen, the core, autostart and the inbounds (with sniffing) are in place and suggests a command if not. Optional, on the Keenetic/XKeen side: encrypted DNS (DoT/DoH), an `xkeen` policy if only some devices should use the VPN, IPv6 (`xkeen -ipv6`), and XKeen's "exclude Russian IPs" option, which keeps those addresses away from Xray even if a site is on the "Via VPN" list.

To update via `opkg upgrade`, add the package feed:

```sh
curl -fsSL https://raw.githubusercontent.com/furriest/xsub/main/install.sh | XSUB_FEED=1 sh
```

After that: `opkg update && opkg upgrade xsub`, or the "Update" button in Settings.

## Docker (server, x86_64 and arm64)

The same xsub in a container: the Xray core, subscriptions, the watchdog with real-traffic health checks and fastest-node selection. All traffic of the built-in SOCKS5 proxy is routed through a working subscription node.

```sh
curl -fsSL -o docker-compose.yml https://raw.githubusercontent.com/furriest/xsub/main/docker-compose.yml
docker compose up -d
```

The web UI credentials (`http://<server>:8099/`) are printed to the log on first start: `docker compose logs`. Add your subscription on the Subscriptions tab.

The `ghcr.io/furriest/xsub` image is built by GitHub Actions from the same tag as the release — **update with `docker compose pull && docker compose up -d`** (or watchtower using the label in the compose file). The in-app Update button is hidden in the container: the image updates, not the process.

Inside the container (server mode) things differ from the router setup:

- **SOCKS5 inbound.** The entrypoint builds it on first start from `SOCKS_PORT` (1080 by default), `SOCKS_USER` and `SOCKS_PASSWORD` — file `01_inbounds.json` in the confdir. Without user/password the inbound has no authentication: do not expose such a port to the internet. To rebuild the inbound, delete the file from the confdir and restart the container.
- **Routing** works exactly as on the router: "Direct" rules, then groups, then "Via VPN", and traffic outside all lists follows the **"Default"** toggle on the "Lists and groups" tab. In server mode it is set to "Via VPN" (all SOCKS traffic goes through the best node); switch it to "Direct" to send only the listed traffic via VPN.
- **Logging** goes to stdout (`docker compose logs`); the check history lives in the `xsub-data` volume and survives container recreation.
- **Web UI** is reachable from private addresses only (LAN, SSH tunnel `ssh -L 8099:127.0.0.1:8099 server`) unless you enable "Access from the internet" in Settings (a password is mandatory).
- Server mode enables itself via `/.dockerenv` or the `XSUB_SERVER=1` variable. Its defaults differ: `/usr/local/bin/xray`, confdir `/data/xray`, `xsub-xray-restart` instead of `xkeen -restart`, stats next to `config.json`.

Without Docker, grab the `xsub-<version>-x86_64` binary from the release: install Xray separately, set paths and `restart_cmd` in `config.json`, and run with `XSUB_SERVER=1`.

## What changes in the Xray configs

xsub writes two files to the XKeen config folder (`/opt/etc/xray/configs`):

| File | Contents |
|---|---|
| `05_routing.json` | rules from the lists and groups, a rule for XKeen `force-proxy-*` inbounds, balancers |
| `07_xsub.json` | subscription nodes, observatory, API (`127.0.0.1:10085`), local inbounds for checks (`127.0.0.1:10990–10998`, `11000+`) |

`05_routing.json` belongs to xsub entirely: move your rules into the lists on the page instead of editing the file.

The original files are saved to `/opt/etc/xsub/backup/original/` before the first write. To roll back: `/opt/etc/init.d/S99xsub stop && xsub -restore`. `opkg remove xsub` does this automatically.

## Lists

One entry per line, comments after `#`:

```
example.com                      # domain with all subdomains
=example.com                     # this exact domain only
ext:geosite_itdog.dat:youtube    # category from a file in the geo folder
geosite:telegram                 # category from geosite.dat
1.2.3.0/24                       # IP or subnet
regexp:^ads\.                    # regular expression
https://example.com/list.lst     # remote list (one domain/IP per line, dnsmasq format understood)
```

Rule order: "Direct", then groups (in page order), then "Via VPN". Traffic that matches no list follows the **"Default"** toggle on the same tab: direct on the router, via VPN in server mode.

## Log and flash wear

The log goes to `/tmp/xsub.log` by default — the router's RAM — so neither internal flash nor a USB drive wears out. The file is capped by `log_max_kb` (256 KB) with one `.old` rotation. The last 80 lines are on the page (300 are kept in memory). Node statistics are copied to
`watchdog.stats_file`, so they survive an xsub restart but not a router reboot. xsub writes to storage only when something actually changes.

## Security

- The page is password-protected and by default only reachable from the home network (and Keenetic VPN clients). After 10 wrong passwords the address is locked out for 10 minutes.
- Changes are accepted only with a special request header, so a foreign website cannot forge them.
- Do not expose port 8099 to the internet: the page is plain HTTP.
- Subscription links are secrets: they are stored with `0600` permissions and never logged.

## Limitations

Skipped with a warning (not supported by Xray itself): TUIC, Hysteria v1, AnyTLS, NaiveProxy, ShadowsocksR, SSH, Mieru; shadowsocks plugins; VMess with `alterId > 0`; the removed `h2` and QUIC transports; proxy chains (`dialerProxy`) in JSON subscriptions.

- Recent Xray versions cannot disable certificate verification (`allowInsecure` / `insecure=1`); such nodes are added with normal verification.
- If the installed Xray rejects a node, xsub tries a simplified variant for older cores and otherwise drops only that node, explaining why on the page.
- WireGuard runs in userspace (`noKernelTun`).
- Messages generated by xsub itself (log, history, errors, notifications) are in Russian for now; the page interface is available in English.

## Build

No network dependencies: the YAML library is vendored in `third_party/` (go-yaml v3.0.1, MIT/Apache-2.0).

```sh
go vet ./... && go test -race ./...
scripts/build.sh                 # version comes from git describe → dist/
VERSION=1.2.3 scripts/build.sh   # or set it explicitly
```

Releases are built by GitHub Actions on `v*` tags; the opkg feed is published to GitHub Pages.

## Community

- News and releases channel (in Russian): [t.me/xsuby](https://t.me/xsuby)
- Chat for questions and discussion: [t.me/xsuby_chat](https://t.me/xsuby_chat)

## License

MIT
