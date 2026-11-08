<div align="center">

**English** | [Русский](README.ru.md)

<img src="docs/logo.png" alt="Eleutheria" width="360">

### Your own VPN on your own server. In two clicks.

Server setup over SSH, censorship circumvention with VLESS + Reality, a client with a system-wide tunnel,
automatic server selection and per-category traffic checks. All in one app, no third-party services.

![Version](https://img.shields.io/badge/version-1.0.1-3b82f6)
![License](https://img.shields.io/badge/license-GPL--3.0--or--later-informational)
![Rust](https://img.shields.io/badge/Rust-2021-orange?logo=rust)
![Tauri](https://img.shields.io/badge/Tauri-2-24c8db?logo=tauri&logoColor=white)
![sing-box](https://img.shields.io/badge/sing--box-1.14-8b5cf6)

**[⬇ Download the latest release](https://github.com/MrChifir/Eleutheria/releases/latest)**

<br>

<img src="docs/screenshots/home-connected.png" alt="Eleutheria main screen: connected through the system VPN" width="860">

</div>

> The screenshots show the Russian-language interface.

---

## Table of contents

- [What it is](#what-it-is)
- [Features](#features)
- [Tour of the app](#tour-of-the-app)
  - [Guide and tour](#guide-and-tour-the-app-explains-itself)
- [How it works](#how-it-works)
- [Quick start](#quick-start)
- [Building](#building)
- [No server yet?](#no-server-yet)
- [Server installation (CLI)](#server-installation)
- [Client (CLI)](#client)
- [System VPN (TUN)](#system-vpn-tun)
- [Updates and releasing](#updates)
- [GUI](#gui)
- [Tests and CI](#tests-and-ci)
- [Limitations](#limitations)
- [Roadmap](#roadmap)
- [Advanced features](#fallback-protocols)

## What it is

Eleutheria is an open-source tool for running your own VPN. You rent a server, Eleutheria connects to it over SSH,
installs sing-box, configures censorship circumvention with the VLESS + Reality protocol and gives you a link and a
QR code for the client. The client works either as a local proxy or as a system-wide VPN through TUN.

There are two ways to use it: the **graphical app** (Tauri 2, described below) or the **command line**
(`eleutheria …`). Both are built on the same library, so the result is identical.

Works on Linux and Windows. macOS builds in CI but has not been tested on a real machine.

## Features

| | |
| --- | --- |
| 🚀 **One-step server setup** | OS check, sing-box installed with SHA256 verification, Reality keys, systemd service. |
| 🔒 **Server hardening** | SSH key login instead of a password, BBR, ufw. Every step is rolled back on failure. |
| 👥 **Users** | Each user gets their own UUID, link and QR code. |
| 🧭 **Smart client** | Import a link or a subscription, automatic server selection by latency, failover. |
| 🛡️ **System VPN (TUN)** | Through a root helper service, with DNS leak protection (fake-ip). |
| 🎯 **Traffic categories** | Video, messengers, social networks and AI services are probed separately and can take a different route. |
| 🇷🇺 **Russian resources direct** | Three modes: everything through the VPN, only `.ru/.su/.рф`, or rule sets for services and IPs. |
| 🔁 **Fallback protocols** | Hysteria2, TUIC v5, Shadowsocks 2022, VLESS + WebSocket through a CDN. |
| 🧩 **Third-party profiles** | Add your own protocol as a three-file folder, with strict validation, a diff and a confirmation prompt. |
| 🌐 **Server fleet** | Several VPS, one user, one subscription. |
| ⛓️ **External exit** | Chain someone else's SOCKS5 proxy through your server, only for selected categories and only with explicit consent. |
| ⬆️ **Updates** | Update sing-box on the server and the app itself: signature verification, rollback watchdog. |
| 🔑 **Secrets** | System keyring, or files with 600 permissions when there is none. |

## Tour of the app

The interface has four sections: **Home**, **Server**, **Updates** and **Guide**. The connection status is always visible on the left.

> Screenshots were taken from the real app frontend with test data: addresses from documentation ranges, made-up servers, a mock backend.

### Home: connect with one button

<img src="docs/screenshots/home-disconnected.png" alt="Home screen, VPN disconnected" width="860">

Everything you need for daily use lives here:

- **A big "Connect / Disconnect" button** and the current status. In TUN mode the process pid is shown.
- **Mode:** system VPN (all traffic) or a local proxy at `127.0.0.1:7890`. If the helper is not installed yet,
  TUN is unavailable and an install-helper button appears right in the card.
- **Server:** "Auto (by latency)" or a specific one. With several servers the client fails over on its own.
- **Russian resources:** "Everything through the VPN", "Direct: .ru, .su, .рф and local" (default) or with rule sets.
- **Servers:** the list of imported servers and a "Check latency" button.
- **Add a server:** paste a link (`vless://`, `hysteria2://`, `tuic://`, `ss://`) or a subscription URL.

### Connected: traffic categories under control

<img src="docs/screenshots/home-connected.png" alt="Home screen, VPN connected, traffic categories" width="860">

When the tunnel is up, the "Traffic categories" card shows live checks:

- a **"Tunnel"** row with overall connection health and latency;
- one row per category (**Video, Messengers, Social networks, AI services**) with a colored indicator and latency;
- a toggle for each category. A disabled category takes the common route; the change applies on the next connection;
- an event log at the bottom: what switched and when.

If a site refuses the server's exit IP, only that category moves to another path, not all of your traffic.

### Server: install a VPN without a terminal

<img src="docs/screenshots/server.png" alt="Server tab" width="860">

A one-window setup wizard:

1. **No server?** Quick links to partner hosting providers (VDSina, Fornex, IHC, Justhost, Nodex).
   The app only opens addresses from the built-in list.
2. **Server access:** address, SSH user and port, password or key path. The "Check server" button shows the
   fingerprint that you should compare with the one from your hosting provider.
3. **VPN installation:** port, masquerade site (SNI), profile name, first user. Hardening switches:
   key login, BBR, ufw. Fallback protocols can be enabled right at install time.

### Installation result: link and QR code

<img src="docs/screenshots/server-provisioned.png" alt="Installation result: report, link and QR code" width="860">

After installation the app shows a report for every step, the client link with a "Copy" button and a QR code
for your phone. Below are server controls: protocols (switch on and off on the fly), users
(add, remove, get a link) and the sing-box update.

### Updates: signed, and usable without GitHub access

<img src="docs/screenshots/updates.png" alt="Updates tab" width="860">

A dedicated **Updates** tab. The app checks for new versions once a day and on demand. The downloaded file is
verified against its signature before any change is made to the system. If neither GitHub nor the mirror is reachable,
you can pick the update file and its `.sig` manually. If an outdated helper is installed, the app suggests updating it.

### Guide and tour: the app explains itself

<img src="docs/screenshots/guide.png" alt="Guide section: in-app help" width="860">

The **Guide** section collects the help: where to start, what each section does, how the connection modes differ,
how traffic categories work, what matters for security, and answers to common questions ("The Connect button is
disabled", "The server key has changed" and others).

<img src="docs/screenshots/tour.png" alt="Step-by-step tour: traffic categories highlighted" width="860">

The **"Take the tour"** button starts an interactive 17-step walkthrough: the app switches sections by itself,
highlights the relevant block and briefly explains what it does. Control the tour with the buttons or the `←` `→`
keys, and close it at any moment (`Esc`). On first launch, while there are no servers yet, the tour is offered automatically.

## How it works

```mermaid
flowchart LR
    subgraph PC["Your computer"]
        GUI["Eleutheria<br/>GUI / CLI"] --> CORE["eleutheria-core"]
        CORE -->|"UNIX socket / named pipe"| HELPER["helper (root)"]
        HELPER --> SB1["sing-box<br/>TUN + fake-ip DNS"]
        CORE -.->|"proxy mode"| SB2["sing-box<br/>127.0.0.1:7890"]
    end
    CORE -->|"SSH: install and manage"| VPS
    SB1 ==>|"VLESS + Reality"| VPS["Your VPS<br/>sing-box"]
    SB2 ==>|"VLESS + Reality"| VPS
    VPS --> NET(("Internet"))
```

Project layout:

| Crate | Purpose |
| --- | --- |
| `eleutheria-core` | Core: server installation, SSH, hardening, users, protocol profiles (built-in and third-party), client config, prober and watch, server fleet, secret storage. |
| `eleutheria-cli` | Command-line interface (`eleutheria …`). |
| `eleutheria-helper` | Root service for TUN: accepts only server data and builds the config itself. |
| `eleutheria-app` | Service layer for the GUI: updates and rollback, partners, privilege elevation, server wizard. |
| `eleutheria-gui` | Tauri 2 shell and a static frontend with no bundler. |

The GUI installer ships the `eleutheria` (CLI) and `eleutheria-helper` binaries as sidecars.

## Quick start

**With the graphical app**

0. Download the app from [Releases](https://github.com/MrChifir/Eleutheria/releases/latest).
1. Open the **Server** tab, enter the VPS address and SSH details, click "Check server" and compare the fingerprint.
2. Click **"Install"**. The server appears in the list on the Home screen by itself.
3. On Home, click **"Connect"**. For "System VPN" mode, install the helper once.
4. Need access for a phone or a friend: copy the link or show the QR code from the installation result.

**From the command line**

```
eleutheria provision <IP>          # install the VPN on a server, get a link and a QR code
eleutheria connect                 # local proxy 127.0.0.1:7890
sudo eleutheria helper install     # once, for the system VPN
eleutheria connect --tun           # route all traffic through the VPN
```

## Building

CLI and tests:

```
cargo build --release                       # CLI: target/release/eleutheria
cargo test --workspace --exclude eleutheria-gui
```

The graphical app and installers are described in the [GUI](#gui) section.

## No server yet?

The "Server" tab has a block with partner hosting providers. You can rent a VPS through a link in the app and then enter
its address in the form. If you already have a server, you do not need this block: the VPN installation works with any
Ubuntu or Debian VPS.

The list of providers is defined in `crates/eleutheria-app/src/partners.rs`. The app only opens addresses from this list.
The links are affiliate links: the project author may receive a commission through them, and you get a 10% discount.

## Server installation

```
eleutheria provision <IP> [--user root] [--ssh-port 22] [--key PATH | --password-env VAR]
                  [--port 443] [--sni www.microsoft.com] [--name Eleutheria] [--user-name default]
                  [--protocols hysteria2,tuic,ss2022,vless-ws,<profile id>|all] [--cdn-host cdn.example.com]
                  [--no-harden-ssh] [--no-bbr] [--no-firewall] [--host-key SHA256:...] [-y]

eleutheria user add|list|link|remove <IP> [<name>]     # each user has their own UUID and link
eleutheria server status|update <IP>                   # sing-box versions, update
eleutheria server protocols <IP> [--enable …] [--disable …] [--cdn-host …]   # without flags shows the state
eleutheria forget <IP>                                 # forget the server key after the server was reinstalled
eleutheria secrets                                     # where SSH keys and server profiles are stored
```

The password is entered once, during the first installation (interactively or via `--password-env`). After that
Eleutheria uses its own SSH key, which it creates and stores itself. `eleutheria secrets` shows what is stored where and
migrates old files into protected storage. `ELEUTHERIA_SECRETS=keyring|file|auto` selects the storage backend.

Running it again is idempotent: keys, port, SNI and users are taken from `/etc/eleutheria/state.json`.
The server key is pinned: if it changes, connecting is blocked until you run `eleutheria forget`.

What `provision` does:

1. Checks the OS (Ubuntu/Debian, systemd, root) and whether the port is free.
2. Downloads sing-box on your machine, verifies its SHA256 against the pinned value (currently sing-box 1.14.3) and uploads it to the server.
3. Generates Reality keys, validates the config (`sing-box check`) and starts the systemd service.
   If the service does not come up, the previous config is restored.
4. Hardens the server. Key login is verified with a new connection, and only then is the password disabled.
   BBR is enabled if the kernel supports it. ufw is enabled only if there are no other public ports.
5. Enables the selected fallback protocols (`--protocols`).
6. Prints links for every user and a QR code.

## Client

```
eleutheria import <link | subscription URL> [--name N]   # a server installed via provision is added automatically
eleutheria servers | remove-server <name>
eleutheria connect [--port 7890] [--clash-port 9090] [--server name] [--ru-direct off|minimal|rulesets]
                   [--test-url https://…] [--tun] [--no-probes]
eleutheria status       # mode, active server, latencies
eleutheria disconnect
eleutheria probe [--timeout 8]     # one probe round and a diagnosis, switches nothing
eleutheria watch [--interval 30] [--no-switch] [--allow-direct] [--allow-external-exit] [--rounds N]
eleutheria categories [enable|disable <id>]    # without arguments: list categories
```

By default `connect` starts a local proxy at `127.0.0.1:7890` (HTTP and SOCKS5), which you need to set in your browser
or system. With several servers, automatic selection by latency and failover are active.

Supported links: `vless://` (Reality or TLS over TCP), `hysteria2://` (and `hy2://`), `tuic://`, `ss://`.
Subscriptions: a base64 list or a plain list of links. Other schemes (vmess, trojan, etc.) and transports (ws, grpc)
are skipped with a message.

`probe` and `watch` use probe ports that `connect` opens. With `--no-probes` they are unavailable.
`watch` monitors the paths and switches categories on failures. Bypassing the VPN (`--allow-direct`) and using an
external exit (`--allow-external-exit`) are enabled only explicitly.

### Russian resources (`--ru-direct`)

- `off`: everything goes through the VPN.
- `minimal` (default): `.ru`, `.su`, `.рф` domains and private addresses go direct. Nothing is downloaded.
- `rulesets`: the same plus the `geoip-ru` and `geosite-category-ru` rule sets, which cover Russian services on other
  domains and Russian IP addresses. The rule sets are downloaded through the proxy at startup.

## System VPN (TUN)

```
sudo eleutheria helper install     # once: installs the helper service and sing-box into /usr/lib/eleutheria
eleutheria connect --tun           # no sudo: all system traffic and DNS go through the VPN
eleutheria helper status           # is the helper responding
eleutheria status | disconnect
sudo eleutheria helper uninstall
```

Windows (PowerShell or a terminal **run as administrator**, a single UAC prompt):

```
eleutheria helper install          # EleutheriaHelper service (LocalSystem), files in %ProgramFiles%\Eleutheria
eleutheria connect --tun           # regular user, no elevation
eleutheria status | disconnect
eleutheria helper uninstall
```

In the GUI the helper is installed with a button in the mode card: the app requests the privileges itself
(polkit on Linux, a system prompt on macOS and Windows).

### How security works

- The helper runs as root and listens on a unix socket owned by the installing user (permissions 600).
  The client uid is additionally checked via SO_PEERCRED. Other users are refused.
- Windows: the helper listens on the named pipe `\\.\pipe\eleutheria-helper` with a DACL. SYSTEM and administrators
  have full access, the installing user has read and write access, network logons are denied. The first instance is created
  with `FILE_FLAG_FIRST_PIPE_INSTANCE`. The `%ProgramData%\Eleutheria` directory with the sing-box config is locked down by ACL.
- The helper does not accept a ready-made sing-box config, because a config can be used to read and write files as root.
  It receives only server data, validates it (host, uuid, sni, keys, fingerprint, third-party profile id)
  and builds the config itself.
  The sing-box binary is taken from a directory that only root can write to, and its SHA256 is checked at install time.
- DNS: all system DNS is intercepted. Regular names get a fake-ip (198.18.0.0/15) and are resolved on the server
  through the tunnel, so queries never reach the local network's DNS. `.ru/.su/.рф` domains are resolved by the system
  DNS by default and go direct. This is a deliberate leak to keep Russian services reachable; disable it with `--ru-direct off`.
- IPv6 is enabled only if the system has it.
- If sing-box crashes, the helper removes the routing rules it left behind.

## Updates

- **Server:** `eleutheria server status <host>` shows the sing-box versions on the server and in the client.
  `eleutheria server update <host>` updates sing-box. Keys and users are preserved, the config is validated
  before the restart, and on failure the previous config and binary are restored. The same is available on the "Server" tab in the GUI.
  For a fleet: `eleutheria fleet update`.
- **App:** the "Updates" tab checks for new versions once a day and on demand. Downloads are verified
  against a signature (`requireSignedVersion` protects against version spoofing on the mirror), then the app installs and restarts.
  Before installing, a rollback watchdog is started (`eleutheria update-watchdog`): if the new version does not confirm
  a successful start within the allotted time, the previous one is restored. If neither GitHub nor the mirror is reachable,
  you can choose the update file and its `.sig` manually. While `tauri.conf.json` still contains the placeholder `pubkey` and
  endpoints, updates are disabled and the interface says so. On Linux, in-app updating works only in the AppImage.

### Releasing

The repository secrets `TAURI_SIGNING_PRIVATE_KEY` and `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` (Settings → Secrets and variables →
Actions) are required by the `release.yml` workflow to sign updates. They do not replace the placeholders in
`tauri.conf.json`: the public key and the endpoints must be set in the config.

1. Generate the signing key (once): `cargo tauri signer generate -w ~/.tauri/eleutheria.key`. This creates
   `eleutheria.key` (private) and `eleutheria.key.pub` (public). The private key and its password go into the repository
   secrets. An offline backup of the private key is mandatory: without it installed copies cannot be updated and
   users will have to reinstall the app.
2. Set the public key and the update endpoints in `tauri.conf.json`:

   ```
   scripts/set-updater.sh --pubkey-file ~/.tauri/eleutheria.key.pub --github OWNER/REPO [--mirror https://updates.site/eleutheria]
   ```

   The script replaces `plugins.updater.pubkey` and `plugins.updater.endpoints` and finishes by running the release check.
   It refuses a private key.
3. Make sure the version in `Cargo.toml` (`[workspace.package]`) and in `tauri.conf.json` match, then check:
   `scripts/check-release.sh vX.Y.Z`. The check blocks a release with placeholders, non-https addresses, disabled
   `requireSignedVersion` or mismatched versions.
4. Create the tag `vX.Y.Z` and push it to GitHub. The `release.yml` workflow runs:
   - `guard`: placeholder and version checks, mirror and signing script tests, the end-to-end app rollback test;
   - `build`: installers for Linux (deb, AppImage), macOS (dmg) and Windows (msi, exe) via `tauri-action`,
     signed update artifacts and `latest.json` in a **draft** release;
   - `mirror`: upload to an S3-compatible mirror, skipped if the `MIRROR_*` secrets are not set.

   Review the draft and click Publish: until then `latest.json` is not visible to users. It is best to do the first run
   on a test tag (for example `v0.0.1-test`), after bumping the version in both files.
5. Signing the installers is optional, but without it SmartScreen and Gatekeeper warn users.
   Windows: `WINDOWS_CERTIFICATE` (base64 of the `.pfx`), `WINDOWS_CERTIFICATE_PASSWORD`. macOS: `APPLE_CERTIFICATE`,
   `APPLE_CERTIFICATE_PASSWORD`, `APPLE_SIGNING_IDENTITY`, `APPLE_ID`, `APPLE_PASSWORD`, `APPLE_TEAM_ID`.
   A partially set group counts as an error. The repository variable `REQUIRE_SIGNING=true` forbids a release
   without complete signing (`scripts/check-signing.sh`).
6. The mirror is optional: secrets `MIRROR_S3_ENDPOINT`, `MIRROR_S3_BUCKET`, `MIRROR_BASE_URL`,
   `MIRROR_ACCESS_KEY_ID`, `MIRROR_SECRET_ACCESS_KEY`. `scripts/mirror-manifest.py` rewrites the addresses in `latest.json`.

## GUI

- `crates/eleutheria-app`: the service layer for the interface. Tests: `cargo test -p eleutheria-app`.
- `crates/eleutheria-gui`: the Tauri 2 shell, frontend in `frontend/` (static, no bundler, the Manrope font
  is bundled locally). Screen logic is split into pure modules with no DOM: `model.js` (home), `servermodel.js`
  (server wizard), `updatemodel.js`, `probermodel.js`, `guidemodel.js` (tour and help). Window permissions
  are minimal (`core:default`), app commands are declared in `src/main.rs`, and the CSP forbids external resources.
- Building on Linux requires `libwebkit2gtk-4.1-dev libxdo-dev libayatana-appindicator3-dev librsvg2-dev libssl-dev`.
- Running on Linux: `cargo run -p eleutheria-gui` (a display is required; in a container use Xvfb and
  `WEBKIT_DISABLE_COMPOSITING_MODE=1 WEBKIT_DISABLE_DMABUF_RENDERER=1`).
- Installers: `scripts/prepare-sidecars.sh` (builds `eleutheria` and `eleutheria-helper` and puts them in
  `crates/eleutheria-gui/binaries/`), then run in `crates/eleutheria-gui`:
  `cargo tauri build --config tauri.bundle.conf.json` (requires `cargo install tauri-cli --version "^2"`).
  Update artifacts (`createUpdaterArtifacts`) are added by the `tauri.updater.conf.json` config and are needed
  only for a release. Icons: `python3 scripts/gen-icons.py`.

## Tests and CI

- `cargo test --workspace --exclude eleutheria-gui`: unit tests for the core, CLI, helper and service layer (state
  and migration, config, links, pinning, key generation, profiles, updates, rollback).
- `npm install && npm test` in `crates/eleutheria-gui`: interface tests (Node and jsdom: screen models and
  `tests/ui.test.mjs`).
- `python3 -m unittest -v scripts/test_mirror_manifest.py` and `scripts/test_signing.sh`: mirror and signing scripts.
- `scripts/e2e-tun.sh`: client (helper, sing-box, CLI) and server in a network namespace. Checks the route through TUN,
  traffic leaving from the server, fake-ip DNS, absence of leaks, helper access rights, disconnect and reconnect.
  Creates a netns, veth and an address on lo.
- `scripts/e2e-prober.sh`: the prober and category switching. `scripts/e2e-rollback.sh`: app update rollback
  with the watchdog (also run in the release CI).
- `scripts/e2e-helper-install.sh`: `helper install/uninstall` with a systemctl stub.
- `scripts/e2e-local.sh`: an end-to-end rig on a local sshd with a real sing-box. It modifies the system (sshd_config,
  stubs in /usr/local/bin, an address on lo); run it only in a disposable container or VM as root.

CI (`.github/workflows/build.yml`) runs on every push and pull request on Linux, macOS and Windows: it runs the Rust
and interface tests, checks the GUI build and builds installers (artifacts are uploaded to the run). The release is described above.

## Limitations

- Server: root only, Ubuntu and Debian only. sing-box runs as root.
- The main protocol is VLESS + Reality. The fallback ones (Hysteria2, TUIC v5, Shadowsocks 2022, VLESS + WebSocket via CDN)
  and third-party profiles are enabled separately and are less tested.
- macOS builds in CI but has not been tested on a real machine.
- There is no kill-switch: if the helper or sing-box is stopped, traffic goes direct. This is intentional,
  so that a crash does not leave the system without a network.
- The helper service unit has almost no sandbox restrictions. A strict `CapabilityBoundingSet`
  is not enabled because sing-box needs several capabilities for auto_route.
- Fake-ip addresses are not preserved between tunnel restarts.
- `--ru-direct rulesets` has not been tested on a live network. The rule sets are downloaded from GitHub, which may be
  unavailable in Russia. `minimal` is enabled by default.
- `--test-url` must be https://, because the sing-box Clash API rewrites http:// to gstatic.
- Restarting the service when adding or removing a user briefly drops active connections.
- Hosting rules may change. At the time of release a VPN was allowed at all partners in the list (checked by the authors).
- The private SSH key is stored as a file with 600 permissions, unencrypted, unless the keyring is used.
- Installers are not signed with a Windows or Apple certificate until the corresponding CI secrets are set.
- In-app self-update will work only after the real public key and endpoints are put into `tauri.conf.json`
  (see [Releasing](#releasing)).
- The app does not host a subscription, and imports only the link schemes listed above.

## Roadmap

Next tasks:

- Testing the GUI and installer on a real macOS machine.
- Verifying update signing end to end on a test tag.
- Importing other protocols (vmess, trojan, etc.).
- Storing the SSH key in the keyring without a file.

## Fallback protocols

Besides VLESS + Reality, you can enable extra protocols on the server: `hysteria2`, `tuic`, `ss2022` and
`vless-ws` (needs a domain, see below). They are enabled at install time (`provision --protocols …`) or later:

```
eleutheria server protocols <IP>                          # what is enabled
eleutheria server protocols <IP> --enable hysteria2,tuic  # enable
eleutheria server protocols <IP> --disable tuic           # disable
```

The value `all` enables all built-in protocols except `vless-ws`. The user link for VLESS + Reality is printed
first, followed by one link for each enabled built-in protocol.

## CDN profile (VLESS + WebSocket)

If the server's IP is blocked but the VPS itself is alive, traffic can be routed through a CDN. You need your own domain
proxied by Cloudflare (orange cloud, TLS mode "Full"):

```
eleutheria server protocols <IP> --enable vless-ws --cdn-host cdn.example.com
```

The client connects to `cdn.example.com:443`, and Cloudflare forwards the traffic to the server (port 8443). The WebSocket
path is random and secret. The domain and the CDN are set up manually by you: the app only checks the shape of the name.

## Server fleet

Several of your own VPS with one user and one subscription (the servers must already be installed via `provision`):

```
eleutheria fleet add 203.0.113.5
eleutheria fleet add 203.0.113.6
eleutheria fleet list | remove <IP>
eleutheria fleet user-add alice      # one uuid and secret on all servers
eleutheria fleet sub alice --out sub.txt   # a base64 subscription with the links of all servers
eleutheria fleet update              # update sing-box everywhere, up-to-date ones are skipped
```

The app does not host the subscription: you have to serve the file yourself (it contains access keys, treat it like a password).

## External exit (someone else's proxy for selected sites)

If a site refuses the exit IPs of all your servers and you have another SOCKS5 proxy, you can chain it through
your server. The proxy sees which sites are opened through it, so explicit consent is required:

```
eleutheria exit add resi "socks5://login:password@198.51.100.7:1080" --via my-server --accept-exit-risk
eleutheria exit list
eleutheria watch --allow-external-exit
```

All traffic never goes to such a proxy: only categories (for example, video), and only when the site refuses the exit IP
of your servers but opens through the proxy. When your own server works again, the category returns to it.
Without `--allow-external-exit` the proxy is not even probed. The proxy address can only be given as an IP.

## Third-party protocol profiles

A profile is a folder of three files: `meta.yaml`, `server.json.tpl`, `client.json.tpl` (the format is the same as the
built-in ones in `crates/eleutheria-core/profiles/`: `vless-ws`, `ss2022`, `tuic`, `hysteria2`). The server template becomes
a sing-box inbound that runs on the VPS as root, so a third-party profile is validated strictly:

```
eleutheria profile list                   # built-in and installed
eleutheria profile diff ./my-profile      # what will change, writes nothing
eleutheria profile install ./my-profile   # validation, diff, [y/N] prompt
eleutheria profile remove my-profile
```

What is forbidden: types outside the list (vless, vmess, trojan, shadowsocks, hysteria2, tuic, shadowtls, anytls), the keys
`detour`, `fallback`, `acme` and any `*_path` (except the certificate and key, which Eleutheria itself substitutes),
unknown variables, `listen` other than `::`, a port not from `{{port}}`, a `tag` not equal to `id`, the `id` of a built-in
profile, and any extra files. `install.sh` is intentionally not supported: it would run on the server as root.
The result of substitution is validated, not the template text. On install a summary, a fingerprint and a diff are printed;
without a `y` answer (or `--yes`) nothing is written. Profiles are stored in `~/.config/eleutheria/profiles/<id>/` and are
re-validated on every read.

An installed profile is selected the same way as the built-in fallback protocols: by its `id`.

```
eleutheria provision <IP> --protocols my-profile
eleutheria server protocols <IP> --enable my-profile
```

There are no ready-made links for third-party profiles: client data is taken from the server state and the manifest, and the
`client.json.tpl` template decides which of it is needed. A server with such a profile is added to the client when it is installed
via `provision` on the same machine. Third-party profiles are the least tested: before using one on a real server,
read the `diff` and compare the fingerprint with the profile's author.
