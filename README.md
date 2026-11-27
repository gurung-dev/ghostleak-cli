# GhostLeak CLI

A terminal scanner for **your own device**. It reads local OS files and a short allow-list of local commands, then prints an exposure score. It does not open a socket, does not resolve DNS, and does not print secret values.

```
GhostLeak CLI Score: 74/100 [HIGH]
```

Python 3.8+ standard library only. After `git clone`, this works on Termux, Kali, Ubuntu/Debian, and macOS:

```bash
python3 ghostleak.py
```

## Privacy guarantee

GhostLeak is **100% offline**, has **zero runtime dependencies**, and makes **zero network calls**.

- No telemetry, no update check, no phone-home, no HTTP, no DNS lookups.
- Environment values, proxy URLs, shell history, SSH private keys, cookies, and saved passwords are never printed. Sensitive names show as `NAME = [REDACTED]`.
- History files and credential files are `stat`’d for permissions only. Their bytes are not read.
- Browser checks look for a Firefox `user.js` or a known content-blocker folder. They do not open cookie, history, or login databases.
- `--share` prints the score and risk tier only. No hostname, IP, username, path, or hash.

## Install

### Termux (Android)

```bash
pkg update && pkg install git python
git clone https://github.com/gurung-dev/ghostleak-cli.git
cd ghostleak-cli
python3 ghostleak.py
```

Optional command on `$PATH` (`$PREFIX/bin/ghostleak`):

```bash
sh install.sh
ghostleak --share
```

### Kali Linux / Ubuntu / Debian

```bash
sudo apt update && sudo apt install -y git python3
git clone https://github.com/gurung-dev/ghostleak-cli.git
cd ghostleak-cli
python3 ghostleak.py
```

Optional command in `~/.local/bin`:

```bash
sh install.sh
export PATH="$HOME/.local/bin:$PATH"
ghostleak --lang en
```

### macOS

```bash
git clone https://github.com/gurung-dev/ghostleak-cli.git
cd ghostleak-cli
python3 ghostleak.py
sh install.sh
```

`python3` from Xcode or python.org is enough. Nothing is installed from PyPI unless you want a console script:

```bash
pip install .
ghostleak --share
```

`pip install .` uses the included `pyproject.toml`. The scanner imports nothing outside the standard library, so there is no dependency list to install.

## Usage

```bash
python3 ghostleak.py                         # full color scan
python3 ghostleak.py --lang ne               # Nepali labels and tips
python3 ghostleak.py --share                 # score and tier only
python3 ghostleak.py --json                   # redacted JSON on stdout
python3 ghostleak.py --no-color               # plain ASCII, no ANSI
python3 ghostleak.py --export report.md       # private Markdown report
python3 ghostleak.py --export report.json     # private JSON report
python3 ghostleak.py --share --export share.txt
```

`NO_COLOR=1` also turns color off. JSON `risk_tier` stays `LOW`, `MODERATE`, `HIGH`, or `CRITICAL` in both languages. The Nepali label is `risk_tier_label`.

Exit status is `0` when the scan finishes, including a high score. Argument errors use status `2`. A failed export uses status `1`.

If a probe cannot run, that section shows `[RESTRICTED]` or `[NOT AVAILABLE]` and the rest of the scan continues. That is normal for unprivileged Termux and for firewall checks without root.

## Sample output

Plain mode (`--no-color`) looks like this. The colored UI uses the same layout with a cyan banner and a risk-colored meter.

```
   ____ _               _   _               _
  / ___| |__   ___  ___| |_| |    ___  __ _| | __
 | |  _| '_ \ / _ \/ __| __| |   / _ \/ _` | |/ /
 | |_| | | | | (_) \__ \ |_| |__|  __/ (_| |   <
  \____|_| |_|\___/|___/\__|_____\___|\__,_|_|\_\
GHOSTLEAK CLI  v1.0.0
local  |  offline  |  secrets redacted  |  zero network

-- exposure ------------------------------------
  exposure     [##########--------------]  42/100  MODERATE
  ghost id     7c1e0a9b2d4f86a1c0e5b7d39a24f6180c6e1b5a4d8f907132ab54cd67e809f1
  sources      machine-id, cpu-model, system, arch
  Score uses the static weight table (capped at 100).

-- scan readout --------------------------------
  [ok]  OS & Device Fingerprint
  [warn]  Network & VPN/Proxy Posture
  [warn]  Open Listening Ports
  [warn]  Environment & Shell Exposure
  [warn]  Firewall & Hardening
  [ok]  Browser Privacy Footprint

-- OS & Device Fingerprint ---------------------
  system       Linux
  distro       Kali GNU/Linux
  kernel       6.8.0-kali
  arch         x86_64
  cpu          4 cores | Example CPU
  hostname     devbox
  termux       no
  timezone     Asia/Kathmandu
  locale       en_US.UTF-8

-- Network & VPN/Proxy Posture -----------------
  eth0         192.168.1.20
  gateway      192.168.1.1
  dns          1.1.1.1
  vpn          none
  proxy        none

-- Open Listening Ports ------------------------
  EXPOSED  tcp  0.0.0.0:22
  LOCAL    tcp  127.0.0.1:5432

-- Environment & Shell Exposure ----------------
  sensitive    1  = [REDACTED]
  - GITHUB_TOKEN = [REDACTED]
  ssh          ~/.ssh  0700
  history      ~/.bash_history 0644

-- Firewall & Hardening ------------------------
  firewall     [NOT AVAILABLE]
  privileges   unprivileged

-- findings ------------------------------------
  [MODERATE] 1 socket(s) listening on all interfaces (tcp/0.0.0.0:22)  +8
  [MODERATE] Routable network is up and no VPN/tunnel interface was detected  +6
  [LOW] 1 sensitive environment name(s): GITHUB_TOKEN = [REDACTED]  +3
  [MODERATE] Shell history is world-readable (~/.bash_history (0644))  +8
  [LOW] Host firewall state could not be read  +4

-- hardening tips ------------------------------
  1. Bind the service to 127.0.0.1. For OpenSSH, set `ListenAddress 127.0.0.1` in `/etc/ssh/sshd_config` and restart sshd.
  2. No tun*, wg*, or tailscale* interface was seen. Bring up WireGuard (`wg-quick up <name>`) or Tailscale if you want a tunnel.
  3. These names are visible to every child process: GITHUB_TOKEN. Remove unused exports from ~/.bashrc or ~/.zshrc. GhostLeak does not print the values.
  4. History files can contain tokens you typed (~/.bash_history (0644)). Run: chmod 600 ~/.bash_history ~/.zsh_history ~/.sh_history
  5. Firewall state was not readable without privileges. Check `sudo ufw status` or `sudo nft list ruleset`. Unknown scores 4; running the scan as root scores 12.

Educational self-audit of this device only. GhostLeak does not open network connections, and it never prints secret values.
```

Safe share:

```
----------------------------------
GhostLeak CLI  |  safe share
100% offline  |  no host identifiers

GhostLeak CLI Score: 42/100 [MODERATE]
----------------------------------
```

## What it checks

| Probe | Local sources |
| --- | --- |
| OS & device | `platform`, `/etc/os-release`, `/proc/cpuinfo`, `sw_vers` on macOS, `getprop` on Android/Termux |
| Network & VPN | `ip` or `ifconfig`, `/proc/net/route` or `route`, `/etc/resolv.conf`, tunnel names `tun*`, `wg*`, `utun*`, `tailscale*` |
| Listening ports | `ss`, else `netstat`, else `/proc/net/tcp` and `udp` |
| Env & shell | Sensitive **names** only; modes of `~/.ssh`, history, and credential files |
| Firewall | `ufw`, `nft`, `iptables` on Linux; Application Firewall / `pfctl` on macOS. Skipped on Termux |
| Browsers | Installed browser plus a privacy marker. Stores are not opened |

Termux is detected from `TERMUX_VERSION`, `PREFIX` containing `com.termux`, or the Termux filesystem prefix. Android properties are read with `getprop` when it exists.

The **Machine Ghost ID** is the SHA-256 of stable local signals (machine-id or platform UUID or Android serial, plus CPU model, OS name, and architecture). The raw signals are not printed. The id is omitted from `--share`.

## Score

Each finding adds the points below, up to that row’s cap. The total is capped at **100**.

| Signal | Points each | Cap | Meaning |
| --- | ---: | ---: | --- |
| `wildcard_listener` | 8 | 24 | TCP/UDP socket bound to 0.0.0.0, ::, or * |
| `interface_listener` | 3 | 9 | Socket bound to a specific non-loopback address |
| `no_vpn` | 6 | 6 | Routable interface present and no VPN/tunnel interface |
| `sensitive_env` | 3 | 15 | Sensitive environment variable name is set (value is never stored) |
| `ssh_world_readable` | 12 | 12 | SSH directory or private key is world-readable or world-writable |
| `ssh_permissive` | 6 | 12 | SSH directory or private key is group-readable |
| `history_world_readable` | 8 | 8 | Shell history file is world-readable or world-writable |
| `history_group_readable` | 4 | 8 | Shell history file is group-readable |
| `secret_file_exposed` | 10 | 20 | Credential file is world-readable or world-writable |
| `secret_file_group` | 5 | 10 | Credential file is group-readable |
| `config_world_writable` | 6 | 12 | Shell startup file is world-writable |
| `firewall_off` | 15 | 15 | Host firewall reports that it is inactive |
| `firewall_unknown` | 4 | 4 | Host firewall state could not be read |
| `running_as_root` | 12 | 12 | The scan is running as root |
| `browser_no_privacy` | 3 | 9 | Installed browser has no detected privacy extension or user.js |

| Score | Tier |
| --- | --- |
| 0–24 | `LOW` |
| 25–49 | `MODERATE` |
| 50–74 | `HIGH` |
| 75–100 | `CRITICAL` |

Names treated as sensitive include `*_TOKEN`, `*_SECRET`, `*_PASSWORD`, `*_KEY`, `AWS_*`, `GITHUB_*`, and common database URLs. `PATH`, `HOME`, `USER`, and `PUBLIC_KEY` are not. A world-readable `~/.bash_history` is scored; its lines are not loaded.

Tips are chosen for Termux, macOS, or Linux (with an extra Kali note when a service listens on every interface). Do not run the whole scan under `sudo`. Root is its own finding (+12). Checking the firewall with `sudo ufw status` afterwards is enough.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

The suite covers scoring and caps, secret redaction (history, key material, env values, JSON, and export), `--share`, missing-command and Termux fallbacks, `--lang ne`, and a source scan that rejects `urllib.request`, `http.client`, `requests`, and other outbound modules.

## Disclaimer

GhostLeak is an educational local self-audit. It does not scan other hosts, exploit services, capture packets, or upload findings. A score is a weighted reading of this machine’s local posture, not a certificate of security. You are responsible for the changes you make from the tips.
