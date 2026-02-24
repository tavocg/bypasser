# bypasser

`bypasser` is a small Go library + CLI helper that generates WireGuard configuration files for building server-side VPN/peer topologies (useful for CGNAT bypass setups).

It focuses on file creation and safe server-side workflow helpers:

- Create/delete VPN configs
- Create/delete peer configs
- Prepare base server directories and forwarding sysctl file
- Optionally run `systemctl` / `wg-quick` / `sysctl` when available and running as root
- Otherwise print suggested commands

## Project Layout

- Library package: `github.com/tavocg/bypasser`
- CLI entrypoint: `./cmd/bp`

## Build

```bash
go build -o ./bp ./cmd/bp
```

## Usage

```bash
bp [-a|-add|-d|-del|-server] [vpn|peer] [-n name]
```

Rules:

- If target is omitted, `peer` is assumed
- For peer operations, `name` must be `vpn:peer`
- Names must be lowercase alphanumeric (`[a-z0-9]+`)
- If `-n` is omitted, interactive prompts/menus are shown

Examples:

```bash
bp -server
bp -a vpn -n home
bp -a -n home:laptop
bp -d vpn
bp -d
```

## Safe Local Testing (no `/etc` writes)

```bash
BP_WG_DIR=./.bypasser-test/wg \
SYSCTL_CONF_FILE=./.bypasser-test/sysctl.conf \
./bp -server
```

For VPN/peer creation you need `wg` installed (`wireguard-tools`). `ip` is only used as a fallback on Linux if native interface detection fails.

## Deploy / Update (Linux Server)

Install dependencies (Debian/Ubuntu example):

```bash
sudo apt-get update
sudo apt-get install -y wireguard-tools iproute2 iptables curl tar
```

Download/update the latest release binary to `/usr/local/bin/bp`:

```bash
OS="$(uname -s)"
ARCH="$(uname -m)"
ASSET="bp_${OS,,}_${ARCH}"
URL="https://github.com/tavocg/bypasser/releases/latest/download/${ASSET}.tar.gz"

curl -fsSL "$URL" | sudo tar -xz -C /usr/local/bin --strip-components=1 "${ASSET}/bp"
sudo chmod 0755 /usr/local/bin/bp
```

First-time server setup (creates WireGuard directories and forwarding sysctl file):

```bash
sudo bp -server
```

## Environment Overrides

| Variable | Default | Purpose |
| --- | --- | --- |
| `BP_WG_DIR` | OS-specific (`/etc/wireguard` on Linux, Homebrew `etc/wireguard` on macOS, `C:\Program Files\WireGuard\Data\Configurations` on Windows) | Base directory for generated WireGuard configs |
| `SYSCTL_CONF_FILE` | Linux only: `/etc/sysctl.d/bypasser-forwarding.conf` | Forwarding sysctl file written by `bp -server` |
| `BP_WG_DEFAULT_MIN_PORT` | `55107` | Minimum listen port when auto-assigning new VPN ports |
| `BP_WG_DEFAULT_MAX_PORT` | `55207` | Maximum listen port when auto-assigning new VPN ports |
| `BP_PUBLIC_IFACE` | auto-detected | Public server interface used in iptables `PostUp`/`PostDown` |
| `BP_ENDPOINT_HOST` | auto-detected | Endpoint host/IP written to generated peer configs |

## Import as a Package

```go
package main

import (
	"context"

	"github.com/tavocg/bypasser"
)

func main() {
	mgr := bypasser.NewManager(bypasser.DefaultConfig(), bypasser.Dependencies{})
	_, _ = mgr.SetupServer(context.Background())
}
```

## Notes

- The generated files follow the conventions from the original shell prototype in this repository.
- `-server` prepares server base files (directories + sysctl forwarding config on Linux); it does not create a VPN interface by itself.
