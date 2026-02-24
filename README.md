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
BP_WG_DIR=/tmp/bypasser-test/wg \
SYSCTL_CONF_FILE=/tmp/bypasser-test/sysctl.conf \
./bp -server
```

For VPN/peer creation you also need `wg` and `ip` installed on the machine.

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
- `-server` prepares server base files (directories + sysctl forwarding config); it does not create a VPN interface by itself.
