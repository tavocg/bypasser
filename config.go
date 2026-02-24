package bypasser

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
)

type Config struct {
	WireGuardDir    string
	PeersSubdir     string
	InterfacePrefix string
	SysctlFile      string

	MinPort int
	MaxPort int

	SubnetPrefix    string
	InterfaceMask   int
	PeerMask        int
	PublicInterface string
	EndpointHost    string

	FilePerm os.FileMode
	DirPerm  os.FileMode
}

func DefaultConfig() Config {
	return Config{
		WireGuardDir:    envOr("BP_WG_DIR", defaultWireGuardDir()),
		PeersSubdir:     "peers",
		InterfacePrefix: "bp-",
		SysctlFile:      envOr("SYSCTL_CONF_FILE", defaultSysctlFile()),
		MinPort:         envInt("BP_WG_DEFAULT_MIN_PORT", 55107),
		MaxPort:         envInt("BP_WG_DEFAULT_MAX_PORT", 55207),
		SubnetPrefix:    "69.0",
		InterfaceMask:   24,
		PeerMask:        32,
		PublicInterface: os.Getenv("BP_PUBLIC_IFACE"),
		EndpointHost:    os.Getenv("BP_ENDPOINT_HOST"),
		FilePerm:        0o600,
		DirPerm:         0o700,
	}
}

func (c Config) normalized() Config {
	d := DefaultConfig()
	if c.WireGuardDir == "" {
		c.WireGuardDir = d.WireGuardDir
	}
	if c.PeersSubdir == "" {
		c.PeersSubdir = d.PeersSubdir
	}
	if c.InterfacePrefix == "" {
		c.InterfacePrefix = d.InterfacePrefix
	}
	if c.SysctlFile == "" {
		c.SysctlFile = d.SysctlFile
	}
	if c.MinPort == 0 {
		c.MinPort = d.MinPort
	}
	if c.MaxPort == 0 {
		c.MaxPort = d.MaxPort
	}
	if c.SubnetPrefix == "" {
		c.SubnetPrefix = d.SubnetPrefix
	}
	if c.InterfaceMask == 0 {
		c.InterfaceMask = d.InterfaceMask
	}
	if c.PeerMask == 0 {
		c.PeerMask = d.PeerMask
	}
	if c.FilePerm == 0 {
		c.FilePerm = d.FilePerm
	}
	if c.DirPerm == 0 {
		c.DirPerm = d.DirPerm
	}
	return c
}

func (c Config) PeersDir() string {
	c = c.normalized()
	return filepath.Join(c.WireGuardDir, c.PeersSubdir)
}

func (c Config) InterfaceName(vpn string) string {
	c = c.normalized()
	return c.InterfacePrefix + vpn
}

func (c Config) VPNConfigPath(vpn string) string {
	c = c.normalized()
	return filepath.Join(c.WireGuardDir, c.InterfaceName(vpn)+".conf")
}

func (c Config) PeerConfigPath(vpn, peer string) string {
	c = c.normalized()
	return filepath.Join(c.PeersDir(), c.InterfaceName(vpn)+"-"+peer+".conf")
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

func defaultWireGuardDir() string {
	switch runtime.GOOS {
	case "linux":
		return "/etc/wireguard"
	case "darwin":
		for _, path := range darwinWireGuardCandidates(runtime.GOARCH) {
			if dirExists(path) {
				return path
			}
		}
		candidates := darwinWireGuardCandidates(runtime.GOARCH)
		if len(candidates) > 0 {
			return candidates[0]
		}
		return "/usr/local/etc/wireguard"
	case "windows":
		programFiles := os.Getenv("ProgramFiles")
		if programFiles == "" {
			programFiles = `C:\Program Files`
		}
		return filepath.Join(programFiles, "WireGuard", "Data", "Configurations")
	default:
		cfgDir, err := os.UserConfigDir()
		if err == nil && cfgDir != "" {
			return filepath.Join(cfgDir, "wireguard")
		}
		return filepath.Join(".", "wireguard")
	}
}

func defaultSysctlFile() string {
	if runtime.GOOS != "linux" {
		return ""
	}
	return "/etc/sysctl.d/bypasser-forwarding.conf"
}

func darwinWireGuardCandidates(goarch string) []string {
	var out []string
	if brewPrefix := os.Getenv("HOMEBREW_PREFIX"); brewPrefix != "" {
		out = append(out, filepath.Join(brewPrefix, "etc", "wireguard"))
	}
	if goarch == "arm64" {
		out = append(out, "/opt/homebrew/etc/wireguard", "/usr/local/etc/wireguard")
	} else {
		out = append(out, "/usr/local/etc/wireguard", "/opt/homebrew/etc/wireguard")
	}
	out = append(out, "/etc/wireguard")
	return out
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
