package bypasser

import (
	"os"
	"path/filepath"
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
		WireGuardDir:    envOr("BP_WG_DIR", "/etc/wireguard"),
		PeersSubdir:     "peers",
		InterfacePrefix: "bp-",
		SysctlFile:      envOr("SYSCTL_CONF_FILE", "/etc/sysctl.d/bypasser-forwarding.conf"),
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
