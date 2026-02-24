package bypasser

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Dependencies struct {
	System System
	Keys   KeyGenerator
}

type Manager struct {
	cfg  Config
	sys  System
	keys KeyGenerator
}

func NewManager(cfg Config, deps Dependencies) *Manager {
	cfg = cfg.normalized()
	sys := deps.System
	if sys == nil {
		sys = ExecSystem{}
	}
	keys := deps.Keys
	if keys == nil {
		keys = WGCLIKeyGenerator{System: sys}
	}
	return &Manager{cfg: cfg, sys: sys, keys: keys}
}

func (m *Manager) Config() Config { return m.cfg }

func (m *Manager) SetupServer(ctx context.Context) (Report, error) {
	var rep Report

	if err := m.ensureDir(m.cfg.WireGuardDir, &rep); err != nil {
		return rep, err
	}
	if err := m.ensureDir(m.cfg.PeersDir(), &rep); err != nil {
		return rep, err
	}

	if m.cfg.SysctlFile == "" {
		rep.warnf("skipping sysctl forwarding file setup on %s; set SYSCTL_CONF_FILE if you want to override", runtime.GOOS)
		return rep, nil
	}

	sysctl := "net.ipv4.ip_forward = 1\nnet.ipv6.conf.all.forwarding = 1\n"
	if err := m.writeFile(m.cfg.SysctlFile, []byte(sysctl), &rep); err != nil {
		return rep, err
	}

	m.maybeRun(ctx, &rep, "Apply sysctl forwarding settings", []string{"sysctl", "--system"})
	return rep, nil
}

func (m *Manager) ListVPNs() ([]string, error) {
	entries, err := os.ReadDir(m.cfg.WireGuardDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}

	var vpns []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, m.cfg.InterfacePrefix) || !strings.HasSuffix(name, ".conf") {
			continue
		}
		vpn := strings.TrimSuffix(strings.TrimPrefix(name, m.cfg.InterfacePrefix), ".conf")
		if vpn == "" {
			continue
		}
		vpns = append(vpns, vpn)
	}
	sort.Strings(vpns)
	return vpns, nil
}

func (m *Manager) ListPeers() ([]PeerRef, error) {
	entries, err := os.ReadDir(m.cfg.PeersDir())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}

	var peers []PeerRef
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, m.cfg.InterfacePrefix) || !strings.HasSuffix(name, ".conf") {
			continue
		}
		base := strings.TrimSuffix(strings.TrimPrefix(name, m.cfg.InterfacePrefix), ".conf")
		parts := strings.SplitN(base, "-", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			continue
		}
		peers = append(peers, PeerRef{VPN: parts[0], Peer: parts[1]})
	}
	sort.Slice(peers, func(i, j int) bool {
		if peers[i].VPN == peers[j].VPN {
			return peers[i].Peer < peers[j].Peer
		}
		return peers[i].VPN < peers[j].VPN
	})
	return peers, nil
}

func (m *Manager) AddVPN(ctx context.Context, name string) (AddVPNResult, error) {
	var out AddVPNResult
	if err := ValidateName("vpn", name); err != nil {
		return out, err
	}

	if err := m.ensureDir(m.cfg.WireGuardDir, &out.Report); err != nil {
		return out, err
	}
	if err := m.ensureDir(m.cfg.PeersDir(), &out.Report); err != nil {
		return out, err
	}

	confPath := m.cfg.VPNConfigPath(name)
	if _, err := os.Stat(confPath); err == nil {
		return out, fmt.Errorf("vpn %q already exists (%s)", name, confPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return out, err
	}

	port, err := m.nextAvailablePort()
	if err != nil {
		return out, err
	}
	vpnOctet, err := m.nextVPNSubnetOctet()
	if err != nil {
		return out, err
	}
	iface, err := m.detectDefaultInterface(ctx)
	if err != nil {
		return out, err
	}
	privateKey, err := m.keys.GeneratePrivateKey(ctx)
	if err != nil {
		return out, err
	}

	interfaceName := m.cfg.InterfaceName(name)
	conf := m.renderVPNConfig(name, interfaceName, privateKey, port, vpnOctet, iface)
	if err := m.writeFile(confPath, []byte(conf), &out.Report); err != nil {
		return out, err
	}

	out.VPN = name
	out.Interface = interfaceName
	out.ConfigPath = confPath

	m.maybeVPNEnable(ctx, &out.Report, name)
	return out, nil
}

func (m *Manager) DeleteVPN(ctx context.Context, name string) (Report, error) {
	var rep Report
	if err := ValidateName("vpn", name); err != nil {
		return rep, err
	}

	confPath := m.cfg.VPNConfigPath(name)
	if _, err := os.Stat(confPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return rep, fmt.Errorf("vpn %q does not exist (%s)", name, confPath)
		}
		return rep, err
	}

	m.maybeVPNDisable(ctx, &rep, name)
	if err := os.Remove(confPath); err != nil {
		return rep, err
	}
	rep.addChange("deleted", confPath)

	peers, _ := m.ListPeers()
	count := 0
	for _, p := range peers {
		if p.VPN == name {
			count++
		}
	}
	if count > 0 {
		rep.warnf("%d peer file(s) for vpn %q still exist under %s", count, name, m.cfg.PeersDir())
	}

	return rep, nil
}

func (m *Manager) AddPeer(ctx context.Context, vpnName, peerName string) (AddPeerResult, error) {
	var out AddPeerResult
	if err := ValidateName("vpn", vpnName); err != nil {
		return out, err
	}
	if err := ValidateName("peer", peerName); err != nil {
		return out, err
	}

	if err := m.ensureDir(m.cfg.PeersDir(), &out.Report); err != nil {
		return out, err
	}

	vpnPath := m.cfg.VPNConfigPath(vpnName)
	vpnBytes, err := os.ReadFile(vpnPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return out, fmt.Errorf("vpn %q does not exist (%s)", vpnName, vpnPath)
		}
		return out, err
	}
	vpnContent := string(vpnBytes)

	peerPath := m.cfg.PeerConfigPath(vpnName, peerName)
	if _, err := os.Stat(peerPath); err == nil {
		return out, fmt.Errorf("peer %q already exists (%s)", PeerRef{VPN: vpnName, Peer: peerName}.String(), peerPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return out, err
	}

	serverPriv := firstSectionValue(vpnContent, "Interface", "PrivateKey")
	if serverPriv == "" {
		return out, fmt.Errorf("vpn config %s is missing Interface.PrivateKey", vpnPath)
	}
	serverPub, err := m.keys.DerivePublicKey(ctx, serverPriv)
	if err != nil {
		return out, err
	}
	listenPortStr := firstSectionValue(vpnContent, "Interface", "ListenPort")
	if listenPortStr == "" {
		return out, fmt.Errorf("vpn config %s is missing Interface.ListenPort", vpnPath)
	}
	listenPort, err := strconv.Atoi(listenPortStr)
	if err != nil {
		return out, fmt.Errorf("invalid ListenPort %q in %s", listenPortStr, vpnPath)
	}
	addr := firstSectionValue(vpnContent, "Interface", "Address")
	if addr == "" {
		return out, fmt.Errorf("vpn config %s is missing Interface.Address", vpnPath)
	}
	vpnOctet, _, err := parseBPAddress(m.cfg.SubnetPrefix, addr)
	if err != nil {
		return out, err
	}
	nextHost, err := m.nextPeerHostOctet(vpnContent, vpnOctet)
	if err != nil {
		return out, err
	}

	peerPriv, err := m.keys.GeneratePrivateKey(ctx)
	if err != nil {
		return out, err
	}
	peerPub, err := m.keys.DerivePublicKey(ctx, peerPriv)
	if err != nil {
		return out, err
	}
	psk, err := m.keys.GeneratePresharedKey(ctx)
	if err != nil {
		return out, err
	}

	endpointHost := m.cfg.EndpointHost
	if endpointHost == "" {
		host, hostErr := m.detectServerIPv4(ctx)
		if hostErr != nil {
			endpointHost = "<server-public-ip>"
			out.Report.warnf("could not detect server public IPv4 automatically: %v", hostErr)
		} else {
			endpointHost = host
		}
	}

	peerAddr := fmt.Sprintf("%s.%d.%d/%d", m.cfg.SubnetPrefix, vpnOctet, nextHost, m.cfg.PeerMask)
	meshCIDR := fmt.Sprintf("%s.%d.0/%d", m.cfg.SubnetPrefix, vpnOctet, m.cfg.InterfaceMask)

	serverBlock := m.renderServerPeerBlock(vpnName, peerName, peerPub, psk, peerAddr)
	updatedVPN := strings.TrimRight(vpnContent, "\n") + "\n\n" + serverBlock
	if err := m.writeFile(vpnPath, []byte(updatedVPN), &out.Report); err != nil {
		return out, err
	}

	clientConf := m.renderClientPeerConfig(vpnName, peerName, peerPriv, peerAddr, serverPub, psk, meshCIDR, endpointHost, listenPort)
	if err := m.writeFile(peerPath, []byte(clientConf), &out.Report); err != nil {
		return out, err
	}

	out.PeerRef = PeerRef{VPN: vpnName, Peer: peerName}
	out.PeerConfigPath = peerPath
	out.PeerConfig = clientConf

	m.maybeVPNRestart(ctx, &out.Report, vpnName)
	return out, nil
}

func (m *Manager) DeletePeer(ctx context.Context, vpnName, peerName string) (Report, error) {
	var rep Report
	if err := ValidateName("vpn", vpnName); err != nil {
		return rep, err
	}
	if err := ValidateName("peer", peerName); err != nil {
		return rep, err
	}

	peerPath := m.cfg.PeerConfigPath(vpnName, peerName)
	peerBytes, err := os.ReadFile(peerPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return rep, fmt.Errorf("peer %q does not exist (%s)", PeerRef{VPN: vpnName, Peer: peerName}.String(), peerPath)
		}
		return rep, err
	}
	peerAddr := firstSectionValue(string(peerBytes), "Interface", "Address")
	if peerAddr == "" {
		rep.warnf("peer file %s missing Interface.Address; will remove file but may not clean vpn peer block", peerPath)
	}
	peerAddr = normalizeCIDR(peerAddr, m.cfg.PeerMask)

	vpnPath := m.cfg.VPNConfigPath(vpnName)
	vpnBytes, err := os.ReadFile(vpnPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			rep.warnf("vpn config %s not found; only deleting peer file", vpnPath)
		} else {
			return rep, err
		}
	} else {
		updated, removed := removePeerBlock(string(vpnBytes), PeerRef{VPN: vpnName, Peer: peerName}, peerAddr)
		if removed {
			if err := m.writeFile(vpnPath, []byte(updated), &rep); err != nil {
				return rep, err
			}
		} else {
			rep.warnf("peer block for %s was not found in %s", PeerRef{VPN: vpnName, Peer: peerName}.String(), vpnPath)
		}
	}

	if err := os.Remove(peerPath); err != nil {
		return rep, err
	}
	rep.addChange("deleted", peerPath)

	m.maybeVPNRestart(ctx, &rep, vpnName)
	return rep, nil
}

func (m *Manager) ensureDir(path string, rep *Report) error {
	info, err := os.Stat(path)
	if err == nil {
		if !info.IsDir() {
			return fmt.Errorf("%s exists but is not a directory", path)
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(path, m.cfg.DirPerm); err != nil {
		return err
	}
	rep.addChange("created", path)
	return nil
}

func (m *Manager) writeFile(path string, data []byte, rep *Report) error {
	action := "created"
	if old, err := os.ReadFile(path); err == nil {
		if bytes.Equal(old, data) {
			return nil
		}
		action = "updated"
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(path), m.cfg.DirPerm); err != nil {
		return err
	}
	if err := os.WriteFile(path, data, m.cfg.FilePerm); err != nil {
		return err
	}
	rep.addChange(action, path)
	return nil
}

func (m *Manager) nextAvailablePort() (int, error) {
	vpns, err := m.ListVPNs()
	if err != nil {
		return 0, err
	}
	maxPort := m.cfg.MinPort - 1
	for _, vpn := range vpns {
		b, err := os.ReadFile(m.cfg.VPNConfigPath(vpn))
		if err != nil {
			return 0, err
		}
		p := firstSectionValue(string(b), "Interface", "ListenPort")
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err == nil && n > maxPort {
			maxPort = n
		}
	}
	next := maxPort + 1
	if next < m.cfg.MinPort {
		next = m.cfg.MinPort
	}
	if next > m.cfg.MaxPort {
		return 0, fmt.Errorf("no available port in range %d-%d", m.cfg.MinPort, m.cfg.MaxPort)
	}
	return next, nil
}

func (m *Manager) nextVPNSubnetOctet() (int, error) {
	vpns, err := m.ListVPNs()
	if err != nil {
		return 0, err
	}
	highest := 0
	for _, vpn := range vpns {
		b, err := os.ReadFile(m.cfg.VPNConfigPath(vpn))
		if err != nil {
			return 0, err
		}
		addr := firstSectionValue(string(b), "Interface", "Address")
		if addr == "" {
			continue
		}
		vpnOctet, _, err := parseBPAddress(m.cfg.SubnetPrefix, addr)
		if err != nil {
			continue
		}
		if vpnOctet > highest {
			highest = vpnOctet
		}
	}
	next := highest + 1
	if next > 254 {
		return 0, fmt.Errorf("no available vpn subnet octet left in %s.X.0/24", m.cfg.SubnetPrefix)
	}
	return next, nil
}

func (m *Manager) nextPeerHostOctet(vpnConfig string, vpnOctet int) (int, error) {
	highest := 1
	for _, ip := range allSectionValues(vpnConfig, "Peer", "AllowedIPs") {
		v, h, err := parseBPAddress(m.cfg.SubnetPrefix, ip)
		if err != nil || v != vpnOctet {
			continue
		}
		if h > highest {
			highest = h
		}
	}
	next := highest + 1
	if next > 254 {
		return 0, fmt.Errorf("no available peer addresses left in vpn %d", vpnOctet)
	}
	return next, nil
}

func (m *Manager) detectDefaultInterface(ctx context.Context) (string, error) {
	if m.cfg.PublicInterface != "" {
		return m.cfg.PublicInterface, nil
	}

	if localIP, err := m.detectOutboundIPv4(ctx); err == nil {
		if iface, err := m.findInterfaceByIPv4(localIP); err == nil {
			return iface, nil
		}
	}

	if !m.sys.HasCommand("ip") {
		return "", fmt.Errorf("could not determine default interface natively and ip command not found; set BP_PUBLIC_IFACE or Config.PublicInterface")
	}
	out, err := m.sys.Output(ctx, "ip", "-4", "route", "show", "default")
	if err != nil {
		return "", err
	}
	fields := strings.Fields(out)
	for i := 0; i < len(fields)-1; i++ {
		if fields[i] == "dev" && fields[i+1] != "" {
			return fields[i+1], nil
		}
	}
	return "", fmt.Errorf("could not determine default interface from %q", out)
}

func (m *Manager) detectServerIPv4(ctx context.Context) (string, error) {
	if m.cfg.EndpointHost != "" {
		return m.cfg.EndpointHost, nil
	}

	if localIP, err := m.detectOutboundIPv4(ctx); err == nil {
		return localIP.String(), nil
	}

	iface, err := m.detectDefaultInterface(ctx)
	if err != nil {
		return "", err
	}
	if !m.sys.HasCommand("ip") {
		return "", fmt.Errorf("ip command not found")
	}
	out, err := m.sys.Output(ctx, "ip", "-4", "-o", "addr", "show", "dev", iface, "scope", "global")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		for i := 0; i < len(fields)-1; i++ {
			if fields[i] == "inet" {
				ip := strings.TrimSpace(fields[i+1])
				if slash := strings.IndexByte(ip, '/'); slash >= 0 {
					ip = ip[:slash]
				}
				if net.ParseIP(ip) != nil {
					return ip, nil
				}
			}
		}
	}
	return "", fmt.Errorf("could not detect ipv4 on interface %s", iface)
}

func (m *Manager) detectOutboundIPv4(ctx context.Context) (net.IP, error) {
	dialCtx := ctx
	if dialCtx == nil {
		dialCtx = context.Background()
	}

	// UDP "connect" picks a route and local address without requiring a real handshake.
	probes := []string{"1.1.1.1:53", "8.8.8.8:53"}
	dialer := net.Dialer{Timeout: 2 * time.Second}

	var lastErr error
	for _, probe := range probes {
		conn, err := dialer.DialContext(dialCtx, "udp4", probe)
		if err != nil {
			lastErr = err
			continue
		}

		localAddr := conn.LocalAddr()
		addr, ok := localAddr.(*net.UDPAddr)
		_ = conn.Close()
		if !ok || addr == nil || addr.IP == nil {
			lastErr = fmt.Errorf("unexpected local address type %T", localAddr)
			continue
		}

		ip := addr.IP.To4()
		if ip == nil {
			lastErr = fmt.Errorf("detected non-ipv4 local address %q", addr.IP.String())
			continue
		}
		return ip, nil
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("no probe address succeeded")
	}
	return nil, lastErr
}

func (m *Manager) findInterfaceByIPv4(target net.IP) (string, error) {
	target = target.To4()
	if target == nil {
		return "", fmt.Errorf("target is not an ipv4 address")
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ip := ipv4FromAddr(addr)
			if ip == nil {
				continue
			}
			if ip.Equal(target) {
				return iface.Name, nil
			}
		}
	}

	return "", fmt.Errorf("no interface found for local ipv4 %s", target.String())
}

func ipv4FromAddr(addr net.Addr) net.IP {
	switch a := addr.(type) {
	case *net.IPNet:
		return a.IP.To4()
	case *net.IPAddr:
		return a.IP.To4()
	default:
		return nil
	}
}

func (m *Manager) renderVPNConfig(vpnName, ifaceName, privateKey string, port, vpnOctet int, publicIface string) string {
	meshCIDR := fmt.Sprintf("%s.%d.0/%d", m.cfg.SubnetPrefix, vpnOctet, m.cfg.InterfaceMask)
	addr := fmt.Sprintf("%s.%d.1/%d", m.cfg.SubnetPrefix, vpnOctet, m.cfg.InterfaceMask)
	postUp := fmt.Sprintf(
		"iptables -t nat -A POSTROUTING -s %s -o %s -j MASQUERADE; iptables -A INPUT -p udp -m udp --dport %d -j ACCEPT; iptables -A FORWARD -i %s -j ACCEPT; iptables -A FORWARD -o %s -j ACCEPT;",
		meshCIDR, publicIface, port, ifaceName, ifaceName,
	)
	postDown := fmt.Sprintf(
		"iptables -t nat -D POSTROUTING -s %s -o %s -j MASQUERADE; iptables -D INPUT -p udp -m udp --dport %d -j ACCEPT; iptables -D FORWARD -i %s -j ACCEPT; iptables -D FORWARD -o %s -j ACCEPT;",
		meshCIDR, publicIface, port, ifaceName, ifaceName,
	)
	return fmt.Sprintf(`# bp-managed: vpn=%s
[Interface]
PrivateKey = %s
ListenPort = %d
Address = %s
PostUp = %s
PostDown = %s
`, vpnName, privateKey, port, addr, postUp, postDown)
}

func (m *Manager) renderServerPeerBlock(vpnName, peerName, peerPub, psk, allowedIP string) string {
	return fmt.Sprintf(`# bp-managed: vpn=%s,peer=%s
[Peer]
PublicKey = %s
PresharedKey = %s
AllowedIPs = %s
`, vpnName, peerName, peerPub, psk, allowedIP)
}

func (m *Manager) renderClientPeerConfig(vpnName, peerName, peerPriv, peerAddr, serverPub, psk, meshCIDR, endpointHost string, port int) string {
	return fmt.Sprintf(`# bp-managed: vpn=%s,peer=%s
[Interface]
PrivateKey = %s
Address = %s

[Peer]
PublicKey = %s
PresharedKey = %s
AllowedIPs = %s
Endpoint = %s:%d
PersistentKeepalive = 25
`, vpnName, peerName, peerPriv, peerAddr, serverPub, psk, meshCIDR, endpointHost, port)
}

func (m *Manager) maybeRun(ctx context.Context, rep *Report, description string, cmd []string) {
	if len(cmd) == 0 {
		return
	}
	act := RuntimeAction{
		Description: description,
		Command:     strings.Join(cmd, " "),
		Status:      "suggested",
	}

	if !m.sys.HasCommand(cmd[0]) {
		act.Message = "command not available"
		rep.addRuntime(act)
		return
	}
	if !m.sys.IsRoot() {
		act.Message = "not running as root"
		rep.addRuntime(act)
		return
	}
	if err := m.sys.Run(ctx, cmd[0], cmd[1:]...); err != nil {
		act.Message = err.Error()
		rep.addRuntime(act)
		return
	}
	act.Status = "executed"
	act.Message = "ok"
	rep.addRuntime(act)
}

func (m *Manager) maybeVPNEnable(ctx context.Context, rep *Report, vpn string) {
	iface := m.cfg.InterfaceName(vpn)
	if m.sys.HasCommand("systemctl") {
		m.maybeRun(ctx, rep, "Enable/start WireGuard interface", []string{"systemctl", "enable", "--now", "wg-quick@" + iface})
		return
	}
	m.maybeRun(ctx, rep, "Bring up WireGuard interface", []string{"wg-quick", "up", iface})
}

func (m *Manager) maybeVPNDisable(ctx context.Context, rep *Report, vpn string) {
	iface := m.cfg.InterfaceName(vpn)
	if m.sys.HasCommand("systemctl") {
		m.maybeRun(ctx, rep, "Disable/stop WireGuard interface", []string{"systemctl", "disable", "--now", "wg-quick@" + iface})
		return
	}
	m.maybeRun(ctx, rep, "Bring down WireGuard interface", []string{"wg-quick", "down", iface})
}

func (m *Manager) maybeVPNRestart(ctx context.Context, rep *Report, vpn string) {
	iface := m.cfg.InterfaceName(vpn)
	if m.sys.HasCommand("systemctl") {
		m.maybeRun(ctx, rep, "Restart WireGuard interface", []string{"systemctl", "restart", "wg-quick@" + iface})
		return
	}
	m.maybeRun(ctx, rep, "Restart WireGuard interface", []string{"wg-quick", "down", iface})
	m.maybeRun(ctx, rep, "Restart WireGuard interface", []string{"wg-quick", "up", iface})
}
