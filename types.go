package bypasser

import (
	"fmt"
	"regexp"
)

type Change struct {
	Action string
	Path   string
}

type RuntimeAction struct {
	Description string
	Command     string
	Status      string // "executed" or "suggested"
	Message     string
}

type Report struct {
	Changes        []Change
	RuntimeActions []RuntimeAction
	Warnings       []string
}

type AddVPNResult struct {
	Report
	VPN        string
	Interface  string
	ConfigPath string
}

type PeerRef struct {
	VPN  string
	Peer string
}

func (p PeerRef) String() string { return p.VPN + ":" + p.Peer }

type AddPeerResult struct {
	Report
	PeerRef
	PeerConfigPath string
	PeerConfig     string
}

var nameRE = regexp.MustCompile(`^[a-z0-9]+$`)

func ValidateName(kind, name string) error {
	if !nameRE.MatchString(name) {
		return fmt.Errorf("invalid %s name %q: use only lowercase letters and numbers", kind, name)
	}
	return nil
}

func ParsePeerRef(s string) (PeerRef, error) {
	var p PeerRef
	for i := 0; i < len(s); i++ {
		if s[i] != ':' {
			continue
		}
		p.VPN = s[:i]
		p.Peer = s[i+1:]
		if p.VPN == "" || p.Peer == "" {
			return PeerRef{}, fmt.Errorf("invalid peer name %q: expected vpn:peer", s)
		}
		if err := ValidateName("vpn", p.VPN); err != nil {
			return PeerRef{}, err
		}
		if err := ValidateName("peer", p.Peer); err != nil {
			return PeerRef{}, err
		}
		return p, nil
	}
	return PeerRef{}, fmt.Errorf("invalid peer name %q: expected vpn:peer", s)
}

func (r *Report) addChange(action, path string) {
	r.Changes = append(r.Changes, Change{Action: action, Path: path})
}

func (r *Report) warnf(format string, args ...any) {
	r.Warnings = append(r.Warnings, fmt.Sprintf(format, args...))
}

func (r *Report) addRuntime(a RuntimeAction) {
	r.RuntimeActions = append(r.RuntimeActions, a)
}
