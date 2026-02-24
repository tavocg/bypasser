package bypasser

import (
	"fmt"
	"strconv"
	"strings"
)

func firstSectionValue(content, sectionName, key string) string {
	section := ""
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if isSectionHeader(line) {
			section = strings.TrimSpace(strings.Trim(line, "[]"))
			continue
		}
		if section != sectionName {
			continue
		}
		k, v, ok := splitKV(line)
		if ok && strings.EqualFold(k, key) {
			return v
		}
	}
	return ""
}

func allSectionValues(content, sectionName, key string) []string {
	var out []string
	section := ""
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if isSectionHeader(line) {
			section = strings.TrimSpace(strings.Trim(line, "[]"))
			continue
		}
		if section != sectionName {
			continue
		}
		k, v, ok := splitKV(line)
		if ok && strings.EqualFold(k, key) {
			out = append(out, v)
		}
	}
	return out
}

func splitKV(line string) (key, val string, ok bool) {
	i := strings.Index(line, "=")
	if i < 0 {
		return "", "", false
	}
	key = strings.TrimSpace(line[:i])
	val = strings.TrimSpace(line[i+1:])
	if key == "" {
		return "", "", false
	}
	return key, val, true
}

func isSectionHeader(line string) bool {
	return strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]")
}

func parseBPAddress(prefix, addr string) (vpnOctet, hostOctet int, err error) {
	base := addr
	if i := strings.Index(base, "/"); i >= 0 {
		base = base[:i]
	}
	want := prefix + "."
	if !strings.HasPrefix(base, want) {
		return 0, 0, fmt.Errorf("address %q does not match prefix %q", addr, prefix)
	}
	rest := strings.TrimPrefix(base, want)
	parts := strings.Split(rest, ".")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid address %q", addr)
	}
	vpnOctet, err = strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid vpn octet in %q", addr)
	}
	hostOctet, err = strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid host octet in %q", addr)
	}
	return vpnOctet, hostOctet, nil
}

func normalizeCIDR(addr string, mask int) string {
	if strings.Contains(addr, "/") {
		return addr
	}
	return fmt.Sprintf("%s/%d", addr, mask)
}

func removePeerBlock(content string, ref PeerRef, allowedIP string) (string, bool) {
	lines := strings.Split(content, "\n")
	out := make([]string, 0, len(lines))
	removed := false

	for i := 0; i < len(lines); {
		line := strings.TrimSpace(lines[i])
		if line != "[Peer]" {
			out = append(out, lines[i])
			i++
			continue
		}

		metaLine := ""
		if i > 0 {
			prev := strings.TrimSpace(lines[i-1])
			if strings.HasPrefix(prev, "# bp-managed:") {
				metaLine = prev
			}
		}

		j := i + 1
		for j < len(lines) && !isSectionHeader(strings.TrimSpace(lines[j])) {
			j++
		}
		block := lines[i:j]
		if peerBlockMatches(block, metaLine, ref, allowedIP) {
			removed = true
			if metaLine != "" && len(out) > 0 && strings.TrimSpace(out[len(out)-1]) == metaLine {
				out = out[:len(out)-1]
			}
			if len(out) > 0 && strings.TrimSpace(out[len(out)-1]) == "" {
				out = out[:len(out)-1]
			}

			// Preserve trailing blank/comment lines that actually belong to the next peer block.
			tailStart := j
			for k := j - 1; k > i; k-- {
				t := strings.TrimSpace(lines[k])
				if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, ";") {
					tailStart = k
					continue
				}
				break
			}
			if tailStart < j {
				out = append(out, lines[tailStart:j]...)
			}

			i = j
			continue
		}

		out = append(out, lines[i])
		i++
	}

	trimmed := strings.Join(out, "\n")
	trimmed = strings.TrimRight(trimmed, "\n")
	if trimmed != "" {
		trimmed += "\n"
	}
	return trimmed, removed
}

func peerBlockMatches(block []string, metaLine string, ref PeerRef, allowedIP string) bool {
	if metaLine != "" &&
		strings.Contains(metaLine, "vpn="+ref.VPN) &&
		strings.Contains(metaLine, "peer="+ref.Peer) {
		return true
	}

	for _, raw := range block {
		k, v, ok := splitKV(strings.TrimSpace(raw))
		if !ok || !strings.EqualFold(k, "AllowedIPs") {
			continue
		}
		if strings.TrimSpace(v) == strings.TrimSpace(allowedIP) {
			return true
		}
	}
	return false
}
