package bypasser

import (
	"strings"
	"testing"
)

func TestParsePeerRef(t *testing.T) {
	t.Parallel()

	got, err := ParsePeerRef("home:laptop")
	if err != nil {
		t.Fatalf("ParsePeerRef returned error: %v", err)
	}
	if got.VPN != "home" || got.Peer != "laptop" {
		t.Fatalf("unexpected peer ref: %#v", got)
	}
}

func TestRemovePeerBlockByManagedComment(t *testing.T) {
	t.Parallel()

	in := `# bp-managed: vpn=home,peer=laptop
[Peer]
PublicKey = AAA
AllowedIPs = 69.0.1.2/32

# bp-managed: vpn=home,peer=phone
[Peer]
PublicKey = BBB
AllowedIPs = 69.0.1.3/32
`

	out, removed := removePeerBlock(in, PeerRef{VPN: "home", Peer: "laptop"}, "69.0.1.2/32")
	if !removed {
		t.Fatal("expected peer block to be removed")
	}
	if out == in {
		t.Fatal("expected content to change")
	}
	if wantMissing := "peer=laptop"; strings.Contains(out, wantMissing) {
		t.Fatalf("expected output not to contain %q", wantMissing)
	}
	if !strings.Contains(out, "peer=phone") {
		t.Fatal("expected other peer block to remain")
	}
}
