package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/tavocg/bypasser"
)

type actionKind string

const (
	actionNone   actionKind = ""
	actionAdd    actionKind = "add"
	actionDelete actionKind = "del"
	actionServer actionKind = "server"
)

type targetKind string

const (
	targetPeer targetKind = "peer"
	targetVPN  targetKind = "vpn"
)

type options struct {
	Action actionKind
	Target targetKind
	Name   string
	Help   bool
}

func main() {
	opts, err := parseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		printUsage(os.Stderr)
		os.Exit(2)
	}
	if opts.Help || opts.Action == actionNone {
		printUsage(os.Stdout)
		return
	}

	mgr := bypasser.NewManager(bypasser.DefaultConfig(), bypasser.Dependencies{})
	ctx := context.Background()
	reader := bufio.NewReader(os.Stdin)

	switch opts.Action {
	case actionServer:
		rep, err := mgr.SetupServer(ctx)
		exitOnErr(err)
		fmt.Println("Server base files prepared (directories + forwarding sysctl config).")
		printReport(rep)
		return
	case actionAdd:
		handleAdd(ctx, mgr, reader, opts)
		return
	case actionDelete:
		handleDelete(ctx, mgr, reader, opts)
		return
	default:
		fmt.Fprintln(os.Stderr, "Error: unsupported action")
		os.Exit(2)
	}
}

func handleAdd(ctx context.Context, mgr *bypasser.Manager, reader *bufio.Reader, opts options) {
	switch opts.Target {
	case targetVPN:
		name := opts.Name
		if name == "" {
			name = promptValidatedName(reader, "vpn")
		} else {
			exitOnErr(bypasser.ValidateName("vpn", name))
		}
		res, err := mgr.AddVPN(ctx, name)
		exitOnErr(err)
		fmt.Printf("Created VPN %q (%s)\n", res.VPN, res.Interface)
		fmt.Printf("Config: %s\n", res.ConfigPath)
		printReport(res.Report)
	case targetPeer:
		ref := mustResolvePeerRefForAdd(reader, opts.Name)
		res, err := mgr.AddPeer(ctx, ref.VPN, ref.Peer)
		exitOnErr(err)
		fmt.Printf("Created peer %q\n", res.PeerRef.String())
		fmt.Printf("Client config: %s\n", res.PeerConfigPath)
		printReport(res.Report)
		fmt.Println()
		fmt.Println("Client configuration:")
		fmt.Println(res.PeerConfig)
	default:
		fmt.Fprintln(os.Stderr, "Error: unsupported target")
		os.Exit(2)
	}
}

func handleDelete(ctx context.Context, mgr *bypasser.Manager, reader *bufio.Reader, opts options) {
	switch opts.Target {
	case targetVPN:
		name := opts.Name
		if name == "" {
			var err error
			name, err = selectVPN(reader, mgr)
			exitOnErr(err)
		} else {
			exitOnErr(bypasser.ValidateName("vpn", name))
		}
		rep, err := mgr.DeleteVPN(ctx, name)
		exitOnErr(err)
		fmt.Printf("Deleted VPN %q\n", name)
		printReport(rep)
	case targetPeer:
		ref, err := resolvePeerRefForDelete(reader, mgr, opts.Name)
		exitOnErr(err)
		rep, err := mgr.DeletePeer(ctx, ref.VPN, ref.Peer)
		exitOnErr(err)
		fmt.Printf("Deleted peer %q\n", ref.String())
		printReport(rep)
	default:
		fmt.Fprintln(os.Stderr, "Error: unsupported target")
		os.Exit(2)
	}
}

func parseArgs(args []string) (options, error) {
	opts := options{Target: targetPeer}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "-h" || arg == "--help" || arg == "help":
			opts.Help = true
		case arg == "-a" || arg == "-add" || arg == "--add":
			if err := setAction(&opts, actionAdd); err != nil {
				return opts, err
			}
		case arg == "-d" || arg == "-del" || arg == "--del":
			if err := setAction(&opts, actionDelete); err != nil {
				return opts, err
			}
		case arg == "-server" || arg == "--server":
			if err := setAction(&opts, actionServer); err != nil {
				return opts, err
			}
		case arg == "vpn":
			opts.Target = targetVPN
		case arg == "peer":
			opts.Target = targetPeer
		case arg == "-n":
			if i+1 >= len(args) {
				return opts, errors.New("missing value for -n")
			}
			i++
			opts.Name = args[i]
		case strings.HasPrefix(arg, "-n="):
			opts.Name = strings.TrimPrefix(arg, "-n=")
		case strings.HasPrefix(arg, "-n:"):
			opts.Name = strings.TrimPrefix(arg, "-n:")
		case strings.HasPrefix(arg, "-"):
			return opts, fmt.Errorf("unknown flag %q", arg)
		default:
			if opts.Name != "" {
				return opts, fmt.Errorf("unexpected extra argument %q", arg)
			}
			opts.Name = arg
		}
	}

	if opts.Action == actionServer && opts.Name != "" {
		return opts, errors.New("-server does not take a name")
	}
	return opts, nil
}

func setAction(opts *options, a actionKind) error {
	if opts.Action != actionNone && opts.Action != a {
		return fmt.Errorf("conflicting actions %q and %q", opts.Action, a)
	}
	opts.Action = a
	return nil
}

func mustResolvePeerRefForAdd(reader *bufio.Reader, raw string) bypasser.PeerRef {
	if raw != "" {
		ref, err := bypasser.ParsePeerRef(raw)
		exitOnErr(err)
		return ref
	}
	for {
		fmt.Print("Enter peer name (vpn:peer): ")
		text, err := readLine(reader)
		exitOnErr(err)
		ref, err := bypasser.ParsePeerRef(text)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
			continue
		}
		return ref
	}
}

func resolvePeerRefForDelete(reader *bufio.Reader, mgr *bypasser.Manager, raw string) (bypasser.PeerRef, error) {
	if raw != "" {
		return bypasser.ParsePeerRef(raw)
	}
	return selectPeer(reader, mgr)
}

func promptValidatedName(reader *bufio.Reader, kind string) string {
	for {
		fmt.Printf("Enter %s name: ", kind)
		text, err := readLine(reader)
		exitOnErr(err)
		if err := bypasser.ValidateName(kind, text); err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
			continue
		}
		return text
	}
}

func selectVPN(reader *bufio.Reader, mgr *bypasser.Manager) (string, error) {
	vpns, err := mgr.ListVPNs()
	if err != nil {
		return "", err
	}
	if len(vpns) == 0 {
		return "", errors.New("no VPNs found")
	}
	fmt.Println("Select VPN to delete:")
	for i, vpn := range vpns {
		fmt.Printf("  %d. %s\n", i+1, vpn)
	}
	for {
		fmt.Print("Choice (number or name): ")
		in, err := readLine(reader)
		if err != nil {
			return "", err
		}
		if n, err := strconv.Atoi(in); err == nil && n >= 1 && n <= len(vpns) {
			return vpns[n-1], nil
		}
		if err := bypasser.ValidateName("vpn", in); err == nil {
			return in, nil
		}
		fmt.Fprintln(os.Stderr, "Error: invalid selection")
	}
}

func selectPeer(reader *bufio.Reader, mgr *bypasser.Manager) (bypasser.PeerRef, error) {
	peers, err := mgr.ListPeers()
	if err != nil {
		return bypasser.PeerRef{}, err
	}
	if len(peers) == 0 {
		return bypasser.PeerRef{}, errors.New("no peers found")
	}
	fmt.Println("Select peer to delete:")
	for i, p := range peers {
		fmt.Printf("  %d. %s\n", i+1, p.String())
	}
	for {
		fmt.Print("Choice (number or vpn:peer): ")
		in, err := readLine(reader)
		if err != nil {
			return bypasser.PeerRef{}, err
		}
		if n, err := strconv.Atoi(in); err == nil && n >= 1 && n <= len(peers) {
			return peers[n-1], nil
		}
		p, err := bypasser.ParsePeerRef(in)
		if err == nil {
			return p, nil
		}
		fmt.Fprintln(os.Stderr, "Error:", err)
	}
}

func readLine(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		if len(line) == 0 {
			return "", err
		}
	}
	if err != nil && errors.Is(err, io.EOF) && len(line) == 0 {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func printReport(rep bypasser.Report) {
	if len(rep.Changes) > 0 {
		fmt.Println("Changes:")
		for _, c := range rep.Changes {
			fmt.Printf("  - %s %s\n", c.Action, c.Path)
		}
	}
	if len(rep.Warnings) > 0 {
		fmt.Println("Warnings:")
		for _, w := range rep.Warnings {
			fmt.Printf("  - %s\n", w)
		}
	}
	if len(rep.RuntimeActions) > 0 {
		fmt.Println("Runtime helper:")
		for _, a := range rep.RuntimeActions {
			switch a.Status {
			case "executed":
				fmt.Printf("  - executed: %s (%s)\n", a.Command, a.Description)
			default:
				msg := a.Message
				if msg == "" {
					msg = "not executed"
				}
				fmt.Printf("  - suggested: %s (%s; %s)\n", a.Command, a.Description, msg)
			}
		}
	}
}

func printUsage(w *os.File) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  bp [-a|-add|-d|-del|-server] [vpn|peer] [-n name]")
	fmt.Fprintln(w, "  If target is omitted, 'peer' is assumed.")
	fmt.Fprintln(w, "  For peer operations, name must be 'vpn:peer'.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Examples:")
	fmt.Fprintln(w, "  bp -server")
	fmt.Fprintln(w, "  bp -a vpn -n home")
	fmt.Fprintln(w, "  bp -a -n home:laptop")
	fmt.Fprintln(w, "  bp -d vpn")
	fmt.Fprintln(w, "  bp -d")
}

func exitOnErr(err error) {
	if err == nil {
		return
	}
	fmt.Fprintln(os.Stderr, "Error:", err)
	os.Exit(1)
}
