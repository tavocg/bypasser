package bypasser

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type System interface {
	IsRoot() bool
	HasCommand(name string) bool
	Run(ctx context.Context, name string, args ...string) error
	Output(ctx context.Context, name string, args ...string) (string, error)
	OutputInput(ctx context.Context, input, name string, args ...string) (string, error)
}

type KeyGenerator interface {
	GeneratePrivateKey(ctx context.Context) (string, error)
	DerivePublicKey(ctx context.Context, privateKey string) (string, error)
	GeneratePresharedKey(ctx context.Context) (string, error)
}

type ExecSystem struct{}

func (ExecSystem) IsRoot() bool {
	return os.Geteuid() == 0
}

func (ExecSystem) HasCommand(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func (ExecSystem) Run(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			return err
		}
		return fmt.Errorf("%w: %s", err, msg)
	}
	return nil
}

func (ExecSystem) Output(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			return "", err
		}
		return "", fmt.Errorf("%w: %s", err, msg)
	}
	return strings.TrimSpace(stdout.String()), nil
}

func (ExecSystem) OutputInput(ctx context.Context, input, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = strings.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			return "", err
		}
		return "", fmt.Errorf("%w: %s", err, msg)
	}
	return strings.TrimSpace(stdout.String()), nil
}

type WGCLIKeyGenerator struct {
	System System
}

func (g WGCLIKeyGenerator) sys() System {
	if g.System == nil {
		return ExecSystem{}
	}
	return g.System
}

func (g WGCLIKeyGenerator) GeneratePrivateKey(ctx context.Context) (string, error) {
	s := g.sys()
	if !s.HasCommand("wg") {
		return "", fmt.Errorf("wg command not found (install wireguard-tools)")
	}
	return s.Output(ctx, "wg", "genkey")
}

func (g WGCLIKeyGenerator) DerivePublicKey(ctx context.Context, privateKey string) (string, error) {
	s := g.sys()
	if !s.HasCommand("wg") {
		return "", fmt.Errorf("wg command not found (install wireguard-tools)")
	}
	return s.OutputInput(ctx, privateKey+"\n", "wg", "pubkey")
}

func (g WGCLIKeyGenerator) GeneratePresharedKey(ctx context.Context) (string, error) {
	s := g.sys()
	if !s.HasCommand("wg") {
		return "", fmt.Errorf("wg command not found (install wireguard-tools)")
	}
	return s.Output(ctx, "wg", "genpsk")
}
