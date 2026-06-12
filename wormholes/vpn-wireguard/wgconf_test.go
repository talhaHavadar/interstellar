package main

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

func randKey(t *testing.T) string {
	t.Helper()
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b[:])
}

func TestParseWgQuick(t *testing.T) {
	priv, pub := randKey(t), randKey(t)
	conf := "[Interface]\n" +
		"PrivateKey = " + priv + "\n" +
		"Address = 192.168.2.2/32\n" +
		"DNS = 192.168.2.1\n" +
		"\n" +
		"[Peer]\n" +
		"PublicKey = " + pub + "\n" +
		"AllowedIPs = 0.0.0.0/0\n" +
		"Endpoint = 73.131.172.35:51820\n"

	cfg, err := parseWgQuick(conf)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PrivateKey != priv || cfg.PeerPublicKey != pub {
		t.Error("keys not parsed")
	}
	if len(cfg.Address) != 1 || cfg.Address[0].String() != "192.168.2.2" {
		t.Errorf("address = %v", cfg.Address)
	}
	if len(cfg.DNS) != 1 || cfg.DNS[0].String() != "192.168.2.1" {
		t.Errorf("dns = %v", cfg.DNS)
	}
	if cfg.Endpoint != "73.131.172.35:51820" {
		t.Errorf("endpoint = %q", cfg.Endpoint)
	}
	if cfg.MTU != 1420 {
		t.Errorf("mtu default = %d", cfg.MTU)
	}

	uapi, err := cfg.uapiConfig()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"private_key=", "public_key=", "endpoint=73.131.172.35:51820", "allowed_ip=0.0.0.0/0"} {
		if !strings.Contains(uapi, want) {
			t.Errorf("uapi missing %q:\n%s", want, uapi)
		}
	}
	// Keys must be 64 hex chars in UAPI.
	for _, line := range strings.Split(uapi, "\n") {
		if k, v, ok := strings.Cut(line, "="); ok && (k == "private_key" || k == "public_key") {
			if len(v) != 64 {
				t.Errorf("%s should be 64 hex chars, got %d", k, len(v))
			}
		}
	}
}

func TestParseWgQuickErrors(t *testing.T) {
	cases := map[string]string{
		"missing private key": "[Interface]\nAddress = 10.0.0.1/32\n[Peer]\nPublicKey = x\nEndpoint = h:1\n",
		"missing address":     "[Interface]\nPrivateKey = " + randKey(t) + "\n[Peer]\nPublicKey = x\nEndpoint = h:1\n",
		"missing peer":        "[Interface]\nPrivateKey = " + randKey(t) + "\nAddress = 10.0.0.1/32\n",
	}
	for name, conf := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseWgQuick(conf); err == nil {
				t.Error("want error")
			}
		})
	}
}

func TestKeyToHexRejectsBadKey(t *testing.T) {
	if _, err := keyToHex("not-base64!!"); err == nil {
		t.Error("want error for bad base64")
	}
	if _, err := keyToHex(base64.StdEncoding.EncodeToString([]byte("short"))); err == nil {
		t.Error("want error for wrong length")
	}
}
