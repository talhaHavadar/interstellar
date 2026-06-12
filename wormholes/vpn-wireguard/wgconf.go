package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// wgConfig is the subset of a wg-quick configuration the wormhole needs.
type wgConfig struct {
	PrivateKey string       // base64
	Address    []netip.Addr // interface addresses (mask stripped)
	DNS        []netip.Addr
	MTU        int

	PeerPublicKey string // base64
	PresharedKey  string // base64, optional
	Endpoint      string // host:port
	AllowedIPs    []string
	Keepalive     int
}

// parseWgQuick parses the standard wg-quick INI format (the same file
// `wg-quick up` consumes).
func parseWgQuick(text string) (*wgConfig, error) {
	cfg := &wgConfig{MTU: 1420}
	section := ""
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.Trim(line, "[]"))
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(strings.ToLower(key))
		value = strings.TrimSpace(value)

		switch section {
		case "interface":
			switch key {
			case "privatekey":
				cfg.PrivateKey = value
			case "address":
				addrs, err := parseAddrList(value)
				if err != nil {
					return nil, fmt.Errorf("Address: %w", err)
				}
				cfg.Address = addrs
			case "dns":
				addrs, err := parseAddrList(value)
				if err != nil {
					return nil, fmt.Errorf("DNS: %w", err)
				}
				cfg.DNS = addrs
			case "mtu":
				n, err := strconv.Atoi(value)
				if err != nil {
					return nil, fmt.Errorf("MTU: %w", err)
				}
				cfg.MTU = n
			}
		case "peer":
			switch key {
			case "publickey":
				cfg.PeerPublicKey = value
			case "presharedkey":
				cfg.PresharedKey = value
			case "endpoint":
				cfg.Endpoint = value
			case "allowedips":
				for _, a := range strings.Split(value, ",") {
					if a = strings.TrimSpace(a); a != "" {
						cfg.AllowedIPs = append(cfg.AllowedIPs, a)
					}
				}
			case "persistentkeepalive":
				n, err := strconv.Atoi(value)
				if err != nil {
					return nil, fmt.Errorf("PersistentKeepalive: %w", err)
				}
				cfg.Keepalive = n
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if cfg.PrivateKey == "" {
		return nil, fmt.Errorf("missing Interface PrivateKey")
	}
	if len(cfg.Address) == 0 {
		return nil, fmt.Errorf("missing Interface Address")
	}
	if cfg.PeerPublicKey == "" || cfg.Endpoint == "" {
		return nil, fmt.Errorf("missing Peer PublicKey or Endpoint")
	}
	return cfg, nil
}

// parseAddrList parses a comma-separated list of addresses, tolerating CIDR
// suffixes (the mask is dropped — netstack wants bare addresses).
func parseAddrList(value string) ([]netip.Addr, error) {
	var out []netip.Addr
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "/") {
			pfx, err := netip.ParsePrefix(part)
			if err != nil {
				return nil, err
			}
			out = append(out, pfx.Addr())
		} else {
			a, err := netip.ParseAddr(part)
			if err != nil {
				return nil, err
			}
			out = append(out, a)
		}
	}
	return out, nil
}

// uapiConfig renders the device configuration in WireGuard's UAPI format.
// Keys are hex there, but wg-quick files carry them base64, so they are
// converted here.
func (c *wgConfig) uapiConfig() (string, error) {
	priv, err := keyToHex(c.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("PrivateKey: %w", err)
	}
	pub, err := keyToHex(c.PeerPublicKey)
	if err != nil {
		return "", fmt.Errorf("Peer PublicKey: %w", err)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", priv)
	fmt.Fprintf(&b, "public_key=%s\n", pub)
	if c.PresharedKey != "" {
		psk, err := keyToHex(c.PresharedKey)
		if err != nil {
			return "", fmt.Errorf("PresharedKey: %w", err)
		}
		fmt.Fprintf(&b, "preshared_key=%s\n", psk)
	}
	fmt.Fprintf(&b, "endpoint=%s\n", c.Endpoint)
	if c.Keepalive > 0 {
		fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", c.Keepalive)
	}
	if len(c.AllowedIPs) == 0 {
		// Default to a full tunnel if the file omitted AllowedIPs.
		fmt.Fprintf(&b, "allowed_ip=0.0.0.0/0\n")
	}
	for _, aip := range c.AllowedIPs {
		fmt.Fprintf(&b, "allowed_ip=%s\n", aip)
	}
	return b.String(), nil
}

// keyToHex converts a base64 WireGuard key to the hex form UAPI expects.
func keyToHex(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("not valid base64: %w", err)
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("expected 32-byte key, got %d bytes", len(raw))
	}
	return hex.EncodeToString(raw), nil
}
