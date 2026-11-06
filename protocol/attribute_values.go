package protocol

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"strings"
)

// parseExtraAttributes is called for every build, so random expressions are
// sampled anew for every packet (including concurrent/repeated requests).
// Syntax: Name = value; Name = random(min,max) for numeric attributes;
// Name = random(length) for text/string attributes (ASCII letters/digits).
func parseExtraAttributes(text string) ([]byte, error) {
	var out []byte
	for _, line := range strings.Split(strings.ReplaceAll(text, ";", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		p := strings.SplitN(line, "=", 2)
		if len(p) != 2 {
			return nil, fmt.Errorf("attribute must use name = value")
		}
		name, value := strings.TrimSpace(p[0]), strings.TrimSpace(p[1])
		spec, ok := ianaAttributes[name]
		if !ok {
			return nil, fmt.Errorf("unsupported attribute %q", name)
		}
		if _, managed := managedAttributes[spec.typ]; managed {
			return nil, fmt.Errorf("%s is managed by request fields", name)
		}
		var b []byte
		var e error
		switch spec.kind {
		case "text", "string":
			if strings.HasPrefix(value, "random(") {
				b, e = randomText(value)
			} else {
				b = []byte(value)
			}
		case "integer", "enum", "time", "integer64":
			bits := 32
			if spec.kind == "integer64" {
				bits = 64
			}
			var n uint64
			if strings.HasPrefix(value, "random(") {
				n, e = randomNumber(value, bits)
			} else {
				n, e = strconv.ParseUint(value, 10, bits)
			}
			if e == nil {
				b = make([]byte, bits/8)
				if bits == 64 {
					binary.BigEndian.PutUint64(b, n)
				} else {
					binary.BigEndian.PutUint32(b, uint32(n))
				}
			}
			if e != nil {
				return nil, fmt.Errorf("invalid integer for %s: %w", name, e)
			}
		case "ipv4addr":
			ip := net.ParseIP(value)
			if ip == nil || strings.Contains(value, ":") {
				e = fmt.Errorf("invalid IPv4 for %s", name)
			} else {
				b = ip.To4()
				if b == nil {
					e = fmt.Errorf("invalid IPv4 for %s", name)
				}
			}
		case "ipv6addr":
			ip := net.ParseIP(value)
			if ip == nil || !strings.Contains(value, ":") {
				e = fmt.Errorf("invalid IPv6 for %s", name)
			} else {
				b = ip.To16()
			}
		default:
			return nil, fmt.Errorf("%s uses unsupported %s encoding", name, spec.kind)
		}
		if e != nil {
			return nil, e
		}
		out, e = add(out, spec.typ, b)
		if e != nil {
			return nil, e
		}
	}
	return out, nil
}

var managedAttributes = map[byte]struct{}{1: {}, 2: {}, 3: {}, 40: {}, 44: {}, 80: {}}

func randomText(expression string) ([]byte, error) {
	args, e := randomArgs(expression)
	if e != nil || len(args) != 1 {
		return nil, fmt.Errorf("random text requires random(length)")
	}
	length, e := strconv.Atoi(args[0])
	if e != nil || length < 1 || length > 253 {
		return nil, fmt.Errorf("random text length must be 1..253")
	}
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		n, e := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if e != nil {
			return nil, e
		}
		b[i] = alphabet[n.Int64()]
	}
	return b, nil
}
func randomNumber(expression string, bits int) (uint64, error) {
	args, e := randomArgs(expression)
	if e != nil || len(args) != 2 {
		return 0, fmt.Errorf("random integer requires random(min,max)")
	}
	low, e := strconv.ParseUint(args[0], 10, bits)
	if e != nil {
		return 0, e
	}
	high, e := strconv.ParseUint(args[1], 10, bits)
	if e != nil {
		return 0, e
	}
	if low > high {
		return 0, fmt.Errorf("random integer min exceeds max")
	}
	span := new(big.Int).SetUint64(high)
	span.Sub(span, new(big.Int).SetUint64(low))
	span.Add(span, big.NewInt(1))
	n, e := rand.Int(rand.Reader, span)
	if e != nil {
		return 0, e
	}
	return n.Uint64() + low, nil
}
func randomArgs(value string) ([]string, error) {
	if !strings.HasPrefix(value, "random(") || !strings.HasSuffix(value, ")") {
		return nil, fmt.Errorf("invalid random expression")
	}
	parts := strings.Split(value[len("random("):len(value)-1], ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts, nil
}
