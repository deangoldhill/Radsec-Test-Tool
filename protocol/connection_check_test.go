package protocol

import (
    "encoding/binary"
    "net"
    "strings"
    "testing"
    "time"
)

// FreeRADIUS check_client_connections=yes writes a synthetic Access-Accept
// with ID 0 on the same TLS stream before the reply to our Access-Request.
func connectionCheckReply() []byte {
    synthetic := make([]byte, 20)
    synthetic[0] = 1
    binary.BigEndian.PutUint16(synthetic[2:4], 20)
    // FreeRADIUS's connection-check reply includes Message-Authenticator.
    attrs := append([]byte{80, 18}, make([]byte, 16)...)
    return MakeResponse(2, synthetic, []byte("radsec"), attrs)
}

func TestTLSConnectionCheckReplyDoesNotMaskRealAccept(t *testing.T) {
    addr, ca, _ := localTLS(t, func(c net.Conn) {
        if _, err := c.Write(connectionCheckReply()); err != nil { t.Error(err); return }
        req, err := ReadPacket(c)
        if err != nil { t.Error(err); return }
        if req[1] == 0 { t.Error("request used reserved connection-check ID 0"); return }
        if _, err := c.Write(MakeResponse(2, req, []byte("radsec"), nil)); err != nil { t.Error(err) }
    })
    h, port, _ := net.SplitHostPort(addr)
    result, err := Exchange(Config{Host: h, Port: port, ServerName: "localhost", CA: ca, Secret: "radsec", Timeout: 3*time.Second}, Request{Kind: "auth", Username: "alice", Password: "test"})
    if err != nil || result.Code != 2 { t.Fatalf("real Access-Accept lost behind connection-check: result=%+v err=%v", result, err) }
}

func TestConnectionCheckCannotBecomeLoginSuccess(t *testing.T) {
    addr, ca, _ := localTLS(t, func(c net.Conn) {
        c.Write(connectionCheckReply())
        ReadPacket(c)
    })
    h, port, _ := net.SplitHostPort(addr)
    result, err := Exchange(Config{Host: h, Port: port, ServerName: "localhost", CA: ca, Secret: "radsec", Timeout: time.Second}, Request{Kind: "auth", Username: "alice", Password: "test"})
    if err == nil || result.Code == 2 { t.Fatalf("connection-check packet counted as login: result=%+v err=%v", result, err) }
}

func TestMatchingReplyStillMustValidateAfterConnectionCheck(t *testing.T) {
    addr, ca, _ := localTLS(t, func(c net.Conn) {
        c.Write(connectionCheckReply())
        req, err := ReadPacket(c)
        if err != nil { t.Error(err); return }
        c.Write(MakeResponse(2, req, []byte("forged"), nil))
    })
    h, port, _ := net.SplitHostPort(addr)
    _, err := Exchange(Config{Host: h, Port: port, ServerName: "localhost", CA: ca, Secret: "radsec", Timeout: 3*time.Second}, Request{Kind: "auth", Username: "alice", Password: "test"})
    if err == nil || !strings.Contains(err.Error(), "invalid response authenticator") { t.Fatalf("matching forged reply was not rejected: %v", err) }
}

func TestOnlyOneConnectionCheckPacketMayBeSkipped(t *testing.T) {
    addr, ca, _ := localTLS(t, func(c net.Conn) {
        c.Write(connectionCheckReply())
        c.Write(connectionCheckReply())
        req, err := ReadPacket(c)
        if err != nil { t.Error(err); return }
        c.Write(MakeResponse(2, req, []byte("radsec"), nil))
    })
    h, port, _ := net.SplitHostPort(addr)
    result, err := Exchange(Config{Host: h, Port: port, ServerName: "localhost", CA: ca, Secret: "radsec", Timeout: 3*time.Second}, Request{Kind: "auth", Username: "alice", Password: "test"})
    if err == nil || result.Code == 2 { t.Fatalf("unbounded connection-check packets accepted: result=%+v err=%v", result, err) }
}

func TestAccessRequestNeverUsesReservedIDZero(t *testing.T) {
    for i := 0; i < 5000; i++ {
        p, err := build(Request{Kind: "auth", Username: "alice", Password: "test"}, "radsec")
        if err != nil { t.Fatal(err) }
        if p[1] == 0 { t.Fatal("Access-Request used ID 0, reserved for the server's connection check") }
    }
}
