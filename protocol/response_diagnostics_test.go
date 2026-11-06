package protocol

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestInvalidResponseMetadataIsBoundedAndAvailable(t *testing.T) {
	req := make([]byte, 20)
	req[0] = 1
	req[1] = 131
	binary.BigEndian.PutUint16(req[2:4], uint16(len(req)))
	response := MakeResponse(2, req, []byte("radsec"), nil)
	response[1] = 0
	err := verifyResponse(response, req, "radsec")
	if err == nil || !strings.Contains(err.Error(), "expected 131, received 0") {
		t.Fatalf("want ID metadata, got %v", err)
	}
	response[1] = req[1]
	response[0] = 12
	err = verifyResponse(response, req, "radsec")
	if err == nil || !strings.Contains(err.Error(), "code 12") {
		t.Fatalf("want unexpected response code metadata, got %v", err)
	}
}
