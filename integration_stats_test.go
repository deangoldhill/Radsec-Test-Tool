package main

import (
 "radsec-windows-tester/protocol"
 "testing"
 "time"
)

func TestRunStatsCountsFullTransactionWithoutInventingAccountingReply(t *testing.T) {
 r:=newRunStats(1,time.Now())
 r.record(protocol.Result{Name:"Full transaction",Duration:10*time.Millisecond,TLSVersion:0x0304},nil)
 s:=r.Snapshot()
 if s.Full!=1 || s.Accounting!=0 || s.Other!=0 || s.TransportSuccessRate!=100 {t.Fatalf("incorrect transaction outcome: %+v",s)}
}
