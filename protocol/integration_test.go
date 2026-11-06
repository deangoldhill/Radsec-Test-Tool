package protocol

import (
 "context"
 "errors"
 "testing"
 "time"
)

func TestTransactionContextCancelsBetweenAccountingStages(t *testing.T) {
 ctx, cancel := context.WithCancel(context.Background())
 calls := 0
 stages, err := transactionContext(ctx, Config{Secret:"s"}, Request{Username:"u",Password:"p"}, time.Hour, func(_ context.Context, _ Config, q Request) (Result,error) {
  calls++
  if calls == 2 { cancel() }
  if q.Kind == "auth" { return Result{Name:"Access-Accept"},nil }
  return Result{Name:"Accounting-Response"},nil
 })
 if !errors.Is(err, context.Canceled) || calls != 2 || len(stages) != 2 { t.Fatalf("calls=%d stages=%d err=%v",calls,len(stages),err) }
}

func TestTransactionContextAggregatesVerifiedStages(t *testing.T) {
 calls:=0
 stages,err:=transactionContext(context.Background(), Config{Secret:"s"}, Request{Username:"u",Password:"p"}, 0, func(_ context.Context,_ Config,q Request)(Result,error){
  calls++
  name:="Accounting-Response"; if q.Kind=="auth" {name="Access-Accept"}
  return Result{Name:name, Duration:time.Duration(calls)*time.Millisecond, TLSVersion:0x0304, Observations:Observations{RequestBytes:12,ResponseBytes:24,Phases:map[string]time.Duration{"tcp dial":time.Millisecond}}},nil
 })
 if err!=nil || len(stages)!=4 {t.Fatalf("stages=%d err=%v",len(stages),err)}
}
