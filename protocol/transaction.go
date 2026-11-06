package protocol

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// TransactionStage records the verified reply to one stage; failures include the
// failed stage and no later stages are sent.
type TransactionStage struct {
	Name   string
	Result Result
	Err    error
}

// Transaction performs one authentication followed by three accounting exchanges.
// A unique cryptographic session ID is shared by the accounting stages, not by
// independent repeated transactions. Delay is applied only between accounting stages.
func Transaction(c Config, q Request, delay time.Duration) ([]TransactionStage, error) {
	return transaction(c, q, delay, Exchange, time.Sleep)
}

func TransactionContext(ctx context.Context, c Config, q Request, delay time.Duration) ([]TransactionStage, error) {
 return transactionContext(ctx,c,q,delay,func(ctx context.Context,c Config,q Request)(Result,error){return ExchangeContext(ctx,c,q)})
}

// transactionContext shares the same stages and validation as Transaction, but
// cancellation interrupts dial, packet I/O and the delay between stages.
func transactionContext(ctx context.Context,c Config,q Request,delay time.Duration,exchange func(context.Context,Config,Request)(Result,error))([]TransactionStage,error){
 return transactionRun(ctx,c,q,delay,exchange,func(ctx context.Context,d time.Duration)error{
  timer:=time.NewTimer(d);defer timer.Stop()
  select {case <-ctx.Done():return ctx.Err();case <-timer.C:return nil}
 })
}

func transaction(c Config, q Request, delay time.Duration, exchange func(Config, Request) (Result, error), sleep func(time.Duration)) ([]TransactionStage, error) {
 return transactionRun(context.Background(),c,q,delay,func(_ context.Context,c Config,q Request)(Result,error){return exchange(c,q)},func(_ context.Context,d time.Duration)error{sleep(d);return nil})
}
func transactionRun(ctx context.Context,c Config,q Request,delay time.Duration,exchange func(context.Context,Config,Request)(Result,error),sleep func(context.Context,time.Duration)error)([]TransactionStage,error){
	if delay < 0 || delay > 24*time.Hour {
		return nil, errors.New("accounting delay must be 0..24 hours")
	}
	if q.Username == "" || q.Password == "" {
		return nil, errors.New("username and authentication password required")
	}
	// Check static request attributes before any network traffic, including the accounting form.
	if _, err := build(Request{Kind: "auth", Username: q.Username, Password: q.Password, Extra: q.Extra}, c.Secret); err != nil {
		return nil, err
	}
	if _, err := build(Request{Kind: "acct", Username: q.Username, Status: "Start", SessionID: "validation", Extra: q.Extra}, c.Secret); err != nil {
		return nil, err
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	sessionID := "radsec-" + hex.EncodeToString(id)
	stages := []string{"auth", "Start", "Interim-Update", "Stop"}
	out := make([]TransactionStage, 0, len(stages))
	for i, stage := range stages {
        if err := ctx.Err(); err != nil {return out,err}
		if i >= 2 && delay > 0 {
            if err := sleep(ctx,delay);err!=nil{return out,err}
		}
		request := q
		if i == 0 {
			request.Kind = "auth"
			request.Status = ""
			request.SessionID = ""
			request.SessionTime = 0
		} else {
			request.Kind = "acct"
			request.Password = ""
			request.Status = stage
			request.SessionID = sessionID
		}
		result, err := exchange(ctx, c, request)
		if err == nil && ((i == 0 && result.Name != "Access-Accept") || (i > 0 && result.Name != "Accounting-Response")) {
			err = fmt.Errorf("unexpected %s result", stage)
		}
		out = append(out, TransactionStage{Name: stage, Result: result, Err: err})
		if err != nil {
			return out, fmt.Errorf("%s stage failed: %w", stage, err)
		}
	}
	return out, nil
}
