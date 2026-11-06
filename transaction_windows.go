//go:build windows

package main

import (
	"context"
	"fmt"
	"radsec-windows-tester/protocol"
	"time"
)

// Each repeated transaction gets its own generated accounting session ID.
func runFullTransaction(c protocol.Config, q protocol.Request, delay time.Duration, index int) (protocol.Result, error) {
	stages, err := protocol.Transaction(c, q, delay)
	for _, stage := range stages {
		if stage.Err != nil {
			appendLog(eventError, fmt.Sprintf("#%d %s failed · %s", index, stage.Name, safeExchangeError(stage.Err)))
		} else {
			appendLog(eventSuccess, fmt.Sprintf("#%d %s · %s · %d ms", index, stage.Name, stage.Result.Name, stage.Result.Duration.Milliseconds()))
		}
	}
	if err != nil {
		return protocol.Result{}, err
	}
	result := stages[len(stages)-1].Result
	result.Name = "Full transaction"
	return result, nil
}

func runFullTransactionContext(ctx context.Context, c protocol.Config, q protocol.Request, delay time.Duration, index int) (protocol.Result, error) {
	started := time.Now()
	stages, err := protocol.TransactionContext(ctx, c, q, delay)
	var result protocol.Result
	for _, stage := range stages {
		if stage.Err != nil {
			appendLog(eventError, fmt.Sprintf("#%d %s failed · %s", index, stage.Name, safeExchangeError(stage.Err)))
		} else {
			appendLog(eventSuccess, fmt.Sprintf("#%d %s · %s · %d ms", index, stage.Name, stage.Result.Name, stage.Result.Duration.Milliseconds()))
		}
		for name, d := range stage.Result.Observations.Phases {
			if result.Observations.Phases == nil {
				result.Observations.Phases = map[string]time.Duration{}
			}
			result.Observations.Phases[name] += d
		}
		result.Observations.RequestBytes += stage.Result.Observations.RequestBytes
		result.Observations.RequestPackets += stage.Result.Observations.RequestPackets
		result.Observations.ResponsePackets += stage.Result.Observations.ResponsePackets
		result.Observations.ResponseBytes += stage.Result.Observations.ResponseBytes
		result.Observations.ResponseAttributes += stage.Result.Observations.ResponseAttributes
		result.Observations.ConnectionChecks += stage.Result.Observations.ConnectionChecks
		result.TLSVersion = stage.Result.TLSVersion
	}
	if err != nil {
		return result, err
	}
	result.Name = "Full transaction"
	result.Duration = time.Since(started)
	return result, nil
}
