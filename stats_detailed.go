package main

import (
	"fmt"
	"radsec-windows-tester/protocol"
	"sort"
	"strings"
	"time"
)

// detailData stores only observed phase samples. No CPU, memory, or network
// utilization estimate is inferred from elapsed wall-clock time.
type detailData struct {
	phases                                            map[string][]time.Duration
	latencies                                         []time.Duration
	requestBytes, responseBytes, responseAttributes   []int
	connectionChecks, peerCerts, resumed, tlsObserved int
	requestPackets, responsePackets                   int
}

var phaseNames = []string{"prepare", "tcp dial", "tls handshake", "request write", "response read", "response verify"}

func (d *detailData) record(o protocol.Observations, verified bool) {
	d.requestPackets += o.RequestPackets
	d.responsePackets += o.ResponsePackets
	if d.phases == nil {
		d.phases = make(map[string][]time.Duration)
	}
	for _, name := range phaseNames {
		if v, ok := o.Phases[name]; ok {
			d.phases[name] = append(d.phases[name], v)
		}
	}
	if _, ok := o.Phases["request write"]; ok {
		d.requestBytes = append(d.requestBytes, o.RequestBytes)
	}
	if _, ok := o.Phases["response verify"]; ok {
		d.responseBytes = append(d.responseBytes, o.ResponseBytes)
	}
	if o.TLSObserved {
		d.tlsObserved++
		d.peerCerts += o.PeerCerts
		if o.TLSResumed {
			d.resumed++
		}
	}
	d.connectionChecks += o.ConnectionChecks
	// Attribute count belongs only to a fully verified response. A failed
	// authenticator never contributes peer attribute statistics.
	if verified {
		d.responseAttributes = append(d.responseAttributes, o.ResponseAttributes)
	}
}
func (d detailData) copy() detailData {
	out := d
	out.phases = make(map[string][]time.Duration, len(d.phases))
	for k, v := range d.phases {
		out.phases[k] = append([]time.Duration(nil), v...)
	}
	out.requestBytes = append([]int(nil), d.requestBytes...)
	out.responseBytes = append([]int(nil), d.responseBytes...)
	out.responseAttributes = append([]int(nil), d.responseAttributes...)
	return out
}
func durationLines(name string, samples []time.Duration) []string {
	lines := []string{fmt.Sprintf("%s samples: %d", name, len(samples))}
	if len(samples) == 0 {
		for _, label := range []string{"min", "mean", "p50", "p75", "p90", "p95", "p99", "max", "total"} {
			lines = append(lines, name+" "+label+": unavailable")
		}
		return lines
	}
	v := append([]time.Duration(nil), samples...)
	sort.Slice(v, func(i, j int) bool { return v[i] < v[j] })
	var total time.Duration
	for _, x := range v {
		total += x
	}
	values := []struct {
		label string
		value time.Duration
	}{{"min", v[0]}, {"mean", total / time.Duration(len(v))}, {"p50", quantile(v, 50)}, {"p75", quantile(v, 75)}, {"p90", quantile(v, 90)}, {"p95", quantile(v, 95)}, {"p99", quantile(v, 99)}, {"max", v[len(v)-1]}, {"total", total}}
	for _, x := range values {
		lines = append(lines, fmt.Sprintf("%s %s: %s", name, x.label, x.value))
	}
	return lines
}
func byteLines(name string, samples []int) []string {
	lines := []string{fmt.Sprintf("%s samples: %d", name, len(samples))}
	if len(samples) == 0 {
		for _, label := range []string{"total", "min", "mean", "max"} {
			lines = append(lines, name+" "+label+": unavailable")
		}
		return lines
	}
	total, min, max := 0, samples[0], samples[0]
	for _, v := range samples {
		total += v
		if v < min {
			min = v
		}
		if v > max {
			max = v
		}
	}
	return append(lines, fmt.Sprintf("%s total: %d", name, total), fmt.Sprintf("%s min: %d", name, min), fmt.Sprintf("%s mean: %.2f", name, float64(total)/float64(len(samples))), fmt.Sprintf("%s max: %d", name, max))
}
func rate(n, d int) string {
	if d == 0 {
		return "unavailable"
	}
	return fmt.Sprintf("%.2f%%", float64(n)*100/float64(d))
}

// Detailed presents 70+ independent observed or transparently derived fields.
// Samples are 0 and statistics unavailable when a phase was not reached.
func (s RunSnapshot) Detailed() string {
	d := s.Detail
	lines := []string{"LAST RUN · DETAILED OBSERVATIONS", "Counts include only this run; no resource-exhaustion counters are available.", fmt.Sprintf("planned: %d", s.Planned), fmt.Sprintf("completed: %d", s.Completed), fmt.Sprintf("requests sent: %d", d.requestPackets), fmt.Sprintf("responses received: %d", d.responsePackets), fmt.Sprintf("malformed responses: %d", s.Malformed), fmt.Sprintf("in flight: %d", s.InFlight), fmt.Sprintf("not started: %d", s.Planned-s.Completed-s.InFlight), fmt.Sprintf("accept: %d", s.Accept), fmt.Sprintf("reject: %d", s.Reject), fmt.Sprintf("challenge: %d", s.Challenge), fmt.Sprintf("accounting response: %d", s.Accounting), fmt.Sprintf("other verified response: %d", s.Other), fmt.Sprintf("errors: %d", s.Errors), fmt.Sprintf("cancelled in flight: %d", s.Cancelled), fmt.Sprintf("TLS 1.2 verified: %d", s.TLS12), fmt.Sprintf("TLS 1.3 verified: %d", s.TLS13), fmt.Sprintf("TLS other verified: %d", s.TLSUnknown), fmt.Sprintf("TLS handshakes observed: %d", d.tlsObserved), fmt.Sprintf("TLS resumed: %d", d.resumed), fmt.Sprintf("peer certificates seen: %d", d.peerCerts), fmt.Sprintf("connection checks discarded: %d", d.connectionChecks), "transport success rate: " + rate(s.Accept+s.Reject+s.Challenge+s.Accounting+s.Other, s.Completed), "auth accept rate: " + rate(s.Accept, s.Accept+s.Reject+s.Challenge), "reject share of verified auth: " + rate(s.Reject, s.Accept+s.Reject+s.Challenge), "cancel share of completed: " + rate(s.Cancelled, s.Completed), fmt.Sprintf("elapsed: %s", s.Elapsed.Round(time.Millisecond))}
	if s.Elapsed > 0 {
		lines = append(lines, fmt.Sprintf("completed throughput: %.2f/s", s.Throughput))
	} else {
		lines = append(lines, "completed throughput: unavailable")
	}
	for _, name := range phaseNames {
		lines = append(lines, "— "+name+" —")
		lines = append(lines, durationLines(name, d.phases[name])...)
	}
	lines = append(lines, "— verified end-to-end latency —")
	lines = append(lines, durationLines("verified latency", d.latencies)...)
	for _, field := range []struct {
		name    string
		samples []int
	}{{"request bytes", d.requestBytes}, {"response bytes", d.responseBytes}, {"response attributes", d.responseAttributes}} {
		lines = append(lines, byteLines(field.name, field.samples)...)
	}
	keys := make([]string, 0, len(s.ErrorCategories))
	for k := range s.ErrorCategories {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		lines = append(lines, fmt.Sprintf("error %s: %d", key, s.ErrorCategories[key]))
	}
	lines = append(lines, "resource exhaustion: unavailable (CPU/memory/socket counters not instrumented)")
	return strings.Join(lines, "\r\n") + "\r\n"
}
