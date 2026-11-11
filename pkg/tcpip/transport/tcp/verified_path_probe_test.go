// Copyright 2026 StannisMod.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy at https://www.apache.org/licenses/LICENSE-2.0.
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

package tcp

import (
	"bytes"
	"context"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/state"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"testing"
	"time"
)

func TestVerifiedPathProbeRejectsUnsafeSenderStates(t *testing.T) {
	for _, name := range []string{"no-sender", "no-recovery", "zero-window", "no-timer", "no-data", "fin-only", "oversized", "not-retransmitted", "not-first-unacked", "too-recent", "rto-too-close", "same-deadline", "replayed-proof"} {
		t.Run(name, func(t *testing.T) {
			clock := faketime.NewManualClock()
			clock.Advance(time.Second)
			st := stack.New(stack.Options{Clock: clock})
			defer st.Close()
			e := &endpoint{stack: st}
			s := &sender{ep: e, state: tcpip.RTORecovery, TCPSenderState: stack.TCPSenderState{SndUna: 1000, SndWnd: 65535, MaxPayloadSize: 1200}}
			e.snd = s
			s.resendTimer.state = timerStateEnabled
			s.resendTimer.target = clock.NowMonotonic().Add(2 * time.Second)
			payload := 1200
			if name == "fin-only" {
				payload = 0
			}
			if name == "oversized" {
				payload = 1201
			}
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(make([]byte, payload))})
			defer pkt.DecRef()
			seg := &segment{pkt: pkt, sequenceNumber: seqnum.Value(1000), xmitCount: 2, xmitTime: clock.NowMonotonic().Add(-200 * time.Millisecond)}
			if name == "fin-only" {
				seg.flags = header.TCPFlagFin
			}
			if name != "no-data" {
				s.writeList.PushBack(seg)
			}
			switch name {
			case "no-sender":
				e.snd = nil
			case "no-recovery":
				s.state = tcpip.Open
			case "zero-window":
				s.SndWnd = 0
			case "no-timer":
				s.resendTimer.state = timerStateDisabled
			case "not-retransmitted":
				seg.xmitCount = 1
			case "not-first-unacked":
				seg.sequenceNumber++
			case "too-recent":
				seg.xmitTime = clock.NowMonotonic().Add(-99 * time.Millisecond)
			case "rto-too-close":
				s.resendTimer.target = clock.NowMonotonic().Add(99 * time.Millisecond)
			case "same-deadline":
				s.lastPathProbeDeadline = s.resendTimer.target
			case "replayed-proof":
				s.lastPathProof = 1
			}
			attempts, normalTime, lost := seg.xmitCount, seg.xmitTime, seg.lost
			rto, cwnd, deadline, lastSend := s.RTO, s.SndCwnd, s.resendTimer.target, s.LastSendTime
			wantHint := name == "too-recent" || name == "rto-too-close" || name == "same-deadline" || name == "replayed-proof"
			proofBefore := s.lastPathProof
			for i := 0; i < 2; i++ {
				if got := e.NeedsVerifiedPathProbe(); got != wantHint {
					t.Fatalf("recovery hint=%v want=%v", got, wantHint)
				}
			}
			if s.lastPathProof != proofBefore {
				t.Fatal("read-only hint consumed proof")
			}
			if e.ProbeVerifiedPath(1) {
				t.Fatal("unsafe state accepted probe")
			}
			if seg.xmitCount != attempts || seg.xmitTime != normalTime || seg.lost != lost || s.RTO != rto || s.SndCwnd != cwnd || s.resendTimer.target != deadline || s.LastSendTime != lastSend {
				t.Fatal("rejected probe changed sender/transmission state")
			}
		})
	}
}

func TestVerifiedPathProbeStateRoundTrip(t *testing.T) {
	before := sender{lastPathProof: 991, lastPathProbeDeadline: tcpip.MonotonicTime{}.Add(9 * time.Second)}
	var encoded bytes.Buffer
	if _, err := state.Save(context.Background(), &encoded, &before); err != nil {
		t.Fatal(err)
	}
	var after sender
	if _, err := state.Load(context.Background(), &encoded, &after); err != nil {
		t.Fatal(err)
	}
	if after.lastPathProof != before.lastPathProof || after.lastPathProbeDeadline != before.lastPathProbeDeadline {
		t.Fatal("checkpoint lost proof replay/rate guard")
	}
}
