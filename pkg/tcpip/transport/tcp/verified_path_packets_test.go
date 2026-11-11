// Copyright 2026 StannisMod.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy at https://www.apache.org/licenses/LICENSE-2.0.
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

package tcp_test

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// A packet-level regression: lose the initial flight and tail probe, deliver
// the first timeout repair, then allow ACKs to drain the flight. Advancing only
// 10 ms per ACK prevents another RTO from concealing stalled recovery.
// This exercises the same pinned TCP protocol as FlowStack, without VPN/TLS,
// wall-clock outages, OS routes, or random packet losses.
func TestTCPTimeoutRecoveryDrainsThroughACKs(t *testing.T) {

	for _, rack := range []bool{false, true} {
		for _, timestamps := range []bool{false, true} {
			for _, scenario := range []string{"ordered", "reordered_repair", "lost_repair"} {
				if !rack && scenario == "lost_repair" {
					continue
				} // One SACK need not trigger classic recovery.
				t.Run(fmt.Sprintf("rack=%t/timestamps=%t/%s", rack, timestamps, scenario), func(t *testing.T) { testTCPTimeoutRecovery(t, rack, timestamps, scenario) })
			}
		}
	}
}
func testTCPTimeoutRecovery(t *testing.T, rack, timestamps bool, scenario string, budgetResult ...*uint64) {
	noSecondProbe := scenario == "path_proof_lost_no_second"
	if noSecondProbe {
		scenario = "path_proof_lost"
	}
	clock := faketime.NewManualClock()
	link := channel.New(128, 1280, "")
	processed := make(chan struct{}, 256)
	s := newTCPRecoveryTestStack(clock, func() { processed <- struct{}{} })
	defer func() { s.Close(); s.Wait(); link.Close() }()
	local := tcpip.AddrFrom4([4]byte{10, 77, 0, 1})
	remote := tcpip.AddrFrom4([4]byte{10, 77, 0, 2})
	if e := s.CreateNIC(1, link); e != nil {
		t.Fatal(e)
	}
	if e := s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: local.WithPrefix()}, stack.AddressProperties{}); e != nil {
		t.Fatal(e)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	sack := tcpip.TCPSACKEnabled(true)
	if e := s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack); e != nil {
		t.Fatal(e)
	}
	recovery := tcpip.TCPRecovery(0)
	if rack {
		recovery = tcpip.TCPRACKLossDetection
	}
	if e := s.SetTransportProtocolOption(tcp.ProtocolNumber, &recovery); e != nil {
		t.Fatal(e)
	}
	var queue waiter.Queue
	ep, e := s.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &queue)
	if e != nil {
		t.Fatal(e)
	}
	defer ep.Close()
	read := func(timeout time.Duration) header.TCP {
		p := link.Read()
		if p == nil && timeout > 0 {
			c, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			p = link.ReadContext(c)
		}
		if p == nil {
			return nil
		}
		defer p.DecRef()
		v := p.ToView()
		defer v.Release()
		data := append([]byte(nil), v.AsSlice()...)
		return header.TCP(header.IPv4(data).Payload())
	}
	info := func() tcpip.TCPInfoOption {
		t.Helper()
		var i tcpip.TCPInfoOption
		if e := ep.GetSockOpt(&i); e != nil {
			t.Fatal(e)
		}
		return i
	}
	if e := ep.Connect(tcpip.FullAddress{NIC: 1, Addr: remote, Port: 18443}); e == nil {
		t.Fatal("connect completed without SYN/ACK")
	} else if _, ok := e.(*tcpip.ErrConnectStarted); !ok {
		t.Fatal(e)
	}
	syn := read(time.Second)
	if syn == nil || syn.Flags()&header.TCPFlagSyn == 0 {
		t.Fatal("missing SYN")
	}
	port, first := syn.SourcePort(), syn.SequenceNumber()+1
	peerSeq := uint32(10001)
	lastTS := syn.ParsedOptions().TSVal
	send := func(ack uint32, flags header.TCPFlags, options []byte) {
		t.Helper()
		b := make([]byte, 40+len(options))
		ip := header.IPv4(b[:20])
		ip.Encode(&header.IPv4Fields{TotalLength: uint16(len(b)), TTL: 64, Protocol: uint8(tcp.ProtocolNumber), SrcAddr: remote, DstAddr: local})
		ip.SetChecksum(^ip.CalculateChecksum())
		h := header.TCP(b[20:])
		h.Encode(&header.TCPFields{SrcPort: 18443, DstPort: port, SeqNum: peerSeq, AckNum: ack, Flags: flags, WindowSize: 60000, DataOffset: uint8(20 + len(options))})
		copy(h[20:], options)
		h.SetChecksum(^checksum.Checksum(h, header.PseudoHeaderChecksum(tcp.ProtocolNumber, remote, local, uint16(len(h)))))
		p := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(b)})
		link.InjectInbound(ipv4.ProtocolNumber, p)
		p.DecRef()
	}
	tsOptions := func() []byte {
		if !timestamps {
			return nil
		}
		b := make([]byte, 12)
		b[0], b[1] = 1, 1
		header.EncodeTSOption(uint32(1000+clock.NowMonotonic().Sub(tcpip.MonotonicTime{}).Milliseconds()), lastTS, b[2:])
		return b
	}
	options := []byte{2, 4, 4, 216, 4, 2, 1, 1} // MSS 1240, SACK permitted.
	if timestamps {
		options = append(options, tsOptions()...)
	}
	clock.Advance(10 * time.Millisecond)
	send(first, header.TCPFlagSyn|header.TCPFlagAck, options)
	ackPacket := read(time.Second)
	if ackPacket == nil {
		t.Fatal("missing handshake ACK")
	}
	peerSeq++
	for len(processed) > 0 {
		<-processed
	}
	if scenario == "path_proof" || scenario == "path_proof_lost" {
		if ep.(interface{ ProbeVerifiedPath(uint64) bool }).ProbeVerifiedPath(1) {
			t.Fatal("idle connection sent a repair")
		}
	}
	payload := make([]byte, 32*1240)
	for i := range payload {
		payload[i] = byte(i*17 + i/251)
	}
	if n, e := ep.Write(bytes.NewReader(payload), tcpip.WriteOptions{}); e != nil || n != int64(len(payload)) {
		t.Fatalf("write %d %v", n, e)
	}
	for i := 0; i < tcp.InitialCwnd; i++ {
		if p := read(time.Second); p == nil || len(p.Payload()) == 0 {
			t.Fatal("incomplete initial flight")
		}
	}
	// All original packets are lost. Consume the tail probe and first RTO repair.
	var repair header.TCP
	for round := 0; round < 6; round++ {
		clock.Advance(info().RTO)
		p := read(time.Second)
		if p == nil {
			t.Fatal("no tail probe or RTO repair")
		}
		if s.Stats().TCP.Timeouts.Value() > 0 {
			repair = p
			break
		}
	}
	if repair == nil || repair.SequenceNumber() != first {
		t.Fatal("missing repair of initial byte")
	}
	if got := s.Stats().TCP.Timeouts.Value(); got != 1 {
		t.Fatalf("timeouts=%d, want one", got)
	}
	if info().CcState != tcpip.RTORecovery {
		t.Fatalf("first RTO state=%v", info().CcState)
	}
	expectedTimeouts := uint64(1)
	if scenario == "path_proof" || scenario == "path_proof_lost" || scenario == "path_control" {
		probe := ep.(interface{ ProbeVerifiedPath(uint64) bool })
		for i := 0; info().RTO < 6400*time.Millisecond && i < 1000; i++ {
			clock.Advance(10 * time.Millisecond)
			for read(0) != nil {
			}
		}
		if info().RTO < 6400*time.Millisecond {
			t.Fatal("backoff did not reach target")
		}
		expectedTimeouts = s.Stats().TCP.Timeouts.Value()
		clock.Advance(info().RTO / 2)
		original := info()
		if scenario != "path_control" {
			if !probe.ProbeVerifiedPath(2) || probe.ProbeVerifiedPath(2) {
				t.Fatal("expected exactly one probe for the proof")
			}
			repair = read(time.Second)
			if repair == nil || repair.SequenceNumber() != first || read(0) != nil {
				t.Fatal("unexpected probe flight")
			}
			if next := info(); next.RTO != original.RTO || next.SndCwnd != original.SndCwnd {
				t.Fatal("probe changed congestion window or timeout")
			}
			// Repeated successful path challenges are not permission to send
			// an unbounded train of repairs during the same timeout interval.
			for serial := uint64(3); serial < 8; serial++ {
				clock.Advance(110 * time.Millisecond)
				if probe.ProbeVerifiedPath(serial) {
					t.Fatalf("fresh proof serial %d caused another repair before the normal RTO", serial)
				}
				if read(0) != nil {
					t.Fatal("proof storm emitted extra TCP data")
				}
			}
		}
		if scenario == "path_proof_lost" || scenario == "path_control" {
			clock.Advance(original.RTO / 2)
			repair = read(time.Second)
			if repair == nil || repair.SequenceNumber() != first || info().RTO <= original.RTO {
				t.Fatal("lost probe disturbed ordinary backoff")
			}
		}
		if scenario == "path_proof_lost" {
			// A normal RTO opens a fresh bounded interval. The old proof is
			// still consumed; a new proof can prompt exactly one new probe.
			clock.Advance(110 * time.Millisecond)
			afterTimeout := info()
			if probe.ProbeVerifiedPath(2) {
				t.Fatal("old proof reused after another RTO")
			}
			if !noSecondProbe {
				if !probe.ProbeVerifiedPath(9) {
					t.Fatal("new proof rejected after normal RTO")
				}
				extra := read(time.Second)
				if extra == nil || extra.SequenceNumber() != first || read(0) != nil {
					t.Fatal("unexpected second interval probe flight")
				}
				if next := info(); next.RTO != afterTimeout.RTO || next.SndCwnd != afterTimeout.SndCwnd {
					t.Fatal("second probe changed RTO or congestion window")
				}
				if probe.ProbeVerifiedPath(10) {
					t.Fatal("second interval allowed a duplicate probe")
				}
			}
		}
		t.Logf("at verification, normal timeout remaining %v", original.RTO/2)
	}
	if len(budgetResult) > 0 {
		for i := 0; i < 40; i++ {
			clock.Advance(info().RTO + time.Millisecond)
			for read(20*time.Millisecond) != nil {
			}
			if s.Stats().TCP.EstablishedTimedout.Value() > 0 {
				*budgetResult[0] = s.Stats().TCP.Timeouts.Value()
				t.Logf("connection exhausted normal retry budget after %d timeouts", *budgetResult[0])
				return
			}
		}
		t.Fatal("connection did not reach its normal retry limit")
	}
	received := 0
	buffered := map[int]header.TCP{}
	var pending []header.TCP
	injected := false
	duplicates := 0
	for {
		offset := int(repair.SequenceNumber() - first)
		previousReceived := received
		n := len(repair.Payload())
		if n == 0 || offset < 0 || offset+n > len(payload) || !bytes.Equal(repair.Payload(), payload[offset:offset+n]) {
			t.Fatal("incorrect repair payload")
		}
		if offset < received {
			duplicates++
			if duplicates > 16 {
				t.Fatal("excess duplicate repairs")
			}
		} else {
			buffered[offset] = repair
		}
		for {
			p, ok := buffered[received]
			if !ok {
				break
			}
			delete(buffered, received)
			received += len(p.Payload())
		}
		// RFC 7323: out-of-order data must not replace the timestamp
		// echoed for the last in-order boundary.
		if offset <= previousReceived {
			lastTS = repair.ParsedOptions().TSVal
		}
		beforeCwnd := info().SndCwnd
		clock.Advance(10 * time.Millisecond)
		for len(processed) > 0 {
			<-processed
		}
		options := tsOptions()
		var offsets []int
		for offset := range buffered {
			offsets = append(offsets, offset)
		}
		sort.Ints(offsets)
		var sacks []header.SACKBlock
		for _, offset := range offsets {
			end := offset + len(buffered[offset].Payload())
			if len(sacks) > 0 && uint32(sacks[len(sacks)-1].End) == first+uint32(offset) {
				sacks[len(sacks)-1].End = seqnum.Value(first + uint32(end))
			} else {
				sacks = append(sacks, header.SACKBlock{Start: seqnum.Value(first + uint32(offset)), End: seqnum.Value(first + uint32(end))})
			}
		}
		if len(sacks) > 3 {
			sacks = sacks[len(sacks)-3:]
		}
		if len(sacks) > 0 {
			space := make([]byte, 28)
			space[0], space[1] = 1, 1
			n := header.EncodeSACKBlocks(sacks, space[2:])
			options = append(options, space[:2+n]...)
			for len(options)%4 != 0 {
				options = append(options, 1)
			}
		}
		send(first+uint32(received), header.TCPFlagAck, options)
		select {
		case <-processed:
		case <-time.After(time.Second):
			t.Fatal("ACK not processed")
		}
		state := info()
		wantTimeouts := expectedTimeouts
		if scenario == "path_proof_lost" || scenario == "path_control" {
			wantTimeouts++
		}
		if got := s.Stats().TCP.Timeouts.Value(); got != wantTimeouts {
			t.Fatalf("additional timeout during ACK-driven recovery: %d", got)
		}
		if received == len(payload) {
			break
		}
		newPackets := 0
		for {
			p := read(0)
			if p == nil {
				break
			}
			if len(p.Payload()) > 0 {
				pending = append(pending, p)
				newPackets++
			}
		}
		// A congestion event may reduce cwnd below packets already emitted.
		// Check the new burst, not the sum with older queued packets. Permit
		// one legal probe; a larger new burst needs a separate explanation.
		limit := max(beforeCwnd, state.SndCwnd)
		if newPackets > int(limit)+1 {
			t.Fatalf("new burst=%d exceeds cwnd=%d/%d plus one probe", newPackets, beforeCwnd, state.SndCwnd)
		}

		if !injected && scenario != "ordered" {
			if len(pending) < 2 {
				t.Fatalf("need two repairs after first ACK, got %d", len(pending))
			}
			injected = true
			if scenario == "reordered_repair" {
				pending[0], pending[1] = pending[1], pending[0]
			} else {
				pending = pending[1:]
			} // Lose repair #2, deliver #3.
		}
		if len(pending) > 0 {
			repair = pending[0]
			pending = pending[1:]
		} else {
			// Allow a real reordering timer to fire, still well short of RTO.
			if scenario == "lost_repair" || scenario == "path_proof_lost" {
				// Delayed ACKs can enlarge RACK's reordering interval. The
				// manual clock must advance too; wall-clock read timeout
				// does not run a virtual reordering timer. Stay below RTO.
				clock.Advance(min(40*time.Millisecond, info().RTO/4))
			}
			repair = read(time.Second)
			if repair == nil {
				t.Fatalf("ACK-driven recovery stalled at %d bytes: %+v", received, state)
			}
		}
	}

	if info().CcState != tcpip.Open {
		t.Fatalf("final state=%v", info().CcState)
	}
	t.Logf("all %d bytes recovered; timeouts=%d duplicate repairs=%d", received, s.Stats().TCP.Timeouts.Value(), duplicates)
}
