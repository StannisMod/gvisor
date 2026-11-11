// Copyright 2026 StannisMod.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy at https://www.apache.org/licenses/LICENSE-2.0.
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

package tcp

import (
	"gvisor.dev/gvisor/pkg/tcpip"
	"time"
)

// ProbeVerifiedPath permits one additional retransmission per armed RTO
// deadline after the owner has authenticated a bidirectional, sufficiently
// large challenge on the current tunnel path. The owner must assign monotonic
// proof serials; this method does not authenticate a serial by itself.
// It preserves normal retransmission timing, loss marks, retry budget and cwnd.
func (e *endpoint) ProbeVerifiedPath(serial uint64) bool {
	e.LockUser()
	defer e.UnlockUser()
	s := e.snd
	if s == nil || serial <= s.lastPathProof {
		return false
	}
	s.lastPathProof = serial
	if s.state != tcpip.RTORecovery || s.SndWnd == 0 || !s.resendTimer.enabled() {
		return false
	}
	seg := s.writeList.Front()
	if seg == nil || seg.sequenceNumber != s.SndUna || seg.payloadSize() == 0 || seg.payloadSize() > s.MaxPayloadSize || seg.xmitCount < 2 {
		return false
	}
	now := e.stack.Clock().NowMonotonic()
	if now.Sub(seg.xmitTime) < 100*time.Millisecond || s.resendTimer.target.Sub(now) < 100*time.Millisecond {
		return false
	}
	if s.lastPathProbeDeadline == s.resendTimer.target {
		return false
	}
	s.lastPathProbeDeadline = s.resendTimer.target
	s.RTTMeasureSeqNum = s.SndNxt
	// This extra transmission is not another normal RTO attempt. Keep
	// the segment marked retransmitted (it was already sent at least twice),
	// but do not consume the connection's normal timeout retry budget.
	attempts, normalXmitTime, normalLost := seg.xmitCount, seg.xmitTime, seg.lost
	err := s.sendSegment(seg)
	// A late ACK of the normal retransmission must remain usable by RACK.
	// This extra copy must not overwrite that transmission's timing/loss
	// accounting. Wire retransmission counters still include the probe.
	seg.xmitCount, seg.xmitTime, seg.lost = attempts, normalXmitTime, normalLost
	return err == nil
}
