// Copyright 2026 StannisMod.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy at https://www.apache.org/licenses/LICENSE-2.0.
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

package gonet

// ProbeVerifiedPath forwards a host-verified path notification to TCP. It does
// not create or authenticate a path proof; see tcp.endpoint.ProbeVerifiedPath.
func (c *TCPConn) ProbeVerifiedPath(serial uint64) bool {
	if c == nil || c.ep == nil {
		return false
	}
	probe, ok := c.ep.(interface{ ProbeVerifiedPath(uint64) bool })
	return ok && probe.ProbeVerifiedPath(serial)
}
