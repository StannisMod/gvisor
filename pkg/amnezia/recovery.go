// Copyright 2026 StannisMod.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy at https://www.apache.org/licenses/LICENSE-2.0.
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

// Package amnezia identifies the reviewed dependency changes required by
// Amnezia's routed AWG/WireGuard build. It has no runtime initialization.
package amnezia

const TCPRecoveryFix = "rack-flight-v1"
const UpstreamCommit = "1f7806d17489620e45d46c33933cf8f7010a1436"
const UpstreamVersion = "v0.0.0-20231202080848-1f7806d17489"

// VerifiedPathProbe identifies the optional host-verified early TCP probe API.
// No probe runs unless the owner explicitly supplies a new path-proof serial.
const VerifiedPathProbe = "verified-path-probe-v1"
