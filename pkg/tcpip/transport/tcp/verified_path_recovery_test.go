// Copyright 2026 StannisMod.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy at https://www.apache.org/licenses/LICENSE-2.0.
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

package tcp_test

import "testing"

func TestVerifiedPathRepair(t *testing.T) {
	for _, scenario := range []string{"path_control", "path_proof", "path_proof_lost", "path_proof_lost_no_second"} {
		t.Run(scenario, func(t *testing.T) { testTCPTimeoutRecovery(t, true, true, scenario) })
	}
}

func TestPathProbeDoesNotShortenNormalRetryBudget(t *testing.T) {
	var control, probed uint64
	t.Run("control", func(t *testing.T) { testTCPTimeoutRecovery(t, true, true, "path_control", &control) })
	t.Run("lost_early_probe", func(t *testing.T) { testTCPTimeoutRecovery(t, true, true, "path_proof_lost", &probed) })
	if control == 0 || probed != control {
		t.Fatalf("normal RTO attempts before closure: control=%d with early probe=%d", control, probed)
	}
}
