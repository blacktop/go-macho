//go:build darwin && cgo

package swift

import "testing"

func TestDarwinEngineMatchesPureGo(t *testing.T) {
	darwin := newDarwinEngine()
	pure := newPureGoEngine()

	testCases := []struct {
		symbol    string
		supported bool
	}{
		{"_$s16DemangleFixtures7CounterC5valueSivg", true},
		{"$sSS7cStringSSSPys4Int8VG_tcfC", true},
		{"_$s10ObjectiveC8ObjCBoolVMn", true},
		{"$sSaySiG", true},
		{"_$sScA15unownedExecutorScevgTq", true},
		{"_$s16DemangleFixtures15ObjCBridgeClassC7payloadAA5OuterV5InnerVvg", true},
		{"_$s16DemangleFixtures15ObjCBridgeClassC5label7payloadACSS_AA5OuterV5InnerVtcfC", true},
		{"_$s16DemangleFixtures15ObjCBridgeClassC12payloadValueSiyF", true},
		{"_$s16DemangleFixtures12DemoProtocolP", true},
		{"_$ss21_ObjectiveCBridgeableP016_forceBridgeFromA1C_6resulty01_A5CTypeQz_xSgztFZTq", true},
		{"_$s13lockdownmoded18LockdownModeServerC10setEnabled7enabled7options10completionySb_SDys11AnyHashableVypGSgys5Error_pSgctF", false},
		{"_$s13lockdownmoded18LockdownModeServerC19getEnabledInAccount11synchronize10completionySb_ySbctF", false},
		{"_$s13lockdownmoded18LockdownModeServerC24notifyRestrictionChanged_10completionySS_ys5Error_pSgctF", false},
		{"_$s13lockdownmoded18LockdownModeServerC14enableIfNeeded6reboot10completionySb_ySb_s5Error_pSgtctF", false},
		{"_$s13lockdownmoded18LockdownModeServerC15migrateIfNeeded10completionyys5Error_pSgc_tF", false},
		{"_$s13lockdownmoded18LockdownModeServerC14rebootIfNeeded10completionyys5Error_pSgc_tF", false},
		{"_$s13lockdownmoded18LockdownModeServerC28setManagedConfigurationState7enabled10completionySb_ys5Error_pSgctF", false},
		{"_$sypyc", false},
		{"_$syypc", false},
		{"_$sypSg", false},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.symbol, func(t *testing.T) {
			t.Parallel()
			want, err := darwin.Demangle(tc.symbol)
			if err != nil {
				t.Fatalf("darwin demangle failed: %v", err)
			}
			got, err := pure.Demangle(tc.symbol)
			if !tc.supported {
				if err == nil {
					t.Fatalf("expected pure Go demangler to fail for %q but succeeded with %q", tc.symbol, got)
				}
				t.Skipf("pure Go demangler does not yet support %q: %v", tc.symbol, err)
			}
			if err != nil {
				t.Fatalf("pure Go demangler does not yet support %q: %v", tc.symbol, err)
			}
			if got != want {
				t.Fatalf("demangle mismatch:\n got  %q\n want %q", got, want)
			}
		})
	}

	// TODO: add DemangleSimple parity once the simplified formatter matches libswiftDemangle output.
}
