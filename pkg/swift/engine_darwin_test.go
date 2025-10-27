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
		// Remaining symbols observed from lockdownmoded that pure Go still fails to demangle.
		{"_$ss35_HasCustomAnyHashableRepresentationMp", false},
		{"_$s8RawValueSYTl", false},
		{"_$sSY8rawValuexSg03RawB0Qz_tcfCTq", false},
		{"_$ss20_SwiftNewtypeWrapperMp", false},
		{"_$ss20_SwiftNewtypeWrapperPSYTb", false},
		{"_$ss20_SwiftNewtypeWrapperPs35_HasCustomAnyHashableRepresentationTb", false},
		{"_$sSQ2eeoiySbx_xtFZTq", false},
		{"_$ss21_ObjectiveCBridgeableMp", false},
		{"_$s15_ObjectiveCTypes01_A11CBridgeablePTl", false},
		{"_$sSHSQTb", false},
		{"_$sSH4hash4intoys6HasherVz_tFTq", false},
		{"_$sSH13_rawHashValue4seedS2i_tFTq", false},
		{"_$s10Foundation18_ErrorCodeProtocolMp", false},
		{"_$s10Foundation18_ErrorCodeProtocolPSQTb", false},
		{"_$s10Foundation18_ErrorCodeProtocolP01_B4TypeAC_AA21_BridgedStoredNSErrorTn", false},
		{"_$s10_ErrorType10Foundation01_A12CodeProtocolPTl", false},
		{"_$s10Foundation21_BridgedStoredNSErrorMp", false},
		{"_$s10Foundation21_BridgedStoredNSErrorPAA06CustomD0Tb", false},
		{"_$s10Foundation21_BridgedStoredNSErrorPAA26_ObjectiveCBridgeableErrorTb", false},
		{"_$s10Foundation21_BridgedStoredNSErrorPSHTb", false},
		{"_$s10Foundation21_BridgedStoredNSErrorP4CodeAC_AA06_ErrorE8ProtocolTn", false},
		{"_$s10Foundation21_BridgedStoredNSErrorP4CodeAC_SYTn", false},
		{"_$s10Foundation21_BridgedStoredNSErrorP4CodeAC_8RawValueSYs17FixedWidthIntegerTn", false},
		{"_$s4Code10Foundation21_BridgedStoredNSErrorPTl", false},
		{"_$s10Foundation26_ObjectiveCBridgeableErrorMp", false},
		{"_$s10Foundation26_ObjectiveCBridgeableErrorPs0D0Tb", false},
		{"_$s10Foundation26_ObjectiveCBridgeableErrorP15_bridgedNSErrorxSgSo0F0Ch_tcfCTq", false},
		{"_$ss5ErrorMp", false},
		{"_$ss5ErrorP9_userInfoyXlSgvgTq", false},
		{"_$ss5ErrorP19_getEmbeddedNSErroryXlSgyFTq", false},
		{"_$s10Foundation13CustomNSErrorMp", false},
		{"_$s10Foundation13CustomNSErrorPs5ErrorTb", false},
		{"_$s10Foundation13CustomNSErrorP13errorUserInfoSDySSypGvgTq", false},
		{"_$s14CoreFoundation9_CFObjectMp", false},
		{"_$s14CoreFoundation9_CFObjectPSHTb", false},
		{"_$ss23CustomStringConvertibleMp", false},
		{"_$s10Foundation14LocalizedErrorMp", false},
		{"_$s10Foundation14LocalizedErrorPs0C0Tb", false},
		{"_$ss12CaseIterableMp", false},
		{"_$ss12CaseIterableP8AllCasesAB_SlTn", false},
		{"_$s8AllCasess12CaseIterablePTl", false},
		{"_$sScA_pSg", false},
		{"_$sytIeAgHr_", false},
		{"_$sIeyBh_", false},
		{"_$sIeghH_", false},
		{"_$sIeAgH_", false},
		{"_$sXDXMT", false},
		{"_$sSgIegg_", false},
		{"_$sSbIegy_", false},
		{"_$sIegg_", false},
		{"_$sSo7NSErrorCSgIeyBy_", false},
		{"_$sSo7NSErrorCSgIeyByy_", false},
		{"_$sSgIegyg_", false},
		{"_$sIeyBy_", false},
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
