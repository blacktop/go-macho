//go:build darwin && cgo

package swift

import "testing"

func TestDarwinEngineMatchesPureGo(t *testing.T) {
	darwin := newDarwinEngine()
	pure := newPureGoEngine()

	symbols := []string{
		"_$s16DemangleFixtures7CounterC5valueSivg",
		"$sSS7cStringSSSPys4Int8VG_tcfC",
		"_$s10ObjectiveC8ObjCBoolVMn",
		"$sSaySiG",
		"_$sScA15unownedExecutorScevgTq",
		"_$s16DemangleFixtures15ObjCBridgeClassC7payloadAA5OuterV5InnerVvg",
		"_$s16DemangleFixtures15ObjCBridgeClassC5label7payloadACSS_AA5OuterV5InnerVtcfC",
		"_$s16DemangleFixtures15ObjCBridgeClassC12payloadValueSiyF",
		"_$s16DemangleFixtures12DemoProtocolP",
	}

	for _, symbol := range symbols {
		symbol := symbol
		t.Run(symbol, func(t *testing.T) {
			t.Parallel()
			want, err := darwin.Demangle(symbol)
			if err != nil {
				t.Fatalf("darwin demangle failed: %v", err)
			}
			got, err := pure.Demangle(symbol)
			if err != nil {
				t.Fatalf("pure Go demangler does not yet support %q: %v", symbol, err)
			}
			if got != want {
				t.Fatalf("demangle mismatch:\n got  %q\n want %q", got, want)
			}
		})
	}

	// TODO: add DemangleSimple parity once the simplified formatter matches libswiftDemangle output.
}
