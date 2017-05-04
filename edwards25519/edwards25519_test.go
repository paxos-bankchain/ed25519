package edwards25519

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func HexToBytes(h string) (result [32]byte) {
	byteSlice, _ := hex.DecodeString(h)
	copy(result[:], byteSlice)
	return
}

func TestGeMul8(t *testing.T) {
	tests := []struct {
		name     string
		pointHex string
		wantHex  string
	}{
		{
			name:     "zero",
			pointHex: "0100000000000000000000000000000000000000000000000000000000000000",
			wantHex:  "0100000000000000000000000000000000000000000000000000000000000000",
		},
		{
			name:     "basepoint",
			pointHex: "5866666666666666666666666666666666666666666666666666666666666666",
			wantHex:  "b4b937fca95b2f1e93e41e62fc3c78818ff38a66096fad6e7973e5c90006d321",
		},
	}
	for _, test := range tests {
		pointBytes := HexToBytes(test.pointHex)
		want := HexToBytes(test.wantHex)
		point := new(ExtendedGroupElement)
		point.FromBytes(&pointBytes)
		tmp := new(CompletedGroupElement)
		result := new(ExtendedGroupElement)
		var got [32]byte
		GeMul8(tmp, point)
		tmp.ToExtended(result)
		result.ToBytes(&got)
		if bytes.Compare(want[:], got[:]) != 0 {
			t.Errorf("%s: want %x, got %x", test.name, want, got)
		}
	}
}

func TestGeDoubleScalarMultVartime(t *testing.T) {
	tests := []struct {
		name       string
		pointHex   string
		scalar1Hex string
		scalar2Hex string
		wantHex    string
	}{
		{
			name:       "zero",
			pointHex:   "0100000000000000000000000000000000000000000000000000000000000000",
			scalar1Hex: "0000000000000000000000000000000000000000000000000000000000000000",
			scalar2Hex: "0000000000000000000000000000000000000000000000000000000000000000",
			wantHex:    "0100000000000000000000000000000000000000000000000000000000000000",
		},
		{
			name:       "8 times base point only",
			pointHex:   "0100000000000000000000000000000000000000000000000000000000000000",
			scalar1Hex: "0000000000000000000000000000000000000000000000000000000000000000",
			scalar2Hex: "0800000000000000000000000000000000000000000000000000000000000000",
			wantHex:    "b4b937fca95b2f1e93e41e62fc3c78818ff38a66096fad6e7973e5c90006d321",
		},
		{
			name:       "2 times non-base-point",
			pointHex:   "2f1132ca61ab38dff00f2fea3228f24c6c71d58085b80e47e19515cb27e8d047",
			scalar1Hex: "0200000000000000000000000000000000000000000000000000000000000000",
			scalar2Hex: "0000000000000000000000000000000000000000000000000000000000000000",
			wantHex:    "b4b937fca95b2f1e93e41e62fc3c78818ff38a66096fad6e7973e5c90006d321",
		},
		{
			name:       "Combination",
			pointHex:   "2f1132ca61ab38dff00f2fea3228f24c6c71d58085b80e47e19515cb27e8d047",
			scalar1Hex: "0100000000000000000000000000000000000000000000000000000000000000",
			scalar2Hex: "0400000000000000000000000000000000000000000000000000000000000000",
			wantHex:    "b4b937fca95b2f1e93e41e62fc3c78818ff38a66096fad6e7973e5c90006d321",
		},
	}
	for _, test := range tests {
		pointBytes := HexToBytes(test.pointHex)
		a := HexToBytes(test.scalar1Hex)
		b := HexToBytes(test.scalar2Hex)
		want := HexToBytes(test.wantHex)
		point := new(ExtendedGroupElement)
		point.FromBytes(&pointBytes)
		result := new(ProjectiveGroupElement)
		GeDoubleScalarMultVartime(result, &a, point, &b)
		var got [32]byte
		result.ToBytes(&got)
		if bytes.Compare(want[:], got[:]) != 0 {
			t.Errorf("%s: want %x, got %x", test.name, want, got)
		}
	}
}

func TestGeDoubleScalarMultPrecompVartime(t *testing.T) {
	tests := []struct {
		name       string
		point1Hex  string
		point2Hex  string
		scalar1Hex string
		scalar2Hex string
		wantHex    string
	}{
		{
			name:       "zero",
			point1Hex:  "0100000000000000000000000000000000000000000000000000000000000000",
			point2Hex:  "0100000000000000000000000000000000000000000000000000000000000000",
			scalar1Hex: "0000000000000000000000000000000000000000000000000000000000000000",
			scalar2Hex: "0000000000000000000000000000000000000000000000000000000000000000",
			wantHex:    "0100000000000000000000000000000000000000000000000000000000000000",
		},
		{
			name:       "scalar 1 only",
			point1Hex:  "5866666666666666666666666666666666666666666666666666666666666666",
			point2Hex:  "0100000000000000000000000000000000000000000000000000000000000000",
			scalar1Hex: "0800000000000000000000000000000000000000000000000000000000000000",
			scalar2Hex: "0000000000000000000000000000000000000000000000000000000000000000",
			wantHex:    "b4b937fca95b2f1e93e41e62fc3c78818ff38a66096fad6e7973e5c90006d321",
		},
		{
			name:       "scalar 2 only",
			point1Hex:  "0100000000000000000000000000000000000000000000000000000000000000",
			point2Hex:  "5866666666666666666666666666666666666666666666666666666666666666",
			scalar1Hex: "0000000000000000000000000000000000000000000000000000000000000000",
			scalar2Hex: "0800000000000000000000000000000000000000000000000000000000000000",
			wantHex:    "b4b937fca95b2f1e93e41e62fc3c78818ff38a66096fad6e7973e5c90006d321",
		},
		{
			name:       "Combination",
			point1Hex:  "2f1132ca61ab38dff00f2fea3228f24c6c71d58085b80e47e19515cb27e8d047",
			point2Hex:  "5866666666666666666666666666666666666666666666666666666666666666",
			scalar1Hex: "0100000000000000000000000000000000000000000000000000000000000000",
			scalar2Hex: "0400000000000000000000000000000000000000000000000000000000000000",
			wantHex:    "b4b937fca95b2f1e93e41e62fc3c78818ff38a66096fad6e7973e5c90006d321",
		},
	}
	for _, test := range tests {
		point1Bytes := HexToBytes(test.point1Hex)
		point2Bytes := HexToBytes(test.point2Hex)
		a := HexToBytes(test.scalar1Hex)
		b := HexToBytes(test.scalar2Hex)
		want := HexToBytes(test.wantHex)
		point1 := new(ExtendedGroupElement)
		point1.FromBytes(&point1Bytes)
		point2 := new(ExtendedGroupElement)
		point2.FromBytes(&point2Bytes)
		var point2Precomp [8]CachedGroupElement
		GePrecompute(&point2Precomp, point2)
		result := new(ProjectiveGroupElement)
		GeDoubleScalarMultPrecompVartime(result, &a, point1, &b, point2Precomp)
		var got [32]byte
		result.ToBytes(&got)
		if bytes.Compare(want[:], got[:]) != 0 {
			t.Errorf("%s: want %x, got %x", test.name, want, got)
		}
	}
}
