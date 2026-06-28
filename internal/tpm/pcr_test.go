package tpm

import (
	"bytes"
	"testing"
)

func TestPCRSelectionNormalize(t *testing.T) {
	selection, err := (PCRSelection{Hash: "SHA256", PCRs: []int{7, 0}}).Normalize()
	if err != nil {
		t.Fatalf("Normalize returned error: %v", err)
	}
	if selection.Hash != HashSHA256 {
		t.Fatalf("hash = %q, want %q", selection.Hash, HashSHA256)
	}
	if got, want := selection.PCRs, []int{0, 7}; !sameInts(got, want) {
		t.Fatalf("PCRs = %v, want %v", got, want)
	}
}

func TestPCRSelectionRejectsDuplicate(t *testing.T) {
	_, err := (PCRSelection{Hash: HashSHA256, PCRs: []int{7, 7}}).Normalize()
	if err == nil {
		t.Fatal("Normalize returned nil error for duplicate PCR")
	}
}

func TestComputePCRDigestRequiresSelectedValues(t *testing.T) {
	_, err := ComputePCRDigest(PCRSelection{Hash: HashSHA256, PCRs: []int{7}}, nil)
	if err == nil {
		t.Fatal("ComputePCRDigest returned nil error without PCR values")
	}
}

func TestComputePCRDigestIsStable(t *testing.T) {
	zero := bytes.Repeat([]byte{0}, 32)
	one := bytes.Repeat([]byte{1}, 32)
	got, err := ComputePCRDigest(PCRSelection{Hash: HashSHA256, PCRs: []int{0, 7}}, map[int][]byte{
		0: zero,
		7: one,
	})
	if err != nil {
		t.Fatalf("ComputePCRDigest returned error: %v", err)
	}
	again, err := ComputePCRDigest(PCRSelection{Hash: HashSHA256, PCRs: []int{7, 0}}, map[int][]byte{
		0: zero,
		7: one,
	})
	if err != nil {
		t.Fatalf("ComputePCRDigest returned error: %v", err)
	}
	if !bytes.Equal(got, again) {
		t.Fatalf("digest changed with PCR order: %x != %x", got, again)
	}
}

func sameInts(left []int, right []int) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
