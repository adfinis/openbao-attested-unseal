package keyring

import "testing"

func FuzzParseCanonicalAAD(f *testing.F) {
	seed, err := NewMetadata(testVersion(StatusActive, 1)).CanonicalAAD([]byte("openbao aad"))
	if err != nil {
		f.Fatalf("CanonicalAAD returned error: %v", err)
	}
	f.Add(seed)
	f.Add([]byte(`{"metadata":{"schema_version":99}}`))
	f.Add([]byte("not-json"))

	f.Fuzz(func(t *testing.T, payload []byte) {
		metadata, callerAAD, err := ParseCanonicalAAD(payload)
		if err != nil {
			return
		}
		if err := metadata.Validate(); err != nil {
			t.Fatalf("parsed metadata did not validate: %v", err)
		}
		encoded, err := metadata.CanonicalAAD(callerAAD)
		if err != nil {
			t.Fatalf("CanonicalAAD returned error: %v", err)
		}
		if _, _, err := ParseCanonicalAAD(encoded); err != nil {
			t.Fatalf("ParseCanonicalAAD rejected round-tripped payload: %v", err)
		}
	})
}
