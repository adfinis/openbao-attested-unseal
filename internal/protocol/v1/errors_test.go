package protocolv1

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func TestGRPCCode(t *testing.T) {
	tests := []struct {
		name string
		code ErrorCode
		want codes.Code
	}{
		{name: "invalid request", code: ErrorCode_ERROR_CODE_INVALID_REQUEST, want: codes.InvalidArgument},
		{name: "unauthenticated", code: ErrorCode_ERROR_CODE_UNAUTHENTICATED, want: codes.Unauthenticated},
		{name: "permission denied", code: ErrorCode_ERROR_CODE_PERMISSION_DENIED, want: codes.PermissionDenied},
		{name: "key not found", code: ErrorCode_ERROR_CODE_KEY_NOT_FOUND, want: codes.NotFound},
		{name: "key not usable", code: ErrorCode_ERROR_CODE_KEY_NOT_USABLE, want: codes.FailedPrecondition},
		{name: "broker unavailable", code: ErrorCode_ERROR_CODE_BROKER_UNAVAILABLE, want: codes.Unavailable},
		{name: "internal", code: ErrorCode_ERROR_CODE_INTERNAL, want: codes.Internal},
		{name: "unknown", code: ErrorCode_ERROR_CODE_UNSPECIFIED, want: codes.Unknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GRPCCode(tt.code); got != tt.want {
				t.Fatalf("GRPCCode() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestStatusResponseJSONGolden(t *testing.T) {
	message := &StatusResponse{
		ActiveKeyId: "prod-eu1/root/v1",
		Ready:       true,
		Errors: []*BrokerError{
			{
				Code:    ErrorCode_ERROR_CODE_KEY_NOT_USABLE,
				Message: "key is decrypt-only",
			},
		},
	}
	got, err := protojson.MarshalOptions{
		Multiline: true,
		Indent:    "  ",
	}.Marshal(message)
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}
	want, err := os.ReadFile(filepath.Join("testdata", "status-response.golden.json"))
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	if !sameJSON(got, want) {
		t.Fatalf("status-response.golden.json mismatch\nwant:\n%s\ngot:\n%s", want, got)
	}
}

func TestUnmarshalBoundedRejectsMalformedPayload(t *testing.T) {
	var response StatusResponse
	err := UnmarshalBounded([]byte{0xff, 0xff, 0xff}, &response)
	if !errors.Is(err, ErrInvalidProtoPayload) {
		t.Fatalf("UnmarshalBounded error = %v, want ErrInvalidProtoPayload", err)
	}
}

func TestUnmarshalBoundedRejectsOversizedPayload(t *testing.T) {
	var response StatusResponse
	payload := bytes.Repeat([]byte{1}, MaxProtoPayloadSize+1)
	err := UnmarshalBounded(payload, &response)
	if !errors.Is(err, ErrInvalidProtoPayload) {
		t.Fatalf("UnmarshalBounded error = %v, want ErrInvalidProtoPayload", err)
	}
}

func TestUnmarshalBoundedAcceptsValidPayload(t *testing.T) {
	want := &StatusResponse{ActiveKeyId: "prod-eu1/root/v1", Ready: true}
	payload, err := proto.Marshal(want)
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}

	var got StatusResponse
	if err := UnmarshalBounded(payload, &got); err != nil {
		t.Fatalf("UnmarshalBounded returned error: %v", err)
	}
	if got.GetActiveKeyId() != want.GetActiveKeyId() || got.GetReady() != want.GetReady() {
		t.Fatalf("decoded response = %#v, want %#v", &got, want)
	}
}

func sameJSON(left []byte, right []byte) bool {
	var compactLeft bytes.Buffer
	var compactRight bytes.Buffer
	if err := json.Compact(&compactLeft, left); err != nil {
		return false
	}
	if err := json.Compact(&compactRight, right); err != nil {
		return false
	}
	return bytes.Equal(compactLeft.Bytes(), compactRight.Bytes())
}
