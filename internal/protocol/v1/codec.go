package protocolv1

import (
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"
)

const (
	// MaxProtoPayloadSize bounds diagnostic and persisted protobuf payloads accepted by helpers.
	MaxProtoPayloadSize = 1 << 20
)

// ErrInvalidProtoPayload indicates malformed or oversized protobuf input.
var ErrInvalidProtoPayload = errors.New("invalid protobuf payload")

// UnmarshalBounded rejects nil, oversized, and malformed protobuf payloads before decoding.
func UnmarshalBounded(payload []byte, message proto.Message) error {
	if message == nil {
		return fmt.Errorf("%w: nil destination message", ErrInvalidProtoPayload)
	}
	if len(payload) == 0 {
		return fmt.Errorf("%w: empty payload", ErrInvalidProtoPayload)
	}
	if len(payload) > MaxProtoPayloadSize {
		return fmt.Errorf("%w: payload exceeds maximum size", ErrInvalidProtoPayload)
	}
	if err := proto.Unmarshal(payload, message); err != nil {
		return fmt.Errorf("%w: decode protobuf: %w", ErrInvalidProtoPayload, err)
	}
	return nil
}
