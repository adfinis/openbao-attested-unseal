package protocolv1

import (
	"google.golang.org/grpc/codes"
)

// GRPCCode maps broker error codes onto the closest gRPC status code.
func GRPCCode(code ErrorCode) codes.Code {
	switch code {
	case ErrorCode_ERROR_CODE_INVALID_REQUEST:
		return codes.InvalidArgument
	case ErrorCode_ERROR_CODE_UNAUTHENTICATED:
		return codes.Unauthenticated
	case ErrorCode_ERROR_CODE_PERMISSION_DENIED:
		return codes.PermissionDenied
	case ErrorCode_ERROR_CODE_KEY_NOT_FOUND:
		return codes.NotFound
	case ErrorCode_ERROR_CODE_KEY_NOT_USABLE, ErrorCode_ERROR_CODE_ATTESTATION_FAILED:
		return codes.FailedPrecondition
	case ErrorCode_ERROR_CODE_BROKER_UNAVAILABLE:
		return codes.Unavailable
	case ErrorCode_ERROR_CODE_INTERNAL:
		return codes.Internal
	default:
		return codes.Unknown
	}
}
