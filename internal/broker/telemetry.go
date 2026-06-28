package broker

import (
	"context"
	"errors"
	"time"

	protocolv1 "github.com/dc-tec/openbao-attested-unseal/internal/protocol/v1"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/stdout/stdoutmetric"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	otelmetric "go.opentelemetry.io/otel/metric"
	metricsdk "go.opentelemetry.io/otel/sdk/metric"
	tracesdk "go.opentelemetry.io/otel/sdk/trace"
	oteltrace "go.opentelemetry.io/otel/trace"
)

const instrumentationName = "github.com/dc-tec/openbao-attested-unseal/internal/broker"

// Telemetry contains broker OpenTelemetry hooks without installing an exporter.
type Telemetry struct {
	tracer              oteltrace.Tracer
	wrapRequests        otelmetric.Int64Counter
	unwrapRequests      otelmetric.Int64Counter
	challengeRequests   otelmetric.Int64Counter
	auditFailures       otelmetric.Int64Counter
	policyLatency       otelmetric.Float64Histogram
	keyringLatency      otelmetric.Float64Histogram
	attestationLatency  otelmetric.Float64Histogram
	brokerKeyringLocked otelmetric.Int64Gauge
	shutdown            func(context.Context) error
}

// NewTelemetry initializes broker metrics and traces.
func NewTelemetry(config Config) (*Telemetry, error) {
	switch config.Exporter() {
	case OTelExporterNone:
		return newTelemetry(
			otel.GetTracerProvider(),
			otel.GetMeterProvider(),
			nil,
		)
	case OTelExporterStdout:
		return newStdoutTelemetry()
	default:
		return nil, errors.New("unsupported OpenTelemetry exporter")
	}
}

func newStdoutTelemetry() (*Telemetry, error) {
	traceExporter, err := stdouttrace.New(
		stdouttrace.WithPrettyPrint(),
		stdouttrace.WithoutTimestamps(),
	)
	if err != nil {
		return nil, err
	}
	metricExporter, err := stdoutmetric.New(
		stdoutmetric.WithPrettyPrint(),
		stdoutmetric.WithoutTimestamps(),
	)
	if err != nil {
		return nil, err
	}
	tracerProvider := tracesdk.NewTracerProvider(tracesdk.WithSyncer(traceExporter))
	meterProvider := metricsdk.NewMeterProvider(metricsdk.WithReader(
		metricsdk.NewPeriodicReader(metricExporter, metricsdk.WithInterval(5*time.Second)),
	))
	return newTelemetry(tracerProvider, meterProvider, func(ctx context.Context) error {
		return errors.Join(meterProvider.Shutdown(ctx), tracerProvider.Shutdown(ctx))
	})
}

func newTelemetry(
	tracerProvider oteltrace.TracerProvider,
	meterProvider otelmetric.MeterProvider,
	shutdown func(context.Context) error,
) (*Telemetry, error) {
	meter := meterProvider.Meter(instrumentationName)
	wrapRequests, err := meter.Int64Counter("broker.wrap.requests")
	if err != nil {
		return nil, err
	}
	unwrapRequests, err := meter.Int64Counter("broker.unwrap.requests")
	if err != nil {
		return nil, err
	}
	challengeRequests, err := meter.Int64Counter("broker.challenge.requests")
	if err != nil {
		return nil, err
	}
	auditFailures, err := meter.Int64Counter("broker.audit.write.failures")
	if err != nil {
		return nil, err
	}
	policyLatency, err := meter.Float64Histogram("broker.policy.duration_ms")
	if err != nil {
		return nil, err
	}
	keyringLatency, err := meter.Float64Histogram("broker.keyring.duration_ms")
	if err != nil {
		return nil, err
	}
	attestationLatency, err := meter.Float64Histogram("broker.attestation.duration_ms")
	if err != nil {
		return nil, err
	}
	brokerKeyringLocked, err := meter.Int64Gauge("broker.keyring.locked")
	if err != nil {
		return nil, err
	}
	return &Telemetry{
		tracer:              tracerProvider.Tracer(instrumentationName),
		wrapRequests:        wrapRequests,
		unwrapRequests:      unwrapRequests,
		challengeRequests:   challengeRequests,
		auditFailures:       auditFailures,
		policyLatency:       policyLatency,
		keyringLatency:      keyringLatency,
		attestationLatency:  attestationLatency,
		brokerKeyringLocked: brokerKeyringLocked,
		shutdown:            shutdown,
	}, nil
}

// Shutdown flushes and releases configured telemetry exporters.
func (t *Telemetry) Shutdown(ctx context.Context) error {
	if t == nil || t.shutdown == nil {
		return nil
	}
	return t.shutdown(ctx)
}

func (t *Telemetry) start(
	ctx context.Context,
	name string,
	attrs ...attribute.KeyValue,
) (context.Context, oteltrace.Span) {
	return t.tracer.Start(ctx, name, oteltrace.WithAttributes(attrs...))
}

func (t *Telemetry) recordChallenge(ctx context.Context, attrs []attribute.KeyValue) {
	t.challengeRequests.Add(ctx, 1, otelmetric.WithAttributes(attrs...))
}

func (t *Telemetry) recordWrap(ctx context.Context, attrs []attribute.KeyValue) {
	t.wrapRequests.Add(ctx, 1, otelmetric.WithAttributes(attrs...))
}

func (t *Telemetry) recordUnwrap(ctx context.Context, attrs []attribute.KeyValue) {
	t.unwrapRequests.Add(ctx, 1, otelmetric.WithAttributes(attrs...))
}

func (t *Telemetry) recordAuditFailure(ctx context.Context, attrs []attribute.KeyValue) {
	t.auditFailures.Add(ctx, 1, otelmetric.WithAttributes(attrs...))
}

func (t *Telemetry) recordPolicyLatency(ctx context.Context, started time.Time, attrs []attribute.KeyValue) {
	t.policyLatency.Record(ctx, elapsedMilliseconds(started), otelmetric.WithAttributes(attrs...))
}

func (t *Telemetry) recordKeyringLatency(ctx context.Context, started time.Time, attrs []attribute.KeyValue) {
	t.keyringLatency.Record(ctx, elapsedMilliseconds(started), otelmetric.WithAttributes(attrs...))
}

func (t *Telemetry) recordAttestationPlaceholder(ctx context.Context, attrs []attribute.KeyValue) {
	t.attestationLatency.Record(ctx, 0, otelmetric.WithAttributes(attrs...))
}

func (t *Telemetry) recordKeyringUnlocked(ctx context.Context, attrs []attribute.KeyValue) {
	t.brokerKeyringLocked.Record(ctx, 0, otelmetric.WithAttributes(attrs...))
}

func elapsedMilliseconds(started time.Time) float64 {
	return float64(time.Since(started).Microseconds()) / 1000
}

func safeAttributes(
	clusterID string,
	keyID string,
	keyVersion uint32,
	operation protocolv1.Operation,
	decision PolicyDecision,
	auditID string,
) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.String("cluster.id", clusterID),
		attribute.String("key.id", keyID),
		attribute.Int("key.version", int(keyVersion)),
		attribute.String("operation", operation.String()),
		attribute.String("decision", decision.State.String()),
		attribute.String("error.code", decision.ErrorCode.String()),
		attribute.String("policy.id", decision.PolicyID),
		attribute.String("audit.id", auditID),
	}
}
