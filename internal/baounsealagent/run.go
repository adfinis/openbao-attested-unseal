package baounsealagent

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/adfinis/openbao-attested-unseal/internal/cli"
	protocolv1 "github.com/adfinis/openbao-attested-unseal/internal/protocol/v1"
)

const (
	defaultRunInterval = time.Minute
	runEventPublished  = "node_evidence_published"
	runEventFailed     = "node_evidence_publish_failed"
)

type runOptions struct {
	publishOnceOptions
	interval    time.Duration
	maxFailures uint
}

type runEvent struct {
	Event        string `json:"event"`
	Time         string `json:"time"`
	Attempt      uint64 `json:"attempt"`
	FailureCount uint   `json:"failure_count,omitempty"`
	ClusterID    string `json:"cluster_id"`
	NodeName     string `json:"node_name"`
	NodeUID      string `json:"node_uid,omitempty"`
	ProviderID   string `json:"provider_id"`
	EvidenceHash string `json:"evidence_hash,omitempty"`
	CollectedAt  string `json:"collected_at,omitempty"`
	ExpiresAt    string `json:"expires_at,omitempty"`
	Status       string `json:"status,omitempty"`
	Decision     string `json:"decision,omitempty"`
	Error        string `json:"error,omitempty"`
}

type agentRunLoop struct {
	interval    time.Duration
	maxFailures uint
	publish     func(context.Context) (publishOnceOutput, error)
	write       func(runEvent) error
	wait        func(context.Context, time.Duration) error
	now         func() time.Time
}

func runCommand(args []string, stdout io.Writer, stderr io.Writer) error {
	options, err := parseRunOptions(args, stderr)
	if err != nil {
		return err
	}
	ctx, stop := signalContext()
	defer stop()
	return runAgent(ctx, options, stdout)
}

func parseRunOptions(args []string, stderr io.Writer) (runOptions, error) {
	flags := flag.NewFlagSet(commandRun, flag.ContinueOnError)
	flags.SetOutput(stderr)
	values := addPublishFlags(flags)
	interval := flags.Duration("interval", defaultRunInterval, "Node evidence publish interval.")
	maxFailures := flags.Uint("max-failures", 0, "Exit after this many consecutive failures; 0 retries forever.")
	if err := flags.Parse(args); err != nil {
		return runOptions{}, cli.WithExitCode(cli.ExitUsage, err)
	}
	publishOptions, err := publishOptionsFromFlags(values)
	if err != nil {
		return runOptions{}, err
	}
	if *interval <= 0 {
		return runOptions{}, cli.WithExitCode(cli.ExitUsage, errors.New("-interval must be greater than zero"))
	}
	if *interval >= publishOptions.ttl {
		return runOptions{}, cli.WithExitCode(cli.ExitUsage, errors.New("-interval must be shorter than -ttl"))
	}
	return runOptions{
		publishOnceOptions: publishOptions,
		interval:           *interval,
		maxFailures:        *maxFailures,
	}, nil
}

func runAgent(ctx context.Context, options runOptions, stdout io.Writer) error {
	conn, err := brokerAdminConn(options.publishOnceOptions)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	provider, err := publishOnceProvider(options.providerID)
	if err != nil {
		return err
	}
	client := protocolv1.NewAdminServiceClient(conn)
	eventWriter := runEventWriter{
		stdout: stdout,
		format: options.format,
	}
	loop := agentRunLoop{
		interval:    options.interval,
		maxFailures: options.maxFailures,
		publish: func(ctx context.Context) (publishOnceOutput, error) {
			attemptCtx, cancel := context.WithTimeout(ctx, options.timeout)
			defer cancel()
			return publishWithClient(attemptCtx, client, provider, options.publishOnceOptions)
		},
		write: eventWriter.Write,
	}
	return loop.Run(ctx, options.publishOnceOptions)
}

func (l agentRunLoop) Run(ctx context.Context, options publishOnceOptions) error {
	if l.publish == nil {
		return cli.WithExitCode(cli.ExitUsage, errors.New("publish function is required"))
	}
	if l.write == nil {
		return cli.WithExitCode(cli.ExitUsage, errors.New("event writer is required"))
	}
	interval := l.interval
	if interval <= 0 {
		interval = defaultRunInterval
	}
	var attempt uint64
	var failures uint
	for {
		attempt++
		out, err := l.publish(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			failures++
			event := l.failureEvent(options, attempt, failures, err)
			if writeErr := l.write(event); writeErr != nil {
				return cli.WithExitCode(cli.ExitRuntime, writeErr)
			}
			if l.maxFailures > 0 && failures >= l.maxFailures {
				return cli.WithExitCode(cli.ExitRuntime, err)
			}
		} else {
			failures = 0
			if writeErr := l.write(l.successEvent(out, attempt)); writeErr != nil {
				return cli.WithExitCode(cli.ExitRuntime, writeErr)
			}
		}
		if err := l.waitForNext(ctx, interval); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return cli.WithExitCode(cli.ExitRuntime, err)
		}
	}
}

func (l agentRunLoop) successEvent(out publishOnceOutput, attempt uint64) runEvent {
	return runEvent{
		Event:        runEventPublished,
		Time:         l.nowUTC().Format(time.RFC3339Nano),
		Attempt:      attempt,
		ClusterID:    out.ClusterID,
		NodeName:     out.NodeName,
		NodeUID:      out.NodeUID,
		ProviderID:   out.ProviderID,
		EvidenceHash: out.EvidenceHash,
		CollectedAt:  out.CollectedAt,
		ExpiresAt:    out.ExpiresAt,
		Status:       out.Status,
		Decision:     out.Decision,
	}
}

func (l agentRunLoop) failureEvent(
	options publishOnceOptions,
	attempt uint64,
	failures uint,
	err error,
) runEvent {
	return runEvent{
		Event:        runEventFailed,
		Time:         l.nowUTC().Format(time.RFC3339Nano),
		Attempt:      attempt,
		FailureCount: failures,
		ClusterID:    options.clusterID,
		NodeName:     options.nodeName,
		NodeUID:      options.nodeUID,
		ProviderID:   options.providerID,
		Error:        err.Error(),
	}
}

func (l agentRunLoop) waitForNext(ctx context.Context, interval time.Duration) error {
	if l.wait != nil {
		return l.wait(ctx, interval)
	}
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (l agentRunLoop) nowUTC() time.Time {
	if l.now == nil {
		return time.Now().UTC()
	}
	return l.now().UTC()
}

type runEventWriter struct {
	stdout io.Writer
	format string
}

func (w runEventWriter) Write(event runEvent) error {
	if w.format == formatJSON {
		return json.NewEncoder(w.stdout).Encode(event)
	}
	switch event.Event {
	case runEventPublished:
		_, err := fmt.Fprintf(
			w.stdout,
			"%s %s node=%s cluster=%s provider=%s status=%s decision=%s expires=%s\n",
			event.Time,
			event.Event,
			event.NodeName,
			event.ClusterID,
			event.ProviderID,
			event.Status,
			event.Decision,
			event.ExpiresAt,
		)
		return err
	case runEventFailed:
		_, err := fmt.Fprintf(
			w.stdout,
			"%s %s node=%s cluster=%s provider=%s failure_count=%d error=%s\n",
			event.Time,
			event.Event,
			event.NodeName,
			event.ClusterID,
			event.ProviderID,
			event.FailureCount,
			event.Error,
		)
		return err
	default:
		_, err := fmt.Fprintf(w.stdout, "%s %s\n", event.Time, event.Event)
		return err
	}
}
