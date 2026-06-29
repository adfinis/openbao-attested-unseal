package broker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	protocolv1 "github.com/adfinis/openbao-attested-unseal/internal/protocol/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Runtime owns broker resources for one daemon process.
type Runtime struct {
	Config Config
	Store  Store
	Audit  *FileAuditSink
	Server *grpc.Server
	Tel    *Telemetry
}

// NewRuntime initializes state, policy inputs, audit, telemetry, and gRPC services.
func NewRuntime(ctx context.Context, config Config) (*Runtime, error) {
	var err error
	config, err = config.WithLoadedPolicy()
	if err != nil {
		return nil, err
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	store, err := OpenSQLiteStore(ctx, config.SQLitePath)
	if err != nil {
		return nil, err
	}
	if len(config.DevelopmentSubjects()) > 0 {
		key, err := config.DevelopmentWrappingKey()
		if err != nil {
			_ = store.Close()
			return nil, err
		}
		if err := store.ConfigureDevelopment(ctx, config, key); err != nil {
			_ = store.Close()
			return nil, err
		}
	}
	telemetry, err := NewTelemetry(config)
	if err != nil {
		_ = store.Close()
		return nil, err
	}
	audit := NewFileAuditSink(config.AuditFilePath, config.AuditFsync)
	server, err := NewGRPCServer(config, NewService(config, store, audit, telemetry))
	if err != nil {
		_ = telemetry.Shutdown(ctx)
		_ = store.Close()
		return nil, err
	}
	return &Runtime{Config: config, Store: store, Audit: audit, Server: server, Tel: telemetry}, nil
}

// Close stops broker resources.
func (r *Runtime) Close(ctx context.Context) error {
	if r.Server != nil {
		r.Server.Stop()
	}
	var err error
	if r.Store != nil {
		err = errors.Join(err, r.Store.Close())
	}
	if r.Tel != nil {
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		err = errors.Join(err, r.Tel.Shutdown(shutdownCtx))
	}
	return err
}

// ListenAndServe starts the broker until the process receives cancellation or a fatal listener error.
func ListenAndServe(ctx context.Context, config Config) error {
	runtime, err := NewRuntime(ctx, config)
	if err != nil {
		return err
	}
	defer func() { _ = runtime.Close(ctx) }()

	listener, err := net.Listen("tcp", config.ListenAddress)
	if err != nil {
		return fmt.Errorf("listen on broker address: %w", err)
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- runtime.Server.Serve(listener)
	}()
	select {
	case <-ctx.Done():
		runtime.Server.GracefulStop()
		return ctx.Err()
	case err := <-errCh:
		if errors.Is(err, grpc.ErrServerStopped) {
			return nil
		}
		return err
	}
}

// NewGRPCServer builds a broker gRPC server.
func NewGRPCServer(config Config, service *Service) (*grpc.Server, error) {
	options, err := grpcServerOptions(config)
	if err != nil {
		return nil, err
	}
	server := grpc.NewServer(options...)
	protocolv1.RegisterUnsealServiceServer(server, service)
	protocolv1.RegisterEnrollmentServiceServer(server, EnrollmentStub{})
	protocolv1.RegisterRecoveryServiceServer(server, RecoveryStub{})
	protocolv1.RegisterAdminServiceServer(server, AdminStub{})
	return server, nil
}

func grpcServerOptions(config Config) ([]grpc.ServerOption, error) {
	if config.AllowPlaintextForTests && config.TLSCertFile == "" && config.TLSKeyFile == "" {
		return nil, nil
	}
	tlsConfig, err := loadTLSConfig(config)
	if err != nil {
		return nil, err
	}
	return []grpc.ServerOption{grpc.Creds(credentials.NewTLS(tlsConfig))}, nil
}

func loadTLSConfig(config Config) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(config.TLSCertFile, config.TLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load broker TLS keypair: %w", err)
	}
	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
	}
	if config.ClientCAFile != "" {
		// #nosec G304 -- client CA path is operator supplied.
		caPEM, err := os.ReadFile(config.ClientCAFile)
		if err != nil {
			return nil, fmt.Errorf("read client CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, errors.New("client CA file does not contain certificates")
		}
		tlsConfig.ClientCAs = pool
		if config.RequireClientCert {
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		} else {
			tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
		}
	}
	return tlsConfig, nil
}
