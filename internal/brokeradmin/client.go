// Package brokeradmin contains reusable broker admin client helpers.
package brokeradmin

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// ClientOptions configures a broker admin gRPC client.
type ClientOptions struct {
	Plaintext      bool
	CACertPath     string
	TLSServerName  string
	ClientCertPath string
	ClientKeyPath  string
}

// DialOptions returns gRPC dial options for the broker admin API.
func DialOptions(options ClientOptions) ([]grpc.DialOption, error) {
	options = normalizeClientOptions(options)
	if (options.ClientCertPath == "") != (options.ClientKeyPath == "") {
		return nil, errors.New("client certificate and key must be provided together")
	}
	if options.Plaintext {
		return []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}, nil
	}
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: options.TLSServerName,
	}
	if options.CACertPath != "" {
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		// #nosec G304 -- broker CA path is operator supplied.
		caPEM, err := os.ReadFile(options.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("read broker CA certificate: %w", err)
		}
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, errors.New("broker CA certificate did not contain a PEM certificate")
		}
		tlsConfig.RootCAs = pool
	}
	if options.ClientCertPath != "" {
		cert, err := tls.LoadX509KeyPair(options.ClientCertPath, options.ClientKeyPath)
		if err != nil {
			return nil, fmt.Errorf("load broker client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}
	return []grpc.DialOption{grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig))}, nil
}

func normalizeClientOptions(options ClientOptions) ClientOptions {
	return ClientOptions{
		Plaintext:      options.Plaintext,
		CACertPath:     strings.TrimSpace(options.CACertPath),
		TLSServerName:  strings.TrimSpace(options.TLSServerName),
		ClientCertPath: strings.TrimSpace(options.ClientCertPath),
		ClientKeyPath:  strings.TrimSpace(options.ClientKeyPath),
	}
}
