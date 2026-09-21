// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	proxyecosystem "github.com/DataDog/supply-chain-firewall/scfw/internal/proxy/ecosystem"
)

// RegistryConfiguration is the package-manager-independent result of registry
// discovery. Named registries are scopes for JavaScript managers and additional
// indexes or source names for Python managers.
type RegistryConfiguration struct {
	Default               *url.URL
	Named                 map[string]*url.URL
	Handler               proxyecosystem.Handler
	Credentials           map[string]RegistryCredential
	UseNPMCredentials     bool
	UseNetrc              bool
	CAFile                string
	CACertificates        []string
	InsecureTLS           bool
	ClientCertificateFile string
	ClientKeyFile         string
}

// RegistryCredential is attached only to upstream URLs matching its configured
// registry prefix. It is never forwarded to a cross-origin artifact host.
type RegistryCredential struct {
	BearerToken string
	Username    string
	Password    string
}

// PreparedCommand is a process-local package-manager invocation. Cleanup must
// remove any temporary configuration created by Prepare.
type PreparedCommand struct {
	Executable string
	Args       []string
	Env        []string
	Cleanup    func() error
}

// Manager isolates package-manager-specific registry discovery and overrides.
type Manager interface {
	Name() string
	Registries(context.Context, string, []string) (RegistryConfiguration, error)
	Prepare(string, []string, string, map[string]string) (PreparedCommand, error)
}

// Run starts the shared registry proxy and launches one configured manager.
func Run(ctx context.Context, manager Manager, executable string, args []string, streams Streams, options Options) (returnErr error) {
	configuration, err := manager.Registries(ctx, executable, args)
	if err != nil {
		return fmt.Errorf("read %s registry configuration: %w", manager.Name(), err)
	}
	if configuration.Default == nil {
		return fmt.Errorf("read %s registry configuration: missing default registry", manager.Name())
	}
	stdout := streams.Stdout
	if stdout == nil {
		stdout = io.Discard
	}
	synchronizedStdout := &synchronizedWriter{writer: stdout}
	serverConfig := NPMConfig{
		Registry:                          configuration.Default,
		ScopedRegistries:                  configuration.Named,
		ResponseHandler:                   configuration.Handler,
		AllowUnauthenticatedLocalRequests: true,
		ForwardAuthorization:              true,
		lockfileDestinations:              make(map[string]*url.URL),
		caFile:                            configuration.CAFile,
		caCertificates:                    configuration.CACertificates,
		insecureSkipTLSVerify:             configuration.InsecureTLS,
	}
	if configuration.ClientCertificateFile != "" || configuration.ClientKeyFile != "" {
		if configuration.ClientCertificateFile == "" || configuration.ClientKeyFile == "" {
			return fmt.Errorf("read %s registry TLS configuration: client certificate and key must both be configured", manager.Name())
		}
		certificate, readErr := os.ReadFile(configuration.ClientCertificateFile)
		if readErr != nil {
			return fmt.Errorf("read %s registry client certificate: %w", manager.Name(), readErr)
		}
		key, readErr := os.ReadFile(configuration.ClientKeyFile)
		if readErr != nil {
			return fmt.Errorf("read %s registry client key: %w", manager.Name(), readErr)
		}
		serverConfig.clientCertificate = string(certificate)
		serverConfig.clientKey = string(key)
	}
	if configuration.UseNPMCredentials {
		files := npmCredentialFiles()
		credentials, credentialErr := loadNPMCredentials(files, os.Environ())
		if credentialErr != nil {
			return fmt.Errorf("read %s registry credentials: %w", manager.Name(), credentialErr)
		}
		serverConfig.credentials = credentials
	}
	if serverConfig.credentials == nil {
		serverConfig.credentials = make(map[string]npmCredentials)
	}
	for prefix, credential := range configuration.Credentials {
		parsed, parseErr := url.Parse(prefix)
		if parseErr != nil || parsed.Host == "" {
			return fmt.Errorf("read %s registry credentials: invalid registry prefix", manager.Name())
		}
		key := normalizeCredentialPrefix("//" + parsed.Host + parsed.EscapedPath())
		serverConfig.credentials[key] = npmCredentials{
			token:    credential.BearerToken,
			username: credential.Username,
			password: credential.Password,
		}
	}
	if configuration.UseNetrc {
		credentials, credentialErr := loadNetrcCredentials()
		if credentialErr != nil {
			return fmt.Errorf("read %s netrc credentials: %w", manager.Name(), credentialErr)
		}
		serverConfig.basicCredentials = credentials
	}
	server, err := StartWithOptions(serverConfig, synchronizedStdout, options)
	if err != nil {
		return err
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		returnErr = errors.Join(returnErr, server.Close(shutdownCtx))
	}()
	prepared, err := manager.Prepare(executable, args, server.URL(), server.RegistryURLs())
	if err != nil {
		return err
	}
	if prepared.Cleanup != nil {
		defer func() { returnErr = errors.Join(returnErr, prepared.Cleanup()) }()
	}
	childContext, cancelChild := context.WithCancel(ctx)
	defer cancelChild()
	childExecutable := prepared.Executable
	if childExecutable == "" {
		childExecutable = executable
	}
	child := exec.CommandContext(childContext, childExecutable, prepared.Args...)
	child.Stdin = streams.Stdin
	child.Stdout = synchronizedStdout
	child.Stderr = streams.Stderr
	child.Env = prepared.Env
	if child.Env == nil {
		child.Env = os.Environ()
	}
	if err := child.Start(); err != nil {
		return fmt.Errorf("start %s command: %w", manager.Name(), err)
	}
	childDone := make(chan error, 1)
	go func() { childDone <- child.Wait() }()
	select {
	case err := <-childDone:
		if err != nil {
			return fmt.Errorf("run %s command: %w", manager.Name(), err)
		}
		return nil
	case err := <-server.Errors():
		cancelChild()
		return errors.Join(err, <-childDone)
	}
}

func npmCredentialFiles() []string {
	files := make([]string, 0, 2)
	userConfig := os.Getenv("npm_config_userconfig")
	if userConfig == "" {
		userConfig = os.Getenv("NPM_CONFIG_USERCONFIG")
	}
	if userConfig != "" {
		files = append(files, userConfig)
	} else if home, err := os.UserHomeDir(); err == nil {
		files = append(files, filepath.Join(home, ".npmrc"))
	}
	if directory, err := os.Getwd(); err == nil {
		files = append(files, filepath.Join(directory, ".npmrc"))
	}
	return files
}

func loadNetrcCredentials() (map[string]basicCredential, error) {
	credentials := make(map[string]basicCredential)
	path := os.Getenv("NETRC")
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return credentials, nil
		}
		path = filepath.Join(home, ".netrc")
	}
	contents, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return credentials, nil
	}
	if err != nil {
		return nil, err
	}
	tokens := strings.Fields(string(contents))
	for index := 0; index < len(tokens); {
		if tokens[index] != "machine" || index+1 >= len(tokens) {
			index++
			continue
		}
		host := strings.ToLower(tokens[index+1])
		index += 2
		credential := basicCredential{}
		for index < len(tokens) && tokens[index] != "machine" && tokens[index] != "default" {
			if index+1 >= len(tokens) {
				break
			}
			switch tokens[index] {
			case "login":
				credential.username = tokens[index+1]
			case "password":
				credential.password = tokens[index+1]
			}
			index += 2
		}
		if credential.username != "" {
			credentials[host] = credential
		}
	}
	return credentials, nil
}
