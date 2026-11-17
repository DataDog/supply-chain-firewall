// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/build"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/diagnostic"
	npmregistry "github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem/npm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem/pypi"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/home"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

func debugCaptureEnabled() bool { return os.Getenv("SCFW_DEBUG") == "1" }

func warnNoDebugCapture() {
	if debugCaptureEnabled() {
		fmt.Fprintln(os.Stderr, "SCFW debug capture skipped: this command is not using the proxy.")
	}
}

type proxyDiagnostic struct {
	recorder *diagnostic.Recorder
	previous *slog.Logger
	once     sync.Once
}

func startProxyDiagnostic(ctx context.Context, manager pm.PackageManager, args []string) (context.Context, *proxyDiagnostic) {
	redactor := diagnostic.NewRedactor(os.Environ(), args)
	path := os.Getenv("SCFW_DEBUG_OUTPUT")
	if path == "" {
		root := home.Dir()
		if root == "" {
			fmt.Fprintln(os.Stderr, "SCFW debug capture unavailable: cannot determine a diagnostic directory.")
			return ctx, nil
		}
		dir := filepath.Join(root, "diagnostics")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			fmt.Fprintln(os.Stderr, "SCFW debug capture unavailable: cannot create diagnostic directory.")
			return ctx, nil
		}
		// CreateTemp provides the collision-resistant suffix; New uses another
		// sibling temporary file and atomically publishes without replacement.
		name, err := os.CreateTemp(dir, "scfw-debug-"+time.Now().UTC().Format("20060102T150405Z")+"-*.yaml")
		if err != nil {
			fmt.Fprintln(os.Stderr, "SCFW debug capture unavailable: cannot reserve diagnostic name.")
			return ctx, nil
		}
		path = name.Name()
		_ = name.Close()
		_ = os.Remove(path)
	}
	cwd, _ := os.Getwd()
	manifest := map[string]any{"scfw_version": build.GetVersion(), "os": runtime.GOOS, "architecture": runtime.GOARCH, "package_manager": filepath.Base(args[0]), "executable": manager.Executable(), "command": redactor.Arguments(args), "working_directory": cwd, "proxy_enabled": proxyEnabled()}
	recorder, err := diagnostic.New(path, manifest, redactor)
	if err != nil {
		fmt.Fprintln(os.Stderr, "SCFW debug capture unavailable: destination cannot be created or already exists.")
		return ctx, nil
	}
	capture := &proxyDiagnostic{recorder: recorder, previous: slog.Default()}
	slog.SetDefault(slog.New(diagnostic.LogHandler(capture.previous.Handler(), recorder)))
	fmt.Fprintln(os.Stderr, "SCFW debug capture:", redactor.Text(recorder.Path()))
	ctx = diagnostic.WithRecorder(ctx, recorder)
	if provider, ok := manager.(pm.DiagnosticProvider); ok {
		info := provider.DiagnosticInfo(ctx, args[1:])
		recorder.Record("manager.context", "Package-manager version context", map[string]any{"version": info.Version, "installed_version": info.InstalledVersion})
	}
	paths := make(map[string]any)
	for _, key := range []string{"REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "SSL_CERT_FILE", "SSL_CERT_DIR", "NODE_EXTRA_CA_CERTS", "PIP_CERT", "UV_CONFIG_FILE", "NPM_CONFIG_USERCONFIG", "NPM_CONFIG_GLOBALCONFIG"} {
		if value := os.Getenv(key); value != "" {
			paths[key] = value
		}
	}
	recorder.Record("configuration.paths", "Selected explicit configuration paths (not an environment dump)", paths)
	return ctx, capture
}

func (capture *proxyDiagnostic) finish(outcome string) {
	if capture == nil {
		return
	}
	capture.once.Do(func() {
		path, err := capture.recorder.Close(outcome)
		slog.SetDefault(capture.previous)
		if err != nil {
			fmt.Fprintln(os.Stderr, "SCFW debug capture incomplete; readable records may be recovered at:", capture.recorder.Redactor().Text(path))
		}
	})
}

func diagnosticObserver(ctx context.Context, manager pm.PackageManager, command []string) *proxy.Observer {
	recorder := diagnostic.FromContext(ctx)
	if recorder == nil {
		return nil
	}
	var npmClassifier *npmregistry.Classifier
	var pyPIClassifier *pypi.RequestClassifier
	if provider, ok := manager.(interface {
		NpmClassifierOptions([]string) (npmregistry.ClassifierOptions, error)
	}); ok {
		if options, err := provider.NpmClassifierOptions(command); err == nil {
			npmClassifier, _ = npmregistry.NewClassifier(options)
			recorder.Record("configuration.registry", "Configured npm registry roots", map[string]any{"registries": options.RegistryURLs})
		}
	}
	if provider, ok := manager.(interface {
		PyPIClassifierOptions([]string) (pypi.RequestClassifierOptions, error)
	}); ok {
		if options, err := provider.PyPIClassifierOptions(command); err == nil {
			pyPIClassifier, _ = pypi.NewRequestClassifier(options)
		}
	}
	return proxy.NewObserver(recorder.Record, func(request proxy.Request, header http.Header, body []byte, complete bool) map[string]any {
		return diagnostic.MetadataBody(header, body, complete, func(decoded []byte) bool {
			if npmClassifier != nil {
				return npmClassifier.DiagnosticMetadata(request.URL, decoded, request.ClientIdentity == "publication")
			}
			return pyPIClassifier != nil && pyPIClassifier.DiagnosticMetadata(request.URL, header, decoded)
		}, recorder.Redactor())
	})
}
