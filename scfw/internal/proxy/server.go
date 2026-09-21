// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package proxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
	proxyecosystem "github.com/DataDog/supply-chain-firewall/scfw/internal/proxy/ecosystem"
	npmecosystem "github.com/DataDog/supply-chain-firewall/scfw/internal/proxy/ecosystem/npm"
)

const maxLoggedResponseBodySize = 4 << 20
const maxLoggedResponseBodyTotal = 16 << 20
const logQueueCapacity = 256

type logRecord struct {
	line      string
	requestID uint64
	body      []byte
	mediaType string
	isBody    bool
}

// Options controls optional proxy behavior.
type Options struct {
	// HTTPStatus makes the proxy synthesize this status without contacting the
	// upstream registry. Zero forwards requests normally.
	HTTPStatus int
	// Evaluate runs once for each distinct distribution before it is downloaded.
	// Returning an error blocks the download.
	Evaluate func(context.Context, pm.Package) error
}

// Server is an ephemeral reverse proxy for package registry traffic.
type Server struct {
	config           NPMConfig
	listener         net.Listener
	httpServer       *http.Server
	baseURL          *url.URL
	forwardPrefix    string
	registryRoutes   map[string]*url.URL
	scopedURLs       map[string]string
	transport        http.RoundTripper
	scopedTransports map[string]http.RoundTripper
	options          Options
	responseHandler  proxyecosystem.Handler
	authSecret       string
	output           io.Writer
	requestID        atomic.Uint64
	loggedBodyBytes  atomic.Int64
	droppedLogs      atomic.Uint64
	logQueue         chan logRecord
	logDone          chan struct{}
	logClose         sync.Once
	errors           chan error
	evaluationMu     sync.Mutex
	evaluations      map[pm.Package]*evaluationCall
	artifactMu       sync.RWMutex
	artifactPackages map[string]pm.Package
}

type evaluationCall struct {
	done chan struct{}
	err  error
}

// Start binds an ephemeral loopback port and begins serving registry traffic.
func Start(config NPMConfig, output io.Writer) (*Server, error) {
	return StartWithOptions(config, output, Options{})
}

// StartWithOptions binds an ephemeral loopback port and begins serving registry
// traffic with the supplied behavior options.
func StartWithOptions(config NPMConfig, output io.Writer, options Options) (*Server, error) {
	if config.Registry == nil {
		return nil, errors.New("start registry proxy: missing default registry")
	}
	if options.HTTPStatus != 0 && (options.HTTPStatus < 200 || options.HTTPStatus > 599) {
		return nil, fmt.Errorf("start registry proxy: invalid HTTP status %d: must be between 200 and 599", options.HTTPStatus)
	}
	if output == nil {
		output = io.Discard
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("start registry proxy: %w", err)
	}
	registryToken, err := randomToken(18)
	if err != nil {
		return nil, errors.Join(
			fmt.Errorf("start registry proxy: generate registry token: %w", err),
			listener.Close(),
		)
	}
	forwardToken, err := randomToken(18)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("start registry proxy: generate forwarding token: %w", err), listener.Close())
	}
	authSecret, err := randomToken(32)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("start registry proxy: generate authentication secret: %w", err), listener.Close())
	}

	baseURL, err := url.Parse("http://" + listener.Addr().String() + "/")
	if err != nil {
		return nil, errors.Join(
			fmt.Errorf("start registry proxy: construct URL: %w", err),
			listener.Close(),
		)
	}
	var transport http.RoundTripper
	var scopedTransports map[string]http.RoundTripper
	if options.HTTPStatus == 0 {
		baseTransport, err := config.transport()
		if err != nil {
			return nil, errors.Join(fmt.Errorf("start registry proxy: configure outbound transport: %w", err), listener.Close())
		}
		transport = baseTransport
		scopedTransports, err = config.scopedTransports(baseTransport)
		if err != nil {
			return nil, errors.Join(fmt.Errorf("start registry proxy: configure scoped outbound transport: %w", err), listener.Close())
		}
	}

	server := &Server{
		config:           config,
		listener:         listener,
		baseURL:          baseURL,
		forwardPrefix:    "/-/scfw/forward/" + forwardToken + "/",
		registryRoutes:   make(map[string]*url.URL, len(config.ScopedRegistries)+1),
		scopedURLs:       make(map[string]string, len(config.ScopedRegistries)),
		transport:        transport,
		scopedTransports: scopedTransports,
		options:          options,
		authSecret:       authSecret,
		output:           output,
		logQueue:         make(chan logRecord, logQueueCapacity),
		logDone:          make(chan struct{}),
		errors:           make(chan error, 1),
		evaluations:      make(map[pm.Package]*evaluationCall),
		artifactPackages: make(map[string]pm.Package),
	}
	server.responseHandler = config.ResponseHandler
	if server.responseHandler == nil {
		server.responseHandler = npmecosystem.Handler{}
	}
	go server.writeLogs()
	registryPrefix := "/-/scfw/registry/" + registryToken + "/"
	defaultRoute := registryPrefix + "default/"
	server.registryRoutes[defaultRoute] = config.Registry
	server.baseURL.Path = defaultRoute
	for scope, registry := range config.ScopedRegistries {
		route := registryPrefix + "scope/" + base64.RawURLEncoding.EncodeToString([]byte(scope)) + "/"
		server.registryRoutes[route] = registry
		scopedURL := *baseURL
		scopedURL.Path = route
		server.scopedURLs[scope] = scopedURL.String()
	}
	server.httpServer = &http.Server{
		Handler:           server,
		ReadHeaderTimeout: 30 * time.Second,
	}

	go func() {
		if err := server.httpServer.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			server.errors <- fmt.Errorf("serve registry proxy: %w", err)
		}
	}()
	return server, nil
}

// URL returns the local registry URL npm should use while the proxy is active.
func (s *Server) URL() string {
	return s.baseURL.String()
}

func (s *Server) scopedRegistryURLs() map[string]string {
	return s.scopedURLs
}

// RegistryURLs returns a copy of the local URLs for named registries.
func (s *Server) RegistryURLs() map[string]string {
	result := make(map[string]string, len(s.scopedURLs))
	for name, registryURL := range s.scopedURLs {
		result[name] = registryURL
	}
	return result
}

// Errors reports asynchronous listener failures.
func (s *Server) Errors() <-chan error {
	return s.errors
}

// Close stops accepting requests, allows in-flight requests to finish, and
// flushes queued logs subject to the supplied context.
func (s *Server) Close(ctx context.Context) error {
	if err := s.httpServer.Shutdown(ctx); err != nil {
		// Shutdown can return while handlers are still active. Keep the log
		// queue open so those handlers cannot send to a closed channel.
		return fmt.Errorf("stop registry proxy: %w", err)
	}
	s.logClose.Do(func() { close(s.logQueue) })
	select {
	case <-s.logDone:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("flush registry proxy logs: %w", ctx.Err())
	}
}

func (s *Server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if !s.config.AllowUnauthenticatedLocalRequests && !s.authenticate(request) {
		http.Error(writer, "registry proxy authentication required", http.StatusUnauthorized)
		return
	}
	forwardedArtifact := strings.HasPrefix(request.URL.Path, s.forwardPrefix)
	destination, err := s.destination(request.URL)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}

	requestID := s.logRequest(request.Method, destination)
	if s.options.HTTPStatus != 0 {
		s.logResponse(requestID, s.options.HTTPStatus, request.Method, destination)
		s.enqueueLog(logRecord{line: fmt.Sprintf("[%d] RESPONSE BODY \"\"\n", requestID)})
		writer.WriteHeader(s.options.HTTPStatus)
		return
	}
	// Only a distribution download is an installation decision point. Metadata,
	// authentication, publishing, and other registry traffic is forwarded
	// without evaluation; ecosystem handlers identify GET artifact URLs.
	if request.Method == http.MethodGet && s.options.Evaluate != nil {
		pkg, ok := s.artifactPackage(destination)
		if !ok {
			pkg, ok = s.responseHandler.Package(destination)
		}
		if ok {
			if err := s.evaluate(request.Context(), pkg); err != nil {
				s.logResponse(requestID, http.StatusForbidden, request.Method, destination)
				s.enqueueLog(logRecord{line: fmt.Sprintf("[%d] RESPONSE BODY %q\n", requestID, "package blocked by Supply Chain Firewall")})
				http.Error(writer, "package blocked by Supply Chain Firewall", http.StatusForbidden)
				return
			}
		}
	}
	reverseProxy := &httputil.ReverseProxy{
		Transport: s.transportFor(destination),
		Rewrite: func(proxyRequest *httputil.ProxyRequest) {
			proxyRequest.Out.URL = cloneURL(destination)
			proxyRequest.Out.Host = destination.Host
			proxyRequest.Out.RequestURI = ""
			proxyRequest.Out.Header.Del("Accept-Encoding")
			if forwardedArtifact && !s.registryOrigin(destination) || !s.config.ForwardAuthorization {
				proxyRequest.Out.Header.Del("Authorization")
			}
			s.config.authorize(proxyRequest.Out)
		},
		ModifyResponse: func(response *http.Response) error {
			s.logResponse(requestID, response.StatusCode, request.Method, destination)
			mediaType, _, _ := mime.ParseMediaType(response.Header.Get("Content-Type"))
			if isTextMediaType(mediaType) && response.ContentLength <= maxLoggedResponseBodySize {
				// Wrap before rewriting so stdout contains the original upstream
				// JSON rather than proxy-rewritten URLs.
				response.Body = &responseBodyLogger{
					ReadCloser: response.Body,
					server:     s,
					requestID:  requestID,
					mediaType:  mediaType,
				}
			} else {
				s.logResponseBodyOmitted(requestID, mediaType, response.ContentLength)
			}
			if request.Method != http.MethodGet && request.Method != http.MethodHead {
				return nil
			}
			registries := make([]*url.URL, 0, len(s.config.ScopedRegistries)+1)
			registries = append(registries, s.config.Registry)
			for _, registry := range s.config.ScopedRegistries {
				registries = append(registries, registry)
			}
			return s.responseHandler.RewriteResponse(response, s.proxyURLForPackage, registries)
		},
		ErrorHandler: func(responseWriter http.ResponseWriter, _ *http.Request, proxyErr error) {
			if errors.Is(proxyErr, context.Canceled) {
				return
			}
			s.logError(proxyErr)
			http.Error(responseWriter, "registry proxy error", http.StatusBadGateway)
		},
	}
	reverseProxy.ServeHTTP(writer, request)
}

func (s *Server) registryOrigin(destination *url.URL) bool {
	for _, registry := range s.registryRoutes {
		if strings.EqualFold(destination.Scheme, registry.Scheme) && strings.EqualFold(destination.Host, registry.Host) {
			return true
		}
	}
	return false
}

func (s *Server) evaluate(ctx context.Context, pkg pm.Package) error {
	s.evaluationMu.Lock()
	if existing := s.evaluations[pkg]; existing != nil {
		s.evaluationMu.Unlock()
		select {
		case <-existing.done:
			return existing.err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	call := &evaluationCall{done: make(chan struct{})}
	s.evaluations[pkg] = call
	s.evaluationMu.Unlock()
	call.err = s.options.Evaluate(ctx, pkg)
	close(call.done)
	return call.err
}

func randomToken(size int) (string, error) {
	token := make([]byte, size)
	if _, err := rand.Read(token); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(token), nil
}

func (s *Server) authenticate(request *http.Request) bool {
	scheme, value, ok := strings.Cut(request.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(value), []byte(s.authSecret)) == 1
}

func (s *Server) npmAuthConfigLine() string {
	return fmt.Sprintf("//%s/:_authToken=%s\n", s.baseURL.Host, s.authSecret)
}

func (s *Server) transportFor(destination *url.URL) http.RoundTripper {
	prefix, _, ok := s.config.credentialsFor(destination)
	if ok {
		if transport, exists := s.scopedTransports[prefix]; exists {
			return transport
		}
	}
	return s.transport
}

func (s *Server) destination(requestURL *url.URL) (*url.URL, error) {
	if strings.HasPrefix(requestURL.Path, s.forwardPrefix) {
		remainder := strings.TrimPrefix(requestURL.Path, s.forwardPrefix)
		encoded, _, _ := strings.Cut(remainder, "/")
		if encoded == "" {
			return nil, errors.New("invalid forwarded npm registry URL")
		}
		data, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			return nil, errors.New("invalid forwarded npm registry URL")
		}
		destination, err := url.Parse(string(data))
		if err != nil || (destination.Scheme != "http" && destination.Scheme != "https") || destination.Host == "" {
			return nil, errors.New("invalid forwarded npm registry URL")
		}
		return destination, nil
	}

	for route, registry := range s.registryRoutes {
		if strings.HasPrefix(requestURL.Path, route) {
			routedURL := cloneURL(requestURL)
			routedURL.Path = "/" + strings.TrimPrefix(requestURL.Path, route)
			if requestURL.RawPath != "" && strings.HasPrefix(requestURL.RawPath, route) {
				routedURL.RawPath = "/" + strings.TrimPrefix(requestURL.RawPath, route)
			} else {
				routedURL.RawPath = ""
			}
			if lockfileDestination, ok := s.config.lockfileDestinations[lockfileDestinationKey(routedURL)]; ok {
				return cloneURL(lockfileDestination), nil
			}
			destination := cloneURL(registry)
			destination.Path, destination.RawPath = joinURLPath(registry, routedURL)
			destination.RawQuery = joinQueries(registry.RawQuery, requestURL.RawQuery)
			return destination, nil
		}
	}
	return nil, errors.New("invalid registry proxy route")
}

func isJSONMediaType(mediaType string) bool {
	return mediaType == "application/json" || strings.HasSuffix(mediaType, "+json")
}

func isTextMediaType(mediaType string) bool {
	return isJSONMediaType(mediaType) || strings.HasPrefix(mediaType, "text/") || strings.HasSuffix(mediaType, "+xml")
}

func (s *Server) proxyURLForPackage(destination *url.URL, pkg *pm.Package) string {
	upstream := cloneURL(destination)
	upstream.Fragment = ""
	if pkg != nil {
		s.artifactMu.Lock()
		s.artifactPackages[upstream.String()] = *pkg
		s.artifactMu.Unlock()
	}
	encoded := base64.RawURLEncoding.EncodeToString([]byte(upstream.String()))
	filename := path.Base(destination.Path)
	if filename == "." || filename == "/" || filename == "" {
		filename = "download"
	}
	rewritten := *s.baseURL
	rewritten.Path = s.forwardPrefix + encoded + "/" + filename
	rewritten.RawPath = ""
	rewritten.Fragment = destination.Fragment
	return rewritten.String()
}

func (s *Server) artifactPackage(destination *url.URL) (pm.Package, bool) {
	key := cloneURL(destination)
	key.Fragment = ""
	s.artifactMu.RLock()
	pkg, ok := s.artifactPackages[key.String()]
	s.artifactMu.RUnlock()
	return pkg, ok
}

func (s *Server) logRequest(method string, destination *url.URL) uint64 {
	requestID := s.requestID.Add(1)
	loggedURL := *destination
	loggedURL.User = nil
	loggedURL.RawQuery = ""
	loggedURL.Fragment = ""
	s.enqueueLog(logRecord{line: fmt.Sprintf("[%d] REQUEST %s %s\n", requestID, method, loggedURL.String())})
	return requestID
}

func (s *Server) logResponse(requestID uint64, statusCode int, method string, destination *url.URL) {
	loggedURL := *destination
	loggedURL.User = nil
	loggedURL.RawQuery = ""
	loggedURL.Fragment = ""
	s.enqueueLog(logRecord{line: fmt.Sprintf("[%d] RESPONSE %d %s %s\n", requestID, statusCode, method, loggedURL.String())})
}

func (s *Server) logResponseBody(requestID uint64, mediaType string, body []byte) {
	size := int64(len(body))
	for {
		used := s.loggedBodyBytes.Load()
		if size > maxLoggedResponseBodyTotal-used {
			s.enqueueLog(logRecord{line: fmt.Sprintf("[%d] RESPONSE BODY OMITTED reason=total_budget_exhausted limit=%d\n", requestID, maxLoggedResponseBodyTotal)})
			return
		}
		if s.loggedBodyBytes.CompareAndSwap(used, used+size) {
			break
		}
	}
	s.enqueueLog(logRecord{requestID: requestID, mediaType: mediaType, body: bytes.Clone(body), isBody: true})
}

func (s *Server) enqueueLog(record logRecord) {
	select {
	case s.logQueue <- record:
	default:
		s.droppedLogs.Add(1)
	}
}

func (s *Server) writeLogs() {
	defer close(s.logDone)
	for record := range s.logQueue {
		s.writeDroppedLogs()
		if !record.isBody {
			_, _ = io.WriteString(s.output, record.line)
			continue
		}
		redacted, err := redactResponseBody(record.body, record.mediaType)
		if err != nil {
			_, _ = fmt.Fprintf(s.output, "[%d] RESPONSE BODY OMITTED reason=invalid_json\n", record.requestID)
			continue
		}
		_, _ = fmt.Fprintf(s.output, "[%d] RESPONSE BODY %s\n", record.requestID, strconv.Quote(string(redacted)))
	}
	s.writeDroppedLogs()
}

func (s *Server) writeDroppedLogs() {
	if count := s.droppedLogs.Swap(0); count > 0 {
		_, _ = fmt.Fprintf(s.output, "proxy log records dropped: %d (output sink too slow)\n", count)
	}
}

func (s *Server) logResponseBodyOmitted(requestID uint64, mediaType string, contentLength int64) {
	s.enqueueLog(logRecord{line: fmt.Sprintf("[%d] RESPONSE BODY OMITTED content_type=%q content_length=%d\n", requestID, mediaType, contentLength)})
}

func (s *Server) logResponseBodyTooLarge(requestID uint64, size int64) {
	s.enqueueLog(logRecord{line: fmt.Sprintf("[%d] RESPONSE BODY OMITTED reason=too_large size=%d limit=%d\n", requestID, size, maxLoggedResponseBodySize)})
}

func (s *Server) logResponseBodyAborted(requestID uint64) {
	s.enqueueLog(logRecord{line: fmt.Sprintf("[%d] RESPONSE BODY OMITTED reason=aborted\n", requestID)})
}

func (s *Server) logError(err error) {
	s.enqueueLog(logRecord{line: fmt.Sprintf("proxy error: %v\n", err)})
}

type responseBodyLogger struct {
	io.ReadCloser
	server    *Server
	requestID uint64
	ended     sync.Once
	body      bytes.Buffer
	size      int64
	mediaType string
}

func (logger *responseBodyLogger) Read(buffer []byte) (int, error) {
	read, err := logger.ReadCloser.Read(buffer)
	if read > 0 {
		logger.size += int64(read)
		remaining := maxLoggedResponseBodySize + 1 - logger.body.Len()
		if remaining > 0 {
			toBuffer := min(read, remaining)
			_, _ = logger.body.Write(buffer[:toBuffer])
		}
	}
	if errors.Is(err, io.EOF) {
		logger.end(true)
	}
	return read, err
}

func (logger *responseBodyLogger) Close() error {
	err := logger.ReadCloser.Close()
	logger.end(false)
	return err
}

func (logger *responseBodyLogger) end(complete bool) {
	logger.ended.Do(func() {
		switch {
		case !complete:
			logger.server.logResponseBodyAborted(logger.requestID)
		case logger.size > maxLoggedResponseBodySize:
			logger.server.logResponseBodyTooLarge(logger.requestID, logger.size)
		default:
			logger.server.logResponseBody(logger.requestID, logger.mediaType, logger.body.Bytes())
		}
	})
}

func redactJSONResponse(body []byte) ([]byte, error) {
	var value any
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	return json.Marshal(redactJSONValue(value, ""))
}

var textURLPattern = regexp.MustCompile(`https?://[^\s"'<>]+`)

func redactResponseBody(body []byte, mediaType string) ([]byte, error) {
	if isJSONMediaType(mediaType) {
		return redactJSONResponse(body)
	}
	return textURLPattern.ReplaceAllFunc(body, func(match []byte) []byte {
		parsed, err := url.Parse(string(match))
		if err != nil {
			return match
		}
		parsed.User = nil
		parsed.RawQuery = ""
		parsed.Fragment = ""
		return []byte(parsed.String())
	}), nil
}

func redactJSONValue(value any, key string) any {
	if isSensitiveJSONKey(key) {
		return "[REDACTED]"
	}
	switch typed := value.(type) {
	case map[string]any:
		redacted := make(map[string]any, len(typed))
		for childKey, child := range typed {
			redacted[childKey] = redactJSONValue(child, childKey)
		}
		return redacted
	case []any:
		redacted := make([]any, len(typed))
		for index, child := range typed {
			redacted[index] = redactJSONValue(child, key)
		}
		return redacted
	case string:
		parsed, err := url.Parse(typed)
		if err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Host != "" {
			parsed.User = nil
			parsed.RawQuery = ""
			parsed.Fragment = ""
			return parsed.String()
		}
	}
	return value
}

func isSensitiveJSONKey(key string) bool {
	switch strings.ToLower(key) {
	case "_auth", "_authtoken", "access_token", "authorization", "otp", "password", "_password", "refresh_token", "secret", "token":
		return true
	default:
		return false
	}
}

func cloneURL(value *url.URL) *url.URL {
	clone := *value
	return &clone
}

func joinQueries(left, right string) string {
	if left == "" {
		return right
	}
	if right == "" {
		return left
	}
	return left + "&" + right
}

// joinURLPath mirrors net/http/httputil's path joining behavior while
// retaining escaped scoped package names such as @scope%2fpackage.
func joinURLPath(left, right *url.URL) (string, string) {
	if left.RawPath == "" && right.RawPath == "" {
		return singleJoiningSlash(left.Path, right.Path), ""
	}
	leftPath := left.EscapedPath()
	rightPath := right.EscapedPath()
	leftSlash := strings.HasSuffix(leftPath, "/")
	rightSlash := strings.HasPrefix(rightPath, "/")
	switch {
	case leftSlash && rightSlash:
		return left.Path + right.Path[1:], leftPath + rightPath[1:]
	case !leftSlash && !rightSlash:
		return left.Path + "/" + right.Path, leftPath + "/" + rightPath
	default:
		return left.Path + right.Path, leftPath + rightPath
	}
}

func singleJoiningSlash(left, right string) string {
	leftSlash := strings.HasSuffix(left, "/")
	rightSlash := strings.HasPrefix(right, "/")
	switch {
	case leftSlash && rightSlash:
		return left + right[1:]
	case !leftSlash && !rightSlash:
		return left + "/" + right
	default:
		return left + right
	}
}
