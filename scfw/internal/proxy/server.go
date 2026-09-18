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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const maxJSONRewriteSize = 64 << 20
const maxLoggedResponseBodySize = 4 << 20
const maxLoggedResponseBodyTotal = 16 << 20
const logQueueCapacity = 256

type logRecord struct {
	line      string
	requestID uint64
	body      []byte
	isBody    bool
}

// Options controls optional proxy behavior.
type Options struct {
	// HTTPStatus makes the proxy synthesize this status without contacting the
	// upstream registry. Zero forwards requests normally.
	HTTPStatus int
}

// Server is an ephemeral reverse proxy for npm registry traffic.
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
	authSecret       string
	output           io.Writer
	requestID        atomic.Uint64
	loggedBodyBytes  atomic.Int64
	droppedLogs      atomic.Uint64
	logQueue         chan logRecord
	logDone          chan struct{}
	logClose         sync.Once
	errors           chan error
}

// Start binds an ephemeral loopback port and begins serving registry traffic.
func Start(config NPMConfig, output io.Writer) (*Server, error) {
	return StartWithOptions(config, output, Options{})
}

// StartWithOptions binds an ephemeral loopback port and begins serving registry
// traffic with the supplied behavior options.
func StartWithOptions(config NPMConfig, output io.Writer, options Options) (*Server, error) {
	if config.Registry == nil {
		return nil, errors.New("start npm proxy: missing default registry")
	}
	if options.HTTPStatus != 0 && (options.HTTPStatus < 200 || options.HTTPStatus > 599) {
		return nil, fmt.Errorf("start npm proxy: invalid HTTP status %d: must be between 200 and 599", options.HTTPStatus)
	}
	if output == nil {
		output = io.Discard
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("start npm proxy: %w", err)
	}
	registryToken, err := randomToken(18)
	if err != nil {
		return nil, errors.Join(
			fmt.Errorf("start npm proxy: generate registry token: %w", err),
			listener.Close(),
		)
	}
	forwardToken, err := randomToken(18)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("start npm proxy: generate forwarding token: %w", err), listener.Close())
	}
	authSecret, err := randomToken(32)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("start npm proxy: generate authentication secret: %w", err), listener.Close())
	}

	baseURL, err := url.Parse("http://" + listener.Addr().String() + "/")
	if err != nil {
		return nil, errors.Join(
			fmt.Errorf("start npm proxy: construct URL: %w", err),
			listener.Close(),
		)
	}
	var transport http.RoundTripper
	var scopedTransports map[string]http.RoundTripper
	if options.HTTPStatus == 0 {
		baseTransport, err := config.transport()
		if err != nil {
			return nil, errors.Join(fmt.Errorf("start npm proxy: configure outbound transport: %w", err), listener.Close())
		}
		transport = baseTransport
		scopedTransports, err = config.scopedTransports(baseTransport)
		if err != nil {
			return nil, errors.Join(fmt.Errorf("start npm proxy: configure scoped outbound transport: %w", err), listener.Close())
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
			server.errors <- fmt.Errorf("serve npm proxy: %w", err)
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
		return fmt.Errorf("stop npm proxy: %w", err)
	}
	s.logClose.Do(func() { close(s.logQueue) })
	select {
	case <-s.logDone:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("flush npm proxy logs: %w", ctx.Err())
	}
}

func (s *Server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if !s.authenticate(request) {
		http.Error(writer, "npm registry proxy authentication required", http.StatusUnauthorized)
		return
	}
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
	reverseProxy := &httputil.ReverseProxy{
		Transport: s.transportFor(destination),
		Rewrite: func(proxyRequest *httputil.ProxyRequest) {
			proxyRequest.Out.URL = cloneURL(destination)
			proxyRequest.Out.Host = destination.Host
			proxyRequest.Out.RequestURI = ""
			proxyRequest.Out.Header.Del("Accept-Encoding")
			proxyRequest.Out.Header.Del("Authorization")
			s.config.authorize(proxyRequest.Out)
		},
		ModifyResponse: func(response *http.Response) error {
			s.logResponse(requestID, response.StatusCode, request.Method, destination)
			mediaType, _, _ := mime.ParseMediaType(response.Header.Get("Content-Type"))
			if isJSONMediaType(mediaType) && response.ContentLength <= maxLoggedResponseBodySize {
				// Wrap before rewriting so stdout contains the original upstream
				// JSON rather than proxy-rewritten URLs.
				response.Body = &responseBodyLogger{
					ReadCloser: response.Body,
					server:     s,
					requestID:  requestID,
				}
			} else {
				s.logResponseBodyOmitted(requestID, mediaType, response.ContentLength)
			}
			return s.rewriteResponse(response)
		},
		ErrorHandler: func(responseWriter http.ResponseWriter, _ *http.Request, proxyErr error) {
			if errors.Is(proxyErr, context.Canceled) {
				return
			}
			s.logError(proxyErr)
			http.Error(responseWriter, "npm registry proxy error", http.StatusBadGateway)
		},
	}
	reverseProxy.ServeHTTP(writer, request)
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
		encoded := strings.TrimPrefix(requestURL.Path, s.forwardPrefix)
		if encoded == "" || strings.Contains(encoded, "/") {
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
	return nil, errors.New("invalid npm proxy route")
}

func (s *Server) rewriteResponse(response *http.Response) error {
	if location := response.Header.Get("Location"); location != "" {
		resolved, err := response.Request.URL.Parse(location)
		if err == nil && (resolved.Scheme == "http" || resolved.Scheme == "https") {
			response.Header.Set("Location", s.proxyURL(resolved))
		}
	}

	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || !isJSONMediaType(mediaType) {
		return nil
	}
	if response.ContentLength > maxJSONRewriteSize {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, maxJSONRewriteSize+1))
	if err != nil {
		return fmt.Errorf("read npm registry response: %w", err)
	}
	if len(body) > maxJSONRewriteSize {
		response.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), response.Body))
		return nil
	}
	if err := response.Body.Close(); err != nil {
		return fmt.Errorf("close npm registry response: %w", err)
	}

	var document any
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		response.Body = io.NopCloser(bytes.NewReader(body))
		return nil
	}
	if !s.rewriteJSON(document, "") {
		response.Body = io.NopCloser(bytes.NewReader(body))
		return nil
	}

	rewritten, err := json.Marshal(document)
	if err != nil {
		return fmt.Errorf("encode npm registry response: %w", err)
	}
	response.Body = io.NopCloser(bytes.NewReader(rewritten))
	response.ContentLength = int64(len(rewritten))
	response.Header.Set("Content-Length", strconv.Itoa(len(rewritten)))
	response.Header.Del("ETag")
	response.Header.Del("Content-MD5")
	return nil
}

func isJSONMediaType(mediaType string) bool {
	return mediaType == "application/json" || strings.HasSuffix(mediaType, "+json")
}

func (s *Server) rewriteJSON(value any, key string) bool {
	changed := false
	switch typed := value.(type) {
	case map[string]any:
		for childKey, child := range typed {
			if stringValue, ok := child.(string); ok && s.shouldRewriteURL(childKey, stringValue) {
				parsed, _ := url.Parse(stringValue)
				typed[childKey] = s.proxyURL(parsed)
				changed = true
				continue
			}
			changed = s.rewriteJSON(child, childKey) || changed
		}
	case []any:
		for _, child := range typed {
			changed = s.rewriteJSON(child, key) || changed
		}
	}
	return changed
}

func (s *Server) shouldRewriteURL(key, value string) bool {
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.Host == s.baseURL.Host {
		return false
	}
	if key == "tarball" {
		return true
	}
	if sameOrigin(parsed, s.config.Registry) {
		return true
	}
	for _, registry := range s.config.ScopedRegistries {
		if sameOrigin(parsed, registry) {
			return true
		}
	}
	return false
}

func (s *Server) proxyURL(destination *url.URL) string {
	encoded := base64.RawURLEncoding.EncodeToString([]byte(destination.String()))
	rewritten := *s.baseURL
	rewritten.Path = s.forwardPrefix + encoded
	rewritten.RawPath = ""
	return rewritten.String()
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

func (s *Server) logResponseBody(requestID uint64, body []byte) {
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
	s.enqueueLog(logRecord{requestID: requestID, body: bytes.Clone(body), isBody: true})
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
		redacted, err := redactJSONResponse(record.body)
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
			logger.server.logResponseBody(logger.requestID, logger.body.Bytes())
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

func sameOrigin(left, right *url.URL) bool {
	return strings.EqualFold(left.Scheme, right.Scheme) && strings.EqualFold(left.Host, right.Host)
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
