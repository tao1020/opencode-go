// Command coder-privacy-guard is a small, localhost-only redaction guard for
// OpenAI-compatible Chat Completions traffic.
//
// It is deliberately narrow: it understands exactly one endpoint
// (POST /v1/chat/completions), masks secrets one-way (no restoration), and
// refuses anything it cannot fully inspect (images, binary, oversized or
// malformed bodies).
package main

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	defaultListenAddr          = "127.0.0.1:8788"
	defaultMaxBody             = int64(8 << 20)  // 8 MiB request cap
	defaultMaxResponse         = int64(32 << 20) // 32 MiB response cap
	defaultMaxConcurrency      = 8
	defaultQueueTimeout        = 5 * time.Second
	defaultScanTimeout         = 10 * time.Second
	defaultRequestTimeout      = 10 * time.Minute
	defaultResponseIdleTimeout = 2 * time.Minute
)

// Config is the complete runtime configuration. Everything sensitive comes
// from the environment; nothing is read from the client request.
type Config struct {
	ListenAddr          string
	UpstreamURL         string
	ClientAPIKey        string
	UpstreamAPIKey      string
	MaxBodyBytes        int64
	MaxResponseBytes    int64
	MaxConcurrency      int
	QueueTimeout        time.Duration
	ScanTimeout         time.Duration
	RequestTimeout      time.Duration
	ResponseIdleTimeout time.Duration
	// Reversible enables local restoration of masked secrets in Chat responses.
	// Off by default so the irreversible behaviour is unchanged.
	Reversible bool
}

func main() {
	cfg, err := configFromEnv()
	if err != nil {
		log.Fatalf("configuration error: %v", err)
	}
	if err := validateListenAddr(cfg.ListenAddr); err != nil {
		log.Fatalf("configuration error: %v", err)
	}

	gateway, err := NewGateway(cfg)
	if err != nil {
		log.Fatalf("startup error: %v", err)
	}

	server := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: gateway.Routes(),
		// Requests are small JSON documents; headers arrive quickly.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		// No write timeout: SSE responses stream for as long as the model talks.
		IdleTimeout: 120 * time.Second,
		ErrorLog:    log.New(os.Stderr, "", log.LstdFlags),
	}

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-shutdown
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()

	// Bind only the configured (loopback) address.
	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		log.Fatalf("listen error: %v", err)
	}
	if gateway.upstream != nil {
		log.Printf("guard listening on http://%s mode=proxy reversible=%t upstream=%s", cfg.ListenAddr, cfg.Reversible, gateway.upstream.Host)
	} else {
		log.Printf("guard listening on http://%s mode=scan-only (/inspect, /mask)", cfg.ListenAddr)
	}

	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server error: %v", err)
	}
}

func configFromEnv() (Config, error) {
	cfg := Config{
		ListenAddr:          envOr("GUARD_LISTEN", defaultListenAddr),
		UpstreamURL:         os.Getenv("UPSTREAM_URL"),
		ClientAPIKey:        os.Getenv("CLIENT_API_KEY"),
		UpstreamAPIKey:      os.Getenv("UPSTREAM_API_KEY"),
		MaxBodyBytes:        defaultMaxBody,
		MaxResponseBytes:    defaultMaxResponse,
		MaxConcurrency:      defaultMaxConcurrency,
		QueueTimeout:        defaultQueueTimeout,
		ScanTimeout:         defaultScanTimeout,
		RequestTimeout:      defaultRequestTimeout,
		ResponseIdleTimeout: defaultResponseIdleTimeout,
	}
	key, err := resolveClientKey()
	if err != nil {
		return Config{}, err
	}
	cfg.ClientAPIKey = key

	upstreamKey, err := resolveUpstreamKey(strings.TrimSpace(cfg.UpstreamURL) != "")
	if err != nil {
		return Config{}, err
	}
	cfg.UpstreamAPIKey = upstreamKey

	if raw := os.Getenv("GUARD_REVERSIBLE"); raw != "" {
		value, err := strconv.ParseBool(raw)
		if err != nil {
			return Config{}, errors.New("GUARD_REVERSIBLE must be true or false")
		}
		cfg.Reversible = value
	}

	if raw := os.Getenv("GUARD_MAX_BODY_BYTES"); raw != "" {
		value, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || value <= 0 {
			return Config{}, errors.New("GUARD_MAX_BODY_BYTES must be a positive integer")
		}
		cfg.MaxBodyBytes = value
	}
	if raw := os.Getenv("GUARD_MAX_CONCURRENCY"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value <= 0 {
			return Config{}, errors.New("GUARD_MAX_CONCURRENCY must be a positive integer")
		}
		cfg.MaxConcurrency = value
	}
	if raw := os.Getenv("GUARD_MAX_RESPONSE_BYTES"); raw != "" {
		value, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || value <= 0 {
			return Config{}, errors.New("GUARD_MAX_RESPONSE_BYTES must be a positive integer")
		}
		cfg.MaxResponseBytes = value
	}
	for name, target := range map[string]*time.Duration{
		"GUARD_QUEUE_TIMEOUT":         &cfg.QueueTimeout,
		"GUARD_SCAN_TIMEOUT":          &cfg.ScanTimeout,
		"GUARD_REQUEST_TIMEOUT":       &cfg.RequestTimeout,
		"GUARD_RESPONSE_IDLE_TIMEOUT": &cfg.ResponseIdleTimeout,
	} {
		raw := os.Getenv(name)
		if raw == "" {
			continue
		}
		value, err := time.ParseDuration(raw)
		if err != nil || value <= 0 {
			return Config{}, errors.New(name + " must be a positive duration")
		}
		*target = value
	}
	return cfg, nil
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

// validateListenAddr keeps the guard on loopback. Binding a wildcard address
// would expose an unauthenticated-to-the-network redaction service.
func validateListenAddr(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return errors.New("GUARD_LISTEN must be host:port")
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("GUARD_LISTEN must bind a loopback address (for example 127.0.0.1:8788)")
	}
	return nil
}

// resolveClientKey loads the client virtual key from the environment or from a
// protected file. Exactly one source may be configured.
func resolveClientKey() (string, error) {
	inline := os.Getenv("CLIENT_API_KEY")
	path := os.Getenv("CLIENT_API_KEY_FILE")

	switch {
	case inline != "" && path != "":
		return "", errors.New("set only one of CLIENT_API_KEY or CLIENT_API_KEY_FILE")
	case path != "":
		return readClientKeyFile(path)
	case inline != "":
		return inline, nil
	default:
		return "", errors.New("CLIENT_API_KEY or CLIENT_API_KEY_FILE is required")
	}
}

// readKeyFile loads a credential from a protected file: absolute, regular, not
// a symlink, and not readable by group or others. label only names the variable
// in error messages and never contains the value.
func readKeyFile(path, label string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", errors.New(label + " must be an absolute path")
	}
	link, err := os.Lstat(path)
	if err != nil {
		return "", errors.New(label + " is not readable")
	}
	if link.Mode()&os.ModeSymlink != 0 {
		return "", errors.New(label + " must not be a symlink")
	}
	if !link.Mode().IsRegular() {
		return "", errors.New(label + " must be a regular file")
	}
	if link.Mode().Perm()&0o077 != 0 {
		return "", errors.New(label + " must not be accessible by group or others (use chmod 600)")
	}

	file, err := os.Open(path)
	if err != nil {
		return "", errors.New(label + " is not readable")
	}
	defer file.Close()

	opened, err := file.Stat()
	if err != nil {
		return "", errors.New(label + " is not readable")
	}
	if !os.SameFile(link, opened) || !opened.Mode().IsRegular() {
		return "", errors.New(label + " changed while reading")
	}

	raw, err := io.ReadAll(io.LimitReader(file, 4096))
	if err != nil {
		return "", errors.New(label + " is not readable")
	}
	key := strings.TrimSpace(string(raw))
	if key == "" {
		return "", errors.New(label + " is empty")
	}
	return key, nil
}

// resolveUpstreamKey loads the provider credential from the environment or a
// protected file (for systemd LoadCredential). Exactly one source may be set.
func resolveUpstreamKey(upstreamConfigured bool) (string, error) {
	inline := os.Getenv("UPSTREAM_API_KEY")
	path := os.Getenv("UPSTREAM_API_KEY_FILE")

	switch {
	case inline != "" && path != "":
		return "", errors.New("set only one of UPSTREAM_API_KEY or UPSTREAM_API_KEY_FILE")
	case path != "":
		return readKeyFile(path, "UPSTREAM_API_KEY_FILE")
	case inline != "":
		return inline, nil
	case !upstreamConfigured:
		return "", nil
	default:
		return "", errors.New("UPSTREAM_API_KEY or UPSTREAM_API_KEY_FILE is required when UPSTREAM_URL is set")
	}
}

// readClientKeyFile accepts an absolute path to a regular file that is not
// readable by group or others. A symlink is refused so the key cannot be
// redirected after deployment.
func readClientKeyFile(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", errors.New("CLIENT_API_KEY_FILE must be an absolute path")
	}
	link, err := os.Lstat(path)
	if err != nil {
		return "", errors.New("CLIENT_API_KEY_FILE is not readable")
	}
	if link.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("CLIENT_API_KEY_FILE must not be a symlink")
	}
	if !link.Mode().IsRegular() {
		return "", errors.New("CLIENT_API_KEY_FILE must be a regular file")
	}
	if link.Mode().Perm()&0o077 != 0 {
		return "", errors.New("CLIENT_API_KEY_FILE must not be accessible by group or others (use chmod 600)")
	}

	file, err := os.Open(path)
	if err != nil {
		return "", errors.New("CLIENT_API_KEY_FILE is not readable")
	}
	defer file.Close()

	// Re-check the opened descriptor so a file swapped between Lstat and Open
	// cannot change what is read.
	opened, err := file.Stat()
	if err != nil {
		return "", errors.New("CLIENT_API_KEY_FILE is not readable")
	}
	if !os.SameFile(link, opened) || !opened.Mode().IsRegular() {
		return "", errors.New("CLIENT_API_KEY_FILE changed while reading")
	}

	raw, err := io.ReadAll(io.LimitReader(file, 4096))
	if err != nil {
		return "", errors.New("CLIENT_API_KEY_FILE is not readable")
	}
	key := strings.TrimSpace(string(raw))
	if key == "" {
		return "", errors.New("CLIENT_API_KEY_FILE is empty")
	}
	return key, nil
}
