package whatsmeow

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/proxy"
)

// UTLSClientHelloID defines the uTLS ClientHello fingerprint preset.
type UTLSClientHelloID string

const (
	UTLSClientHelloChromeAuto  UTLSClientHelloID = "chrome-auto"
	UTLSClientHelloFirefoxAuto UTLSClientHelloID = "firefox-auto"
	UTLSClientHelloRandomized  UTLSClientHelloID = "randomized"
)

func (id UTLSClientHelloID) toUTLS() (utls.ClientHelloID, error) {
	switch id {
	case "", UTLSClientHelloChromeAuto:
		return utls.HelloChrome_Auto, nil
	case UTLSClientHelloFirefoxAuto:
		return utls.HelloFirefox_Auto, nil
	case UTLSClientHelloRandomized:
		return utls.HelloRandomizedALPN, nil
	default:
		return utls.ClientHelloID{}, fmt.Errorf("unsupported uTLS client hello id %q", id)
	}
}

// SetUTLSProxyAddress configures outbound TLS dials to use uTLS with the given fingerprint,
// and tunnels through the provided proxy address (http, https or socks5).
//
// Must be called before Connect() to affect websocket TLS handshakes.
func (cli *Client) SetUTLSProxyAddress(addr string, helloID UTLSClientHelloID, opts ...SetProxyOptions) error {
	var opt SetProxyOptions
	if len(opts) > 0 {
		opt = opts[0]
	}

	dialTLS, err := makeUTLSDialTLSContext(addr, helloID)
	if err != nil {
		return err
	}

	transport := (http.DefaultTransport.(*http.Transport)).Clone()
	transport.Proxy = nil
	transport.DialTLSContext = dialTLS
	cli.setTransport(transport, opt)
	return nil
}

func makeUTLSDialTLSContext(proxyAddr string, helloID UTLSClientHelloID) (func(context.Context, string, string) (net.Conn, error), error) {
	helloPreset, err := helloID.toUTLS()
	if err != nil {
		return nil, err
	}

	parsedProxy, err := parseOptionalProxy(proxyAddr)
	if err != nil {
		return nil, err
	}

	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}

	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("invalid target address %q: %w", address, err)
		}

		rawConn, err := dialThroughProxy(ctx, dialer, parsedProxy, network, address)
		if err != nil {
			return nil, err
		}

		tlsConf := &utls.Config{ServerName: host}
		uconn := utls.UClient(rawConn, tlsConf, helloPreset)
		if err = uconn.HandshakeContext(ctx); err != nil {
			_ = rawConn.Close()
			return nil, fmt.Errorf("uTLS handshake failed: %w", err)
		}
		return uconn, nil
	}, nil
}

func parseOptionalProxy(addr string) (*url.URL, error) {
	if addr == "" {
		return nil, nil
	}
	parsed, err := url.Parse(addr)
	if err != nil {
		return nil, err
	}
	switch parsed.Scheme {
	case "http", "https", "socks5":
		return parsed, nil
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q", parsed.Scheme)
	}
}

func dialThroughProxy(ctx context.Context, dialer *net.Dialer, parsedProxy *url.URL, network, targetAddr string) (net.Conn, error) {
	if parsedProxy == nil {
		return dialer.DialContext(ctx, network, targetAddr)
	}

	switch parsedProxy.Scheme {
	case "socks5":
		return dialViaSOCKS5(ctx, parsedProxy, network, targetAddr, dialer)
	case "http", "https":
		return dialViaHTTPConnect(ctx, parsedProxy, network, targetAddr, dialer)
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q", parsedProxy.Scheme)
	}
}

func dialViaSOCKS5(ctx context.Context, parsedProxy *url.URL, network, targetAddr string, forward proxy.Dialer) (net.Conn, error) {
	var auth *proxy.Auth
	if parsedProxy.User != nil {
		password, _ := parsedProxy.User.Password()
		auth = &proxy.Auth{User: parsedProxy.User.Username(), Password: password}
	}

	px, err := proxy.SOCKS5("tcp", parsedProxy.Host, auth, forward)
	if err != nil {
		return nil, fmt.Errorf("create socks5 proxy dialer: %w", err)
	}
	ctxDialer, ok := px.(proxy.ContextDialer)
	if !ok {
		return nil, errors.New("socks5 dialer doesn't support context")
	}
	return ctxDialer.DialContext(ctx, network, targetAddr)
}

func dialViaHTTPConnect(ctx context.Context, parsedProxy *url.URL, network, targetAddr string, dialer *net.Dialer) (net.Conn, error) {
	conn, err := dialer.DialContext(ctx, network, parsedProxy.Host)
	if err != nil {
		return nil, fmt.Errorf("dial proxy %q: %w", parsedProxy.Host, err)
	}

	if parsedProxy.Scheme == "https" {
		host := parsedProxy.Hostname()
		cfg := &tls.Config{ServerName: host}
		tlsConn := tls.Client(conn, cfg)
		if err = tlsConn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("https proxy handshake failed: %w", err)
		}
		conn = tlsConn
	}

	if err = writeProxyConnect(conn, parsedProxy, targetAddr); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err = readProxyConnectResponse(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func writeProxyConnect(conn net.Conn, parsedProxy *url.URL, targetAddr string) error {
	var b strings.Builder
	_, _ = b.WriteString("CONNECT ")
	_, _ = b.WriteString(targetAddr)
	_, _ = b.WriteString(" HTTP/1.1\r\nHost: ")
	_, _ = b.WriteString(targetAddr)
	_, _ = b.WriteString("\r\nProxy-Connection: Keep-Alive\r\n")

	if parsedProxy.User != nil {
		password, _ := parsedProxy.User.Password()
		encoded := base64.StdEncoding.EncodeToString([]byte(parsedProxy.User.Username() + ":" + password))
		_, _ = b.WriteString("Proxy-Authorization: Basic ")
		_, _ = b.WriteString(encoded)
		_, _ = b.WriteString("\r\n")
	}
	_, _ = b.WriteString("\r\n")

	_, err := conn.Write([]byte(b.String()))
	if err != nil {
		return fmt.Errorf("send CONNECT to proxy: %w", err)
	}
	return nil
}

func readProxyConnectResponse(conn net.Conn) error {
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		return fmt.Errorf("read proxy CONNECT response: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("proxy CONNECT failed: %s", resp.Status)
	}
	return nil
}
