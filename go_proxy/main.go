package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// =============================================================================
// Конфигурация
// =============================================================================

const (
	// TCP буфер per-connection. 1MB достаточно для BDP=720KB (50Mbps*115ms).
	// Каждое SOCKS5-подключение получает своё TCP-соединение с VDS,
	// поэтому при 6 параллельных потоках: 6 × 50 = 300 Mbps.
	sockBufSize = 1024 * 1024

	// Буфер чтения из TCP (и записи в WS).
	readBuf = 64 * 1024

	// Gorilla WS буферы.
	wsBuf = 64 * 1024
)

// =============================================================================
// optimizeTCP — максимизация пропускной способности TCP
// =============================================================================

func optimizeTCP(conn net.Conn) {
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	_ = tc.SetNoDelay(true)
	_ = tc.SetReadBuffer(sockBufSize)
	_ = tc.SetWriteBuffer(sockBufSize)
}

// =============================================================================
// bridge — двунаправленная пересылка данных между WS и TCP
// =============================================================================

// bridge пересылает данные между WebSocket и TCP-сокетом.
// Каждое направление работает в своей горутине.
// Завершение одного направления вызывает закрытие обоих сокетов.
func bridge(ws *websocket.Conn, tcp net.Conn) {
	var once sync.Once
	done := make(chan struct{})

	cleanup := func() {
		once.Do(func() {
			ws.Close()
			tcp.Close()
		})
	}

	// TCP → WS (Download для браузера / Upload для сервера).
	go func() {
		defer func() {
			cleanup()
			done <- struct{}{}
		}()
		buf := make([]byte, readBuf)
		for {
			n, err := tcp.Read(buf)
			if n > 0 {
				if wErr := ws.WriteMessage(websocket.BinaryMessage, buf[:n]); wErr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// WS → TCP (Upload для браузера / Download для сервера).
	go func() {
		defer func() {
			cleanup()
			done <- struct{}{}
		}()
		for {
			_, msg, err := ws.ReadMessage()
			if err != nil {
				return
			}
			if _, wErr := tcp.Write(msg); wErr != nil {
				return
			}
		}
	}()

	// Ждём завершения обоих направлений.
	<-done
	<-done
}

// =============================================================================
// Сервер (VDS) — принимает WS-подключения, проксирует к целям
// =============================================================================

type Server struct {
	listenAddr string
	tlsCert    string
	tlsKey     string
	autoTLS    bool
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  wsBuf,
	WriteBufferSize: wsBuf,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	ws.SetReadLimit(0)
	defer ws.Close()

	// 1. Читаем первое сообщение — куда подключаться.
	_, msg, err := ws.ReadMessage()
	if err != nil {
		return
	}

	var target struct {
		Host string `json:"host"`
		Port int    `json:"port"`
	}
	if err := json.Unmarshal(msg, &target); err != nil {
		return
	}

	addr := fmt.Sprintf("%s:%d", target.Host, target.Port)
	log.Printf("[S] %s → %s", r.RemoteAddr, addr)

	// 2. Подключаемся к цели.
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		log.Printf("[S] dial %s: %v", addr, err)
		return
	}
	optimizeTCP(conn)

	// 3. Двунаправленный мост WS ↔ TCP.
	bridge(ws, conn)
}

// bufferListener оборачивает listener, выставляя TCP-буферы на каждое принятое соединение.
type bufferListener struct {
	net.Listener
}

func (bl *bufferListener) Accept() (net.Conn, error) {
	conn, err := bl.Listener.Accept()
	if err != nil {
		return nil, err
	}
	optimizeTCP(conn)
	return conn, nil
}

func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "proxy"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, nil
}

func (s *Server) run() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", s.handleWS)

	ln, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return err
	}
	bl := &bufferListener{ln}

	if s.autoTLS || (s.tlsCert != "" && s.tlsKey != "") {
		var tc *tls.Config
		if s.autoTLS {
			cert, err := generateSelfSignedCert()
			if err != nil {
				return err
			}
			tc = &tls.Config{Certificates: []tls.Certificate{cert}}
			log.Printf("[S] TLS: auto-generated")
		} else {
			cert, err := tls.LoadX509KeyPair(s.tlsCert, s.tlsKey)
			if err != nil {
				return err
			}
			tc = &tls.Config{Certificates: []tls.Certificate{cert}}
		}
		log.Printf("[S] Listening on %s (WSS)", s.listenAddr)
		return (&http.Server{Handler: mux}).Serve(tls.NewListener(bl, tc))
	}

	log.Printf("[S] Listening on %s (WS)", s.listenAddr)
	return (&http.Server{Handler: mux}).Serve(bl)
}

// =============================================================================
// Клиент (Локальная машина) — SOCKS5 прокси, туннелирует через WS
// =============================================================================

type Client struct {
	socksAddr  string
	serverURL  string
	skipVerify bool
}

// dialWS создаёт новое WS-подключение к серверу с оптимизированным TCP.
func (c *Client) dialWS() (*websocket.Conn, error) {
	dialer := websocket.Dialer{
		NetDialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			d := &net.Dialer{Timeout: 15 * time.Second}
			conn, err := d.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			optimizeTCP(conn)
			return conn, nil
		},
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: c.skipVerify},
		ReadBufferSize:   wsBuf,
		WriteBufferSize:  wsBuf,
		HandshakeTimeout: 15 * time.Second,
	}

	// DPI-маскировка: заголовки как у обычного браузера.
	headers := http.Header{
		"User-Agent": {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"},
		"Origin":     {"https://app.example.com"},
	}

	ws, _, err := dialer.Dial(c.serverURL, headers)
	if err != nil {
		return nil, err
	}
	ws.SetReadLimit(0)
	return ws, nil
}

func (c *Client) handleSOCKS5(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	buf := make([]byte, 258)

	// --- SOCKS5 Handshake ---
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return
	}
	if buf[0] != 0x05 {
		return
	}
	nMethods := int(buf[1])
	if _, err := io.ReadFull(conn, buf[:nMethods]); err != nil {
		return
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// --- SOCKS5 CONNECT ---
	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		return
	}
	if buf[1] != 0x01 {
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var host string
	switch buf[3] {
	case 0x01: // IPv4
		if _, err := io.ReadFull(conn, buf[:4]); err != nil {
			return
		}
		host = net.IP(buf[:4]).String()
	case 0x03: // Domain
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return
		}
		dl := int(buf[0])
		if _, err := io.ReadFull(conn, buf[:dl]); err != nil {
			return
		}
		host = string(buf[:dl])
	case 0x04: // IPv6
		if _, err := io.ReadFull(conn, buf[:16]); err != nil {
			return
		}
		host = net.IP(buf[:16]).String()
	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return
	}
	port := int(binary.BigEndian.Uint16(buf[:2]))
	_ = conn.SetDeadline(time.Time{})

	// --- Открыть WS-туннель к серверу ---
	ws, err := c.dialWS()
	if err != nil {
		log.Printf("[C] WS dial error: %v", err)
		conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// Отправить цель на сервер.
	info, _ := json.Marshal(struct {
		Host string `json:"host"`
		Port int    `json:"port"`
	}{Host: host, Port: port})

	if err := ws.WriteMessage(websocket.TextMessage, info); err != nil {
		ws.Close()
		conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// SOCKS5 OK.
	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		ws.Close()
		return
	}

	log.Printf("[C] %s:%d", host, port)

	// Двунаправленный мост SOCKS5 ↔ WS.
	bridge(ws, conn)
}

func (c *Client) run() error {
	ln, err := net.Listen("tcp", c.socksAddr)
	if err != nil {
		return err
	}
	log.Printf("[C] SOCKS5 proxy on %s → %s", c.socksAddr, c.serverURL)

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.SetNoDelay(true)
		}
		go c.handleSOCKS5(conn)
	}
}

// =============================================================================
// main
// =============================================================================

func main() {
	mode := flag.String("mode", "", "'server' или 'client'")
	listen := flag.String("listen", "", "Адрес прослушивания")
	serverURL := flag.String("server", "", "URL сервера (wss://...)")
	tlsCert := flag.String("tls-cert", "", "TLS cert")
	tlsKey := flag.String("tls-key", "", "TLS key")
	autoTLS := flag.Bool("tls", false, "Auto TLS")
	insecure := flag.Bool("insecure", true, "Skip TLS verify")

	flag.Parse()
	log.SetOutput(os.Stdout)
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	switch *mode {
	case "server":
		a := *listen
		if a == "" {
			a = "0.0.0.0:8443"
		}
		s := &Server{listenAddr: a, tlsCert: *tlsCert, tlsKey: *tlsKey, autoTLS: *autoTLS}
		log.Fatal(s.run())

	case "client":
		a := *listen
		if a == "" {
			a = "127.0.0.1:1081"
		}
		if *serverURL == "" {
			log.Fatal("-server required. Example: -server wss://IP:8443/ws")
		}
		c := &Client{socksAddr: a, serverURL: *serverURL, skipVerify: *insecure}
		log.Fatal(c.run())

	default:
		fmt.Fprintln(os.Stderr, "Universal Proxy (Go)")
		fmt.Fprintln(os.Stderr, "  Server: proxy -mode server -tls")
		fmt.Fprintln(os.Stderr, "  Client: proxy -mode client -server wss://IP:8443/ws")
		flag.PrintDefaults()
		os.Exit(1)
	}
}
