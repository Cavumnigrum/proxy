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
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

// =============================================================================
// Конфигурация: ключевые параметры производительности
// =============================================================================

const (
	// TCP буфер (send/receive) для WS-туннеля.
	// BDP для 200Mbps @ 150ms RTT = 3.75MB. Ставим 4MB.
	tcpBufSize = 4 * 1024 * 1024

	// Размер буферов gorilla/websocket для WS-фреймов.
	// Большие буферы = меньше системных вызовов.
	wsBufSize = 256 * 1024

	// Размер чанка чтения из TCP-сокета.
	readBufSize = 128 * 1024

	// Размер очереди данных на стрим.
	streamQueueSize = 128
)

const (
	cmdOpen  byte = 0x01
	cmdData  byte = 0x02
	cmdClose byte = 0x03
)

// =============================================================================
// Мультиплексный кадр
// =============================================================================

type muxFrame struct {
	Cmd      byte
	StreamID uint32
	Payload  []byte
}

func encodeMuxFrame(f *muxFrame) []byte {
	buf := make([]byte, 9+len(f.Payload))
	buf[0] = f.Cmd
	binary.BigEndian.PutUint32(buf[1:5], f.StreamID)
	binary.BigEndian.PutUint32(buf[5:9], uint32(len(f.Payload)))
	copy(buf[9:], f.Payload)
	return buf
}

func decodeMuxFrame(data []byte) (*muxFrame, error) {
	if len(data) < 9 {
		return nil, fmt.Errorf("frame too short: %d", len(data))
	}
	f := &muxFrame{
		Cmd:      data[0],
		StreamID: binary.BigEndian.Uint32(data[1:5]),
	}
	pLen := binary.BigEndian.Uint32(data[5:9])
	if int(pLen) != len(data)-9 {
		return nil, fmt.Errorf("payload mismatch")
	}
	f.Payload = data[9:]
	return f, nil
}

// =============================================================================
// stream — безопасная обёртка канала данных
// =============================================================================

type stream struct {
	ch   chan []byte
	once sync.Once
	id   uint32
}

func newStream(id uint32) *stream {
	return &stream{ch: make(chan []byte, streamQueueSize), id: id}
}

func (st *stream) Close() {
	st.once.Do(func() { close(st.ch) })
}

func (st *stream) Send(data []byte) bool {
	select {
	case st.ch <- data:
		return true
	default:
		return false
	}
}

// =============================================================================
// optimizeTCP — настройка TCP-сокета для максимальной пропускной способности
// =============================================================================

func optimizeTCP(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetReadBuffer(tcpBufSize)
		_ = tc.SetWriteBuffer(tcpBufSize)
	}
}

// =============================================================================
// bufferListener — слушатель, автоматически настраивающий TCP-буферы
// =============================================================================

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

// =============================================================================
// Сервер (VDS)
// =============================================================================

type Server struct {
	listenAddr string
	tlsCert    string
	tlsKey     string
	autoTLS    bool

	streams   map[uint32]*stream
	streamsMu sync.Mutex

	wsConn  *websocket.Conn
	writeMu sync.Mutex
}

func newServer(addr, cert, key string, autoTLS bool) *Server {
	return &Server{
		listenAddr: addr,
		tlsCert:    cert,
		tlsKey:     key,
		autoTLS:    autoTLS,
		streams:    make(map[uint32]*stream),
	}
}

func (s *Server) sendFrame(f *muxFrame) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.wsConn == nil {
		return fmt.Errorf("ws nil")
	}
	return s.wsConn.WriteMessage(websocket.BinaryMessage, encodeMuxFrame(f))
}

func (s *Server) removeStream(id uint32) {
	s.streamsMu.Lock()
	st, ok := s.streams[id]
	if ok {
		delete(s.streams, id)
	}
	s.streamsMu.Unlock()
	if ok {
		st.Close()
	}
}

func (s *Server) handleStream(streamID uint32, targetHost string, targetPort int) {
	target := fmt.Sprintf("%s:%d", targetHost, targetPort)
	log.Printf("[S][%d] → %s", streamID, target)

	defer func() {
		s.removeStream(streamID)
		_ = s.sendFrame(&muxFrame{Cmd: cmdClose, StreamID: streamID})
	}()

	s.streamsMu.Lock()
	st, ok := s.streams[streamID]
	s.streamsMu.Unlock()
	if !ok {
		return
	}

	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		log.Printf("[S][%d] dial error: %v", streamID, err)
		return
	}
	defer conn.Close()
	optimizeTCP(conn)

	done := make(chan struct{}, 2)

	// Target → WS (Download для браузера).
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, readBufSize)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				payload := make([]byte, n)
				copy(payload, buf[:n])
				if sendErr := s.sendFrame(&muxFrame{
					Cmd: cmdData, StreamID: streamID, Payload: payload,
				}); sendErr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// WS → Target (Upload от браузера).
	go func() {
		defer func() { done <- struct{}{} }()
		for data := range st.ch {
			if _, err := conn.Write(data); err != nil {
				return
			}
		}
	}()

	<-done
	conn.Close()
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  wsBufSize,
	WriteBufferSize: wsBufSize,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[S] WS upgrade error: %v", err)
		return
	}
	defer ws.Close()

	peer := r.RemoteAddr
	log.Printf("[S] Туннель: %s", peer)
	s.wsConn = ws
	ws.SetReadLimit(0)

	for {
		_, msg, err := ws.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				log.Printf("[S] WS error: %v", err)
			}
			break
		}

		frame, err := decodeMuxFrame(msg)
		if err != nil {
			continue
		}

		switch frame.Cmd {
		case cmdOpen:
			var info struct {
				Host string `json:"host"`
				Port int    `json:"port"`
			}
			if err := json.Unmarshal(frame.Payload, &info); err != nil {
				continue
			}
			st := newStream(frame.StreamID)
			s.streamsMu.Lock()
			s.streams[frame.StreamID] = st
			s.streamsMu.Unlock()
			go s.handleStream(frame.StreamID, info.Host, info.Port)

		case cmdData:
			s.streamsMu.Lock()
			st, ok := s.streams[frame.StreamID]
			s.streamsMu.Unlock()
			if ok {
				st.Send(frame.Payload)
			}

		case cmdClose:
			s.removeStream(frame.StreamID)
		}
	}

	log.Printf("[S] Туннель закрыт: %s", peer)
	s.streamsMu.Lock()
	for id, st := range s.streams {
		st.Close()
		delete(s.streams, id)
	}
	s.streamsMu.Unlock()
}

func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "UniversalProxy"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: priv}, nil
}

func (s *Server) run() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleWS)

	// Создаём TCP-слушатель с увеличенными буферами.
	rawLn, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("listen error: %w", err)
	}
	bufferedLn := &bufferListener{rawLn}

	if s.autoTLS || (s.tlsCert != "" && s.tlsKey != "") {
		var tlsConfig *tls.Config
		if s.autoTLS {
			cert, err := generateSelfSignedCert()
			if err != nil {
				return fmt.Errorf("TLS gen error: %w", err)
			}
			tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
			log.Printf("[S] TLS: auto-generated certificate")
		} else {
			cert, err := tls.LoadX509KeyPair(s.tlsCert, s.tlsKey)
			if err != nil {
				return fmt.Errorf("TLS load error: %w", err)
			}
			tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
			log.Printf("[S] TLS: %s / %s", s.tlsCert, s.tlsKey)
		}

		tlsLn := tls.NewListener(bufferedLn, tlsConfig)
		log.Printf("[S] Слушаю на %s (WSS, TCP buf=%dMB)", s.listenAddr, tcpBufSize/1024/1024)

		server := &http.Server{Handler: mux}
		return server.Serve(tlsLn)
	}

	log.Printf("[S] Слушаю на %s (WS, TCP buf=%dMB)", s.listenAddr, tcpBufSize/1024/1024)
	server := &http.Server{Handler: mux}
	return server.Serve(bufferedLn)
}

// =============================================================================
// Клиент (Локальная машина)
// =============================================================================

type Client struct {
	socksAddr  string
	serverURL  string
	skipVerify bool

	streams   map[uint32]*stream
	streamsMu sync.Mutex
	nextID    atomic.Uint32

	wsConn  *websocket.Conn
	writeMu sync.Mutex
	wsMu    sync.Mutex
}

func newClient(socksAddr, serverURL string, skipVerify bool) *Client {
	c := &Client{
		socksAddr:  socksAddr,
		serverURL:  serverURL,
		skipVerify: skipVerify,
		streams:    make(map[uint32]*stream),
	}
	c.nextID.Store(1)
	return c
}

func (c *Client) sendFrame(f *muxFrame) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.wsConn == nil {
		return fmt.Errorf("ws nil")
	}
	return c.wsConn.WriteMessage(websocket.BinaryMessage, encodeMuxFrame(f))
}

func (c *Client) removeStream(id uint32) {
	c.streamsMu.Lock()
	st, ok := c.streams[id]
	if ok {
		delete(c.streams, id)
	}
	c.streamsMu.Unlock()
	if ok {
		st.Close()
	}
}

func (c *Client) ensureConnection() (*websocket.Conn, error) {
	c.wsMu.Lock()
	defer c.wsMu.Unlock()

	if c.wsConn != nil {
		return c.wsConn, nil
	}

	dialer := websocket.Dialer{
		// Критически важно: перехватываем TCP-соединение чтобы
		// выставить SO_SNDBUF / SO_RCVBUF = 4MB ДО TLS-хендшейка.
		// Без этого Windows использует дефолтные ~64KB буферы,
		// что при RTT=115ms ограничивает upload до ~4.4 Mbps.
		NetDialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			d := &net.Dialer{Timeout: 15 * time.Second}
			conn, err := d.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			optimizeTCP(conn)
			log.Printf("[C] TCP буферы: %dMB (send/recv)", tcpBufSize/1024/1024)
			return conn, nil
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: c.skipVerify},
		ReadBufferSize:  wsBufSize,
		WriteBufferSize: wsBufSize,
		HandshakeTimeout: 15 * time.Second,
	}

	log.Printf("[C] Подключение к %s...", c.serverURL)
	ws, _, err := dialer.Dial(c.serverURL, nil)
	if err != nil {
		return nil, fmt.Errorf("WS dial: %w", err)
	}

	ws.SetReadLimit(0)
	c.wsConn = ws
	go c.readLoop(ws)
	log.Printf("[C] Туннель установлен")
	return ws, nil
}

func (c *Client) readLoop(ws *websocket.Conn) {
	defer func() {
		c.wsMu.Lock()
		c.wsConn = nil
		c.wsMu.Unlock()

		c.streamsMu.Lock()
		for id, st := range c.streams {
			st.Close()
			delete(c.streams, id)
		}
		c.streamsMu.Unlock()
		log.Printf("[C] Туннель закрыт")
	}()

	for {
		_, msg, err := ws.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				log.Printf("[C] WS read error: %v", err)
			}
			return
		}

		frame, err := decodeMuxFrame(msg)
		if err != nil {
			continue
		}

		switch frame.Cmd {
		case cmdData:
			c.streamsMu.Lock()
			st, ok := c.streams[frame.StreamID]
			c.streamsMu.Unlock()
			if ok {
				st.Send(frame.Payload)
			}
		case cmdClose:
			c.removeStream(frame.StreamID)
		}
	}
}

func (c *Client) handleSOCKS5(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 258)

	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return
	}
	if buf[0] != 0x05 {
		return
	}
	if _, err := io.ReadFull(conn, buf[:int(buf[1])]); err != nil {
		return
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		return
	}
	if buf[1] != 0x01 {
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var targetHost string
	switch buf[3] {
	case 0x01:
		if _, err := io.ReadFull(conn, buf[:4]); err != nil {
			return
		}
		targetHost = net.IP(buf[:4]).String()
	case 0x03:
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return
		}
		dLen := int(buf[0])
		if _, err := io.ReadFull(conn, buf[:dLen]); err != nil {
			return
		}
		targetHost = string(buf[:dLen])
	case 0x04:
		if _, err := io.ReadFull(conn, buf[:16]); err != nil {
			return
		}
		targetHost = net.IP(buf[:16]).String()
	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return
	}
	targetPort := int(binary.BigEndian.Uint16(buf[:2]))
	_ = conn.SetDeadline(time.Time{})

	if _, err := c.ensureConnection(); err != nil {
		log.Printf("[C] Server connect error: %v", err)
		conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	streamID := c.nextID.Add(1) - 1
	st := newStream(streamID)
	c.streamsMu.Lock()
	c.streams[streamID] = st
	c.streamsMu.Unlock()
	defer c.removeStream(streamID)

	info, _ := json.Marshal(struct {
		Host string `json:"host"`
		Port int    `json:"port"`
	}{Host: targetHost, Port: targetPort})

	if err := c.sendFrame(&muxFrame{Cmd: cmdOpen, StreamID: streamID, Payload: info}); err != nil {
		conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	done := make(chan struct{}, 2)

	// Браузер → WS (Upload).
	go func() {
		defer func() { done <- struct{}{} }()
		readBuf := make([]byte, readBufSize)
		for {
			n, err := conn.Read(readBuf)
			if n > 0 {
				payload := make([]byte, n)
				copy(payload, readBuf[:n])
				if sendErr := c.sendFrame(&muxFrame{
					Cmd: cmdData, StreamID: streamID, Payload: payload,
				}); sendErr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// WS → Браузер (Download).
	go func() {
		defer func() { done <- struct{}{} }()
		for data := range st.ch {
			if _, err := conn.Write(data); err != nil {
				return
			}
		}
	}()

	<-done
	_ = c.sendFrame(&muxFrame{Cmd: cmdClose, StreamID: streamID})
}

func (c *Client) run() error {
	ln, err := net.Listen("tcp", c.socksAddr)
	if err != nil {
		return fmt.Errorf("listen error: %w", err)
	}
	log.Printf("[C] SOCKS5 на %s → %s", c.socksAddr, c.serverURL)
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
	listen := flag.String("listen", "", "Адрес прослушки")
	serverURL := flag.String("server", "", "URL сервера (wss://...)")
	tlsCert := flag.String("tls-cert", "", "TLS сертификат")
	tlsKey := flag.String("tls-key", "", "TLS ключ")
	autoTLS := flag.Bool("tls", false, "Авто TLS")
	insecure := flag.Bool("insecure", true, "Пропустить TLS verify")

	flag.Parse()
	log.SetOutput(os.Stdout)
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	switch *mode {
	case "server":
		addr := *listen
		if addr == "" {
			addr = "0.0.0.0:8443"
		}
		log.Fatal(newServer(addr, *tlsCert, *tlsKey, *autoTLS).run())

	case "client":
		addr := *listen
		if addr == "" {
			addr = "127.0.0.1:1081"
		}
		if *serverURL == "" {
			log.Fatal("Укажите -server wss://HOST:PORT")
		}
		log.Fatal(newClient(addr, *serverURL, *insecure).run())

	default:
		fmt.Fprintln(os.Stderr, "Universal Proxy (Go)")
		fmt.Fprintln(os.Stderr, "  Сервер: proxy -mode server -tls")
		fmt.Fprintln(os.Stderr, "  Клиент: proxy -mode client -server wss://IP:8443")
		flag.PrintDefaults()
		os.Exit(1)
	}
}
