package main

import (
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
// Конфигурация
// =============================================================================

const (
	// Размер буфера чтения/записи WebSocket.
	// 64KB — оптимальный баланс для высокой пропускной способности.
	wsBufSize = 64 * 1024

	// Размер буфера для TCP-пересылки.
	tcpBufSize = 64 * 1024
)

// Команды мультиплексора.
const (
	cmdOpen  byte = 0x01
	cmdData  byte = 0x02
	cmdClose byte = 0x03
)

// =============================================================================
// Мультиплексный кадр
// =============================================================================

// muxFrame — один кадр мультиплексора.
// Формат проводника: [CMD:1][StreamID:4][PayloadLen:4][Payload:N]
type muxFrame struct {
	Cmd      byte
	StreamID uint32
	Payload  []byte
}

// encodeMuxFrame кодирует кадр в байты для отправки через WebSocket.
func encodeMuxFrame(f *muxFrame) []byte {
	buf := make([]byte, 9+len(f.Payload))
	buf[0] = f.Cmd
	binary.BigEndian.PutUint32(buf[1:5], f.StreamID)
	binary.BigEndian.PutUint32(buf[5:9], uint32(len(f.Payload)))
	copy(buf[9:], f.Payload)
	return buf
}

// decodeMuxFrame декодирует кадр из байтов.
func decodeMuxFrame(data []byte) (*muxFrame, error) {
	if len(data) < 9 {
		return nil, fmt.Errorf("frame too short: %d bytes", len(data))
	}
	f := &muxFrame{
		Cmd:      data[0],
		StreamID: binary.BigEndian.Uint32(data[1:5]),
	}
	payloadLen := binary.BigEndian.Uint32(data[5:9])
	if int(payloadLen) != len(data)-9 {
		return nil, fmt.Errorf("payload length mismatch: header=%d actual=%d", payloadLen, len(data)-9)
	}
	f.Payload = data[9:]
	return f, nil
}

// =============================================================================
// Сервер (VDS)
// =============================================================================

// Server — мультиплексный WS-сервер.
type Server struct {
	listenAddr string
	tlsCert    string
	tlsKey     string
	autoTLS    bool

	// Потоки (стримы) текущего туннеля.
	streams   map[uint32]chan []byte
	streamsMu sync.RWMutex

	// WebSocket-соединение для записи (защищено мьютексом).
	wsConn  *websocket.Conn
	writeMu sync.Mutex
}

// newServer создаёт экземпляр сервера.
func newServer(addr, cert, key string, autoTLS bool) *Server {
	return &Server{
		listenAddr: addr,
		tlsCert:    cert,
		tlsKey:     key,
		autoTLS:    autoTLS,
		streams:    make(map[uint32]chan []byte),
	}
}

// sendFrame отправляет мультиплексный кадр в WebSocket.
// Потокобезопасно: защищено writeMu.
func (s *Server) sendFrame(f *muxFrame) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.wsConn == nil {
		return fmt.Errorf("ws connection is nil")
	}
	return s.wsConn.WriteMessage(websocket.BinaryMessage, encodeMuxFrame(f))
}

// handleStream обрабатывает один поток (TCP-соединение с целью).
func (s *Server) handleStream(streamID uint32, targetHost string, targetPort int) {
	target := fmt.Sprintf("%s:%d", targetHost, targetPort)
	log.Printf("[S][Ch:%d] → %s", streamID, target)

	// Создаём канал для получения данных из WS.
	dataCh := make(chan []byte, 32)
	s.streamsMu.Lock()
	s.streams[streamID] = dataCh
	s.streamsMu.Unlock()

	defer func() {
		s.streamsMu.Lock()
		delete(s.streams, streamID)
		s.streamsMu.Unlock()
		log.Printf("[S][Ch:%d] ✕ %s", streamID, target)
	}()

	// TCP-соединение с целью.
	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		log.Printf("[S][Ch:%d] Ошибка подключения: %v", streamID, err)
		_ = s.sendFrame(&muxFrame{Cmd: cmdClose, StreamID: streamID})
		return
	}
	defer conn.Close()

	// Оптимизация TCP.
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetReadBuffer(256 * 1024)
		_ = tc.SetWriteBuffer(256 * 1024)
	}

	done := make(chan struct{}, 2)

	// Горутина: Целевой сервер → WS (Download).
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, tcpBufSize)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				// Копируем данные, так как buf будет перезаписан.
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

	// Горутина: WS → Целевой сервер (Upload).
	go func() {
		defer func() { done <- struct{}{} }()
		for data := range dataCh {
			if _, err := conn.Write(data); err != nil {
				return
			}
		}
	}()

	// Ждём завершения любой горутины.
	<-done

	// Закрываем канал и TCP, чтобы вторая горутина тоже завершилась.
	close(dataCh)
	_ = conn.Close()
	_ = s.sendFrame(&muxFrame{Cmd: cmdClose, StreamID: streamID})
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  wsBufSize,
	WriteBufferSize: wsBufSize,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

// handleWS обрабатывает входящее WebSocket-соединение.
func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[S] Ошибка WS upgrade: %v", err)
		return
	}
	defer ws.Close()

	peer := r.RemoteAddr
	log.Printf("[S] Туннель установлен: %s", peer)

	s.wsConn = ws
	ws.SetReadLimit(0) // Без лимита на размер сообщения.

	// Основной цикл чтения.
	for {
		_, msg, err := ws.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(
				err, websocket.CloseGoingAway, websocket.CloseNormalClosure,
			) {
				log.Printf("[S] WS ошибка: %v", err)
			}
			break
		}

		frame, err := decodeMuxFrame(msg)
		if err != nil {
			log.Printf("[S] Ошибка декодирования кадра: %v", err)
			continue
		}

		switch frame.Cmd {
		case cmdOpen:
			var info struct {
				Host string `json:"host"`
				Port int    `json:"port"`
			}
			if err := json.Unmarshal(frame.Payload, &info); err != nil {
				log.Printf("[S] Ошибка парсинга OPEN: %v", err)
				continue
			}
			go s.handleStream(frame.StreamID, info.Host, info.Port)

		case cmdData:
			s.streamsMu.RLock()
			ch, ok := s.streams[frame.StreamID]
			s.streamsMu.RUnlock()
			if ok {
				select {
				case ch <- frame.Payload:
				default:
					// Канал заполнен — дропаем, чтобы не блокировать мультиплексор.
				}
			}

		case cmdClose:
			s.streamsMu.RLock()
			ch, ok := s.streams[frame.StreamID]
			s.streamsMu.RUnlock()
			if ok {
				close(ch)
				s.streamsMu.Lock()
				delete(s.streams, frame.StreamID)
				s.streamsMu.Unlock()
			}
		}
	}

	// Туннель закрыт — очищаем все стримы.
	log.Printf("[S] Туннель закрыт: %s", peer)
	s.streamsMu.Lock()
	for id, ch := range s.streams {
		close(ch)
		delete(s.streams, id)
	}
	s.streamsMu.Unlock()
}

// generateSelfSignedCert создаёт самоподписанный TLS-сертификат.
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

	certDER, err := x509.CreateCertificate(
		rand.Reader, &template, &template, &priv.PublicKey, priv,
	)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}, nil
}

// run запускает сервер.
func (s *Server) run() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleWS)

	server := &http.Server{
		Addr:    s.listenAddr,
		Handler: mux,
	}

	if s.autoTLS || (s.tlsCert != "" && s.tlsKey != "") {
		if s.autoTLS {
			cert, err := generateSelfSignedCert()
			if err != nil {
				return fmt.Errorf("ошибка генерации TLS: %w", err)
			}
			server.TLSConfig = &tls.Config{
				Certificates: []tls.Certificate{cert},
			}
			log.Printf("[S] TLS: самоподписанный сертификат")
			log.Printf("[S] Слушаю на %s (WSS)", s.listenAddr)
			return server.ListenAndServeTLS("", "")
		}
		log.Printf("[S] TLS: %s / %s", s.tlsCert, s.tlsKey)
		log.Printf("[S] Слушаю на %s (WSS)", s.listenAddr)
		return server.ListenAndServeTLS(s.tlsCert, s.tlsKey)
	}

	log.Printf("[S] Слушаю на %s (WS, без TLS)", s.listenAddr)
	return server.ListenAndServe()
}

// =============================================================================
// Клиент (Локальная машина)
// =============================================================================

// Client — локальный SOCKS5 прокси с мультиплексированием.
type Client struct {
	socksAddr  string
	serverURL  string
	skipVerify bool

	streams   map[uint32]chan []byte
	streamsMu sync.RWMutex
	nextID    atomic.Uint32

	wsConn  *websocket.Conn
	writeMu sync.Mutex
	wsMu    sync.Mutex
}

// newClient создаёт клиент.
func newClient(socksAddr, serverURL string, skipVerify bool) *Client {
	c := &Client{
		socksAddr:  socksAddr,
		serverURL:  serverURL,
		skipVerify: skipVerify,
		streams:    make(map[uint32]chan []byte),
	}
	c.nextID.Store(1)
	return c
}

// sendFrame отправляет кадр в WS. Потокобезопасно.
func (c *Client) sendFrame(f *muxFrame) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.wsConn == nil {
		return fmt.Errorf("ws not connected")
	}
	return c.wsConn.WriteMessage(websocket.BinaryMessage, encodeMuxFrame(f))
}

// ensureConnection устанавливает или возвращает WS-соединение.
func (c *Client) ensureConnection() (*websocket.Conn, error) {
	c.wsMu.Lock()
	defer c.wsMu.Unlock()

	if c.wsConn != nil {
		return c.wsConn, nil
	}

	dialer := websocket.Dialer{
		ReadBufferSize:  wsBufSize,
		WriteBufferSize: wsBufSize,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: c.skipVerify,
		},
		HandshakeTimeout: 15 * time.Second,
	}

	log.Printf("[C] Подключение к %s...", c.serverURL)
	ws, _, err := dialer.Dial(c.serverURL, nil)
	if err != nil {
		return nil, fmt.Errorf("WS dial error: %w", err)
	}

	ws.SetReadLimit(0)
	c.wsConn = ws

	// Запустить фоновый чтец.
	go c.readLoop(ws)

	log.Printf("[C] Туннель установлен")
	return ws, nil
}

// readLoop — фоновое чтение из WS и распределение по стримам.
func (c *Client) readLoop(ws *websocket.Conn) {
	defer func() {
		c.wsMu.Lock()
		c.wsConn = nil
		c.wsMu.Unlock()

		// Закрыть все стримы.
		c.streamsMu.Lock()
		for id, ch := range c.streams {
			close(ch)
			delete(c.streams, id)
		}
		c.streamsMu.Unlock()
		log.Printf("[C] Туннель закрыт")
	}()

	for {
		_, msg, err := ws.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(
				err, websocket.CloseGoingAway, websocket.CloseNormalClosure,
			) {
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
			c.streamsMu.RLock()
			ch, ok := c.streams[frame.StreamID]
			c.streamsMu.RUnlock()
			if ok {
				select {
				case ch <- frame.Payload:
				default:
				}
			}

		case cmdClose:
			c.streamsMu.Lock()
			ch, ok := c.streams[frame.StreamID]
			if ok {
				close(ch)
				delete(c.streams, frame.StreamID)
			}
			c.streamsMu.Unlock()
		}
	}
}

// handleSOCKS5 обрабатывает одно SOCKS5-подключение от браузера.
func (c *Client) handleSOCKS5(conn net.Conn) {
	defer conn.Close()

	// Установить таймаут на хендшейк.
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	// 1. SOCKS5 приветствие.
	buf := make([]byte, 258)
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
	// Ответ: No auth.
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// 2. SOCKS5 запрос CONNECT.
	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		return
	}
	if buf[1] != 0x01 { // Только CONNECT.
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var targetHost string
	atyp := buf[3]
	switch atyp {
	case 0x01: // IPv4
		if _, err := io.ReadFull(conn, buf[:4]); err != nil {
			return
		}
		targetHost = net.IP(buf[:4]).String()
	case 0x03: // Domain
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return
		}
		domainLen := int(buf[0])
		if _, err := io.ReadFull(conn, buf[:domainLen]); err != nil {
			return
		}
		targetHost = string(buf[:domainLen])
	case 0x04: // IPv6
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

	// Убрать таймаут хендшейка.
	_ = conn.SetDeadline(time.Time{})

	// 3. Открыть канал в мультиплексоре.
	if _, err := c.ensureConnection(); err != nil {
		log.Printf("[C] Ошибка подключения к серверу: %v", err)
		conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	streamID := c.nextID.Add(1) - 1
	dataCh := make(chan []byte, 32)

	c.streamsMu.Lock()
	c.streams[streamID] = dataCh
	c.streamsMu.Unlock()

	defer func() {
		c.streamsMu.Lock()
		delete(c.streams, streamID)
		c.streamsMu.Unlock()
	}()

	// CMD_OPEN
	info, _ := json.Marshal(struct {
		Host string `json:"host"`
		Port int    `json:"port"`
	}{Host: targetHost, Port: targetPort})

	if err := c.sendFrame(&muxFrame{
		Cmd: cmdOpen, StreamID: streamID, Payload: info,
	}); err != nil {
		conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// SOCKS5 OK
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	log.Printf("[C][Ch:%d] → %s:%d", streamID, targetHost, targetPort)

	done := make(chan struct{}, 2)

	// Горутина: Браузер → WS (Upload).
	go func() {
		defer func() { done <- struct{}{} }()
		readBuf := make([]byte, tcpBufSize)
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

	// Горутина: WS → Браузер (Download).
	go func() {
		defer func() { done <- struct{}{} }()
		for data := range dataCh {
			if _, err := conn.Write(data); err != nil {
				return
			}
		}
	}()

	<-done
	_ = c.sendFrame(&muxFrame{Cmd: cmdClose, StreamID: streamID})
}

// run запускает SOCKS5-прокси.
func (c *Client) run() error {
	ln, err := net.Listen("tcp", c.socksAddr)
	if err != nil {
		return fmt.Errorf("ошибка прослушки: %w", err)
	}
	log.Printf("[C] SOCKS5 прокси на %s", c.socksAddr)
	log.Printf("[C] Сервер: %s", c.serverURL)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[C] Accept error: %v", err)
			continue
		}

		// Оптимизация TCP.
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
	mode := flag.String("mode", "", "Режим: 'server' или 'client'")
	listen := flag.String("listen", "", "Адрес прослушки (server: 0.0.0.0:8443, client: 127.0.0.1:1081)")
	serverURL := flag.String("server", "", "URL сервера для клиента (wss://89.22.237.64:8443)")
	tlsCert := flag.String("tls-cert", "", "Путь к TLS-сертификату (сервер)")
	tlsKey := flag.String("tls-key", "", "Путь к TLS-ключу (сервер)")
	autoTLS := flag.Bool("tls", false, "Авто-генерация самоподписанного TLS (сервер)")
	insecure := flag.Bool("insecure", true, "Не проверять TLS-сертификат (клиент)")

	flag.Parse()

	log.SetOutput(os.Stdout)
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	switch *mode {
	case "server":
		addr := *listen
		if addr == "" {
			addr = "0.0.0.0:8443"
		}
		srv := newServer(addr, *tlsCert, *tlsKey, *autoTLS)
		log.Fatal(srv.run())

	case "client":
		addr := *listen
		if addr == "" {
			addr = "127.0.0.1:1081"
		}
		if *serverURL == "" {
			log.Fatal("Укажите -server URL. Пример: -server wss://89.22.237.64:8443")
		}
		cl := newClient(addr, *serverURL, *insecure)
		log.Fatal(cl.run())

	default:
		fmt.Fprintln(os.Stderr, "Universal Proxy (Go)")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Использование:")
		fmt.Fprintln(os.Stderr, "  Сервер: proxy -mode server -listen 0.0.0.0:8443 -tls")
		fmt.Fprintln(os.Stderr, "  Клиент: proxy -mode client -listen 127.0.0.1:1081 -server wss://89.22.237.64:8443")
		fmt.Fprintln(os.Stderr, "")
		flag.PrintDefaults()
		os.Exit(1)
	}
}
