package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"gopkg.in/yaml.v3"
)

// Config represents the client configuration
type Config struct {
	// Client ID (unique identifier for this client)
	ClientID string `yaml:"clientID"`

	// Server address (e.g., "tunnel.example.com:8080")
	ServerAddress string `yaml:"serverAddress"`

	// Access key for authentication
	AccessKey string `yaml:"accessKey"`

	// Optional CA certificate file for custom CA trust
	CAFile string `yaml:"caFile,omitempty"`

	// Whether to use TLS (default: true)
	UseTLS bool `yaml:"useTLS"`

	// Whether to verify TLS certificates (default: true)
	VerifyCert bool `yaml:"verifyCert"`

	// Max reconnect attempts
	MaxReconnectAttempts int `yaml:"maxReconnectAttempts"`

	// Reconnect delay in seconds
	ReconnectDelay int `yaml:"reconnectDelay"`

	// Log level (debug, info, warning, error)
	LogLevel string `yaml:"logLevel"`
}

// Message types for binary protocol (same as server)
const (
	MessageTypeAuth         byte = 1
	MessageTypeAuthResponse byte = 2
	MessageTypeNewConn      byte = 3
	MessageTypeData         byte = 4
	MessageTypeClose        byte = 5
	MessageTypePing         byte = 6
	MessageTypePong         byte = 7
)

// Auth response structure for parsing server response
type AuthResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// Client represents the tunnel client
type Client struct {
	config       Config
	conn         *websocket.Conn
	connections  map[string]*LocalConnection
	connMutex    sync.RWMutex
	done         chan struct{}
	reconnecting bool
	lastActivity time.Time
	writeMutex   sync.Mutex // Ensure write operations are serialized
	// Buffer pool for reusing buffers
	bufferPool sync.Pool
}

// LocalConnection represents a connection to a local service
type LocalConnection struct {
	ID              string
	conn            net.Conn
	client          *Client
	destinationAddr string
	forwardID       string
	lastActivity    time.Time
}

// Initialize random number generator for nonce creation
func init() {
	rand.Seed(time.Now().UnixNano())
}

// NewClient creates a new tunnel client
func NewClient(configFile string) (*Client, error) {
	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("error reading config: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("error parsing config: %w", err)
	}

	// Set defaults
	if config.MaxReconnectAttempts == 0 {
		config.MaxReconnectAttempts = 10
	}
	if config.ReconnectDelay == 0 {
		config.ReconnectDelay = 5
	}
	if config.UseTLS == false {
		log.Println("WARNING: TLS is disabled. This is not recommended for production use.")
	}
	if config.VerifyCert == false {
		log.Println("WARNING: TLS certificate verification is disabled. This is not recommended for production use.")
	}

	client := &Client{
		config:      config,
		connections: make(map[string]*LocalConnection),
		done:        make(chan struct{}),
		bufferPool: sync.Pool{
			New: func() interface{} {
				return make([]byte, 32*1024)
			},
		},
	}

	return client, nil
}

// Start starts the tunnel client
func (c *Client) Start() error {
	log.Printf("Starting tunnel client with ID %s", c.config.ClientID)

	// Set up signal handling for graceful shutdown
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-signals
		log.Println("Received shutdown signal")
		close(c.done)
	}()

	// Connect to server with reconnection logic
	attempt := 0
	for {
		select {
		case <-c.done:
			return nil
		default:
			err := c.connect()
			if err == nil {
				// Connection successful, reset attempt counter
				attempt = 0

				// connect() handles the wait for disconnect
				// When we return here, it's because we need to reconnect
			} else {
				log.Printf("Connection error: %v", err)
			}

			// Connection failed or disconnected
			attempt++
			if attempt > c.config.MaxReconnectAttempts {
				return fmt.Errorf("exceeded maximum reconnection attempts")
			}

			delay := time.Duration(c.config.ReconnectDelay) * time.Second
			log.Printf("Reconnecting in %d seconds (attempt %d/%d)...",
				c.config.ReconnectDelay, attempt, c.config.MaxReconnectAttempts)

			select {
			case <-time.After(delay):
				// Continue with next attempt
			case <-c.done:
				return nil
			}
		}
	}
}

// Generate a random nonce string
func generateNonce(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

// createAuthMessage creates an authentication message with HMAC
func (c *Client) createAuthMessage() []byte {
	clientID := c.config.ClientID
	timestamp := time.Now().Unix()
	nonce := generateNonce(16)

	// Create the message to sign
	message := fmt.Sprintf("%s:%d:%s", clientID, timestamp, nonce)

	// Create HMAC
	h := hmac.New(sha256.New, []byte(c.config.AccessKey))
	h.Write([]byte(message))
	hmacDigest := base64.StdEncoding.EncodeToString(h.Sum(nil))

	// Format binary auth message
	// [type][client ID len][client ID][timestamp][nonce len][nonce][hmac len][hmac]
	clientIDBytes := []byte(clientID)
	nonceBytes := []byte(nonce)
	hmacBytes := []byte(hmacDigest)

	buf := bytes.NewBuffer(make([]byte, 0, 1+4+len(clientIDBytes)+4+4+len(nonceBytes)+4+len(hmacBytes)))

	buf.WriteByte(MessageTypeAuth)
	binary.Write(buf, binary.BigEndian, uint32(len(clientIDBytes)))
	buf.Write(clientIDBytes)
	binary.Write(buf, binary.BigEndian, uint32(timestamp))
	binary.Write(buf, binary.BigEndian, uint32(len(nonceBytes)))
	buf.Write(nonceBytes)
	binary.Write(buf, binary.BigEndian, uint32(len(hmacBytes)))
	buf.Write(hmacBytes)

	return buf.Bytes()
}

// parseAuthResponse parses the authentication response
func parseAuthResponse(data []byte) (AuthResponse, error) {
	var resp AuthResponse

	if len(data) < 2 {
		return resp, fmt.Errorf("auth response too short")
	}

	// First byte is message type, should be AuthResponse
	if data[0] != MessageTypeAuthResponse {
		return resp, fmt.Errorf("unexpected message type: %d", data[0])
	}

	// Second byte is success flag
	resp.Success = data[1] == 1

	// Rest is message
	if len(data) > 2 {
		buf := bytes.NewBuffer(data[2:])

		var msgLen uint32
		err := binary.Read(buf, binary.BigEndian, &msgLen)
		if err != nil {
			return resp, fmt.Errorf("error reading message length: %w", err)
		}

		msgBytes := make([]byte, msgLen)
		_, err = buf.Read(msgBytes)
		if err != nil {
			return resp, fmt.Errorf("error reading message: %w", err)
		}

		resp.Message = string(msgBytes)
	}

	return resp, nil
}

// connect establishes a connection to the server
func (c *Client) connect() error {
	c.reconnecting = true
	defer func() { c.reconnecting = false }()

	// Close any existing connections
	if c.conn != nil {
		c.conn.Close()
	}

	// Close any existing local connections
	c.connMutex.Lock()
	for _, conn := range c.connections {
		conn.conn.Close()
	}
	c.connections = make(map[string]*LocalConnection)
	c.connMutex.Unlock()

	// Build WebSocket URL
	scheme := "ws"
	if c.config.UseTLS {
		scheme = "wss"
	}

	u := url.URL{
		Scheme: scheme,
		Host:   c.config.ServerAddress,
		Path:   "/ws",
	}

	log.Printf("Connecting to %s", u.String())

	// Set up dialer with improved configuration
	var dialer *websocket.Dialer
	if c.config.UseTLS {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: !c.config.VerifyCert,
		}

		// Add custom CA if provided
		if c.config.CAFile != "" {
			caCert, err := os.ReadFile(c.config.CAFile)
			if err != nil {
				return fmt.Errorf("error reading CA file: %w", err)
			}

			caCertPool := x509.NewCertPool()
			if !caCertPool.AppendCertsFromPEM(caCert) {
				return fmt.Errorf("error parsing CA certificate")
			}

			tlsConfig.RootCAs = caCertPool
		}

		dialer = &websocket.Dialer{
			TLSClientConfig:  tlsConfig,
			ReadBufferSize:   32768,
			WriteBufferSize:  32768,
			HandshakeTimeout: 45 * time.Second,
		}
	} else {
		dialer = &websocket.Dialer{
			ReadBufferSize:   32768,
			WriteBufferSize:  32768,
			HandshakeTimeout: 45 * time.Second,
		}
	}

	// Connect to server with more detailed error reporting
	conn, resp, err := dialer.Dial(u.String(), nil)
	if err != nil {
		if resp != nil {
			log.Printf("Server returned HTTP %d: %s", resp.StatusCode, resp.Status)
		}
		return fmt.Errorf("error connecting to server: %w", err)
	}

	// Enable keep-alive with pong handler
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetPongHandler(func(string) error {
		log.Printf("Received pong from server")
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	c.conn = conn
	c.lastActivity = time.Now()

	// Authenticate using HMAC
	log.Printf("Connected to server, sending authentication")
	authMsg := c.createAuthMessage()

	c.writeMutex.Lock()
	if err := conn.WriteMessage(websocket.BinaryMessage, authMsg); err != nil {
		c.writeMutex.Unlock()
		conn.Close()
		return fmt.Errorf("error sending auth request: %w", err)
	}
	c.writeMutex.Unlock()

	// Wait for auth response
	log.Printf("Authentication sent, waiting for response")
	_, respBytes, err := conn.ReadMessage()
	if err != nil {
		conn.Close()
		return fmt.Errorf("error reading auth response: %w", err)
	}

	authResp, err := parseAuthResponse(respBytes)
	if err != nil {
		conn.Close()
		return fmt.Errorf("error parsing auth response: %w", err)
	}

	if !authResp.Success {
		conn.Close()
		return fmt.Errorf("authentication failed: %s", authResp.Message)
	}

	log.Printf("Connected and authenticated successfully, waiting for server messages")

	// Use a WaitGroup and done channel to coordinate goroutine shutdown
	clientDone := make(chan struct{})
	var wg sync.WaitGroup

	// Start message handling
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.handleMessages(clientDone)
	}()

	// Start heartbeat
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.startHeartbeat(clientDone)
	}()

	// Wait for disconnection or done signal
	select {
	case <-c.done:
		log.Printf("Client shutting down due to external signal")
		close(clientDone)
		conn.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, "Client shutting down"))
		conn.Close()
	case <-clientDone:
		log.Printf("Client disconnected due to WebSocket closure")
	}

	wg.Wait()
	log.Printf("Client connection fully cleaned up")

	return nil // Return nil to allow reconnection
}

// handleMessages handles incoming messages from the server
func (c *Client) handleMessages(done chan struct{}) {
	defer func() {
		if !c.reconnecting {
			c.conn.Close()

			// Close all local connections
			c.connMutex.Lock()
			for _, conn := range c.connections {
				conn.conn.Close()
			}
			c.connMutex.Unlock()

			log.Printf("Client message handler exited")
			close(done)
		}
	}()

	for {
		// Read message using binary protocol
		msgType, msgBytes, err := c.conn.ReadMessage()
		if err != nil {
			log.Printf("Error reading message from server: %v", err)
			return
		}

		c.lastActivity = time.Now()

		// Handle control messages (ping, pong, close)
		if msgType == websocket.PingMessage {
			log.Printf("Received ping from server, responding with pong")
			c.writeMutex.Lock()
			c.conn.WriteMessage(websocket.PongMessage, nil)
			c.writeMutex.Unlock()
			continue
		} else if msgType == websocket.PongMessage {
			log.Printf("Received WebSocket pong from server")
			continue
		} else if msgType == websocket.CloseMessage {
			log.Printf("Received close frame from server")
			return
		} else if msgType != websocket.BinaryMessage {
			log.Printf("Received unexpected WebSocket message type: %d", msgType)
			continue
		}

		if len(msgBytes) == 0 {
			log.Printf("Received empty message from server")
			continue
		}

		// Handle based on message type
		msgType = int(msgBytes[0])
		payload := msgBytes[1:]

		switch msgBytes[0] {
		case MessageTypeNewConn:
			log.Printf("Received new connection request")
			// Parse new connection message
			// Format: [conn ID len][conn ID][forward ID len][forward ID][dest addr len][dest addr]
			buf := bytes.NewBuffer(payload)

			var connIDLen uint32
			err := binary.Read(buf, binary.BigEndian, &connIDLen)
			if err != nil {
				log.Printf("Error reading conn ID length: %v", err)
				continue
			}

			connIDBytes := make([]byte, connIDLen)
			_, err = buf.Read(connIDBytes)
			if err != nil {
				log.Printf("Error reading conn ID: %v", err)
				continue
			}
			connID := string(connIDBytes)

			var forwardIDLen uint32
			err = binary.Read(buf, binary.BigEndian, &forwardIDLen)
			if err != nil {
				log.Printf("Error reading forward ID length: %v", err)
				continue
			}

			forwardIDBytes := make([]byte, forwardIDLen)
			_, err = buf.Read(forwardIDBytes)
			if err != nil {
				log.Printf("Error reading forward ID: %v", err)
				continue
			}
			forwardID := string(forwardIDBytes)

			var destAddrLen uint32
			err = binary.Read(buf, binary.BigEndian, &destAddrLen)
			if err != nil {
				log.Printf("Error reading destination address length: %v", err)
				continue
			}

			destAddrBytes := make([]byte, destAddrLen)
			_, err = buf.Read(destAddrBytes)
			if err != nil {
				log.Printf("Error reading destination address: %v", err)
				continue
			}
			destAddr := string(destAddrBytes)

			log.Printf("New connection request: %s, forwarding to %s", connID, destAddr)

			// Handle the new connection
			go c.handleNewConnection(connID, forwardID, destAddr)

		case MessageTypeData:
			// Parse data message
			// Format: [conn ID len][conn ID][forward ID len][forward ID][data len][data]
			buf := bytes.NewBuffer(payload)

			var connIDLen uint32
			err := binary.Read(buf, binary.BigEndian, &connIDLen)
			if err != nil {
				log.Printf("Error reading conn ID length: %v", err)
				continue
			}

			connIDBytes := make([]byte, connIDLen)
			_, err = buf.Read(connIDBytes)
			if err != nil {
				log.Printf("Error reading conn ID: %v", err)
				continue
			}
			connID := string(connIDBytes)

			var forwardIDLen uint32
			err = binary.Read(buf, binary.BigEndian, &forwardIDLen)
			if err != nil {
				log.Printf("Error reading forward ID length: %v", err)
				continue
			}

			forwardIDBytes := make([]byte, forwardIDLen)
			_, err = buf.Read(forwardIDBytes)
			if err != nil {
				log.Printf("Error reading forward ID: %v", err)
				continue
			}

			var dataLen uint32
			err = binary.Read(buf, binary.BigEndian, &dataLen)
			if err != nil {
				log.Printf("Error reading data length: %v", err)
				continue
			}

			data := make([]byte, dataLen)
			_, err = buf.Read(data)
			if err != nil {
				log.Printf("Error reading data: %v", err)
				continue
			}

			// Find local connection
			c.connMutex.RLock()
			localConn, exists := c.connections[connID]
			c.connMutex.RUnlock()

			if !exists {
				log.Printf("Local connection %s not found, closing", connID)
				c.sendCloseMessage(connID, string(forwardIDBytes))
				continue
			}

			// Write data to local connection
			_, err = localConn.conn.Write(data)
			if err != nil {
				log.Printf("Error writing to local connection %s: %v", connID, err)
				localConn.conn.Close()

				c.connMutex.Lock()
				delete(c.connections, connID)
				c.connMutex.Unlock()

				c.sendCloseMessage(connID, string(forwardIDBytes))
			}

		case MessageTypeClose:
			// Parse close message
			// Format: [conn ID len][conn ID][forward ID len][forward ID]
			buf := bytes.NewBuffer(payload)

			var connIDLen uint32
			err := binary.Read(buf, binary.BigEndian, &connIDLen)
			if err != nil {
				log.Printf("Error reading conn ID length: %v", err)
				continue
			}

			connIDBytes := make([]byte, connIDLen)
			_, err = buf.Read(connIDBytes)
			if err != nil {
				log.Printf("Error reading conn ID: %v", err)
				continue
			}
			connID := string(connIDBytes)

			log.Printf("Received close for connection %s", connID)

			// Find and close local connection
			c.connMutex.RLock()
			localConn, exists := c.connections[connID]
			c.connMutex.RUnlock()

			if exists {
				localConn.conn.Close()

				c.connMutex.Lock()
				delete(c.connections, connID)
				c.connMutex.Unlock()

				log.Printf("Closed local connection %s", connID)
			}

		case MessageTypePing:
			log.Printf("Received ping from server")
			// Respond with pong (simple binary message)
			pongMsg := []byte{MessageTypePong}
			c.writeMutex.Lock()
			err := c.conn.WriteMessage(websocket.BinaryMessage, pongMsg)
			c.writeMutex.Unlock()

			if err != nil {
				log.Printf("Error sending pong to server: %v", err)
			}

		case MessageTypePong:
			log.Printf("Received application-level pong from server")
			// Just update last activity time
			// Already done at the start of the message handler
		}
	}
}

// handleNewConnection handles a new connection request from the server
func (c *Client) handleNewConnection(connID, forwardID, destAddr string) {
	log.Printf("New connection request: %s to %s", connID, destAddr)

	// Connect to local service
	localConn, err := net.Dial("tcp", destAddr)
	if err != nil {
		log.Printf("Error connecting to local service %s: %v", destAddr, err)
		c.sendCloseMessage(connID, forwardID)
		return
	}

	log.Printf("Connected to local service %s for connection %s", destAddr, connID)

	// Create local connection
	conn := &LocalConnection{
		ID:              connID,
		conn:            localConn,
		client:          c,
		destinationAddr: destAddr,
		forwardID:       forwardID,
		lastActivity:    time.Now(),
	}

	// Register the connection
	c.connMutex.Lock()
	c.connections[connID] = conn
	c.connMutex.Unlock()

	// Read data from the local connection and forward it to the server
	buffer := c.bufferPool.Get().([]byte)
	defer c.bufferPool.Put(buffer)

	for {
		n, err := localConn.Read(buffer)
		if err != nil {
			if err != io.EOF {
				log.Printf("Error reading from local connection %s: %v", connID, err)
			} else {
				log.Printf("Local connection %s closed by local service", connID)
			}
			break
		}

		conn.lastActivity = time.Now()

		// Send data to server using binary protocol
		// Format: [type][conn ID len][conn ID][forward ID len][forward ID][data len][data]
		connIDBytes := []byte(connID)
		forwardIDBytes := []byte(forwardID)

		dataSize := 1 + 4 + len(connIDBytes) + 4 + len(forwardIDBytes) + 4 + n
		dataBuf := bytes.NewBuffer(make([]byte, 0, dataSize))

		dataBuf.WriteByte(MessageTypeData)
		binary.Write(dataBuf, binary.BigEndian, uint32(len(connIDBytes)))
		dataBuf.Write(connIDBytes)
		binary.Write(dataBuf, binary.BigEndian, uint32(len(forwardIDBytes)))
		dataBuf.Write(forwardIDBytes)
		binary.Write(dataBuf, binary.BigEndian, uint32(n))
		dataBuf.Write(buffer[:n])

		c.writeMutex.Lock()
		err = c.conn.WriteMessage(websocket.BinaryMessage, dataBuf.Bytes())
		c.writeMutex.Unlock()

		if err != nil {
			log.Printf("Error sending data to server: %v", err)
			break
		}
	}

	// Clean up
	localConn.Close()
	c.connMutex.Lock()
	delete(c.connections, connID)
	c.connMutex.Unlock()

	log.Printf("Local connection %s closed and cleaned up", connID)

	// Notify server that connection is closed
	c.sendCloseMessage(connID, forwardID)
}

// sendCloseMessage sends a close message to the server
func (c *Client) sendCloseMessage(connID, forwardID string) {
	log.Printf("Sending close message for connection %s", connID)

	// Format: [type][conn ID len][conn ID][forward ID len][forward ID]
	connIDBytes := []byte(connID)
	forwardIDBytes := []byte(forwardID)

	buf := bytes.NewBuffer(make([]byte, 0, 1+4+len(connIDBytes)+4+len(forwardIDBytes)))

	buf.WriteByte(MessageTypeClose)
	binary.Write(buf, binary.BigEndian, uint32(len(connIDBytes)))
	buf.Write(connIDBytes)
	binary.Write(buf, binary.BigEndian, uint32(len(forwardIDBytes)))
	buf.Write(forwardIDBytes)

	c.writeMutex.Lock()
	err := c.conn.WriteMessage(websocket.BinaryMessage, buf.Bytes())
	c.writeMutex.Unlock()

	if err != nil {
		log.Printf("Error sending close message to server: %v", err)
	}
}

// startHeartbeat starts a heartbeat goroutine for the client
func (c *Client) startHeartbeat(done chan struct{}) {
	ticker := time.NewTicker(15 * time.Second) // More frequent heartbeats
	defer ticker.Stop()

	log.Printf("Started heartbeat")

	for {
		select {
		case <-ticker.C:
			// Check if client is done
			select {
			case <-c.done:
				log.Printf("Heartbeat stopped due to client shutdown")
				return
			default:
				// Continue
			}

			// Check if client is still active
			if time.Since(c.lastActivity) > 45*time.Second {
				log.Printf("Server timed out (no activity for >45s)")
				c.conn.Close()
				return
			}

			// Send ping using binary protocol
			log.Printf("Sending ping to server")
			pingMsg := []byte{MessageTypePing}

			c.writeMutex.Lock()
			err := c.conn.WriteMessage(websocket.BinaryMessage, pingMsg)
			c.writeMutex.Unlock()

			if err != nil {
				log.Printf("Error sending ping to server: %v", err)
				c.conn.Close()
				return
			}

		case <-done:
			log.Printf("Heartbeat stopped due to WebSocket closure")
			return
		}
	}
}

func main() {
	configFile := flag.String("config", "config.yaml", "Path to config file")
	flag.Parse()

	client, err := NewClient(*configFile)
	if err != nil {
		log.Fatalf("Error creating client: %v", err)
	}

	log.Printf("Starting tunnel client...")
	if err := client.Start(); err != nil {
		log.Fatalf("Error starting client: %v", err)
	}
}
