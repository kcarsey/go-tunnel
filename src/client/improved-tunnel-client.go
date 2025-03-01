package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"gopkg.in/yaml.v3"
	"tunneling/common" // our new shared package
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

	// Timeouts in seconds
	ReadTimeout int `yaml:"readTimeout"`
	IdleTimeout int `yaml:"idleTimeout"`
	IdleTimeoutHTTP int `yaml:"idleTimeoutHTTP"`
	HeartbeatInterval int `yaml:"heartbeatInterval"`
	HeartbeatTimeout int `yaml:"heartbeatTimeout"`

	// Buffer sizes
	ReadBufferSize int `yaml:"readBufferSize"`
	WriteBufferSize int `yaml:"writeBufferSize"`
	BufferSize int `yaml:"bufferSize"`
	BufferSizeHTTP int `yaml:"bufferSizeHTTP"`
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
	logger     *log.Logger
}

// LocalConnection represents a connection to a local service
type LocalConnection struct {
	ID              string
	conn            net.Conn
	client          *Client
	destinationAddr string
	forwardID       string
	lastActivity    time.Time
	isHTTP          bool
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
		config.MaxReconnectAttempts = common.DefaultMaxReconnectAttempts
	}
	if config.ReconnectDelay == 0 {
		config.ReconnectDelay = common.DefaultReconnectDelay
	}
	
	// Set security defaults - ensure secure by default
	if !config.UseTLS {
		log.Println("WARNING: TLS is disabled. This is not recommended for production use.")
	} else {
		// If not explicitly disabled, enable security features
		config.UseTLS = true
	}
	
	if !config.VerifyCert {
		log.Println("WARNING: TLS certificate verification is disabled. This is not recommended for production use.")
	} else {
		// If not explicitly disabled, enable security features 
		config.VerifyCert = true
	}

	// Set timeout defaults
	if config.ReadTimeout == 0 {
		config.ReadTimeout = common.DefaultReadTimeout
	}
	if config.IdleTimeout == 0 {
		config.IdleTimeout = common.DefaultIdleTimeoutGeneral
	}
	if config.IdleTimeoutHTTP == 0 {
		config.IdleTimeoutHTTP = common.DefaultIdleTimeoutHTTP
	}
	if config.HeartbeatInterval == 0 {
		config.HeartbeatInterval = common.DefaultHeartbeatInterval
	}
	if config.HeartbeatTimeout == 0 {
		config.HeartbeatTimeout = common.DefaultHeartbeatTimeout
	}

	// Set buffer size defaults
	if config.ReadBufferSize == 0 {
		config.ReadBufferSize = common.DefaultReadBufferSize
	}
	if config.WriteBufferSize == 0 {
		config.WriteBufferSize = common.DefaultWriteBufferSize
	}
	if config.BufferSize == 0 {
		config.BufferSize = common.DefaultBufferSize
	}
	if config.BufferSizeHTTP == 0 {
		config.BufferSizeHTTP = common.DefaultBufferSizeHTTP
	}

	// Create a logger with appropriate prefix
	logger := log.New(os.Stdout, "[CLIENT] ", log.LstdFlags)

	client := &Client{
		config:      config,
		connections: make(map[string]*LocalConnection),
		done:        make(chan struct{}),
		bufferPool: sync.Pool{
			New: func() interface{} {
				return make([]byte, config.BufferSize)
			},
		},
		logger: logger,
	}

	return client, nil
}

// Start the tunnel client
func (c *Client) Start() error {
	c.logger.Printf("Starting tunnel client with ID %s", c.config.ClientID)

	// Set up signal handling for graceful shutdown
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-signals
		c.logger.Println("Received shutdown signal")
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
				c.logger.Printf("Connection error: %v", err)
			}

			// Connection failed or disconnected
			attempt++
			if attempt > c.config.MaxReconnectAttempts {
				return fmt.Errorf("exceeded maximum reconnection attempts")
			}

			delay := time.Duration(c.config.ReconnectDelay) * time.Second
			c.logger.Printf("Reconnecting in %d seconds (attempt %d/%d)...",
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

	c.logger.Printf("Connecting to %s", u.String())

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
			ReadBufferSize:   c.config.ReadBufferSize,
			WriteBufferSize:  c.config.WriteBufferSize,
			HandshakeTimeout: time.Duration(common.DefaultHandshakeTimeout) * time.Second,
		}
	} else {
		dialer = &websocket.Dialer{
			ReadBufferSize:   c.config.ReadBufferSize,
			WriteBufferSize:  c.config.WriteBufferSize,
			HandshakeTimeout: time.Duration(common.DefaultHandshakeTimeout) * time.Second,
		}
	}

	// Connect to server with more detailed error reporting
	conn, resp, err := dialer.Dial(u.String(), nil)
	if err != nil {
		if resp != nil {
			c.logger.Printf("Server returned HTTP %d: %s", resp.StatusCode, resp.Status)
		}
		return fmt.Errorf("error connecting to server: %w", err)
	}

	// Enable keep-alive with pong handler
	readTimeout := time.Duration(c.config.ReadTimeout) * time.Second
	conn.SetReadDeadline(time.Now().Add(readTimeout))
	conn.SetPongHandler(func(string) error {
		c.logger.Printf("Received pong from server")
		conn.SetReadDeadline(time.Now().Add(readTimeout))
		return nil
	})

	c.conn = conn
	c.lastActivity = time.Now()

	// Authenticate using HMAC
	c.logger.Printf("Connected to server, sending authentication")
	authMsg := common.CreateAuthMessage(c.config.ClientID, c.config.AccessKey)

	c.writeMutex.Lock()
	if err := conn.WriteMessage(websocket.BinaryMessage, authMsg); err != nil {
		c.writeMutex.Unlock()
		conn.Close()
		return fmt.Errorf("error sending auth request: %w", err)
	}
	c.writeMutex.Unlock()

	// Wait for auth response
	c.logger.Printf("Authentication sent, waiting for response")
	_, respBytes, err := conn.ReadMessage()
	if err != nil {
		conn.Close()
		return fmt.Errorf("error reading auth response: %w", err)
	}

	authResp, err := common.ParseAuthResponse(respBytes)
	if err != nil {
		conn.Close()
		return fmt.Errorf("error parsing auth response: %w", err)
	}

	if !authResp.Success {
		conn.Close()
		return fmt.Errorf("authentication failed: %s", authResp.Message)
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

			c.logger.Printf("Client message handler exited")
			close(done)
		}
	}()

	for {
		// Read message using binary protocol
		msgType, msgBytes, err := c.conn.ReadMessage()
		if err != nil {
			c.logger.Printf("Error reading message from server: %v", err)
			return
		}

		c.lastActivity = time.Now()

		// Handle control messages (ping, pong, close)
		if msgType == websocket.PingMessage {
			c.logger.Printf("Received ping from server, responding with pong")
			c.writeMutex.Lock()
			c.conn.WriteMessage(websocket.PongMessage, nil)
			c.writeMutex.Unlock()
			continue
		} else if msgType == websocket.PongMessage {
			c.logger.Printf("Received WebSocket pong from server")
			continue
		} else if msgType == websocket.CloseMessage {
			c.logger.Printf("Received close frame from server")
			return
		} else if msgType != websocket.BinaryMessage {
			c.logger.Printf("Received unexpected WebSocket message type: %d", msgType)
			continue
		}

		if len(msgBytes) == 0 {
			c.logger.Printf("Received empty message from server")
			continue
		}

		// Handle based on message type
		messageType := msgBytes[0]
		payload := msgBytes[1:]

		switch messageType {
		case common.MessageTypeNewConn:
			c.handleNewConnMessage(payload)
		case common.MessageTypeData:
			c.handleDataMessage(payload)
		case common.MessageTypeClose:
			c.handleCloseMessage(payload)
		case common.MessageTypePing:
			c.handlePingMessage()
		case common.MessageTypePong:
			c.logger.Printf("Received application-level pong from server")
		default:
			c.logger.Printf("Received unknown message type: %d", messageType)
		}
	}
}

// handleNewConnMessage processes a new connection message from the server
func (c *Client) handleNewConnMessage(payload []byte) {
	c.logger.Printf("Received new connection request")
	// Parse new connection message
	// Format: [conn ID len][conn ID][forward ID len][forward ID][dest addr len][dest addr]
	buf := bytes.NewBuffer(payload)

	var connIDLen uint32
	err := binary.Read(buf, binary.BigEndian, &connIDLen)
	if err != nil {
		c.logger.Printf("Error reading conn ID length: %v", err)
		return
	}

	connIDBytes := make([]byte, connIDLen)
	_, err = buf.Read(connIDBytes)
	if err != nil {
		c.logger.Printf("Error reading conn ID: %v", err)
		return
	}
	connID := string(connIDBytes)

	var forwardIDLen uint32
	err = binary.Read(buf, binary.BigEndian, &forwardIDLen)
	if err != nil {
		c.logger.Printf("Error reading forward ID length: %v", err)
		return
	}

	forwardIDBytes := make([]byte, forwardIDLen)
	_, err = buf.Read(forwardIDBytes)
	if err != nil {
		c.logger.Printf("Error reading forward ID: %v", err)
		return
	}
	forwardID := string(forwardIDBytes)

	var destAddrLen uint32
	err = binary.Read(buf, binary.BigEndian, &destAddrLen)
	if err != nil {
		c.logger.Printf("Error reading destination address length: %v", err)
		return
	}

	destAddrBytes := make([]byte, destAddrLen)
	_, err = buf.Read(destAddrBytes)
	if err != nil {
		c.logger.Printf("Error reading destination address: %v", err)
		return
	}
	destAddr := string(destAddrBytes)

	c.logger.Printf("New connection request: %s, forwarding to %s", connID, destAddr)

	// Handle the new connection
	go c.handleNewConnection(connID, forwardID, destAddr)
}

// handleDataMessage processes a data message from the server
func (c *Client) handleDataMessage(payload []byte) {
	// Parse data message
	// Format: [conn ID len][conn ID][forward ID len][forward ID][data len][data]
	buf := bytes.NewBuffer(payload)

	var connIDLen uint32
	err := binary.Read(buf, binary.BigEndian, &connIDLen)
	if err != nil {
		c.logger.Printf("Error reading conn ID length: %v", err)
		return
	}

	connIDBytes := make([]byte, connIDLen)
	_, err = buf.Read(connIDBytes)
	if err != nil {
		c.logger.Printf("Error reading conn ID: %v", err)
		return
	}
	connID := string(connIDBytes)

	var forwardIDLen uint32
	err = binary.Read(buf, binary.BigEndian, &forwardIDLen)
	if err != nil {
		c.logger.Printf("Error reading forward ID length: %v", err)
		return
	}

	forwardIDBytes := make([]byte, forwardIDLen)
	_, err = buf.Read(forwardIDBytes)
	if err != nil {
		c.logger.Printf("Error reading forward ID: %v", err)
		return
	}
	forwardID := string(forwardIDBytes)

	var dataLen uint32
	err = binary.Read(buf, binary.BigEndian, &dataLen)
	if err != nil {
		c.logger.Printf("Error reading data length: %v", err)
		return
	}

	data := make([]byte, dataLen)
	_, err = buf.Read(data)
	if err != nil {
		c.logger.Printf("Error reading data: %v", err)
		return
	}

	// Find local connection with race condition handling
	c.connMutex.RLock()
	localConn, exists := c.connections[connID]
	c.connMutex.RUnlock()

	if !exists {
		// Check if this is a race condition with a connection that's being established
		// Add a small delay before closing to give handleNewConnection time to establish
		c.logger.Printf("Local connection %s not found, waiting briefly before closing", connID)

		// Wait a short time to see if connection gets established
		time.Sleep(time.Duration(common.RaceConditionDelay) * time.Millisecond)

		// Check again
		c.connMutex.RLock()
		localConn, exists = c.connections[connID]
		c.connMutex.RUnlock()

		if !exists {
			c.logger.Printf("Local connection %s still not found after delay, closing", connID)
			c.sendCloseMessage(connID, forwardID)
			return
		} else {
			c.logger.Printf("Local connection %s found after delay, continuing", connID)
		}
	}

	// Write data to local connection
	_, err = localConn.conn.Write(data)
	if err != nil {
		c.logger.Printf("Error writing to local connection %s: %v", connID, err)
		localConn.conn.Close()

		c.connMutex.Lock()
		delete(c.connections, connID)
		c.connMutex.Unlock()

		c.sendCloseMessage(connID, forwardID)
	}
}

// handleCloseMessage processes a close message from the server
func (c *Client) handleCloseMessage(payload []byte) {
	// Parse close message
	// Format: [conn ID len][conn ID][forward ID len][forward ID]
	buf := bytes.NewBuffer(payload)

	var connIDLen uint32
	err := binary.Read(buf, binary.BigEndian, &connIDLen)
	if err != nil {
		c.logger.Printf("Error reading conn ID length: %v", err)
		return
	}

	connIDBytes := make([]byte, connIDLen)
	_, err = buf.Read(connIDBytes)
	if err != nil {
		c.logger.Printf("Error reading conn ID: %v", err)
		return
	}
	connID := string(connIDBytes)

	c.logger.Printf("Received close for connection %s", connID)

	// Find and close local connection
	c.connMutex.RLock()
	localConn, exists := c.connections[connID]
	c.connMutex.RUnlock()

	if exists {
		localConn.conn.Close()

		c.connMutex.Lock()
		delete(c.connections, connID)
		c.connMutex.Unlock()

		c.logger.Printf("Closed local connection %s", connID)
	}
}

// handlePingMessage processes a ping message from the server
func (c *Client) handlePingMessage() {
	c.logger.Printf("Received ping from server")
	// Respond with pong
	pongMsg := common.CreatePongMessage()
	c.writeMutex.Lock()
	err := c.conn.WriteMessage(websocket.BinaryMessage, pongMsg)
	c.writeMutex.Unlock()

	if err != nil {
		c.logger.Printf("Error sending pong to server: %v", err)
	}
}

// handleNewConnection handles a new connection request from the server
func (c *Client) handleNewConnection(connID, forwardID, destAddr string) {
	c.logger.Printf("New connection request: %s to %s", connID, destAddr)

	// Detect if this is likely HTTP traffic
	isHTTP := common.IsHTTPTraffic(destAddr)
	if isHTTP {
		c.logger.Printf("HTTP traffic detected for connection %s", connID)
	}

	// Connect to local service
	localConn, err := net.Dial("tcp", destAddr)
	if err != nil {
		c.logger.Printf("Error connecting to local service %s: %v", destAddr, err)
		c.sendCloseMessage(connID, forwardID)
		return
	}

	c.logger.Printf("Connected to local service %s for connection %s", destAddr, connID)

	// Create local connection
	conn := &LocalConnection{
		ID:              connID,
		conn:            localConn,
		client:          c,
		destinationAddr: destAddr,
		forwardID:       forwardID,
		lastActivity:    time.Now(),
		isHTTP:          isHTTP,
	}

	// Register the connection
	c.connMutex.Lock()
	c.connections[connID] = conn
	c.connMutex.Unlock()

	// Choose buffer and timeout based on HTTP detection
	var buffer []byte
	var idleTimeout time.Duration

	// If HTTP, use larger buffer and longer idle timeout
	if isHTTP {
		buffer = make([]byte, c.config.BufferSizeHTTP) // Larger buffer for HTTP
		idleTimeout = time.Duration(c.config.IdleTimeoutHTTP) * time.Second
	} else {
		buffer = c.bufferPool.Get().([]byte)
		defer func() {
			// Only return buffer to pool if it's not an HTTP connection
			if !isHTTP {
				c.bufferPool.Put(buffer)
			}
		}()
		idleTimeout = time.Duration(c.config.IdleTimeout) * time.Second
	}

	// Set initial read deadline
	localConn.SetReadDeadline(time.Now().Add(idleTimeout))

	// Read data from the local connection and forward it to the server
	for {
		n, err := localConn.Read(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Just a timeout, reset deadline and continue for HTTP connections
				if isHTTP {
					c.logger.Printf("HTTP connection %s idle, extending timeout", connID)
					localConn.SetReadDeadline(time.Now().Add(idleTimeout))
					continue
				}
			}

			if err != io.EOF {
				c.logger.Printf("Error reading from local connection %s: %v", connID, err)
			} else {
				c.logger.Printf("Local connection %s closed by local service", connID)
			}
			break
		}

		// Reset deadline after successful read
		localConn.SetReadDeadline(time.Now().Add(idleTimeout))

		conn.lastActivity = time.Now()

		// Send data to server
		dataMsg := common.CreateDataMessage(connID, forwardID, buffer[:n])
		
		c.writeMutex.Lock()
		err = c.conn.WriteMessage(websocket.BinaryMessage, dataMsg)
		c.writeMutex.Unlock()

		if err != nil {
			c.logger.Printf("Error sending data to server: %v", err)
			break
		}
	}

	// Clean up
	localConn.Close()
	c.connMutex.Lock()
	delete(c.connections, connID)
	c.connMutex.Unlock()

	c.logger.Printf("Local connection %s closed and cleaned up", connID)

	// For HTTP connections, delay the close message to allow time for any in-flight data
	if isHTTP {
		c.logger.Printf("HTTP connection %s - delaying close message by 100ms", connID)
		time.Sleep(time.Duration(common.HTTPCloseDelay) * time.Millisecond)
	}

	// Notify server that connection is closed
	c.sendCloseMessage(connID, forwardID)
}

// sendCloseMessage sends a close message to the server
func (c *Client) sendCloseMessage(connID, forwardID string) {
	c.logger.Printf("Sending close message for connection %s", connID)

	closeMsg := common.CreateCloseMessage(connID, forwardID)

	c.writeMutex.Lock()
	err := c.conn.WriteMessage(websocket.BinaryMessage, closeMsg)
	c.writeMutex.Unlock()

	if err != nil {
		c.logger.Printf("Error sending close message to server: %v", err)
	}
}

// startHeartbeat starts a heartbeat goroutine for the client
func (c *Client) startHeartbeat(done chan struct{}) {
	ticker := time.NewTicker(time.Duration(c.config.HeartbeatInterval) * time.Second)
	defer ticker.Stop()

	c.logger.Printf("Started heartbeat")

	for {
		select {
		case <-ticker.C:
			// Check if client is done
			select {
			case <-c.done:
				c.logger.Printf("Heartbeat stopped due to client shutdown")
				return
			default:
				// Continue
			}

			// Check if client is still active
			if time.Since(c.lastActivity) > time.Duration(c.config.HeartbeatTimeout)*time.Second {
				c.logger.Printf("Server timed out (no activity for >%ds)", c.config.HeartbeatTimeout)
				c.conn.Close()
				return
			}

			// Send ping using binary protocol
			c.logger.Printf("Sending ping to server")
			pingMsg := common.CreatePingMessage()

			c.writeMutex.Lock()
			err := c.conn.WriteMessage(websocket.BinaryMessage, pingMsg)
			c.writeMutex.Unlock()

			if err != nil {
				c.logger.Printf("Error sending ping to server: %v", err)
				c.conn.Close()
				return
			}

		case <-done:
			c.logger.Printf("Heartbeat stopped due to WebSocket closure")
			return
		}
	}
}

func main() {
	configFile := flag.String("config", "client.yaml", "Path to config file")
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