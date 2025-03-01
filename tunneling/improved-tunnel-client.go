package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
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

	"tunneling/common" // our shared package

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

	// Timeouts in seconds
	ReadTimeout       int `yaml:"readTimeout"`
	IdleTimeout       int `yaml:"idleTimeout"`
	IdleTimeoutHTTP   int `yaml:"idleTimeoutHTTP"`
	HeartbeatInterval int `yaml:"heartbeatInterval"`
	HeartbeatTimeout  int `yaml:"heartbeatTimeout"`

	// Buffer sizes
	ReadBufferSize  int `yaml:"readBufferSize"`
	WriteBufferSize int `yaml:"writeBufferSize"`
	BufferSize      int `yaml:"bufferSize"`
	BufferSizeHTTP  int `yaml:"bufferSizeHTTP"`
}

// Client represents the tunnel client
type Client struct {
	config      Config
	conn        *websocket.Conn
	connections map[string]*LocalConnection // Map of base ID to connection
	// Track connection metadata separately to handle versioning and grace periods
	connInfo     map[string]*common.ConnectionInfo
	connMutex    sync.RWMutex
	done         chan struct{}
	reconnecting bool
	lastActivity time.Time
	writeMutex   sync.Mutex // Ensure write operations are serialized
	// Buffer pool for reusing buffers
	bufferPool sync.Pool
	logger     *log.Logger
	// Cleanup ticker for removing connections after grace period
	cleanupTicker *time.Ticker
}

// LocalConnection represents a connection to a local service
type LocalConnection struct {
	ID              string // Base ID without version
	conn            net.Conn
	client          *Client
	destinationAddr string
	forwardID       string
	buffer          []byte
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
		connInfo:    make(map[string]*common.ConnectionInfo),
		done:        make(chan struct{}),
		bufferPool: sync.Pool{
			New: func() interface{} {
				return make([]byte, config.BufferSize)
			},
		},
		logger:        logger,
		cleanupTicker: time.NewTicker(100 * time.Millisecond), // Check for expired connections every 100ms
	}

	return client, nil
}

// Start the tunnel client
func (c *Client) Start() error {
	c.logger.Printf("Starting tunnel client with ID %s", c.config.ClientID)

	// Set up signal handling for graceful shutdown
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	// Start connection cleanup routine
	go c.startConnectionCleanup()

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
			c.cleanupTicker.Stop()
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
				c.cleanupTicker.Stop()
				return fmt.Errorf("exceeded maximum reconnection attempts")
			}

			delay := time.Duration(c.config.ReconnectDelay) * time.Second
			c.logger.Printf("Reconnecting in %d seconds (attempt %d/%d)...",
				c.config.ReconnectDelay, attempt, c.config.MaxReconnectAttempts)

			select {
			case <-time.After(delay):
				// Continue with next attempt
			case <-c.done:
				c.cleanupTicker.Stop()
				return nil
			}
		}
	}
}

// startConnectionCleanup periodically checks for connections that should be removed
func (c *Client) startConnectionCleanup() {
	for {
		select {
		case <-c.cleanupTicker.C:
			c.cleanupConnections()
		case <-c.done:
			return
		}
	}
}

// cleanupConnections removes connections that have exceeded their grace period
func (c *Client) cleanupConnections() {
	c.connMutex.Lock()
	defer c.connMutex.Unlock()

	var toRemove []string

	// Find connections that should be removed
	for baseID, info := range c.connInfo {
		if info.ShouldBeRemoved() {
			toRemove = append(toRemove, baseID)
		}
	}

	// Remove them
	for _, baseID := range toRemove {
		// Return buffer to pool if it's not an HTTP connection
		if conn, exists := c.connections[baseID]; exists {
			if info, infoExists := c.connInfo[baseID]; infoExists && !info.IsHTTP {
				if conn.buffer != nil {
					c.bufferPool.Put(conn.buffer)
					c.logger.Printf("Connection %s fully removed, buffer returned to pool",
						info.VersionedID.String())
				}
			}
			delete(c.connections, baseID)
		}
		delete(c.connInfo, baseID)
		c.logger.Printf("Connection %s fully removed after grace period", baseID)
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
	// Mark all connections for removal
	for baseID, info := range c.connInfo {
		info.MarkForRemoval()
		c.logger.Printf("Marked connection %s for removal", baseID)
	}
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
	}

	c.logger.Printf("Authentication successful")

	// Set up message handling and heartbeat
	messageDone := make(chan struct{})
	go c.handleMessages(messageDone)
	go c.startHeartbeat(messageDone)

	// Wait for message handler to exit
	<-messageDone
	c.logger.Printf("Connection closed")

	return nil
}

// handleMessages handles incoming messages from the server
func (c *Client) handleMessages(done chan struct{}) {
	defer func() {
		if !c.reconnecting {
			c.conn.Close()

			// Close all local connections and mark them for removal
			c.connMutex.Lock()
			for baseID, conn := range c.connections {
				conn.conn.Close()
				if info, exists := c.connInfo[baseID]; exists {
					info.MarkForRemoval()
				}
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
	connIDStr := string(connIDBytes)

	// Parse versioned connection ID
	versionedID := common.ParseVersionedID(connIDStr)
	baseID := versionedID.BaseID

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

	c.logger.Printf("New connection request: %s (ID: %s), forwarding to %s",
		versionedID.String(), baseID, destAddr)

	// Handle the new connection
	go c.handleNewConnection(versionedID, baseID, forwardID, destAddr)
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
	connIDStr := string(connIDBytes)

	// Parse versioned connection ID
	versionedID := common.ParseVersionedID(connIDStr)
	baseID := versionedID.BaseID

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

	// Find local connection
	c.connMutex.RLock()
	localConn, exists := c.connections[baseID]
	info, infoExists := c.connInfo[baseID]
	c.connMutex.RUnlock()

	// Verify connection exists and versions match
	if !exists || !infoExists {
		c.logger.Printf("Local connection %s not found, rejecting data", versionedID.String())
		c.sendCloseMessage(versionedID, forwardID)
		return
	}

	// Check if connection is closing
	if info.State != common.ConnectionStateActive {
		c.logger.Printf("Connection %s is closing, rejecting data", versionedID.String())
		return
	}

	// Check if versions match
	if info.VersionedID.Version != versionedID.Version {
		c.logger.Printf("Version mismatch for connection %s (have %d, received %d), rejecting data",
			baseID, info.VersionedID.Version, versionedID.Version)
		c.sendCloseMessage(versionedID, forwardID)
		return
	}

	// Write data to local connection
	_, err = localConn.conn.Write(data)
	if err != nil {
		c.logger.Printf("Error writing to local connection %s: %v", versionedID.String(), err)
		localConn.conn.Close()

		c.connMutex.Lock()
		// Mark for removal with grace period
		info.MarkForRemoval()
		c.connMutex.Unlock()

		c.sendCloseMessage(versionedID, forwardID)
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
	connIDStr := string(connIDBytes)

	// Parse versioned connection ID
	versionedID := common.ParseVersionedID(connIDStr)
	baseID := versionedID.BaseID

	c.logger.Printf("Received close for connection %s", versionedID.String())

	// Find and close local connection
	c.connMutex.Lock()
	localConn, exists := c.connections[baseID]
	info, infoExists := c.connInfo[baseID]

	if exists && infoExists {
		// Only close if versions match
		if info.VersionedID.Version == versionedID.Version {
			localConn.conn.Close()

			// Mark for removal with grace period
			info.MarkForRemoval()
			c.logger.Printf("Closed local connection %s", versionedID.String())
		} else {
			c.logger.Printf("Version mismatch on close for connection %s (have %d, received %d)",
				baseID, info.VersionedID.Version, versionedID.Version)
		}
	}
	c.connMutex.Unlock()
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
func (c *Client) handleNewConnection(versionedID *common.VersionedID, baseID, forwardID, destAddr string) {
	c.logger.Printf("Processing new connection request: %s to %s", versionedID.String(), destAddr)

	// Check if connection with this base ID already exists
	c.connMutex.RLock()
	existingInfo, exists := c.connInfo[baseID]
	c.connMutex.RUnlock()

	if exists {
		// If connection exists but is marked for closing, let it be removed
		if existingInfo.State == common.ConnectionStateClosing {
			c.logger.Printf("Connection %s exists but is closing, waiting for cleanup before creating new one", baseID)

			// Wait for the connection to be fully removed
			waitStart := time.Now()
			maxWait := time.Duration(common.DefaultConnectionGracePeriod) * time.Millisecond

			for time.Since(waitStart) < maxWait {
				time.Sleep(50 * time.Millisecond)

				c.connMutex.RLock()
				_, stillExists := c.connInfo[baseID]
				c.connMutex.RUnlock()

				if !stillExists {
					break
				}
			}

			// Check again if it's gone
			c.connMutex.RLock()
			_, stillExists := c.connInfo[baseID]
			c.connMutex.RUnlock()

			if stillExists {
				c.logger.Printf("Connection %s not cleaned up in time, rejecting new connection", baseID)
				c.sendCloseMessage(versionedID, forwardID)
				return
			}
		} else {
			// If connection exists and is active, compare versions
			if existingInfo.VersionedID.Version >= versionedID.Version {
				c.logger.Printf("Ignoring new connection with older or same version: %s (existing: %d, new: %d)",
					baseID, existingInfo.VersionedID.Version, versionedID.Version)
				return
			}

			// Higher version - close existing connection
			c.logger.Printf("Replacing connection %s with newer version %d -> %d",
				baseID, existingInfo.VersionedID.Version, versionedID.Version)

			c.connMutex.RLock()
			if localConn, exists := c.connections[baseID]; exists {
				localConn.conn.Close()
			}
			c.connMutex.RUnlock()

			c.connMutex.Lock()
			existingInfo.MarkForRemoval()
			c.connMutex.Unlock()
		}
	}

	// Detect if this is likely HTTP traffic
	isHTTP := common.IsHTTPTraffic(destAddr)
	if isHTTP {
		c.logger.Printf("HTTP traffic detected for connection %s", versionedID.String())
	}

	// Connect to local service
	localConn, err := net.Dial("tcp", destAddr)
	if err != nil {
		c.logger.Printf("Error connecting to local service %s: %v", destAddr, err)
		c.sendCloseMessage(versionedID, forwardID)
		return
	}

	c.logger.Printf("Connected to local service %s for connection %s", destAddr, versionedID.String())

	// Choose buffer size and timeout based on HTTP detection
	var buffer []byte
	var idleTimeout time.Duration

	// If HTTP, use larger buffer and longer idle timeout
	if isHTTP {
		buffer = make([]byte, c.config.BufferSizeHTTP) // Larger buffer for HTTP
		idleTimeout = time.Duration(c.config.IdleTimeoutHTTP) * time.Second
	} else {
		// Get buffer from pool
		buffer = c.bufferPool.Get().([]byte)
		idleTimeout = time.Duration(c.config.IdleTimeout) * time.Second
	}

	// Create local connection
	conn := &LocalConnection{
		ID:              baseID,
		conn:            localConn,
		client:          c,
		destinationAddr: destAddr,
		forwardID:       forwardID,
		buffer:          buffer,
	}

	// Create connection info
	info := common.NewConnectionInfo(baseID, isHTTP)
	info.VersionedID = versionedID // Use the server-provided version

	// Register the connection
	c.connMutex.Lock()
	c.connections[baseID] = conn
	c.connInfo[baseID] = info
	c.connMutex.Unlock()

	// Set initial read deadline
	localConn.SetReadDeadline(time.Now().Add(idleTimeout))

	// Read data from the local connection and forward it to the server
	for {
		n, err := localConn.Read(conn.buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Just a timeout, reset deadline and continue for HTTP connections
				if isHTTP {
					c.logger.Printf("HTTP connection %s idle, extending timeout", versionedID.String())
					localConn.SetReadDeadline(time.Now().Add(idleTimeout))
					continue
				}
			}

			if err != io.EOF {
				c.logger.Printf("Error reading from local connection %s: %v", versionedID.String(), err)
			} else {
				c.logger.Printf("Local connection %s closed by local service", versionedID.String())
			}
			break
		}

		// Reset deadline after successful read
		localConn.SetReadDeadline(time.Now().Add(idleTimeout))

		// Update last activity
		c.connMutex.Lock()
		if info, exists := c.connInfo[baseID]; exists {
			info.LastActivity = time.Now()
		}
		c.connMutex.Unlock()

		// Send data to server
		dataMsg := common.CreateDataMessage(versionedID, forwardID, conn.buffer[:n])

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
	// Mark for removal with grace period
	if info, exists := c.connInfo[baseID]; exists {
		info.MarkForRemoval()
	}
	c.connMutex.Unlock()

	c.logger.Printf("Local connection %s marked for removal", versionedID.String())

	// For HTTP connections, delay the close message to allow time for any in-flight data
	if isHTTP {
		c.logger.Printf("HTTP connection %s - delaying close message by 100ms", versionedID.String())
		time.Sleep(time.Duration(common.HTTPCloseDelay) * time.Millisecond)
	}

	// Notify server that connection is closed
	c.sendCloseMessage(versionedID, forwardID)
}

// sendCloseMessage sends a close message to the server
func (c *Client) sendCloseMessage(connID *common.VersionedID, forwardID string) {
	c.logger.Printf("Sending close message for connection %s", connID.String())

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
