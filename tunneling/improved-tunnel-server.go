package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"tunneling/common" // our shared package

	"github.com/gorilla/websocket"
	"gopkg.in/yaml.v3"
)

// Config represents the server configuration
type Config struct {
	// Address for the control server to listen on
	ControlAddress string `yaml:"controlAddress"`

	// TLS certificate file path
	CertFile string `yaml:"certFile"`

	// TLS key file path
	KeyFile string `yaml:"keyFile"`

	// List of authorized client keys
	AuthorizedKeys map[string]string `yaml:"authorizedKeys"` // clientID -> accessKey

	// Forwarding configuration
	Forwards []ForwardConfig `yaml:"forwards"`

	// Authentication timeout in seconds
	AuthTimeout int `yaml:"authTimeout"`

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

// ForwardConfig represents a port forwarding configuration
type ForwardConfig struct {
	// Name for this forwarding rule
	Name string `yaml:"name"`

	// Address to listen on (e.g., "0.0.0.0:8080")
	ListenAddress string `yaml:"listenAddress"`

	// Target client ID that will receive forwarded connections
	TargetClient string `yaml:"targetClient"`

	// Destination service on the client side
	DestinationAddress string `yaml:"destinationAddress"`

	// Type of traffic (http, tcp)
	TrafficType string `yaml:"trafficType,omitempty"`
}

// Server represents the tunnel server
type Server struct {
	config        Config
	clients       map[string]*Client
	clientsMutex  sync.RWMutex
	forwards      map[string]*Forward
	forwardsMutex sync.RWMutex
	upgrader      websocket.Upgrader
	// Buffer pool for reusing buffers
	bufferPool sync.Pool
	// Nonce cache for replay protection
	nonceCache *common.NonceCache
	logger     *log.Logger
	// Cleanup ticker for removing connections after grace period
	cleanupTicker *time.Ticker
}

// Client represents a connected client
type Client struct {
	ID     string
	conn   *websocket.Conn
	server *Server
	// Connection tracker now maps baseID to connection
	connTracker map[string]*ForwardedConn
	// Track connection metadata separately
	connInfo     map[string]*common.ConnectionInfo
	connMutex    sync.RWMutex
	lastActivity time.Time
	isActive     bool
	writeMutex   sync.Mutex // Ensure write operations are serialized
	logger       *log.Logger
}

// Forward represents a forwarding listener
type Forward struct {
	config     ForwardConfig
	listener   net.Listener
	server     *Server
	connCount  int
	countMutex sync.Mutex
	isHTTP     bool
	logger     *log.Logger
}

// ForwardedConn represents a forwarded connection
type ForwardedConn struct {
	ID           string // Base ID without version
	conn         net.Conn
	client       *Client
	forwardName  string
	forwardID    string
	lastActivity time.Time
	buffer       []byte
}

// NewServer creates a new tunnel server
func NewServer(configFile string) (*Server, error) {
	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("error reading config: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("error parsing config: %w", err)
	}

	// Set defaults
	if config.AuthTimeout == 0 {
		config.AuthTimeout = common.DefaultAuthTimeout
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
	logger := log.New(os.Stdout, "[SERVER] ", log.LstdFlags)

	// Create nonce cache with expiry equal to auth timeout
	nonceCache := common.NewNonceCache(time.Duration(config.AuthTimeout) * time.Second)

	server := &Server{
		config:   config,
		clients:  make(map[string]*Client),
		forwards: make(map[string]*Forward),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // Allow all connections, we'll authenticate later
			},
			ReadBufferSize:  config.ReadBufferSize,
			WriteBufferSize: config.WriteBufferSize,
			// Add error handling for handshake
			Error: func(w http.ResponseWriter, r *http.Request, status int, reason error) {
				logger.Printf("WebSocket upgrade error: %v, status: %d", reason, status)
			},
		},
		bufferPool: sync.Pool{
			New: func() interface{} {
				return make([]byte, config.BufferSize)
			},
		},
		nonceCache:    nonceCache,
		logger:        logger,
		cleanupTicker: time.NewTicker(100 * time.Millisecond), // Check for expired connections every 100ms
	}

	return server, nil
}

// Start starts the tunnel server
func (s *Server) Start() error {
	// Start connection cleanup routine
	go s.startConnectionCleanup()

	// Set up the control server
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", s.handleControlConnection)

	// Start forwarding listeners
	for _, forwardConfig := range s.config.Forwards {
		if err := s.startForward(forwardConfig); err != nil {
			return err
		}
	}

	// Start the control server with TLS if certificates are provided
	s.logger.Printf("Starting tunnel server...")
	if s.config.CertFile != "" && s.config.KeyFile != "" {
		s.logger.Printf("Starting control server with TLS on %s", s.config.ControlAddress)
		return http.ListenAndServeTLS(s.config.ControlAddress, s.config.CertFile, s.config.KeyFile, mux)
	}

	s.logger.Printf("Starting control server without TLS on %s", s.config.ControlAddress)
	s.logger.Printf("WARNING: Running without TLS is not recommended for production")
	return http.ListenAndServe(s.config.ControlAddress, mux)
}

// startConnectionCleanup periodically checks for connections that should be removed
func (s *Server) startConnectionCleanup() {
	for {
		select {
		case <-s.cleanupTicker.C:
			s.cleanupConnections()
		}
	}
}

// cleanupConnections checks all clients for connections that should be removed
func (s *Server) cleanupConnections() {
	s.clientsMutex.RLock()
	clients := make([]*Client, 0, len(s.clients))
	for _, client := range s.clients {
		clients = append(clients, client)
	}
	s.clientsMutex.RUnlock()

	// Check each client for connections to clean up
	for _, client := range clients {
		client.cleanupConnections()
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
		if conn, exists := c.connTracker[baseID]; exists {
			if info, infoExists := c.connInfo[baseID]; infoExists && !info.IsHTTP {
				if conn.buffer != nil {
					c.server.bufferPool.Put(conn.buffer)
					c.logger.Printf("Connection %s fully removed, buffer returned to pool",
						info.VersionedID.String())
				}
			}
			delete(c.connTracker, baseID)
		}
		delete(c.connInfo, baseID)
		c.logger.Printf("Connection %s fully removed after grace period", baseID)
	}
}

// startForward starts a forwarding listener
func (s *Server) startForward(config ForwardConfig) error {
	listener, err := net.Listen("tcp", config.ListenAddress)
	if err != nil {
		return fmt.Errorf("failed to start listener for %s on %s: %w", config.Name, config.ListenAddress, err)
	}

	// Detect if this is HTTP traffic
	isHTTP := false
	if config.TrafficType == "http" || common.IsHTTPTraffic(config.ListenAddress) {
		isHTTP = true
		s.logger.Printf("HTTP traffic detected for forward %s", config.Name)
	}

	// Create a logger for this forward
	forwardLogger := log.New(os.Stdout, fmt.Sprintf("[FWD:%s] ", config.Name), log.LstdFlags)

	forward := &Forward{
		config:   config,
		listener: listener,
		server:   s,
		isHTTP:   isHTTP,
		logger:   forwardLogger,
	}

	s.forwardsMutex.Lock()
	s.forwards[config.Name] = forward
	s.forwardsMutex.Unlock()

	s.logger.Printf("Started forwarding listener %s on %s for client %s",
		config.Name, config.ListenAddress, config.TargetClient)

	// Accept connections in a goroutine
	go forward.acceptConnections()

	return nil
}

// acceptConnections accepts connections on a forwarding listener
func (f *Forward) acceptConnections() {
	for {
		conn, err := f.listener.Accept()
		if err != nil {
			f.logger.Printf("Error accepting connection on %s: %v", f.config.ListenAddress, err)
			if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			break
		}

		f.logger.Printf("Accepted new connection on %s", f.config.ListenAddress)
		// Handle the connection in a goroutine
		go f.handleConnection(conn)
	}
}

// handleConnection handles a new connection to a forwarding listener
func (f *Forward) handleConnection(conn net.Conn) {
	f.countMutex.Lock()
	f.connCount++
	connID := fmt.Sprintf("%s-%d", f.config.Name, f.connCount)
	f.countMutex.Unlock()

	f.logger.Printf("New connection %s on forwarding listener %s", connID, f.config.Name)

	// Find the target client
	f.server.clientsMutex.RLock()
	client, exists := f.server.clients[f.config.TargetClient]
	f.server.clientsMutex.RUnlock()

	if !exists || !client.isActive {
		f.logger.Printf("Target client %s not connected, closing connection %s", f.config.TargetClient, connID)
		conn.Close()
		return
	}

	// Choose buffer based on connection type
	var buffer []byte
	var idleTimeout time.Duration

	if f.isHTTP {
		buffer = make([]byte, f.server.config.BufferSizeHTTP) // Larger buffer for HTTP
		idleTimeout = time.Duration(f.server.config.IdleTimeoutHTTP) * time.Second
	} else {
		buffer = f.server.bufferPool.Get().([]byte)
		idleTimeout = time.Duration(f.server.config.IdleTimeout) * time.Second
	}

	// Create a connection info with versioned ID
	connInfo := common.NewConnectionInfo(connID, f.isHTTP)
	versionedID := connInfo.VersionedID

	// Create a forwarded connection
	forwarded := &ForwardedConn{
		ID:           connID,
		conn:         conn,
		client:       client,
		forwardName:  f.config.Name,
		forwardID:    f.config.Name,
		lastActivity: time.Now(),
		buffer:       buffer,
	}

	// Register the connection with the client
	client.connMutex.Lock()
	client.connTracker[connID] = forwarded
	client.connInfo[connID] = connInfo
	client.connMutex.Unlock()

	f.logger.Printf("Registered connection %s with client %s", versionedID.String(), client.ID)

	// Notify the client about the new connection
	newConnMsg := common.CreateNewConnMessage(versionedID, f.config.Name, f.config.DestinationAddress)

	// Send the message
	client.writeMutex.Lock()
	err := client.conn.WriteMessage(websocket.BinaryMessage, newConnMsg)
	client.writeMutex.Unlock()

	if err != nil {
		f.logger.Printf("Error sending new connection message to client %s for connection %s: %v",
			client.ID, versionedID.String(), err)
		conn.Close()

		client.connMutex.Lock()
		// Mark for removal
		if info, exists := client.connInfo[connID]; exists {
			info.MarkForRemoval()
			f.logger.Printf("Marked connection %s for removal", versionedID.String())
		}
		client.connMutex.Unlock()
		return
	}

	f.logger.Printf("Sent new connection notification to client %s for connection %s",
		client.ID, versionedID.String())

	// Set initial timeout
	conn.SetReadDeadline(time.Now().Add(idleTimeout))

	// Read data from the connection and forward it to the client
	for {
		n, err := conn.Read(forwarded.buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Just a timeout, reset deadline and continue for HTTP connections
				if f.isHTTP {
					f.logger.Printf("HTTP connection %s idle, extending timeout", versionedID.String())
					conn.SetReadDeadline(time.Now().Add(idleTimeout))
					continue
				}
			}

			if err != io.EOF {
				f.logger.Printf("Error reading from connection %s: %v", versionedID.String(), err)
			} else {
				f.logger.Printf("Connection %s closed by remote end", versionedID.String())
			}
			break
		}

		// Reset deadline after successful read
		conn.SetReadDeadline(time.Now().Add(idleTimeout))

		// Update last activity
		client.connMutex.Lock()
		if info, exists := client.connInfo[connID]; exists {
			info.LastActivity = time.Now()
		}
		client.connMutex.Unlock()

		// Send data to client
		dataMsg := common.CreateDataMessage(versionedID, f.config.Name, forwarded.buffer[:n])

		client.writeMutex.Lock()
		err = client.conn.WriteMessage(websocket.BinaryMessage, dataMsg)
		client.writeMutex.Unlock()

		if err != nil {
			f.logger.Printf("Error sending data to client %s for connection %s: %v",
				client.ID, versionedID.String(), err)
			break
		}
	}

	// Clean up
	conn.Close()

	client.connMutex.Lock()
	// Mark for removal with grace period
	if info, exists := client.connInfo[connID]; exists {
		info.MarkForRemoval()
		f.logger.Printf("Marked connection %s for removal", versionedID.String())
	}
	client.connMutex.Unlock()

	// For HTTP connections, delay the close message to allow time for any in-flight data
	if f.isHTTP {
		f.logger.Printf("HTTP connection %s - delaying close message by 100ms", versionedID.String())
		time.Sleep(time.Duration(common.HTTPCloseDelay) * time.Millisecond)
	}

	// Notify client that connection is closed
	closeMsg := common.CreateCloseMessage(versionedID, f.config.Name)

	client.writeMutex.Lock()
	client.conn.WriteMessage(websocket.BinaryMessage, closeMsg) // Ignore error as client might be gone
	client.writeMutex.Unlock()

	f.logger.Printf("Sent close notification to client %s for connection %s", client.ID, versionedID.String())
}

// handleControlConnection handles a WebSocket control connection
func (s *Server) handleControlConnection(w http.ResponseWriter, r *http.Request) {
	s.logger.Printf("New connection from %s, upgrading to WebSocket", r.RemoteAddr)

	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.logger.Printf("Error upgrading connection from %s: %v", r.RemoteAddr, err)
		return
	}

	// Enable keep-alive with pong handler
	readTimeout := time.Duration(s.config.ReadTimeout) * time.Second
	conn.SetReadDeadline(time.Now().Add(readTimeout))
	conn.SetPongHandler(func(string) error {
		s.logger.Printf("Received pong from client at %s", r.RemoteAddr)
		conn.SetReadDeadline(time.Now().Add(readTimeout))
		return nil
	})

	defer func() {
		s.logger.Printf("Closing WebSocket connection from %s", r.RemoteAddr)
		conn.Close()
	}()

	// Set a deadline for authentication
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	// Wait for authentication
	s.logger.Printf("Waiting for authentication from %s", r.RemoteAddr)
	_, msgBytes, err := conn.ReadMessage()
	if err != nil {
		s.logger.Printf("Error reading auth message from %s: %v", r.RemoteAddr, err)
		return
	}

	// First byte should be the message type
	if len(msgBytes) == 0 || msgBytes[0] != common.MessageTypeAuth {
		s.logger.Printf("Expected auth message from %s, got type %d", r.RemoteAddr, msgBytes[0])
		resp := common.AuthResponse{Success: false, Message: "Authentication required"}
		respBytes := common.SerializeAuthResponse(resp)
		conn.WriteMessage(websocket.BinaryMessage, respBytes)
		return
	}

	// Parse auth request
	authReq, err := common.DeserializeAuthRequest(msgBytes[1:])
	if err != nil {
		s.logger.Printf("Error parsing auth request from %s: %v", r.RemoteAddr, err)
		return
	}

	s.logger.Printf("Received authentication request from client %s at %s",
		authReq.ClientID, r.RemoteAddr)

	// Check if client ID exists
	accessKey, exists := s.config.AuthorizedKeys[authReq.ClientID]
	if !exists {
		s.logger.Printf("Unknown client ID from %s: %s", r.RemoteAddr, authReq.ClientID)
		resp := common.AuthResponse{Success: false, Message: "Unknown client ID"}
		respBytes := common.SerializeAuthResponse(resp)
		conn.WriteMessage(websocket.BinaryMessage, respBytes)
		return
	}

	// Validate HMAC
	valid, msg := common.ValidateHMAC(
		authReq.ClientID,
		authReq.Timestamp,
		authReq.Nonce,
		authReq.HMACDigest,
		accessKey,
		int64(s.config.AuthTimeout),
		s.nonceCache,
	)

	if !valid {
		s.logger.Printf("Invalid authentication from client %s at %s: %s", authReq.ClientID, r.RemoteAddr, msg)
		resp := common.AuthResponse{Success: false, Message: fmt.Sprintf("Invalid authentication: %s", msg)}
		respBytes := common.SerializeAuthResponse(resp)
		conn.WriteMessage(websocket.BinaryMessage, respBytes)
		return
	}

	// Remove the authentication deadline
	conn.SetReadDeadline(time.Time{})

	// Create client
	clientLogger := log.New(os.Stdout, fmt.Sprintf("[CLIENT:%s] ", authReq.ClientID), log.LstdFlags)

	client := &Client{
		ID:           authReq.ClientID,
		conn:         conn,
		server:       s,
		connTracker:  make(map[string]*ForwardedConn),
		connInfo:     make(map[string]*common.ConnectionInfo),
		isActive:     true,
		lastActivity: time.Now(),
		logger:       clientLogger,
	}

	// Register the client
	s.clientsMutex.Lock()
	if existing, exists := s.clients[client.ID]; exists {
		// Close existing connection
		s.logger.Printf("Client %s already connected, closing previous connection", client.ID)
		existing.conn.Close()
		existing.isActive = false
	}
	s.clients[client.ID] = client
	s.clientsMutex.Unlock()

	s.logger.Printf("Client %s connected and authenticated from %s", client.ID, r.RemoteAddr)

	// Send auth success
	s.logger.Printf("Sending authentication success response to client %s", client.ID)
	resp := common.AuthResponse{Success: true, Message: "Authentication successful"}
	respBytes := common.SerializeAuthResponse(resp)

	client.writeMutex.Lock()
	err = conn.WriteMessage(websocket.BinaryMessage, respBytes)
	client.writeMutex.Unlock()

	if err != nil {
		s.logger.Printf("Error sending auth success to %s: %v", client.ID, err)
		return
	}

	s.logger.Printf("Starting message handler and heartbeat for client %s", client.ID)

	// Use a WaitGroup to ensure proper shutdown coordination
	var wg sync.WaitGroup
	clientDone := make(chan struct{})

	// Handle messages from client
	wg.Add(1)
	go func() {
		defer wg.Done()
		client.handleMessages(clientDone)
	}()

	// Start heartbeat
	wg.Add(1)
	go func() {
		defer wg.Done()
		client.startHeartbeat(clientDone)
	}()

	// Wait for client to disconnect
	wg.Wait()
}

// handleMessages handles incoming messages from a client
func (c *Client) handleMessages(done chan struct{}) {
	defer func() {
		c.server.clientsMutex.Lock()
		delete(c.server.clients, c.ID)
		c.server.clientsMutex.Unlock()

		c.isActive = false

		// Mark all connections for removal
		c.connMutex.Lock()
		for baseID, info := range c.connInfo {
			info.MarkForRemoval()
		}
		c.connMutex.Unlock()

		c.logger.Printf("Client %s message handler exited", c.ID)
		close(done)
	}()

	for {
		// Read message using binary protocol
		msgType, msgBytes, err := c.conn.ReadMessage()
		if err != nil {
			c.logger.Printf("Error reading message from client %s: %v", c.ID, err)
			break
		}

		c.lastActivity = time.Now()

		// Handle control messages (ping, pong, close)
		if msgType == websocket.PingMessage {
			c.logger.Printf("Received WebSocket ping from client %s, responding with pong", c.ID)
			c.writeMutex.Lock()
			c.conn.WriteMessage(websocket.PongMessage, nil)
			c.writeMutex.Unlock()
			continue
		} else if msgType == websocket.PongMessage {
			c.logger.Printf("Received WebSocket pong from client %s", c.ID)
			continue
		} else if msgType == websocket.CloseMessage {
			c.logger.Printf("Received close frame from client %s", c.ID)
			return
		} else if msgType != websocket.BinaryMessage {
			c.logger.Printf("Received unexpected WebSocket message type from client %s: %d", c.ID, msgType)
			continue
		}

		if len(msgBytes) == 0 {
			c.logger.Printf("Received empty message from client %s", c.ID)
			continue
		}

		// Handle based on message type
		messageType := msgBytes[0]
		payload := msgBytes[1:]

		switch messageType {
		case common.MessageTypeData:
			c.handleDataMessage(payload)
		case common.MessageTypeClose:
			c.handleCloseMessage(payload)
		case common.MessageTypePing:
			c.handlePingMessage()
		case common.MessageTypePong:
			c.logger.Printf("Received application-level pong from client %s", c.ID)
		default:
			c.logger.Printf("Received unknown message type from client %s: %d", c.ID, messageType)
		}
	}
}

// handleDataMessage processes data messages from clients
func (c *Client) handleDataMessage(payload []byte) {
	// Parse data message
	// Format: [conn ID len][conn ID][forward ID len][forward ID][data len][data]
	buf := bytes.NewBuffer(payload)

	var connIDLen uint32
	err := binary.Read(buf, binary.BigEndian, &connIDLen)
	if err != nil {
		c.logger.Printf("Error reading conn ID length from client %s: %v", c.ID, err)
		return
	}

	connIDBytes := make([]byte, connIDLen)
	_, err = buf.Read(connIDBytes)
	if err != nil {
		c.logger.Printf("Error reading conn ID from client %s: %v", c.ID, err)
		return
	}
	connIDStr := string(connIDBytes)

	// Parse versioned connection ID
	versionedID := common.ParseVersionedID(connIDStr)
	baseID := versionedID.BaseID

	var forwardIDLen uint32
	err = binary.Read(buf, binary.BigEndian, &forwardIDLen)
	if err != nil {
		c.logger.Printf("Error reading forward ID length from client %s: %v", c.ID, err)
		return
	}

	forwardIDBytes := make([]byte, forwardIDLen)
	_, err = buf.Read(forwardIDBytes)
	if err != nil {
		c.logger.Printf("Error reading forward ID from client %s: %v", c.ID, err)
		return
	}
	forwardID := string(forwardIDBytes)

	var dataLen uint32
	err = binary.Read(buf, binary.BigEndian, &dataLen)
	if err != nil {
		c.logger.Printf("Error reading data length from client %s: %v", c.ID, err)
		return
	}

	data := make([]byte, dataLen)
	_, err = buf.Read(data)
	if err != nil {
		c.logger.Printf("Error reading data from client %s: %v", c.ID, err)
		return
	}

	// Find connection and check versions
	c.connMutex.RLock()
	conn, exists := c.connTracker[baseID]
	info, infoExists := c.connInfo[baseID]
	c.connMutex.RUnlock()

	// Verify connection exists and versions match
	if !exists || !infoExists {
		c.logger.Printf("Connection %s not found for client %s", versionedID.String(), c.ID)
		return
	}

	// Check if connection is closing
	if info.State != common.ConnectionStateActive {
		c.logger.Printf("Connection %s is closing, rejecting data", versionedID.String())
		return
	}

	// Check if versions match
	if info.VersionedID.Version != versionedID.Version {
		c.logger.Printf("Version mismatch for connection %s (have %d, received %d)",
			baseID, info.VersionedID.Version, versionedID.Version)
		// Send close to client with our version
		closeMsg := common.CreateCloseMessage(info.VersionedID, forwardID)
		c.writeMutex.Lock()
		c.conn.WriteMessage(websocket.BinaryMessage, closeMsg)
		c.writeMutex.Unlock()
		return
	}

	// Write data to connection
	_, err = conn.conn.Write(data)
	if err != nil {
		c.logger.Printf("Error writing to connection %s: %v", versionedID.String(), err)
		conn.conn.Close()

		c.connMutex.Lock()
		// Mark for removal with grace period
		info.MarkForRemoval()
		c.connMutex.Unlock()

		// Notify client that connection has been closed on server side
		closeMsg := common.CreateCloseMessage(versionedID, forwardID)
		c.writeMutex.Lock()
		c.conn.WriteMessage(websocket.BinaryMessage, closeMsg)
		c.writeMutex.Unlock()
	}
}

// handleCloseMessage processes close messages from clients
func (c *Client) handleCloseMessage(payload []byte) {
	// Parse close message
	// Format: [conn ID len][conn ID][forward ID len][forward ID]
	buf := bytes.NewBuffer(payload)

	var connIDLen uint32
	err := binary.Read(buf, binary.BigEndian, &connIDLen)
	if err != nil {
		c.logger.Printf("Error reading conn ID length from client %s: %v", c.ID, err)
		return
	}

	connIDBytes := make([]byte, connIDLen)
	_, err = buf.Read(connIDBytes)
	if err != nil {
		c.logger.Printf("Error reading conn ID from client %s: %v", c.ID, err)
		return
	}
	connIDStr := string(connIDBytes)

	// Parse versioned connection ID
	versionedID := common.ParseVersionedID(connIDStr)
	baseID := versionedID.BaseID

	c.logger.Printf("Received close request for connection %s from client %s", versionedID.String(), c.ID)

	// Find and close connection
	c.connMutex.Lock()
	conn, exists := c.connTracker[baseID]
	info, infoExists := c.connInfo[baseID]

	if exists && infoExists {
		// Only close if versions match
		if info.VersionedID.Version == versionedID.Version {
			conn.conn.Close()

			// Mark for removal with grace period
			info.MarkForRemoval()
			c.logger.Printf("Closed connection %s per client %s request", versionedID.String(), c.ID)
		} else {
			c.logger.Printf("Version mismatch on close for connection %s (have %d, received %d)",
				baseID, info.VersionedID.Version, versionedID.Version)
		}
	}
	c.connMutex.Unlock()
}

// handlePingMessage handles ping messages from clients
func (c *Client) handlePingMessage() {
	c.logger.Printf("Received ping from client %s", c.ID)
	// Respond with pong (simple binary message)
	pongMsg := common.CreatePongMessage()
	c.writeMutex.Lock()
	err := c.conn.WriteMessage(websocket.BinaryMessage, pongMsg)
	c.writeMutex.Unlock()

	if err != nil {
		c.logger.Printf("Error sending pong to client %s: %v", c.ID, err)
	} else {
		c.logger.Printf("Sent pong to client %s", c.ID)
	}
}

// startHeartbeat starts a heartbeat goroutine for the client
func (c *Client) startHeartbeat(done chan struct{}) {
	ticker := time.NewTicker(time.Duration(c.server.config.HeartbeatInterval) * time.Second)
	defer ticker.Stop()

	c.logger.Printf("Started heartbeat for client %s", c.ID)

	for {
		select {
		case <-ticker.C:
			if !c.isActive {
				c.logger.Printf("Client %s is no longer active", c.ID)
				return
			}

			// Check if client is still active
			heartbeatTimeout := time.Duration(c.server.config.HeartbeatTimeout) * time.Second
			if time.Since(c.lastActivity) > heartbeatTimeout {
				c.logger.Printf("Client %s timed out (no activity for >%ds)", c.ID, c.server.config.HeartbeatTimeout)
				c.conn.Close()
				return
			}

			// Send ping using binary protocol
			c.logger.Printf("Sending ping to client %s", c.ID)
			pingMsg := common.CreatePingMessage()

			c.writeMutex.Lock()
			err := c.conn.WriteMessage(websocket.BinaryMessage, pingMsg)
			c.writeMutex.Unlock()

			if err != nil {
				c.logger.Printf("Error sending ping to client %s: %v", c.ID, err)
				c.conn.Close()
				return
			}

		case <-done:
			c.logger.Printf("Heartbeat for client %s stopped due to client disconnection", c.ID)
			return
		}
	}
}

func main() {
	configFile := flag.String("config", "server.yaml", "Path to config file")
	flag.Parse()

	server, err := NewServer(*configFile)
	if err != nil {
		log.Fatalf("Error creating server: %v", err)
	}

	log.Printf("Starting tunnel server...")
	if err := server.Start(); err != nil {
		log.Fatalf("Error starting server: %v", err)
	}
}
