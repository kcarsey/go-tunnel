package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
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
}

// Message types for binary protocol
const (
	MessageTypeAuth         byte = 1
	MessageTypeAuthResponse byte = 2
	MessageTypeNewConn      byte = 3
	MessageTypeData         byte = 4
	MessageTypeClose        byte = 5
	MessageTypePing         byte = 6
	MessageTypePong         byte = 7
)

// Auth request/response structure for JSON interchange
type AuthRequest struct {
	ClientID   string `json:"client_id"`
	Timestamp  int64  `json:"timestamp"`
	Nonce      string `json:"nonce"`
	HMACDigest string `json:"hmac"`
}

type AuthResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
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
}

// Client represents a connected client
type Client struct {
	ID           string
	conn         *websocket.Conn
	server       *Server
	connTracker  map[string]*ForwardedConn
	connMutex    sync.RWMutex
	lastActivity time.Time
	isActive     bool
	writeMutex   sync.Mutex // Ensure write operations are serialized
}

// Forward represents a forwarding listener
type Forward struct {
	config     ForwardConfig
	listener   net.Listener
	server     *Server
	connCount  int
	countMutex sync.Mutex
}

// ForwardedConn represents a forwarded connection
type ForwardedConn struct {
	ID           string
	conn         net.Conn
	client       *Client
	forwardName  string
	forwardID    string
	lastActivity time.Time
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
		config.AuthTimeout = 300 // 5 minutes by default
	}

	server := &Server{
		config:   config,
		clients:  make(map[string]*Client),
		forwards: make(map[string]*Forward),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // Allow all connections, we'll authenticate later
			},
			ReadBufferSize:  32768,
			WriteBufferSize: 32768,
			// Add error handling for handshake
			Error: func(w http.ResponseWriter, r *http.Request, status int, reason error) {
				log.Printf("WebSocket upgrade error: %v, status: %d", reason, status)
			},
		},
		bufferPool: sync.Pool{
			New: func() interface{} {
				return make([]byte, 32*1024)
			},
		},
	}

	return server, nil
}

// Start starts the tunnel server
func (s *Server) Start() error {
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
	if s.config.CertFile != "" && s.config.KeyFile != "" {
		log.Printf("Starting control server with TLS on %s", s.config.ControlAddress)
		return http.ListenAndServeTLS(s.config.ControlAddress, s.config.CertFile, s.config.KeyFile, mux)
	}

	log.Printf("Starting control server without TLS on %s", s.config.ControlAddress)
	log.Printf("WARNING: Running without TLS is not recommended for production")
	return http.ListenAndServe(s.config.ControlAddress, mux)
}

// startForward starts a forwarding listener
func (s *Server) startForward(config ForwardConfig) error {
	listener, err := net.Listen("tcp", config.ListenAddress)
	if err != nil {
		return fmt.Errorf("failed to start listener for %s on %s: %w", config.Name, config.ListenAddress, err)
	}

	forward := &Forward{
		config:   config,
		listener: listener,
		server:   s,
	}

	s.forwardsMutex.Lock()
	s.forwards[config.Name] = forward
	s.forwardsMutex.Unlock()

	log.Printf("Started forwarding listener %s on %s for client %s",
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
			log.Printf("Error accepting connection on %s: %v", f.config.ListenAddress, err)
			if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			break
		}

		log.Printf("Accepted new connection on %s", f.config.ListenAddress)
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

	log.Printf("New connection %s on forwarding listener %s", connID, f.config.Name)

	// Find the target client
	f.server.clientsMutex.RLock()
	client, exists := f.server.clients[f.config.TargetClient]
	f.server.clientsMutex.RUnlock()

	if !exists || !client.isActive {
		log.Printf("Target client %s not connected, closing connection %s", f.config.TargetClient, connID)
		conn.Close()
		return
	}

	// Create a forwarded connection
	forwarded := &ForwardedConn{
		ID:           connID,
		conn:         conn,
		client:       client,
		forwardName:  f.config.Name,
		forwardID:    f.config.Name,
		lastActivity: time.Now(),
	}

	// Register the connection with the client
	client.connMutex.Lock()
	client.connTracker[connID] = forwarded
	client.connMutex.Unlock()

	log.Printf("Registered connection %s with client %s", connID, client.ID)

	// Notify the client about the new connection using binary protocol
	// Format: [type][conn ID len][conn ID][forward ID len][forward ID][dest addr len][dest addr]
	connIDBytes := []byte(connID)
	forwardIDBytes := []byte(f.config.Name)
	destAddrBytes := []byte(f.config.DestinationAddress)

	msgSize := 1 + 4 + len(connIDBytes) + 4 + len(forwardIDBytes) + 4 + len(destAddrBytes)
	buf := bytes.NewBuffer(make([]byte, 0, msgSize))

	buf.WriteByte(MessageTypeNewConn)
	binary.Write(buf, binary.BigEndian, uint32(len(connIDBytes)))
	buf.Write(connIDBytes)
	binary.Write(buf, binary.BigEndian, uint32(len(forwardIDBytes)))
	buf.Write(forwardIDBytes)
	binary.Write(buf, binary.BigEndian, uint32(len(destAddrBytes)))
	buf.Write(destAddrBytes)

	// Send the message
	client.writeMutex.Lock()
	err := client.conn.WriteMessage(websocket.BinaryMessage, buf.Bytes())
	client.writeMutex.Unlock()

	if err != nil {
		log.Printf("Error sending new connection message to client %s for connection %s: %v",
			client.ID, connID, err)
		conn.Close()
		return
	}

	log.Printf("Sent new connection notification to client %s for connection %s", client.ID, connID)

	// Read data from the connection and forward it to the client
	buffer := f.server.bufferPool.Get().([]byte)
	defer f.server.bufferPool.Put(buffer)

	for {
		n, err := conn.Read(buffer)
		if err != nil {
			if err != io.EOF {
				log.Printf("Error reading from connection %s: %v", connID, err)
			} else {
				log.Printf("Connection %s closed by remote end", connID)
			}
			break
		}

		forwarded.lastActivity = time.Now()

		// Send data to client using binary protocol
		// Format: [type][conn ID len][conn ID][forward ID len][forward ID][data len][data]
		dataSize := 1 + 4 + len(connIDBytes) + 4 + len(forwardIDBytes) + 4 + n
		dataBuf := bytes.NewBuffer(make([]byte, 0, dataSize))

		dataBuf.WriteByte(MessageTypeData)
		binary.Write(dataBuf, binary.BigEndian, uint32(len(connIDBytes)))
		dataBuf.Write(connIDBytes)
		binary.Write(dataBuf, binary.BigEndian, uint32(len(forwardIDBytes)))
		dataBuf.Write(forwardIDBytes)
		binary.Write(dataBuf, binary.BigEndian, uint32(n))
		dataBuf.Write(buffer[:n])

		client.writeMutex.Lock()
		err = client.conn.WriteMessage(websocket.BinaryMessage, dataBuf.Bytes())
		client.writeMutex.Unlock()

		if err != nil {
			log.Printf("Error sending data to client %s for connection %s: %v",
				client.ID, connID, err)
			break
		}
	}

	// Clean up
	conn.Close()
	client.connMutex.Lock()
	delete(client.connTracker, connID)
	client.connMutex.Unlock()

	log.Printf("Connection %s closed and cleaned up", connID)

	// Notify client that connection is closed using binary protocol
	// Format: [type][conn ID len][conn ID][forward ID len][forward ID]
	closeBuf := bytes.NewBuffer(make([]byte, 0, 1+4+len(connIDBytes)+4+len(forwardIDBytes)))

	closeBuf.WriteByte(MessageTypeClose)
	binary.Write(closeBuf, binary.BigEndian, uint32(len(connIDBytes)))
	closeBuf.Write(connIDBytes)
	binary.Write(closeBuf, binary.BigEndian, uint32(len(forwardIDBytes)))
	closeBuf.Write(forwardIDBytes)

	client.writeMutex.Lock()
	client.conn.WriteMessage(websocket.BinaryMessage, closeBuf.Bytes()) // Ignore error as client might be gone
	client.writeMutex.Unlock()

	log.Printf("Sent close notification to client %s for connection %s", client.ID, connID)
}

// validateHMAC validates the HMAC signature from the client
func (s *Server) validateHMAC(clientID string, timestamp int64, nonce string, signature string, accessKey string) bool {
	// Check if timestamp is within acceptable window
	now := time.Now().Unix()
	if now-timestamp > int64(s.config.AuthTimeout) {
		log.Printf("Authentication attempt from %s rejected: timestamp too old (%d seconds)",
			clientID, now-timestamp)
		return false
	}

	// Recreate the message
	message := fmt.Sprintf("%s:%d:%s", clientID, timestamp, nonce)

	// Create HMAC
	h := hmac.New(sha256.New, []byte(accessKey))
	h.Write([]byte(message))
	expectedMAC := base64.StdEncoding.EncodeToString(h.Sum(nil))

	// Constant-time comparison to prevent timing attacks
	return hmac.Equal([]byte(signature), []byte(expectedMAC))
}

// handleControlConnection handles a WebSocket control connection
func (s *Server) handleControlConnection(w http.ResponseWriter, r *http.Request) {
	log.Printf("New connection from %s, upgrading to WebSocket", r.RemoteAddr)

	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Error upgrading connection from %s: %v", r.RemoteAddr, err)
		return
	}

	// Enable keep-alive pings with a shorter interval
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetPongHandler(func(string) error {
		log.Printf("Received pong from client at %s", r.RemoteAddr)
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	defer func() {
		log.Printf("Closing WebSocket connection from %s", r.RemoteAddr)
		conn.Close()
	}()

	// Set a deadline for authentication
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	// Wait for authentication (still using JSON for auth to simplify client configuration)
	log.Printf("Waiting for authentication from %s", r.RemoteAddr)
	_, msgBytes, err := conn.ReadMessage()
	if err != nil {
		log.Printf("Error reading auth message from %s: %v", r.RemoteAddr, err)
		return
	}

	// First byte should be the message type
	if len(msgBytes) == 0 || msgBytes[0] != MessageTypeAuth {
		log.Printf("Expected auth message from %s, got type %d", r.RemoteAddr, msgBytes[0])
		resp := AuthResponse{Success: false, Message: "Authentication required"}
		respBytes := serializeAuthResponse(resp)
		conn.WriteMessage(websocket.BinaryMessage, respBytes)
		return
	}

	// Parse auth request
	authReq, err := deserializeAuthRequest(msgBytes[1:])
	if err != nil {
		log.Printf("Error parsing auth request from %s: %v", r.RemoteAddr, err)
		return
	}

	log.Printf("Received authentication request from client %s at %s",
		authReq.ClientID, r.RemoteAddr)

	// Check if client ID exists
	accessKey, exists := s.config.AuthorizedKeys[authReq.ClientID]
	if !exists {
		log.Printf("Unknown client ID from %s: %s", r.RemoteAddr, authReq.ClientID)
		resp := AuthResponse{Success: false, Message: "Unknown client ID"}
		respBytes := serializeAuthResponse(resp)
		conn.WriteMessage(websocket.BinaryMessage, respBytes)
		return
	}

	// Validate HMAC
	if !s.validateHMAC(authReq.ClientID, authReq.Timestamp, authReq.Nonce, authReq.HMACDigest, accessKey) {
		log.Printf("Invalid HMAC from client %s at %s", authReq.ClientID, r.RemoteAddr)
		resp := AuthResponse{Success: false, Message: "Invalid authentication"}
		respBytes := serializeAuthResponse(resp)
		conn.WriteMessage(websocket.BinaryMessage, respBytes)
		return
	}

	// Remove the authentication deadline
	conn.SetReadDeadline(time.Time{})

	// Create client
	client := &Client{
		ID:           authReq.ClientID,
		conn:         conn,
		server:       s,
		connTracker:  make(map[string]*ForwardedConn),
		isActive:     true,
		lastActivity: time.Now(),
	}

	// Register the client
	s.clientsMutex.Lock()
	if existing, exists := s.clients[client.ID]; exists {
		// Close existing connection
		log.Printf("Client %s already connected, closing previous connection", client.ID)
		existing.conn.Close()
		existing.isActive = false
	}
	s.clients[client.ID] = client
	s.clientsMutex.Unlock()

	log.Printf("Client %s connected and authenticated from %s", client.ID, r.RemoteAddr)

	// Send auth success
	log.Printf("Sending authentication success response to client %s", client.ID)
	resp := AuthResponse{Success: true, Message: "Authentication successful"}
	respBytes := serializeAuthResponse(resp)

	client.writeMutex.Lock()
	err = conn.WriteMessage(websocket.BinaryMessage, respBytes)
	client.writeMutex.Unlock()

	if err != nil {
		log.Printf("Error sending auth success to %s: %v", client.ID, err)
		return
	}

	log.Printf("Starting message handler and heartbeat for client %s", client.ID)

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

// Serialize auth response to binary
func serializeAuthResponse(resp AuthResponse) []byte {
	// Format: [type][success flag][message len][message]
	msgBytes := []byte(resp.Message)
	buf := bytes.NewBuffer(make([]byte, 0, 1+1+4+len(msgBytes)))

	buf.WriteByte(MessageTypeAuthResponse)
	if resp.Success {
		buf.WriteByte(1)
	} else {
		buf.WriteByte(0)
	}

	binary.Write(buf, binary.BigEndian, uint32(len(msgBytes)))
	buf.Write(msgBytes)

	return buf.Bytes()
}

// Deserialize auth request from binary
func deserializeAuthRequest(data []byte) (AuthRequest, error) {
	var req AuthRequest
	buf := bytes.NewBuffer(data)

	// Read client ID
	var clientIDLen uint32
	err := binary.Read(buf, binary.BigEndian, &clientIDLen)
	if err != nil {
		return req, err
	}

	clientIDBytes := make([]byte, clientIDLen)
	_, err = buf.Read(clientIDBytes)
	if err != nil {
		return req, err
	}
	req.ClientID = string(clientIDBytes)

	// Read timestamp
	var timestamp uint32
	err = binary.Read(buf, binary.BigEndian, &timestamp)
	if err != nil {
		return req, err
	}
	req.Timestamp = int64(timestamp)

	// Read nonce
	var nonceLen uint32
	err = binary.Read(buf, binary.BigEndian, &nonceLen)
	if err != nil {
		return req, err
	}

	nonceBytes := make([]byte, nonceLen)
	_, err = buf.Read(nonceBytes)
	if err != nil {
		return req, err
	}
	req.Nonce = string(nonceBytes)

	// Read HMAC
	var hmacLen uint32
	err = binary.Read(buf, binary.BigEndian, &hmacLen)
	if err != nil {
		return req, err
	}

	hmacBytes := make([]byte, hmacLen)
	_, err = buf.Read(hmacBytes)
	if err != nil {
		return req, err
	}
	req.HMACDigest = string(hmacBytes)

	return req, nil
}

// handleMessages handles incoming messages from a client
func (c *Client) handleMessages(done chan struct{}) {
	defer func() {
		c.server.clientsMutex.Lock()
		delete(c.server.clients, c.ID)
		c.server.clientsMutex.Unlock()

		c.isActive = false

		// Close all forwarded connections
		c.connMutex.Lock()
		for _, conn := range c.connTracker {
			conn.conn.Close()
		}
		c.connMutex.Unlock()

		log.Printf("Client %s message handler exited", c.ID)
		close(done)
	}()

	for {
		// Read message using binary protocol
		msgType, msgBytes, err := c.conn.ReadMessage()
		if err != nil {
			log.Printf("Error reading message from client %s: %v", c.ID, err)
			break
		}

		c.lastActivity = time.Now()

		// Handle control messages (ping, pong, close)
		if msgType == websocket.PingMessage {
			log.Printf("Received WebSocket ping from client %s, responding with pong", c.ID)
			c.writeMutex.Lock()
			c.conn.WriteMessage(websocket.PongMessage, nil)
			c.writeMutex.Unlock()
			continue
		} else if msgType == websocket.PongMessage {
			log.Printf("Received WebSocket pong from client %s", c.ID)
			continue
		} else if msgType == websocket.CloseMessage {
			log.Printf("Received close frame from client %s", c.ID)
			return
		} else if msgType != websocket.BinaryMessage {
			log.Printf("Received unexpected WebSocket message type from client %s: %d", c.ID, msgType)
			continue
		}

		if len(msgBytes) == 0 {
			log.Printf("Received empty message from client %s", c.ID)
			continue
		}

		// Handle based on message type
		msgType = int(msgBytes[0])
		payload := msgBytes[1:]

		switch msgBytes[0] {
		case MessageTypeData:
			// Parse data message
			// Format: [conn ID len][conn ID][forward ID len][forward ID][data len][data]
			buf := bytes.NewBuffer(payload)

			var connIDLen uint32
			err := binary.Read(buf, binary.BigEndian, &connIDLen)
			if err != nil {
				log.Printf("Error reading conn ID length from client %s: %v", c.ID, err)
				continue
			}

			connIDBytes := make([]byte, connIDLen)
			_, err = buf.Read(connIDBytes)
			if err != nil {
				log.Printf("Error reading conn ID from client %s: %v", c.ID, err)
				continue
			}
			connID := string(connIDBytes)

			var forwardIDLen uint32
			err = binary.Read(buf, binary.BigEndian, &forwardIDLen)
			if err != nil {
				log.Printf("Error reading forward ID length from client %s: %v", c.ID, err)
				continue
			}

			forwardIDBytes := make([]byte, forwardIDLen)
			_, err = buf.Read(forwardIDBytes)
			if err != nil {
				log.Printf("Error reading forward ID from client %s: %v", c.ID, err)
				continue
			}

			var dataLen uint32
			err = binary.Read(buf, binary.BigEndian, &dataLen)
			if err != nil {
				log.Printf("Error reading data length from client %s: %v", c.ID, err)
				continue
			}

			data := make([]byte, dataLen)
			_, err = buf.Read(data)
			if err != nil {
				log.Printf("Error reading data from client %s: %v", c.ID, err)
				continue
			}

			// Find connection
			c.connMutex.RLock()
			conn, exists := c.connTracker[connID]
			c.connMutex.RUnlock()

			if !exists {
				log.Printf("Connection %s not found for client %s", connID, c.ID)
				continue
			}

			// Write data to connection
			_, err = conn.conn.Write(data)
			if err != nil {
				log.Printf("Error writing to connection %s: %v", connID, err)
				conn.conn.Close()

				c.connMutex.Lock()
				delete(c.connTracker, connID)
				c.connMutex.Unlock()
			}

		case MessageTypeClose:
			// Parse close message
			// Format: [conn ID len][conn ID][forward ID len][forward ID]
			buf := bytes.NewBuffer(payload)

			var connIDLen uint32
			err := binary.Read(buf, binary.BigEndian, &connIDLen)
			if err != nil {
				log.Printf("Error reading conn ID length from client %s: %v", c.ID, err)
				continue
			}

			connIDBytes := make([]byte, connIDLen)
			_, err = buf.Read(connIDBytes)
			if err != nil {
				log.Printf("Error reading conn ID from client %s: %v", c.ID, err)
				continue
			}
			connID := string(connIDBytes)

			log.Printf("Received close request for connection %s from client %s", connID, c.ID)

			// Find and close connection
			c.connMutex.RLock()
			conn, exists := c.connTracker[connID]
			c.connMutex.RUnlock()

			if exists {
				conn.conn.Close()

				c.connMutex.Lock()
				delete(c.connTracker, connID)
				c.connMutex.Unlock()

				log.Printf("Closed connection %s per client %s request", connID, c.ID)
			}

		case MessageTypePing:
			log.Printf("Received ping from client %s", c.ID)
			// Respond with pong (simple binary message)
			pongMsg := []byte{MessageTypePong}
			c.writeMutex.Lock()
			err := c.conn.WriteMessage(websocket.BinaryMessage, pongMsg)
			c.writeMutex.Unlock()

			if err != nil {
				log.Printf("Error sending pong to client %s: %v", c.ID, err)
			} else {
				log.Printf("Sent pong to client %s", c.ID)
			}

		case MessageTypePong:
			log.Printf("Received application-level pong from client %s", c.ID)
			// Just update last activity time
			// Already done at the start of the message handler
		}
	}
}

// startHeartbeat starts a heartbeat goroutine for the client
func (c *Client) startHeartbeat(done chan struct{}) {
	ticker := time.NewTicker(15 * time.Second) // More frequent heartbeats
	defer ticker.Stop()

	log.Printf("Started heartbeat for client %s", c.ID)

	for {
		select {
		case <-ticker.C:
			if !c.isActive {
				log.Printf("Client %s is no longer active", c.ID)
				return
			}

			// Check if client is still active
			if time.Since(c.lastActivity) > 45*time.Second {
				log.Printf("Client %s timed out (no activity for >45s)", c.ID)
				c.conn.Close()
				return
			}

			// Send ping using binary protocol
			log.Printf("Sending ping to client %s", c.ID)
			pingMsg := []byte{MessageTypePing}

			c.writeMutex.Lock()
			err := c.conn.WriteMessage(websocket.BinaryMessage, pingMsg)
			c.writeMutex.Unlock()

			if err != nil {
				log.Printf("Error sending ping to client %s: %v", c.ID, err)
				c.conn.Close()
				return
			}

		case <-done:
			log.Printf("Heartbeat for client %s stopped due to client disconnection", c.ID)
			return
		}
	}
}

func main() {
	configFile := flag.String("config", "config.yaml", "Path to config file")
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
