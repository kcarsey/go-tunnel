package common

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Configurable constants
const (
	// Default buffer sizes in bytes
	DefaultReadBufferSize  = 32768
	DefaultWriteBufferSize = 32768

	// Default timeout values in seconds
	DefaultAuthTimeout        = 300 // 5 minutes
	DefaultHandshakeTimeout   = 45
	DefaultReadTimeout        = 60
	DefaultHeartbeatInterval  = 15
	DefaultHeartbeatTimeout   = 45
	DefaultIdleTimeoutHTTP    = 15
	DefaultIdleTimeoutGeneral = 5

	// Buffer sizes
	DefaultBufferSize     = 32 * 1024
	DefaultBufferSizeHTTP = 64 * 1024

	// Default reconnection settings
	DefaultMaxReconnectAttempts = 10
	DefaultReconnectDelay       = 5

	// Grace period for connection cleanup (milliseconds)
	// Set to accommodate high-latency environments (75-200ms)
	DefaultConnectionGracePeriod = 500

	// Connection close delay for HTTP in milliseconds
	HTTPCloseDelay = 100

	// Nonce length for authentication
	DefaultNonceLength = 16
)

// ConnectionState represents the state of a tunneled connection
type ConnectionState int

const (
	// ConnectionStateActive indicates the connection is active and ready for data
	ConnectionStateActive ConnectionState = iota

	// ConnectionStateClosing indicates the connection is in the process of closing
	ConnectionStateClosing

	// ConnectionStateClosed indicates the connection is closed and can be removed
	ConnectionStateClosed
)

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

// Global connection version counter
var globalVersionCounter uint64 = 0

// GetNextVersion returns the next global connection version number
func GetNextVersion() uint64 {
	return atomic.AddUint64(&globalVersionCounter, 1)
}

// VersionedID represents a connection ID with a version to prevent race conditions
type VersionedID struct {
	BaseID  string
	Version uint64
}

// String returns the string representation of the versioned ID
func (vid *VersionedID) String() string {
	return fmt.Sprintf("%s:v%d", vid.BaseID, vid.Version)
}

// ParseVersionedID parses a string into a VersionedID
func ParseVersionedID(idStr string) *VersionedID {
	parts := strings.Split(idStr, ":v")
	if len(parts) != 2 {
		// If no version is found, treat it as version 0
		return &VersionedID{
			BaseID:  idStr,
			Version: 0,
		}
	}

	var version uint64
	fmt.Sscanf(parts[1], "%d", &version)
	return &VersionedID{
		BaseID:  parts[0],
		Version: version,
	}
}

// AuthResponse structure for parsing server response
type AuthResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// AuthRequest structure for client authentication
type AuthRequest struct {
	ClientID   string `json:"client_id"`
	Timestamp  int64  `json:"timestamp"`
	Nonce      string `json:"nonce"`
	HMACDigest string `json:"hmac"`
}

// NonceCache tracks used nonces to prevent replay attacks
type NonceCache struct {
	nonces    map[string]time.Time
	expiry    time.Duration
	lastClean time.Time
	mutex     *sync.Mutex
}

// NewNonceCache creates a new nonce cache with the specified expiry time
func NewNonceCache(expiry time.Duration) *NonceCache {
	return &NonceCache{
		nonces:    make(map[string]time.Time),
		expiry:    expiry,
		lastClean: time.Now(),
		mutex:     &sync.Mutex{},
	}
}

// Add adds a nonce to the cache, returns false if it already exists
func (nc *NonceCache) Add(nonce string) bool {
	nc.mutex.Lock()
	defer nc.mutex.Unlock()

	// Clean expired nonces occasionally
	if time.Since(nc.lastClean) > nc.expiry/2 {
		nc.cleanExpired()
	}

	// Check if nonce exists
	if _, exists := nc.nonces[nonce]; exists {
		return false
	}

	// Add nonce
	nc.nonces[nonce] = time.Now()
	return true
}

// cleanExpired removes expired nonces
func (nc *NonceCache) cleanExpired() {
	now := time.Now()
	for nonce, timestamp := range nc.nonces {
		if now.Sub(timestamp) > nc.expiry {
			delete(nc.nonces, nonce)
		}
	}
	nc.lastClean = now
}

// Generate a cryptographically secure random nonce string
func GenerateNonce(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	charsetLength := big.NewInt(int64(len(charset)))

	b := make([]byte, length)
	for i := range b {
		// Generate a random number and use it to select a character from the charset
		n, err := rand.Int(rand.Reader, charsetLength)
		if err != nil {
			// In case of error, use a fallback that's still better than math/rand
			// This shouldn't happen in practice, but it's safer than panicking
			h := sha256.New()
			h.Write([]byte(fmt.Sprintf("%d-%d", time.Now().UnixNano(), i)))
			digest := h.Sum(nil)
			b[i] = charset[int(digest[0])%len(charset)]
		} else {
			b[i] = charset[n.Int64()]
		}
	}
	return string(b)
}

// CreateAuthMessage creates an authentication message with HMAC
func CreateAuthMessage(clientID string, accessKey string) []byte {
	timestamp := time.Now().Unix()
	nonce := GenerateNonce(DefaultNonceLength)

	// Create the message to sign
	message := fmt.Sprintf("%s:%d:%s", clientID, timestamp, nonce)

	// Create HMAC
	h := hmac.New(sha256.New, []byte(accessKey))
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

// ParseAuthResponse parses the authentication response
func ParseAuthResponse(data []byte) (AuthResponse, error) {
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

// DeserializeAuthRequest parses an auth request from binary format
func DeserializeAuthRequest(data []byte) (AuthRequest, error) {
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

// SerializeAuthResponse converts an auth response to binary format
func SerializeAuthResponse(resp AuthResponse) []byte {
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

// CreateNewConnMessage creates a message for a new connection request
// Now includes version information in the connection ID
func CreateNewConnMessage(connID *VersionedID, forwardID, destAddr string) []byte {
	// Format: [type][conn ID len][conn ID][forward ID len][forward ID][dest addr len][dest addr]
	connIDString := connID.String()
	connIDBytes := []byte(connIDString)
	forwardIDBytes := []byte(forwardID)
	destAddrBytes := []byte(destAddr)

	msgSize := 1 + 4 + len(connIDBytes) + 4 + len(forwardIDBytes) + 4 + len(destAddrBytes)
	buf := bytes.NewBuffer(make([]byte, 0, msgSize))

	buf.WriteByte(MessageTypeNewConn)
	binary.Write(buf, binary.BigEndian, uint32(len(connIDBytes)))
	buf.Write(connIDBytes)
	binary.Write(buf, binary.BigEndian, uint32(len(forwardIDBytes)))
	buf.Write(forwardIDBytes)
	binary.Write(buf, binary.BigEndian, uint32(len(destAddrBytes)))
	buf.Write(destAddrBytes)

	return buf.Bytes()
}

// CreateDataMessage creates a data message
// Uses versioned connection ID
func CreateDataMessage(connID *VersionedID, forwardID string, data []byte) []byte {
	// Format: [type][conn ID len][conn ID][forward ID len][forward ID][data len][data]
	connIDString := connID.String()
	connIDBytes := []byte(connIDString)
	forwardIDBytes := []byte(forwardID)

	dataSize := 1 + 4 + len(connIDBytes) + 4 + len(forwardIDBytes) + 4 + len(data)
	dataBuf := bytes.NewBuffer(make([]byte, 0, dataSize))

	dataBuf.WriteByte(MessageTypeData)
	binary.Write(dataBuf, binary.BigEndian, uint32(len(connIDBytes)))
	dataBuf.Write(connIDBytes)
	binary.Write(dataBuf, binary.BigEndian, uint32(len(forwardIDBytes)))
	dataBuf.Write(forwardIDBytes)
	binary.Write(dataBuf, binary.BigEndian, uint32(len(data)))
	dataBuf.Write(data)

	return dataBuf.Bytes()
}

// CreateCloseMessage creates a close message
// Uses versioned connection ID
func CreateCloseMessage(connID *VersionedID, forwardID string) []byte {
	// Format: [type][conn ID len][conn ID][forward ID len][forward ID]
	connIDString := connID.String()
	connIDBytes := []byte(connIDString)
	forwardIDBytes := []byte(forwardID)

	buf := bytes.NewBuffer(make([]byte, 0, 1+4+len(connIDBytes)+4+len(forwardIDBytes)))

	buf.WriteByte(MessageTypeClose)
	binary.Write(buf, binary.BigEndian, uint32(len(connIDBytes)))
	buf.Write(connIDBytes)
	binary.Write(buf, binary.BigEndian, uint32(len(forwardIDBytes)))
	buf.Write(forwardIDBytes)

	return buf.Bytes()
}

// CreatePingMessage creates a ping message
func CreatePingMessage() []byte {
	return []byte{MessageTypePing}
}

// CreatePongMessage creates a pong message
func CreatePongMessage() []byte {
	return []byte{MessageTypePong}
}

// ValidateHMAC validates the HMAC signature
func ValidateHMAC(clientID string, timestamp int64, nonce string, signature string, accessKey string, maxAge int64, nonceCache *NonceCache) (bool, string) {
	// Check if timestamp is within acceptable window
	now := time.Now().Unix()
	if now-timestamp > maxAge {
		return false, fmt.Sprintf("timestamp too old (%d seconds)", now-timestamp)
	}

	// Check for nonce reuse if cache is provided
	if nonceCache != nil {
		if !nonceCache.Add(nonce) {
			return false, "nonce has been used before"
		}
	}

	// Recreate the message
	message := fmt.Sprintf("%s:%d:%s", clientID, timestamp, nonce)

	// Create HMAC
	h := hmac.New(sha256.New, []byte(accessKey))
	h.Write([]byte(message))
	expectedMAC := base64.StdEncoding.EncodeToString(h.Sum(nil))

	// Constant-time comparison to prevent timing attacks
	if !hmac.Equal([]byte(signature), []byte(expectedMAC)) {
		return false, "invalid signature"
	}

	return true, ""
}

// IsHTTPTraffic determines if a connection is likely HTTP based on the port
func IsHTTPTraffic(address string) bool {
	return strings.HasSuffix(address, ":80") ||
		strings.HasSuffix(address, ":443") ||
		strings.HasSuffix(address, ":8080") ||
		strings.HasSuffix(address, ":8123")
}

// Error handling helper (return errors as strings to simplify code)
func HandleError(err error, msg string) (string, bool) {
	if err != nil {
		errMsg := fmt.Sprintf("%s: %v", msg, err)
		return errMsg, true
	}
	return "", false
}

// ConnectionInfo represents metadata about a connection
type ConnectionInfo struct {
	VersionedID  *VersionedID
	State        ConnectionState
	LastActivity time.Time
	GracePeriod  time.Time // When the connection can be fully removed
	IsHTTP       bool
}

// NewConnectionInfo creates a new connection info struct
func NewConnectionInfo(baseID string, isHTTP bool) *ConnectionInfo {
	return &ConnectionInfo{
		VersionedID:  &VersionedID{BaseID: baseID, Version: GetNextVersion()},
		State:        ConnectionStateActive,
		LastActivity: time.Now(),
		IsHTTP:       isHTTP,
	}
}

// MarkForRemoval marks a connection for removal after the grace period
func (ci *ConnectionInfo) MarkForRemoval() {
	ci.State = ConnectionStateClosing
	ci.GracePeriod = time.Now().Add(time.Duration(DefaultConnectionGracePeriod) * time.Millisecond)
}

// ShouldBeRemoved returns true if the connection should be fully removed
func (ci *ConnectionInfo) ShouldBeRemoved() bool {
	return ci.State == ConnectionStateClosing && time.Now().After(ci.GracePeriod)
}
