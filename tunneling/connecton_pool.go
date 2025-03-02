package main

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

// ConnectionPool manages a pool of reusable connections
type ConnectionPool struct {
	available   map[string][]*PooledConnection
	inUse       map[string]*PooledConnection
	maxPerDest  int
	idleTimeout time.Duration
	mutex       sync.Mutex
	logger      *log.Logger
}

// PooledConnection represents a connection in the pool
type PooledConnection struct {
	Conn     net.Conn
	DestAddr string
	LastUsed time.Time
	ID       string
}

// NewConnectionPool creates a new connection pool
func NewConnectionPool(maxPerDest int, idleTimeout time.Duration, logger *log.Logger) *ConnectionPool {
	pool := &ConnectionPool{
		available:   make(map[string][]*PooledConnection),
		inUse:       make(map[string]*PooledConnection),
		maxPerDest:  maxPerDest,
		idleTimeout: idleTimeout,
		logger:      logger,
	}

	// Start a goroutine to clean up idle connections
	go func() {
		ticker := time.NewTicker(idleTimeout / 2)
		for range ticker.C {
			pool.CleanupIdleConnections()
		}
	}()

	return pool
}

// GetConnection gets a connection from the pool or creates a new one
func (p *ConnectionPool) GetConnection(destAddr string) (net.Conn, string, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	// Check if we have an available connection
	if connections, ok := p.available[destAddr]; ok && len(connections) > 0 {
		// Get the most recently used connection (last in slice)
		conn := connections[len(connections)-1]
		p.available[destAddr] = connections[:len(connections)-1]

		// Check if the connection is still valid
		if time.Since(conn.LastUsed) > p.idleTimeout {
			// Connection is too old, close it and create a new one
			conn.Conn.Close()
			p.logger.Printf("Closing stale connection to %s", destAddr)
		} else {
			// Connection is still good, reuse it
			p.inUse[conn.ID] = conn
			p.logger.Printf("Reusing existing connection to %s", destAddr)
			return conn.Conn, conn.ID, nil
		}
	}

	// Create a new connection
	newConn, err := net.Dial("tcp", destAddr)
	if err != nil {
		return nil, "", err
	}

	// Generate a unique ID
	id := fmt.Sprintf("conn-%s-%d", destAddr, time.Now().UnixNano())

	// Add to in-use map
	p.inUse[id] = &PooledConnection{
		Conn:     newConn,
		DestAddr: destAddr,
		LastUsed: time.Now(),
		ID:       id,
	}

	p.logger.Printf("Created new connection to %s", destAddr)
	return newConn, id, nil
}

// ReleaseConnection returns a connection to the pool
func (p *ConnectionPool) ReleaseConnection(id string, close bool) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	conn, exists := p.inUse[id]
	if !exists {
		return
	}

	delete(p.inUse, id)

	if close {
		conn.Conn.Close()
		p.logger.Printf("Closed connection to %s", conn.DestAddr)
		return
	}

	// Update last used time
	conn.LastUsed = time.Now()

	// Check if we already have max connections for this destination
	if conns, ok := p.available[conn.DestAddr]; ok && len(conns) >= p.maxPerDest {
		// Too many connections, close this one
		conn.Conn.Close()
		p.logger.Printf("Closed excess connection to %s", conn.DestAddr)
		return
	}

	// Add to available pool
	if _, ok := p.available[conn.DestAddr]; !ok {
		p.available[conn.DestAddr] = make([]*PooledConnection, 0)
	}
	p.available[conn.DestAddr] = append(p.available[conn.DestAddr], conn)
	p.logger.Printf("Returned connection to %s to pool", conn.DestAddr)
}

// CleanupIdleConnections removes idle connections from the pool
func (p *ConnectionPool) CleanupIdleConnections() {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	for destAddr, conns := range p.available {
		var activeConns []*PooledConnection

		for _, conn := range conns {
			if time.Since(conn.LastUsed) > p.idleTimeout {
				conn.Conn.Close()
				p.logger.Printf("Removed idle connection to %s", destAddr)
			} else {
				activeConns = append(activeConns, conn)
			}
		}

		if len(activeConns) == 0 {
			delete(p.available, destAddr)
		} else {
			p.available[destAddr] = activeConns
		}
	}
}
