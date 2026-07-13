package distributed

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/aydocs/fang/pkg/models"
)

const heartbeatInterval = 15 * time.Second

type TaskResult struct {
	TaskID   string
	Findings []*models.Finding
}

type Handler func(msg Message)

type conn struct {
	raw net.Conn
	enc *json.Encoder
	dec *json.Decoder
	mu  sync.Mutex
}

func newConn(c net.Conn) *conn {
	return &conn{raw: c, enc: json.NewEncoder(c), dec: json.NewDecoder(bufio.NewReader(c))}
}

func (c *conn) Send(msg Message) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.enc.Encode(msg)
}

func (c *conn) Read() (Message, error) {
	var m Message
	err := c.dec.Decode(&m)
	return m, err
}

func (c *conn) Close() error {
	return c.raw.Close()
}

type Server struct {
	cluster  *Cluster
	listener net.Listener
	conns    map[string]*conn
	handlers []Handler
	mu       sync.Mutex
}

func NewServer(cluster *Cluster) *Server {
	return &Server{cluster: cluster, conns: make(map[string]*conn)}
}

func (s *Server) OnMessage(h Handler) {
	s.handlers = append(s.handlers, h)
}

func (s *Server) Listen(addr string) error {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.listener = l
	go s.acceptLoop()
	return nil
}

func (s *Server) acceptLoop() {
	for {
		c, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.serveConn(newConn(c))
	}
}

func (s *Server) serveConn(c *conn) {
	for {
		msg, err := c.Read()
		if err != nil {
			return
		}
		switch msg.Type {
		case MsgHeartbeat, MsgNodeStatus:
			var n Node
			if json.Unmarshal(msg.Payload, &n) == nil {
				s.cluster.RegisterNode(&n)
				s.mu.Lock()
				s.conns[n.ID] = c
				s.mu.Unlock()
			}
		case MsgTaskResult:
			var res TaskResult
			if json.Unmarshal(msg.Payload, &res) == nil {
				s.cluster.CompleteTask(res.TaskID, res.Findings)
			}
		}
		for _, h := range s.handlers {
			h(msg)
		}
	}
}

func (s *Server) SendTo(nodeID string, msg Message) error {
	s.mu.Lock()
	c, ok := s.conns[nodeID]
	s.mu.Unlock()
	if !ok {
		return fmt.Errorf("no connection to node %s", nodeID)
	}
	return c.Send(msg)
}

func (s *Server) Close() error {
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func (s *Server) Addr() net.Addr {
	if s.listener != nil {
		return s.listener.Addr()
	}
	return nil
}

type Client struct {
	conn     *conn
	cluster  *Cluster
	self     Node
	interval time.Duration
	handlers []Handler
}

func NewClient(cluster *Cluster, self Node) *Client {
	return &Client{cluster: cluster, self: self, interval: heartbeatInterval}
}

func (c *Client) OnMessage(h Handler) {
	c.handlers = append(c.handlers, h)
}

func (c *Client) Connect(addr string) error {
	nc, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	c.conn = newConn(nc)
	go c.loop()
	return nil
}

func (c *Client) loop() {
	c.sendStatus()
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for range ticker.C {
		c.sendHeartbeat()
	}
}

func (c *Client) sendHeartbeat() {
	payload, _ := json.Marshal(c.self)
	_ = c.Send(Message{Type: MsgHeartbeat, From: c.self.ID, Payload: payload, Timestamp: time.Now()})
}

func (c *Client) sendStatus() {
	payload, _ := json.Marshal(c.self)
	_ = c.Send(Message{Type: MsgNodeStatus, From: c.self.ID, Payload: payload, Timestamp: time.Now()})
}

func (c *Client) Send(msg Message) error {
	if c.conn == nil {
		return fmt.Errorf("not connected")
	}
	return c.conn.Send(msg)
}

func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func (c *Client) HandleIncoming() {
	if c.conn == nil {
		return
	}
	for {
		msg, err := c.conn.Read()
		if err != nil {
			return
		}
		switch msg.Type {
		case MsgTaskAssign:
			var t Task
			if json.Unmarshal(msg.Payload, &t) == nil {
				c.cluster.StoreTask(&t)
			}
		}
		for _, h := range c.handlers {
			h(msg)
		}
	}
}
