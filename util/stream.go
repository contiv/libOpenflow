package util

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"

	"k8s.io/klog/v2"
)

const numParserGoroutines = 25

type BufferPool struct {
	Empty chan *bytes.Buffer
}

func NewBufferPool() *BufferPool {
	m := new(BufferPool)
	m.Empty = make(chan *bytes.Buffer, 50)

	for i := 0; i < 50; i++ {
		m.Empty <- bytes.NewBuffer(make([]byte, 0, 2048))
	}
	return m
}

// Parser interface
type Parser interface {
	Parse(b []byte) (message Message, err error)
}

type streamWorker struct {
	Full chan *bytes.Buffer
}

func (w *streamWorker) parse(stopCh chan bool, parser Parser, inbound chan Message, empty chan *bytes.Buffer) {
	for {
		select {
		case b := <-w.Full:
			msg, err := parser.Parse(b.Bytes())
			// Log all message parsing errors.
			if err != nil {
				klog.ErrorS(err, "Failed to parse received message", "bytes", b.Bytes())
			} else {
				inbound <- msg
			}
			b.Reset()
			empty <- b
		case <-stopCh:
			return
		}
	}
}

type MessageStream struct {
	conn net.Conn
	pool *BufferPool
	// Message parser
	parser Parser
	// Channel to shut down the parser goroutine
	parserShutdown chan bool
	// OpenFlow Version
	Version uint8
	// Channel on which to publish connection errors
	Error chan error
	// Channel on which to publish inbound messages
	Inbound chan Message
	// Channel on which to receive outbound messages
	Outbound chan Message
	// Channel on which to receive a shutdown command
	Shutdown chan bool
	// Worker to parse the message received from the connection
	workers []streamWorker
}

// Returns a pointer to a new MessageStream. Used to parse
// OpenFlow messages from conn.
func NewMessageStream(conn net.Conn, parser Parser) *MessageStream {
	m := &MessageStream{
		conn,
		NewBufferPool(),
		parser,
		make(chan bool, 1),
		0,
		make(chan error, 1),   // Error
		make(chan Message, 1), // Inbound
		make(chan Message, 1), // Outbound
		make(chan bool, 1),    // Shutdown
		make([]streamWorker, numParserGoroutines),
	}

	for i := 0; i < numParserGoroutines; i++ {
		worker := streamWorker{
			Full: make(chan *bytes.Buffer),
		}
		m.workers[i] = worker
		go worker.parse(m.parserShutdown, m.parser, m.Inbound, m.pool.Empty)
	}
	go m.outbound()
	go m.inbound()

	return m
}

func (m *MessageStream) GetAddr() net.Addr {
	return m.conn.RemoteAddr()
}

// Listen for a Shutdown signal or Outbound messages.
func (m *MessageStream) outbound() {
	for {
		select {
		case <-m.Shutdown:
			klog.Infof("Closing OpenFlow message stream.")
			m.conn.Close()
			close(m.parserShutdown)
			return
		case msg := <-m.Outbound:
			// Forward outbound messages to conn
			data, _ := msg.MarshalBinary()
			if _, err := m.conn.Write(data); err != nil {
				klog.ErrorS(err, "OutboundError")
				m.Error <- err
				m.Shutdown <- true
			}

			klog.V(4).InfoS("Sent", "dataLength", len(data), "data", len(data), data)
		}
	}
}

// Handle inbound messages
func (m *MessageStream) inbound() {
	msgLen := 0
	hdr := 0
	hdrBuf := make([]byte, 4)

	tmpBuf := make([]byte, 2048)
	buf := <-m.pool.Empty
	for {
		n, err := m.conn.Read(tmpBuf)
		if err != nil {
			// Handle explicitly disconnecting by closing connection
			if strings.Contains(err.Error(), "use of closed network connection") {
				return
			}
			klog.ErrorS(err, "InboundError")
			m.Error <- err
			m.Shutdown <- true
			return
		}

		for i := 0; i < n; i++ {
			if hdr < 4 {
				hdrBuf[hdr] = tmpBuf[i]
				buf.WriteByte(tmpBuf[i])
				hdr += 1
				if hdr >= 4 {
					// MessageStream is not protocol agnostic. Reading length based
					// on OpenFlow header field.
					msgLen = int(binary.BigEndian.Uint16(hdrBuf[2:])) - 4
				}
				continue
			}
			if msgLen > 0 {
				buf.WriteByte(tmpBuf[i])
				msgLen = msgLen - 1
				if msgLen == 0 {
					hdr = 0
					m.dispatchMessage(buf)
					buf = <-m.pool.Empty
				}
				continue
			}
		}
	}
}

// Dispatch the message to streamWorker according to Xid in the message Header
func (m *MessageStream) dispatchMessage(b *bytes.Buffer) {
	msgBytes := b.Bytes()
	if len(msgBytes) < 8 {
		klog.Error("Buffer too small to parse OpenFlow messages")
		return
	}
	xid := binary.BigEndian.Uint32(msgBytes[4:])
	workerKey := int(xid % uint32(len(m.workers)))
	m.workers[workerKey].Full <- b
}
