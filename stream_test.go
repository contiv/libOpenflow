package libOpenflow

import (
	"io"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	"antrea.io/libOpenflow/common"
	"antrea.io/libOpenflow/openflow13"
	"antrea.io/libOpenflow/util"
)

var helloMessage *common.Hello
var binaryMessage []byte

type fakeConn struct {
	count int
	max   int
}

func (f *fakeConn) Close() error {
	return nil
}

func (f *fakeConn) Read(b []byte) (int, error) {
	if f.count == f.max {
		return 0, io.EOF
	}
	f.count++
	copy(b, binaryMessage)
	return len(binaryMessage), nil
}

func (f *fakeConn) Write(b []byte) (int, error) {
	return len(b), nil
}

func (f *fakeConn) LocalAddr() net.Addr {
	return nil
}

func (f *fakeConn) RemoteAddr() net.Addr {
	return nil
}

func (f *fakeConn) SetDeadline(t time.Time) error {
	return nil
}

func (f *fakeConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (f *fakeConn) SetWriteDeadline(t time.Time) error {
	return nil
}

type parserIntf struct {
}

func (p parserIntf) Parse(b []byte) (message util.Message, err error) {
	switch b[0] {
	case openflow13.VERSION:
		message, err = openflow13.Parse(b)
	default:

	}
	return
}

func init() {
	helloMessage, _ = common.NewHello(4)
	binaryMessage, _ = helloMessage.MarshalBinary()

}

func TestMessageStream(t *testing.T) {
	var (
		c = &fakeConn{
			max: 5000000,
		}
		p                   = parserIntf{}
		goroutineCountStart = runtime.NumGoroutine()
		goroutineCountEnd   int
	)
	logrus.SetLevel(logrus.PanicLevel)
	stream := util.NewMessageStream(c, p)
	go func() {
		_ = <-stream.Error
	}()
	for i := 0; i < 5000000; i++ {
		<-stream.Inbound
	}
	time.Sleep(2 * time.Second)
	goroutineCountEnd = runtime.NumGoroutine()
	if goroutineCountEnd > goroutineCountStart {
		t.Fatalf("found more goroutines: %v before, %v after", goroutineCountStart, goroutineCountEnd)
	}
}
