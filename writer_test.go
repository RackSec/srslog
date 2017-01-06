package srslog

import (
	"crypto/tls"
	"io/ioutil"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func TestCloseNonOpenWriter(t *testing.T) {
	w := Writer{}

	err := w.Close()
	if err != nil {
		t.Errorf("should not fail to close if there is nothing to close")
	}
}

func TestWriteAndRetryFails(t *testing.T) {
	w := Writer{network: "udp", raddr: "fakehost"}

	n, err := w.writeAndRetry(LOG_ERR, "nope")
	if err == nil {
		t.Errorf("should fail to write")
	}
	if n != 0 {
		t.Errorf("should not write any bytes")
	}
}

// Handle cases where a remote server hangs up (e.g. idle timeout),
// without dropping logs.
func _TestSocketClose(l net.Listener, w *Writer, t *testing.T) {
	// This server closes the client connection after receiving one packet,
	// and then listens for a second connection.
	//
	// We want to ensure that our writer reconnects after the socket is closed.
	go func() {
		c, err := l.Accept()
		b := make([]byte, 256)
		c.Read(b)
		c.Close()

		// net.Listener doesn't have SetDeadline, so do this more generically.
		connectionWaiter := make(chan net.Conn, 1)
		go func() {
			cc, e := l.Accept()
			if e != nil {
				t.Errorf("error accepting connection: %v", e)
				return
			}

			connectionWaiter <- cc
		}()

		select {
		case c = <-connectionWaiter:

		case <-time.After(50 * time.Millisecond):
			t.Errorf("didn't get a reconnection: %v", err)
			return
		}

		b = make([]byte, 256)
		c.Read(b)
		c.Close()
	}()

	_, err := w.connect()
	if err != nil {
		t.Errorf("failed connecting to server: %v", err)
		return
	}

	w.Write([]byte("this is a test message"))
	time.Sleep(10 * time.Millisecond)
	w.Write([]byte("this is a test message"))
	time.Sleep(100 * time.Millisecond)
}

func TestSocketCloseTCP(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Errorf("failed starting server: %v", err)
		return
	}

	defer l.Close()

	w := Writer{network: "tcp", raddr: l.Addr().String()}
	_TestSocketClose(l, &w, t)
}

func TestSocketCloseTLS(t *testing.T) {
	cert, err := tls.LoadX509KeyPair("test/cert.pem", "test/privkey.pem")
	if err != nil {
		t.Errorf("failed to load TLS keypair: %v", err)
		return
	}

	config := tls.Config{Certificates: []tls.Certificate{cert}}

	l, err := tls.Listen("tcp", "127.0.0.1:0", &config)
	if err != nil {
		t.Errorf("failed starting server: %v", err)
		return
	}

	defer l.Close()

	// Server's TLS cert is not valid, so skip verifying
	w := Writer{network: "tcp+tls", raddr: l.Addr().String(), tlsConfig: &tls.Config{InsecureSkipVerify: true}}
	_TestSocketClose(l, &w, t)
}

func TestSocketCloseUnix(t *testing.T) {
	// use ioutil.TempFile to get a name that is unique
	f, err := ioutil.TempFile("", "syslogtest")
	if err != nil {
		t.Errorf("TempFile: %v", err)
		return
	}
	f.Close()
	laddr := f.Name()
	os.Remove(laddr)

	l, err := net.Listen("unix", laddr)
	if err != nil {
		t.Errorf("failed starting server: %v", err)
		return
	}

	defer l.Close()

	w := Writer{network: "unix", raddr: laddr}
	_TestSocketClose(l, &w, t)
}

func TestWriteFormatters(t *testing.T) {
	tests := []struct {
		name string
		f    Formatter
	}{
		{"default", nil},
		{"unix", UnixFormatter},
		{"rfc 3164", RFC3164Formatter},
		{"rfc 5424", RFC5424Formatter},
		{"default", DefaultFormatter},
	}

	for _, test := range tests {
		done := make(chan string)
		addr, sock, srvWG := startServer("udp", "", done)
		defer sock.Close()
		defer srvWG.Wait()

		w := Writer{
			priority: LOG_ERR,
			tag:      "tag",
			hostname: "hostname",
			network:  "udp",
			raddr:    addr,
		}

		_, err := w.connect()
		if err != nil {
			t.Errorf("failed to connect: %v", err)
		}
		defer w.Close()

		w.SetFormatter(test.f)

		f := test.f
		if f == nil {
			f = DefaultFormatter
		}
		expected := strings.TrimSpace(f(LOG_ERR, "hostname", "tag", "this is a test message"))

		_, err = w.Write([]byte("this is a test message"))
		if err != nil {
			t.Errorf("failed to write: %v", err)
		}
		sent := strings.TrimSpace(<-done)
		if sent != expected {
			t.Errorf("expected to use the %v formatter, got %v, expected %v", test.name, sent, expected)
		}
	}
}

func TestWriterFramers(t *testing.T) {
	tests := []struct {
		name string
		f    Framer
	}{
		{"default", nil},
		{"rfc 5425", RFC5425MessageLengthFramer},
		{"default", DefaultFramer},
	}

	for _, test := range tests {
		done := make(chan string)
		addr, sock, srvWG := startServer("udp", "", done)
		defer sock.Close()
		defer srvWG.Wait()

		w := Writer{
			priority: LOG_ERR,
			tag:      "tag",
			hostname: "hostname",
			network:  "udp",
			raddr:    addr,
		}

		_, err := w.connect()
		if err != nil {
			t.Errorf("failed to connect: %v", err)
		}
		defer w.Close()

		w.SetFramer(test.f)

		f := test.f
		if f == nil {
			f = DefaultFramer
		}
		expected := strings.TrimSpace(f(DefaultFormatter(LOG_ERR, "hostname", "tag", "this is a test message") + "\n"))

		_, err = w.Write([]byte("this is a test message"))
		if err != nil {
			t.Errorf("failed to write: %v", err)
		}
		sent := strings.TrimSpace(<-done)
		if sent != expected {
			t.Errorf("expected to use the %v framer, got %v, expected %v", test.name, sent, expected)
		}
	}
}

func TestWriteWithDefaultPriority(t *testing.T) {
	done := make(chan string)
	addr, sock, srvWG := startServer("udp", "", done)
	defer sock.Close()
	defer srvWG.Wait()

	w := Writer{
		priority: LOG_ERR,
		tag:      "tag",
		hostname: "hostname",
		network:  "udp",
		raddr:    addr,
	}

	_, err := w.connect()
	if err != nil {
		t.Errorf("failed to connect: %v", err)
	}
	defer w.Close()

	var bytes int
	bytes, err = w.Write([]byte("this is a test message"))
	if err != nil {
		t.Errorf("failed to write: %v", err)
	}
	if bytes == 0 {
		t.Errorf("zero bytes written")
	}

	checkWithPriorityAndTag(t, LOG_ERR, "tag", "hostname", "this is a test message", <-done)
}

func TestWriteWithProvidedPriority(t *testing.T) {
	done := make(chan string)
	addr, sock, srvWG := startServer("udp", "", done)
	defer sock.Close()
	defer srvWG.Wait()

	w := Writer{
		priority: LOG_ERR,
		tag:      "tag",
		hostname: "hostname",
		network:  "udp",
		raddr:    addr,
	}

	_, err := w.connect()
	if err != nil {
		t.Errorf("failed to connect: %v", err)
	}
	defer w.Close()

	var bytes int
	bytes, err = w.WriteWithPriority(LOG_DEBUG, []byte("this is a test message"))
	if err != nil {
		t.Errorf("failed to write: %v", err)
	}
	if bytes == 0 {
		t.Errorf("zero bytes written")
	}

	checkWithPriorityAndTag(t, LOG_DEBUG, "tag", "hostname", "this is a test message", <-done)
}

func TestDebug(t *testing.T) {
	done := make(chan string)
	addr, sock, srvWG := startServer("udp", "", done)
	defer sock.Close()
	defer srvWG.Wait()

	w := Writer{
		priority: LOG_ERR,
		tag:      "tag",
		hostname: "hostname",
		network:  "udp",
		raddr:    addr,
	}

	_, err := w.connect()
	if err != nil {
		t.Errorf("failed to connect: %v", err)
	}
	defer w.Close()

	err = w.Debug("this is a test message")
	if err != nil {
		t.Errorf("failed to debug: %v", err)
	}

	checkWithPriorityAndTag(t, LOG_DEBUG, "tag", "hostname", "this is a test message", <-done)
}

func TestInfo(t *testing.T) {
	done := make(chan string)
	addr, sock, srvWG := startServer("udp", "", done)
	defer sock.Close()
	defer srvWG.Wait()

	w := Writer{
		priority: LOG_ERR,
		tag:      "tag",
		hostname: "hostname",
		network:  "udp",
		raddr:    addr,
	}

	_, err := w.connect()
	if err != nil {
		t.Errorf("failed to connect: %v", err)
	}
	defer w.Close()

	err = w.Info("this is a test message")
	if err != nil {
		t.Errorf("failed to info: %v", err)
	}

	checkWithPriorityAndTag(t, LOG_INFO, "tag", "hostname", "this is a test message", <-done)
}

func TestNotice(t *testing.T) {
	done := make(chan string)
	addr, sock, srvWG := startServer("udp", "", done)
	defer sock.Close()
	defer srvWG.Wait()

	w := Writer{
		priority: LOG_ERR,
		tag:      "tag",
		hostname: "hostname",
		network:  "udp",
		raddr:    addr,
	}

	_, err := w.connect()
	if err != nil {
		t.Errorf("failed to connect: %v", err)
	}
	defer w.Close()

	err = w.Notice("this is a test message")
	if err != nil {
		t.Errorf("failed to notice: %v", err)
	}

	checkWithPriorityAndTag(t, LOG_NOTICE, "tag", "hostname", "this is a test message", <-done)
}

func TestWarning(t *testing.T) {
	done := make(chan string)
	addr, sock, srvWG := startServer("udp", "", done)
	defer sock.Close()
	defer srvWG.Wait()

	w := Writer{
		priority: LOG_ERR,
		tag:      "tag",
		hostname: "hostname",
		network:  "udp",
		raddr:    addr,
	}

	_, err := w.connect()
	if err != nil {
		t.Errorf("failed to connect: %v", err)
	}
	defer w.Close()

	err = w.Warning("this is a test message")
	if err != nil {
		t.Errorf("failed to warn: %v", err)
	}

	checkWithPriorityAndTag(t, LOG_WARNING, "tag", "hostname", "this is a test message", <-done)
}

func TestErr(t *testing.T) {
	done := make(chan string)
	addr, sock, srvWG := startServer("udp", "", done)
	defer sock.Close()
	defer srvWG.Wait()

	w := Writer{
		priority: LOG_ERR,
		tag:      "tag",
		hostname: "hostname",
		network:  "udp",
		raddr:    addr,
	}

	_, err := w.connect()
	if err != nil {
		t.Errorf("failed to connect: %v", err)
	}
	defer w.Close()

	err = w.Err("this is a test message")
	if err != nil {
		t.Errorf("failed to err: %v", err)
	}

	checkWithPriorityAndTag(t, LOG_ERR, "tag", "hostname", "this is a test message", <-done)
}

func TestCrit(t *testing.T) {
	done := make(chan string)
	addr, sock, srvWG := startServer("udp", "", done)
	defer sock.Close()
	defer srvWG.Wait()

	w := Writer{
		priority: LOG_ERR,
		tag:      "tag",
		hostname: "hostname",
		network:  "udp",
		raddr:    addr,
	}

	_, err := w.connect()
	if err != nil {
		t.Errorf("failed to connect: %v", err)
	}
	defer w.Close()

	err = w.Crit("this is a test message")
	if err != nil {
		t.Errorf("failed to crit: %v", err)
	}

	checkWithPriorityAndTag(t, LOG_CRIT, "tag", "hostname", "this is a test message", <-done)
}

func TestAlert(t *testing.T) {
	done := make(chan string)
	addr, sock, srvWG := startServer("udp", "", done)
	defer sock.Close()
	defer srvWG.Wait()

	w := Writer{
		priority: LOG_ERR,
		tag:      "tag",
		hostname: "hostname",
		network:  "udp",
		raddr:    addr,
	}

	_, err := w.connect()
	if err != nil {
		t.Errorf("failed to connect: %v", err)
	}
	defer w.Close()

	err = w.Alert("this is a test message")
	if err != nil {
		t.Errorf("failed to alert: %v", err)
	}

	checkWithPriorityAndTag(t, LOG_ALERT, "tag", "hostname", "this is a test message", <-done)
}

func TestEmerg(t *testing.T) {
	done := make(chan string)
	addr, sock, srvWG := startServer("udp", "", done)
	defer sock.Close()
	defer srvWG.Wait()

	w := Writer{
		priority: LOG_ERR,
		tag:      "tag",
		hostname: "hostname",
		network:  "udp",
		raddr:    addr,
	}

	_, err := w.connect()
	if err != nil {
		t.Errorf("failed to connect: %v", err)
	}
	defer w.Close()

	err = w.Emerg("this is a test message")
	if err != nil {
		t.Errorf("failed to emerg: %v", err)
	}

	checkWithPriorityAndTag(t, LOG_EMERG, "tag", "hostname", "this is a test message", <-done)
}
