package srslog

import (
	"crypto/tls"
	"strings"
	"sync"
)

// A Writer is a connection to a syslog server.
type Writer struct {
	priority  Priority
	tag       string
	hostname  string
	network   string
	raddr     string
	tlsConfig *tls.Config
	framer    Framer
	formatter Formatter

	mu            sync.RWMutex // guards conn
	conn          serverConn
	needReconnect bool
}

// getConn provides access to the internal conn, protected by a mutex. The
// conn is threadsafe, so it can be used while unlocked, but we want to avoid
// race conditions on grabbing a reference to it.
func (w *Writer) getConn() serverConn {
	w.mu.RLock()
	conn := w.conn
	w.mu.RUnlock()
	return conn
}

// setConn updates the internal conn, protected by a mutex.
func (w *Writer) setConn(c serverConn) {
	w.mu.Lock()
	w.conn = c
	w.mu.Unlock()
}

// connect makes a connection to the syslog server.
func (w *Writer) connect() (serverConn, error) {
	conn := w.getConn()
	if conn != nil {
		// ignore err from close, it makes sense to continue anyway
		conn.close()
		w.setConn(nil)
	}

	var hostname string
	var err error
	dialer := w.getDialer()
	conn, hostname, err = dialer.Call()
	if err == nil {
		w.setConn(conn)
		w.hostname = hostname
		w.setNeedReconnect(false)
		if w.network == "tcp" || w.network == "tcp+tls" {
			go w.checkForRemoteDisconnect()
		}

		return conn, nil
	} else {
		return nil, err
	}
}

// SetFormatter changes the formatter function for subsequent messages.
func (w *Writer) SetFormatter(f Formatter) {
	w.formatter = f
}

// SetFramer changes the framer function for subsequent messages.
func (w *Writer) SetFramer(f Framer) {
	w.framer = f
}

// Write sends a log message to the syslog daemon using the default priority
// passed into `srslog.New` or the `srslog.Dial*` functions.
func (w *Writer) Write(b []byte) (int, error) {
	return w.writeAndRetry(w.priority, string(b))
}

// WriteWithPriority sends a log message with a custom priority
func (w *Writer) WriteWithPriority(p Priority, b []byte) (int, error) {
	return w.writeAndRetry(p, string(b))
}

// Close closes a connection to the syslog daemon.
func (w *Writer) Close() error {
	conn := w.getConn()
	if conn != nil {
		err := conn.close()
		w.setConn(nil)
		return err
	}
	return nil
}

// Emerg logs a message with severity LOG_EMERG; this overrides the default
// priority passed to `srslog.New` and the `srslog.Dial*` functions.
func (w *Writer) Emerg(m string) (err error) {
	_, err = w.writeAndRetry(LOG_EMERG, m)
	return err
}

// Alert logs a message with severity LOG_ALERT; this overrides the default
// priority passed to `srslog.New` and the `srslog.Dial*` functions.
func (w *Writer) Alert(m string) (err error) {
	_, err = w.writeAndRetry(LOG_ALERT, m)
	return err
}

// Crit logs a message with severity LOG_CRIT; this overrides the default
// priority passed to `srslog.New` and the `srslog.Dial*` functions.
func (w *Writer) Crit(m string) (err error) {
	_, err = w.writeAndRetry(LOG_CRIT, m)
	return err
}

// Err logs a message with severity LOG_ERR; this overrides the default
// priority passed to `srslog.New` and the `srslog.Dial*` functions.
func (w *Writer) Err(m string) (err error) {
	_, err = w.writeAndRetry(LOG_ERR, m)
	return err
}

// Warning logs a message with severity LOG_WARNING; this overrides the default
// priority passed to `srslog.New` and the `srslog.Dial*` functions.
func (w *Writer) Warning(m string) (err error) {
	_, err = w.writeAndRetry(LOG_WARNING, m)
	return err
}

// Notice logs a message with severity LOG_NOTICE; this overrides the default
// priority passed to `srslog.New` and the `srslog.Dial*` functions.
func (w *Writer) Notice(m string) (err error) {
	_, err = w.writeAndRetry(LOG_NOTICE, m)
	return err
}

// Info logs a message with severity LOG_INFO; this overrides the default
// priority passed to `srslog.New` and the `srslog.Dial*` functions.
func (w *Writer) Info(m string) (err error) {
	_, err = w.writeAndRetry(LOG_INFO, m)
	return err
}

// Debug logs a message with severity LOG_DEBUG; this overrides the default
// priority passed to `srslog.New` and the `srslog.Dial*` functions.
func (w *Writer) Debug(m string) (err error) {
	_, err = w.writeAndRetry(LOG_DEBUG, m)
	return err
}

func (w *Writer) writeAndRetry(p Priority, s string) (int, error) {
	pr := (w.priority & facilityMask) | (p & severityMask)

	conn := w.getConn()
	needReconnect := w.getNeedReconnect()
	if conn != nil && !needReconnect {
		if n, err := w.write(conn, pr, s); err == nil {
			return n, err
		}
	}

	var err error
	if conn, err = w.connect(); err != nil {
		return 0, err
	}
	return w.write(conn, pr, s)
}

// write generates and writes a syslog formatted string. It formats the
// message based on the current Formatter and Framer.
func (w *Writer) write(conn serverConn, p Priority, msg string) (int, error) {
	// ensure it ends in a \n
	if !strings.HasSuffix(msg, "\n") {
		msg += "\n"
	}

	err := conn.writeString(w.framer, w.formatter, p, w.hostname, w.tag, msg)
	if err != nil {
		return 0, err
	}
	// Note: return the length of the input, not the number of
	// bytes printed by Fprintf, because this must behave like
	// an io.Writer.
	return len(msg), nil
}

// checkForRemoteDisconnect attempts to read from the socket, because if that
// fails we know the remote server has closed the connection and we're going to
// want to reconnect before sending another message
func (w *Writer) checkForRemoteDisconnect() {
	// since we don't expect the server to send data back to us, this for
	// loop should never execute more than once; just in case something
	// strange happens, we'll be ready for it
	for {
		// we can use the conn from multiple goroutines at once, but we need
		// to lock in order to get access to the variable itself
		conn := w.getConn()

		// if there is no conn, we will need to reconnect
		if conn == nil {
			w.setNeedReconnect(true)
			return
		}

		// read is blocking, so this will hang until it either succeeds or
		// fails; since syslog servers don't write back to us, we never
		// expect this to succeed; but if it fails, it means the syslog server
		// disconnected unexpectedly and we'll want to reconnect to it
		b := make([]byte, 1)
		_, err := conn.read(b)
		if err != nil {
			w.setNeedReconnect(true)
			return
		}
	}
}

// setNeedReconnect updates our variable that keeps track of whether the
// remote syslog server has unexpectedly closed the connection, and locks
// the mutex to protect us from race conditions
func (w *Writer) setNeedReconnect(needReconnect bool) {
	w.mu.Lock()
	w.needReconnect = needReconnect
	w.mu.Unlock()
}

func (w *Writer) getNeedReconnect() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.needReconnect
}
