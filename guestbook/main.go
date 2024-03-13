package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	_ "modernc.org/sqlite"
)

var (
	listen         = flag.String("listen", "127.0.0.1:9090", "Address and port to listen on")
	caCertPath     = flag.String("ca-cert", "", "Path to CA certs to trust for client certs")
	chainPath      = flag.String("tls-chain", "", "Path to TLS cert chain")
	privateKeyPath = flag.String("tls-key", "", "Path to TLS private key")

	dbPath = flag.String("db-path", "guestbook.sqlite", "Path to sqlite database")
	initDB = flag.Bool("init-db", false, "If set, initialise a fresh database at db-path")
)

func indexPage(db *sql.DB) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			logger := LoggerFromContext(r.Context()).With("handler", "notfound")
			logger.Info("not found", "path", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found"))
			return
		}

		logger := LoggerFromContext(r.Context()).With("handler", "index")

		// TODO: shouldn't run allMessages in handler, should cache the result and rebuild periodically
		content, err := allMessages(r.Context(), db, w)
		if err != nil {
			logger.Error("failed to fetch from database", "error", err)
			http.Error(w, "failed to fetch messages from database", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(content)
	})
}

func allMessages(ctx context.Context, db *sql.DB, w io.Writer) ([]byte, error) {
	rows, err := db.QueryContext(ctx, `SELECT email, user_agent, date, message from entries;`)
	if err != nil {
		return nil, err
	}

	buf := &bytes.Buffer{}
	tw := tabwriter.NewWriter(buf, 10, 80, 2, ' ', 0)
	fmt.Fprintf(tw, "email\tmessage\tuser-agent\ttimestamp\tstar?\n")

	for rows.Next() {
		var email, userAgent, date, message string

		if err := rows.Scan(&email, &userAgent, &date, &message); err != nil {
			return nil, err
		}

		star := "⭐"
		if strings.ToLower(userAgent) == "kiosk" {
			star = "❌"
		}

		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", email, message, userAgent, date, star)
	}

	tw.Flush()

	return buf.Bytes(), nil
}

func addMessage(ctx context.Context, db *sql.DB, email string, userAgent string, msg string) error {
	timestamp := time.Now().Format(time.RFC3339Nano)

	_, err := db.ExecContext(ctx, `insert into entries(email, user_agent, date, message) values($1, $2, $3, $4);`, email, userAgent, timestamp, msg)
	if err != nil {
		return err
	}

	return nil
}

func getUserAgent(r *http.Request) string {
	agent := r.Header.Get("user-agent")
	if agent == "" {
		return "<unknown>"
	}

	return agent
}

func writePage(db *sql.DB) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger := LoggerFromContext(r.Context()).With("handler", "write")
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}

		email := EmailFromContext(r.Context())
		userAgent := getUserAgent(r)
		message := r.Form.Get("message")

		err = addMessage(r.Context(), db, email, userAgent, message)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			http.Error(w, "failed to add message to database", http.StatusBadRequest)
			return
		}

		logger.Info("added message", "email", email, "contents", message, "user-agent", userAgent)

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("successfully added message"))
	})
}

func loadCACerts(path string) (*x509.CertPool, error) {
	certBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	certPool := x509.NewCertPool()
	ok := certPool.AppendCertsFromPEM(certBytes)
	if !ok {
		return nil, fmt.Errorf("failed to add certs from %q to cert pool", path)
	}

	return certPool, nil
}

type contextKey int

const (
	loggerContextKey contextKey = 0
	emailContextKey  contextKey = 1
)

func LoggerFromContext(ctx context.Context) *slog.Logger {
	cert, ok := ctx.Value(loggerContextKey).(*slog.Logger)
	if !ok {
		panic("LoggerFromContext called without a configured logger")
	}

	return cert
}

func EmailFromContext(ctx context.Context) string {
	email, ok := ctx.Value(emailContextKey).(string)
	if !ok {
		panic("EmailFromContext called on context without email")
	}

	return email
}

func certExtractMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger := LoggerFromContext(r.Context()).With("handler", "certExtractMiddleware")

		chains := r.TLS.VerifiedChains

		if len(chains) == 0 {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("no client cert"))
			logger.Error("failed to fetch client identity: no cert")
			return
		}

		if len(chains) > 1 {
			logger.Warn("got more than one verified chain from client", "count", len(chains))
		}

		chain := chains[0]

		if len(chain[0].EmailAddresses) == 0 {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("no email in client cert"))
			logger.Error("failed to fetch client identity: no email addresses")
			return
		}

		email := chain[0].EmailAddresses[0]
		logger.Info("got request", "email", email)

		r = r.WithContext(context.WithValue(r.Context(), emailContextKey, email))

		h.ServeHTTP(w, r)
	})
}

func cachingHeadersMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Vary", "Accept-Encoding")
		w.Header().Set("Cache-Control", "public, max-age=7776000")

		h.ServeHTTP(w, req)
	})

}

func run(ctx context.Context) error {
	if *caCertPath == "" {
		return fmt.Errorf("missing required path to CA cert")
	}

	logger := LoggerFromContext(ctx)

	db, err := sql.Open("sqlite", *dbPath)
	if err != nil {
		return err
	}

	cert, err := tls.LoadX509KeyPair(*chainPath, *privateKeyPath)
	if err != nil {
		return err
	}

	certPool, err := loadCACerts(*caCertPath)
	if err != nil {
		return err
	}

	serveMux := http.NewServeMux()

	serveMux.Handle("GET /", certExtractMiddleware(indexPage(db)))
	serveMux.Handle("POST /write", certExtractMiddleware(writePage(db)))

	server := &http.Server{
		Handler:     serveMux,
		BaseContext: func(_ net.Listener) context.Context { return ctx },
		ErrorLog:    slog.NewLogLogger(logger.With("handler", "http.Server").Handler(), slog.LevelError),
	}

	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return fmt.Errorf("failed to create TCP listener: %s", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    certPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	listener = tls.NewListener(listener, tlsConfig)

	logger.Info("listening", "address", *listen)

	sigs := make(chan os.Signal, 1)

	signal.Notify(sigs, syscall.SIGINT)

	go func() {
		err := server.Serve(listener)
		if err != nil && err != http.ErrServerClosed {
			logger.Info("failed to listen", "error", err)
		}
	}()

	<-sigs
	logger.Info("shutting down")

	err = server.Shutdown(context.Background())
	if err != nil {
		return err
	}

	return nil
}

func createDB(ctx context.Context, path string) error {
	if path == "" {
		return fmt.Errorf("missing required value: path")
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return fmt.Errorf("failed to open database at %q: %w", dbPath, err)
	}

	defer db.Close()

	if _, err = db.ExecContext(ctx, `create table entries(email, user_agent, date, message);`); err != nil {
		return err
	}

	return nil
}

func main() {
	flag.Parse()

	ctx := context.Background()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	ctx = context.WithValue(ctx, loggerContextKey, logger)

	if *initDB {
		err := createDB(ctx, *dbPath)
		if err != nil {
			logger.Error("failed to create sqlite database", "path", *dbPath, "error", err)
			os.Exit(1)
		}

		logger.Info("created sqlite database", "path", *dbPath)
		os.Exit(0)
	}

	err := run(ctx)
	if err != nil {
		logger.Error("fatal error", "err", err)
		os.Exit(1)
	}
}
