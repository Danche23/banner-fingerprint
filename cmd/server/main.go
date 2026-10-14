// server 提供 Banner 指纹识别 HTTP 服务。
// 接口：POST /fingerprint（批量识别）、GET /health（健康检查）。
package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/danche23/banner-fingerprint/internal/fingerprint"
	"github.com/danche23/banner-fingerprint/internal/model"
)

func main() {
	rulesPath := getEnv("RULES_PATH", "./rules/fingerprints.json")
	addr := getEnv("LISTEN_ADDR", ":8080")

	eng, err := fingerprint.New(rulesPath)
	if err != nil {
		slog.Error("load rules failed", "err", err)
		os.Exit(1)
	}
	slog.Info("rules loaded", "path", rulesPath)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", handleHealth)
	mux.HandleFunc("POST /fingerprint", handleFingerprint(eng))

	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		slog.Info("server listening", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("listen error", "err", err)
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)
	<-quit

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("graceful shutdown error", "err", err)
	}
	slog.Info("server stopped")
}

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func handleFingerprint(eng *fingerprint.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req model.FingerprintRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid request body"}`))
			return
		}

		resp := model.FingerprintResponse{
			Results: make([]model.FingerprintResult, len(req.Items)),
		}
		for i, item := range req.Items {
			resp.Results[i] = eng.Identify(item)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
