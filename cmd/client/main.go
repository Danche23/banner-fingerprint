// client 读取本地 JSON 文件，批量发送给 server，展示识别结果。
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/danche23/banner-fingerprint/internal/model"
)

func main() {
	var (
		dataPath  = flag.String("data", "./data/input.json", "path to input JSON file")
		serverURL = flag.String("server", "http://server:8080", "server base URL")
	)
	flag.Parse()

	// 等待 server 就绪（依赖 docker compose depends_on: service_healthy）
	if err := waitHealth(*serverURL, 30*time.Second); err != nil {
		slog.Error("server not ready", "err", err)
		os.Exit(1)
	}

	data, err := os.ReadFile(*dataPath)
	if err != nil {
		slog.Error("read input file failed", "path", *dataPath, "err", err)
		os.Exit(1)
	}

	var items []model.BannerInput
	if err := json.Unmarshal(data, &items); err != nil {
		slog.Error("parse input JSON failed", "err", err)
		os.Exit(1)
	}

	req := model.FingerprintRequest{Items: items}
	body, _ := json.Marshal(req)

	resp, err := http.Post(*serverURL+"/fingerprint", "application/json", bytes.NewReader(body))
	if err != nil {
		slog.Error("request failed", "err", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		slog.Error("unexpected status", "code", resp.StatusCode)
		os.Exit(1)
	}

	var result model.FingerprintResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		slog.Error("decode response failed", "err", err)
		os.Exit(1)
	}

	out, _ := json.MarshalIndent(result.Results, "", "  ")
	fmt.Println(string(out))
}

func waitHealth(baseURL string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(baseURL + "/health")
		if err == nil && resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			return nil
		}
		if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("health check timeout after %v", timeout)
}
