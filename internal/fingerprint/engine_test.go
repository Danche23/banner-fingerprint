// Package fingerprint_test 测试指纹识别引擎，覆盖正常用例、边界输入和异常场景。
package fingerprint_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/danche23/banner-fingerprint/internal/fingerprint"
	"github.com/danche23/banner-fingerprint/internal/model"
)

// 定位 rules 文件：测试从 internal/fingerprint/ 往上两级找
func rulesPath(t *testing.T) string {
	t.Helper()
	// 从当前文件所在目录向上查找 rules/fingerprints.json
	dir, _ := os.Getwd()
	for i := 0; i < 5; i++ {
		p := filepath.Join(dir, "rules", "fingerprints.json")
		if _, err := os.Stat(p); err == nil {
			return p
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("rules/fingerprints.json not found")
	return ""
}

func newEngine(t *testing.T) *fingerprint.Engine {
	t.Helper()
	eng, err := fingerprint.New(rulesPath(t))
	if err != nil {
		t.Fatalf("engine init: %v", err)
	}
	return eng
}

var cases = []struct {
	name     string
	item     model.BannerInput
	wantProto string
	wantProd  string
	wantVer   string
}{
	{
		name:      "SSH OpenSSH Ubuntu",
		item:      model.BannerInput{IP: "1.1.1.1", Port: 22, Banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"},
		wantProto: "SSH", wantProd: "OpenSSH", wantVer: "8.9p1",
	},
	{
		name:      "SSH OpenSSH Debian",
		item:      model.BannerInput{IP: "1.1.1.2", Port: 22, Banner: "SSH-2.0-OpenSSH_9.3 Debian-1"},
		wantProto: "SSH", wantProd: "OpenSSH", wantVer: "9.3",
	},
	{
		name:      "SSH legacy 1.99",
		item:      model.BannerInput{IP: "1.1.1.3", Port: 22, Banner: "SSH-1.99-OpenSSH_4.3"},
		wantProto: "SSH", wantProd: "OpenSSH", wantVer: "4.3",
	},
	{
		name:      "HTTP nginx",
		item:      model.BannerInput{IP: "1.1.1.1", Port: 80, Banner: "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html"},
		wantProto: "HTTP", wantProd: "nginx", wantVer: "1.24.0",
	},
	{
		name:      "HTTP Apache",
		item:      model.BannerInput{IP: "1.1.1.1", Port: 443, Banner: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.57"},
		wantProto: "HTTP", wantProd: "Apache", wantVer: "2.4.57",
	},
	{
		name:      "HTTP Jetty",
		item:      model.BannerInput{IP: "1.1.1.1", Port: 8080, Banner: "HTTP/1.1 404 Not Found\r\nServer: Jetty/9.4.51"},
		wantProto: "HTTP", wantProd: "Jetty", wantVer: "9.4.51",
	},
	{
		name:      "HTTP IIS",
		item:      model.BannerInput{IP: "1.1.1.1", Port: 8888, Banner: "HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0"},
		wantProto: "HTTP", wantProd: "Microsoft-IIS", wantVer: "10.0",
	},
	{
		name:      "MySQL 8.0",
		item:      model.BannerInput{IP: "1.1.1.1", Port: 3306, Banner: "J\x00\x00\x00\n8.0.32\x00"},
		wantProto: "MySQL", wantProd: "MySQL", wantVer: "8.0.32",
	},
	{
		name:      "MySQL 5.7 via literal escape",
		item:      model.BannerInput{IP: "1.1.1.1", Port: 3306, Banner: `J\x00\x00\x00\n5.7.42\x00`},
		wantProto: "MySQL", wantProd: "MySQL", wantVer: "5.7.42",
	},
	{
		name:      "Redis PONG",
		item:      model.BannerInput{IP: "1.1.1.1", Port: 6379, Banner: "+PONG"},
		wantProto: "Redis", wantProd: "Redis",
	},
	{
		name:      "Redis ERR",
		item:      model.BannerInput{IP: "1.1.1.1", Port: 6379, Banner: "-ERR wrong number of arguments for 'get' command"},
		wantProto: "Redis", wantProd: "Redis",
	},
	{
		name:      "Redis NOAUTH",
		item:      model.BannerInput{IP: "1.1.1.1", Port: 6379, Banner: "-NOAUTH Authentication required."},
		wantProto: "Redis", wantProd: "Redis",
	},
	{
		name:      "FTP ProFTPD",
		item:      model.BannerInput{IP: "1.1.1.1", Port: 21, Banner: "220 ProFTPD 1.3.7 Server (ProFTPD)"},
		wantProto: "FTP", wantProd: "ProFTPD", wantVer: "1.3.7",
	},
	{
		name:      "FTP vsFTPd",
		item:      model.BannerInput{IP: "1.1.1.1", Port: 21, Banner: "220 (vsFTPd 3.0.5)"},
		wantProto: "FTP", wantProd: "vsFTPd", wantVer: "3.0.5",
	},
	{
		name:      "FTP Pure-FTPd",
		item:      model.BannerInput{IP: "1.1.1.1", Port: 21, Banner: "220 Welcome to Pure-FTPd"},
		wantProto: "FTP", wantProd: "Pure-FTPd",
	},
	{
		name:      "unknown binary",
		item:      model.BannerInput{IP: "1.1.1.1", Port: 12345, Banner: "QUIT\r\n"},
		wantProto: "unknown",
	},
	{
		name:      "empty banner never panics",
		item:      model.BannerInput{IP: "", Port: 0, Banner: ""},
		wantProto: "unknown",
	},
}

func TestIdentify(t *testing.T) {
	eng := newEngine(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := eng.Identify(tc.item)
			if got.Protocol != tc.wantProto {
				t.Errorf("protocol: got %q, want %q (banner=%q)", got.Protocol, tc.wantProto, tc.item.Banner)
			}
			if tc.wantProd != "" && got.Product != tc.wantProd {
				t.Errorf("product: got %q, want %q", got.Product, tc.wantProd)
			}
			if tc.wantVer != "" && got.Version != tc.wantVer {
				t.Errorf("version: got %q, want %q", got.Version, tc.wantVer)
			}
			if got.Confidence < 0 || got.Confidence > 1 {
				t.Errorf("confidence out of range: %v", got.Confidence)
			}
		})
	}
}

func TestNeverPanics(t *testing.T) {
	eng := newEngine(t)
	weirdBanners := []string{
		"",
		"\x00\x01\x02\x03",
		string(make([]byte, 4096)),
		"220 ",
		"HTTP/1.1",
		`\x16\x03\x01\x00\xa5\x01\x00\x00\xa1`,
	}
	for _, b := range weirdBanners {
		res := eng.Identify(model.BannerInput{IP: "0.0.0.0", Port: 9999, Banner: b})
		if res.Protocol == "" {
			t.Errorf("empty protocol for banner %q", b)
		}
	}
}
