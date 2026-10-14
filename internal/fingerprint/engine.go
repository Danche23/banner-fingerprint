// Package fingerprint 实现 Banner 指纹识别引擎。
// 规则从外部 JSON 文件加载，与程序代码完全解耦。
package fingerprint

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/danche23/banner-fingerprint/internal/model"
)

// rulePattern 对应 JSON 规则文件中每条规则的单个匹配模式。
type rulePattern struct {
	Regex         string `json:"regex"`
	StaticProduct string `json:"static_product"` // 无命名组时使用的固定产品名
	re            *regexp.Regexp
	groupIdx      map[string]int // 命名捕获组 → 下标
}

// rule 是一条协议指纹规则。
type rule struct {
	Protocol   string        `json:"protocol"`
	Confidence float64       `json:"confidence"`
	PortHints  []int         `json:"port_hints"` // 命中端口时额外加分
	Patterns   []rulePattern `json:"patterns"`
}

type rulesConfig struct {
	Rules []rule `json:"rules"`
}

// Engine 持有编译好的规则集，线程安全（只读）。
type Engine struct {
	rules []rule
}

// New 从 rulesPath 加载并编译规则，返回可用的 Engine。
func New(rulesPath string) (*Engine, error) {
	data, err := os.ReadFile(rulesPath)
	if err != nil {
		return nil, fmt.Errorf("read rules file: %w", err)
	}
	var cfg rulesConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse rules JSON: %w", err)
	}
	for ri := range cfg.Rules {
		for pi := range cfg.Rules[ri].Patterns {
			p := &cfg.Rules[ri].Patterns[pi]
			re, err := regexp.Compile(p.Regex)
			if err != nil {
				return nil, fmt.Errorf("rule %q pattern %d: %w", cfg.Rules[ri].Protocol, pi, err)
			}
			p.re = re
			p.groupIdx = make(map[string]int)
			for i, name := range re.SubexpNames() {
				if name != "" {
					p.groupIdx[name] = i
				}
			}
		}
	}
	return &Engine{rules: cfg.Rules}, nil
}

// escapeRe 匹配 JSON 传入的 \xHH 字面量（JSON 不支持 \x 转义，故以4字符形式到达）。
var escapeRe = regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)

// normalizeBanner 将字面转义序列（\xHH、\n、\r、\t）还原为真实字节，
// 以便统一匹配二进制协议和多行 HTTP 响应头。
func normalizeBanner(s string) string {
	// 先处理 \xHH
	s = escapeRe.ReplaceAllStringFunc(s, func(m string) string {
		b, _ := strconv.ParseUint(m[2:], 16, 8)
		return string([]byte{byte(b)})
	})
	// 再处理常见转义字符
	s = strings.NewReplacer(`\n`, "\n", `\r`, "\r", `\t`, "\t").Replace(s)
	return s
}

// Identify 识别单条 Banner，始终返回结果（无法识别时 protocol="unknown"）。
func (e *Engine) Identify(item model.BannerInput) model.FingerprintResult {
	out := model.FingerprintResult{
		IP:       item.IP,
		Port:     item.Port,
		Protocol: "unknown",
	}

	banner := normalizeBanner(item.Banner)
	bestConf := 0.0

	for _, r := range e.rules {
		portBonus := hasPortHint(r.PortHints, item.Port)

		for _, p := range r.Patterns {
			m := p.re.FindStringSubmatch(banner)
			if m == nil {
				continue
			}

			conf := r.Confidence
			if portBonus {
				conf = clamp(conf+0.05, 0, 1)
			}
			if conf <= bestConf {
				break // 当前规则剩余模式置信度只会更低
			}

			bestConf = conf
			out.Protocol   = r.Protocol
			out.Confidence = conf
			out.Product    = groupVal(m, p.groupIdx, "product")
			out.Version    = groupVal(m, p.groupIdx, "version")
			out.OSHint     = groupVal(m, p.groupIdx, "os_hint")
			if p.StaticProduct != "" && out.Product == "" {
				out.Product = p.StaticProduct
			}
			break // 每条规则取第一个匹配的模式
		}
	}
	return out
}

func hasPortHint(hints []int, port int) bool {
	for _, h := range hints {
		if h == port {
			return true
		}
	}
	return false
}

func groupVal(m []string, idx map[string]int, name string) string {
	if i, ok := idx[name]; ok && i < len(m) {
		return m[i]
	}
	return ""
}

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
