// Package model 定义输入输出数据结构。
package model

// BannerInput 是批量识别接口的单条输入。
type BannerInput struct {
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	Banner string `json:"banner"`
}

// FingerprintResult 是单条识别结果。
type FingerprintResult struct {
	IP         string  `json:"ip"`
	Port       int     `json:"port"`
	Protocol   string  `json:"protocol"`
	Product    string  `json:"product"`
	Version    string  `json:"version"`
	OSHint     string  `json:"os_hint"`
	Confidence float64 `json:"confidence"`
}

// FingerprintRequest 是 POST /fingerprint 的请求体。
type FingerprintRequest struct {
	Items []BannerInput `json:"items"`
}

// FingerprintResponse 是 POST /fingerprint 的响应体。
type FingerprintResponse struct {
	Results []FingerprintResult `json:"results"`
}
