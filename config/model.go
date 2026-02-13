package config

var ModelReverseMap = map[string]string{}
var ModelMap = map[string]string{
	"sonar":                    "sonar",
	"gpt-5.2":                  "gpt52",
	"gpt-5.2-think":            "gpt52_thinking",
	"claude-4.5-sonnet":        "claude45sonnet",
	"claude-4.5-sonnet-think":  "claude45sonnetthinking",
	"gemini-3-pro":             "gemini30pro",
	"gemini-3-pro-think":       "gemini30prothinking",
	"gemini-3-flash":           "gemini30flash",
	"gemini-3-flash-think":     "gemini30flashthinking",
	"grok-4.1":                 "grok41",
	"grok-4.1-think":           "grok41thinking",
	"kimi-k2.5-thinking":       "kimik25thinking",
	"o3-pro":                   "o3pro",
	"claude-4.5-opus":          "claude45opus",
	"claude-4.5-opus-think":    "claude45opusthinking",
	"claude-4.6-opus":          "claude46opus",
	"claude-4.6-opus-think":    "claude46opusthinking",
}
var MaxModelMap = map[string]string{
	"o3-pro":                "o3pro",
	"claude-4.5-opus":       "claude45opus",
	"claude-4.5-opus-think": "claude45opusthinking",
	"claude-4.6-opus":       "claude46opus",
	"claude-4.6-opus-think": "claude46opusthinking",
}

// Get returns the value for the given key from the ModelMap.
// If the key doesn't exist, it returns the provided default value.
func ModelMapGet(key string, defaultValue string) string {
	if value, exists := ModelMap[key]; exists {
		return value
	}
	return defaultValue
}

// GetReverse returns the value for the given key from the ModelReverseMap.
// If the key doesn't exist, it returns the provided default value.
func ModelReverseMapGet(key string, defaultValue string) string {
	if value, exists := ModelReverseMap[key]; exists {
		return value
	}
	return defaultValue
}

var ResponseModels []map[string]string

func init() {
	// 构建反向映射
	for k, v := range ModelMap {
		ModelReverseMap[v] = k
	}
	buildResponseModels()
}

// buildResponseModels 构建响应模型列表
func buildResponseModels() {
	ResponseModels = make([]map[string]string, 0, len(ModelMap)*2)

	for modelID := range ModelMap {
		// 如果不是最大订阅用户，跳过最大模型
		if !ConfigInstance.IsMaxSubscribe {
			if _, isMaxModel := MaxModelMap[modelID]; isMaxModel {
				continue
			}
		}

		// 添加普通模型
		ResponseModels = append(ResponseModels, map[string]string{
			"id": modelID,
		})

		// 添加搜索模型
		ResponseModels = append(ResponseModels, map[string]string{
			"id": modelID + "-search",
		})
	}
}
