package detect

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// RemoteNERDetector calls an external named-entity-recognition service over
// HTTP.
// 通过 HTTP 调用外部命名实体识别服务。
//
// # Why it is required
// # 为什么必须有它
//
// Regexes cannot find personal names — names have no stable lexical signature.
// Shipping with only RegexDetector leaves names, addresses and organizations
// completely exposed. A redaction gateway that cannot detect names provides
// **false confidence**, which is worse than none.
// 正则检测不出人名——人名没有稳定的字面特征。只装 RegexDetector 就上线，
// 姓名、地址、机构名会完全裸奔。一个检测不出人名的 PII 脱敏网关，
// 提供的是**虚假的安全感**，比没有更危险。
//
// # Why caching is required
// # 为什么必须缓存
//
// NER is model inference: tens to hundreds of milliseconds, sitting on the TTFT
// critical path. Worse, agents resend an identical system prompt and SOP every
// turn — without a cache the same multi-thousand-token prefix is re-analyzed
// each round, paying full latency again. The cache key is the text hash, so long
// prefixes almost always hit and only the changing user message reaches the
// model.
// NER 是模型推理，单次几十到几百毫秒，而它在 TTFT 的关键路径上。
// 更要命的是 Agent 每轮都携带完全相同的系统提示词与 SOP——
// 不缓存的话，同一段几千字的前缀会被反复识别，每轮多付一次全额延迟。
// 缓存键取文本哈希，长前缀几乎必然命中，变化的用户消息才真正走推理。
//
// # Service contract
// # 服务契约
//
//	POST <endpoint>
//	{"text": "...", "types": ["NAME","ADDRESS","ORG"]}
//
//	200 OK
//	{"entities": [{"type":"NAME", "value":"Zhang Wei", "confidence":0.95}]}
//
// **Offsets are deliberately absent from the contract.** Cross-language offset
// conventions disagree in a way that hides: Python's str index counts runes,
// Go's string index counts bytes, and a Chinese character is 3 bytes. Trusting
// the peer's offsets shreds the text — and only when the text contains Chinese,
// so an English-only test suite passes cleanly all the way to production. The
// service returns entity text only; this side locates it in the original.
// **偏移量刻意不在契约里。** 跨语言偏移约定不一致是个隐蔽的坑：
// Python 的 str 索引是字符，Go 的字符串索引是字节，中文下一个字符占 3 字节。
// 直接采信对端偏移会把文本切碎，且只在含中文时出错——用英文测试完全正常。
// 因此服务只返回实体文本，由本端回原文定位。
type RemoteNERDetector struct {
	endpoint string
	client   *http.Client
	cache    *detectionCache
	types    []EntityType

	// failOpen 决定服务不可用时的行为。
	// 默认 false（fail-closed）：检测不了就不许出站，
	// 由上层 Redactor 阻断请求。这是脱敏网关唯一安全的默认值。
	failOpen bool

	// 熔断：NER 服务挂掉时快速失败，不让每个请求都白等一次超时。
	// 没有这个，一次 NER 故障会让所有请求延迟 +timeout。
	mu            sync.Mutex
	failures      int
	openUntil     time.Time
	failThreshold int
	cooldown      time.Duration
}

// RemoteNEROptions configures the remote NER detector.
// 是远程 NER 检测器的配置。
type RemoteNEROptions struct {
	// Endpoint 是 NER 服务地址，如 http://ner-service:8000/v1/detect
	Endpoint string
	// Timeout 是单次调用超时。它直接叠加在 TTFT 上，必须设得很紧——
	// 宁可让检测失败触发 fail-closed，也不能让每个请求多等一秒。
	Timeout time.Duration
	// CacheTTL / CacheSize 控制检测结果缓存
	CacheTTL  time.Duration
	CacheSize int
	// Types 限定要识别的实体类型。留空则取默认的三类。
	Types []EntityType
	// FailOpen 为 true 时，服务不可用会放行原文（有泄露风险）
	FailOpen bool
	// FailureThreshold / Cooldown 是熔断参数
	FailureThreshold int
	Cooldown         time.Duration
}

// NewRemoteNERDetector creates the remote NER detector.
// 创建远程 NER 检测器。
func NewRemoteNERDetector(opts RemoteNEROptions) (*RemoteNERDetector, error) {
	if opts.Endpoint == "" {
		return nil, fmt.Errorf("NER 服务地址不能为空")
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 300 * time.Millisecond
	}
	if opts.CacheTTL <= 0 {
		opts.CacheTTL = 10 * time.Minute
	}
	if opts.CacheSize <= 0 {
		opts.CacheSize = 4096
	}
	if len(opts.Types) == 0 {
		opts.Types = []EntityType{TypeName, TypeAddress, TypeOrg}
	}
	if opts.FailureThreshold <= 0 {
		opts.FailureThreshold = 5
	}
	if opts.Cooldown <= 0 {
		opts.Cooldown = 15 * time.Second
	}

	return &RemoteNERDetector{
		endpoint: opts.Endpoint,
		types:    opts.Types,
		failOpen: opts.FailOpen,
		cache:    newDetectionCache(opts.CacheSize, opts.CacheTTL),
		client: &http.Client{
			Timeout: opts.Timeout,
			Transport: &http.Transport{
				MaxIdleConnsPerHost: 64,
				IdleConnTimeout:     90 * time.Second,
				DisableCompression:  true,
			},
		},
		failThreshold: opts.FailureThreshold,
		cooldown:      opts.Cooldown,
	}, nil
}

// Name 返回检测器标识。
func (d *RemoteNERDetector) Name() string { return "remote_ner" }

// CoveredTypes 返回本检测器覆盖的类型。
func (d *RemoteNERDetector) CoveredTypes() []EntityType { return d.types }

// nerRequest is the request body sent to the NER service.
// 是发往 NER 服务的请求体。
type nerRequest struct {
	Text  string   `json:"text"`
	Types []string `json:"types"`
}

// nerEntity is one entity returned by the NER service.
// 是 NER 服务返回的单个实体。
//
// Only type/value/confidence are declared — offsets are deliberately not
// accepted; see the type comment on cross-language offset conventions.
// 只声明三个字段，刻意不接受偏移量，见类型注释里的说明。
type nerEntity struct {
	Type       string  `json:"type"`
	Value      string  `json:"value"`
	Confidence float64 `json:"confidence"`
}

// nerResponse is the NER service response body.
// 是 NER 服务的响应体。
type nerResponse struct {
	Entities []nerEntity `json:"entities"`
}

// Detect recognizes named entities in the text.
// 识别文本中的命名实体。
func (d *RemoteNERDetector) Detect(text string) ([]Entity, error) {
	if strings.TrimSpace(text) == "" {
		return nil, nil
	}

	// 缓存命中：Agent 每轮携带的系统提示词与 SOP 完全相同，
	// 这里的命中率决定了 NER 是否可用于生产
	key := cacheKey(text)
	if cached, ok := d.cache.get(key); ok {
		return d.locate(text, cached), nil
	}

	if d.circuitOpen() {
		return d.onFailure(fmt.Errorf("NER 服务处于熔断状态"))
	}

	entities, err := d.call(text)
	if err != nil {
		d.recordFailure()
		return d.onFailure(err)
	}
	d.recordSuccess()

	d.cache.put(key, entities)
	return d.locate(text, entities), nil
}

// call performs one NER service call.
// 执行一次 NER 服务调用。
func (d *RemoteNERDetector) call(text string) ([]nerEntity, error) {
	types := make([]string, len(d.types))
	for i, t := range d.types {
		types[i] = string(t)
	}
	payload, err := json.Marshal(nerRequest{Text: text, Types: types})
	if err != nil {
		return nil, fmt.Errorf("序列化请求失败: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), d.client.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("调用 NER 服务失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("NER 服务返回 %d", resp.StatusCode)
	}

	var out nerResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("解析 NER 响应失败: %w", err)
	}
	return out.Entities, nil
}

// locate maps entity text back to byte offsets in the original.
// 把实体文本回原文定位为字节偏移。
//
// This is the crux of cross-language integration. The service returns text
// only; this side locates it with strings.Index, which naturally yields byte
// offsets matching Go's string indexing — leaving no room for a rune/byte mixup.
// 这是跨语言集成的关键一步。服务只返回实体文本，由本端定位，
// 得到的天然是字节偏移，不存在字符/字节混淆的可能。
//
// Entities that cannot be located are dropped: when the model rewrote the span
// (completing, translating, correcting it), substituting at a wrong offset
// destroys the meaning of the text. Missing one uncertain entity beats shredding
// the body.
// 定位不到的实体会被丢弃：模型改写了片段时，用错误的偏移替换会破坏原文语义。
// 宁可漏掉一个不确定的实体，也不能切碎正文。
func (d *RemoteNERDetector) locate(text string, entities []nerEntity) []Entity {
	if len(entities) == 0 {
		return nil
	}
	allowed := make(map[EntityType]bool, len(d.types))
	for _, t := range d.types {
		allowed[t] = true
	}

	var out []Entity
	for _, e := range entities {
		typ := EntityType(strings.ToUpper(strings.TrimSpace(e.Type)))
		if !allowed[typ] {
			continue // service returned an unrequested type; ignore / 未申请的类型，忽略
		}
		value := e.Value
		if value == "" || !utf8.ValidString(value) {
			continue
		}
		conf := e.Confidence
		if conf <= 0 || conf > 1 {
			conf = 0.85 // conservative default when absent / 未给置信度时取保守默认
		}

		// The same entity may appear more than once; mark them all.
		// 同一实体可能在文中出现多次，全部标记
		from := 0
		for {
			idx := strings.Index(text[from:], value)
			if idx < 0 {
				break
			}
			start := from + idx
			out = append(out, Entity{
				Type: typ, Value: value,
				Start: start, End: start + len(value),
				Confidence: conf, Detector: d.Name(),
			})
			from = start + len(value)
		}
	}
	return out
}

// onFailure applies the fail-open / fail-closed policy to a service failure.
// 按 fail-open / fail-closed 策略处理服务故障。
func (d *RemoteNERDetector) onFailure(err error) ([]Entity, error) {
	if d.failOpen {
		// An explicitly chosen degradation: return no entities without an
		// error, so the caller lets the raw text through. Whoever flipped this
		// switch must know what it means.
		// 显式选择的降级：返回空实体但不报错，上层会放行原文。
		return nil, nil
	}
	return nil, fmt.Errorf("NER 检测失败（fail-closed）: %w", err)
}

// circuitOpen 判断熔断器是否打开。
func (d *RemoteNERDetector) circuitOpen() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return time.Now().Before(d.openUntil)
}

// recordFailure 记录一次失败，达阈值则熔断。
func (d *RemoteNERDetector) recordFailure() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.failures++
	if d.failures >= d.failThreshold {
		d.openUntil = time.Now().Add(d.cooldown)
		d.failures = 0
	}
}

// recordSuccess 记录一次成功，清零失败计数。
func (d *RemoteNERDetector) recordSuccess() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.failures = 0
	d.openUntil = time.Time{}
}

// CacheStats returns hit/miss counts, to verify the cache is actually working.
// A low hit rate means the text changes too often and NER's latency lands
// directly on TTFT.
// 返回缓存命中统计。命中率偏低说明文本变化太频繁，
// NER 的延迟成本会直接压在 TTFT 上。
func (d *RemoteNERDetector) CacheStats() (hits, misses int64) {
	return d.cache.stats()
}

// ---------------------------------------------------------------------------
// Detection result cache / 检测结果缓存
// ---------------------------------------------------------------------------

// cacheKey 计算文本的缓存键。
func cacheKey(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:16])
}

// cacheEntry 是一条缓存记录。
type cacheEntry struct {
	entities []nerEntity
	expireAt time.Time
}

// detectionCache caches detection results with a TTL and a size cap.
// 是带 TTL 与容量上限的检测结果缓存。
//
// Uses "clear everything when full" rather than LRU: the access pattern is a
// handful of long prefixes hit repeatedly, and LRU's bookkeeping (moving list
// nodes and taking a write lock on every read) does not pay for itself here.
// After a clear, hot prefixes refill within a few requests.
// 用简单的「满则整体清空」而非 LRU：NER 缓存的访问模式是少数长前缀
// 被反复命中，LRU 的簿记开销在这个模式下得不偿失。
type detectionCache struct {
	mu      sync.RWMutex
	entries map[string]cacheEntry
	maxSize int
	ttl     time.Duration
	hits    int64
	misses  int64
}

// newDetectionCache 创建缓存。
func newDetectionCache(maxSize int, ttl time.Duration) *detectionCache {
	return &detectionCache{
		entries: make(map[string]cacheEntry, maxSize/4),
		maxSize: maxSize,
		ttl:     ttl,
	}
}

// get 读取缓存。
func (c *detectionCache) get(key string) ([]nerEntity, bool) {
	c.mu.RLock()
	e, ok := c.entries[key]
	c.mu.RUnlock()

	if !ok || time.Now().After(e.expireAt) {
		c.mu.Lock()
		c.misses++
		c.mu.Unlock()
		return nil, false
	}
	c.mu.Lock()
	c.hits++
	c.mu.Unlock()
	return e.entities, true
}

// put 写入缓存。容量满时整体清空。
func (c *detectionCache) put(key string, entities []nerEntity) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= c.maxSize {
		clear(c.entries)
	}
	c.entries[key] = cacheEntry{entities: entities, expireAt: time.Now().Add(c.ttl)}
}

// stats 返回命中与未命中计数。
func (c *detectionCache) stats() (hits, misses int64) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.hits, c.misses
}
