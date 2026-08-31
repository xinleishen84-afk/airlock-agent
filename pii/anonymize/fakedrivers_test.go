package anonymize

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// fakeCache 是 Cache 契约的内存实现，用于在没有 Redis 的环境里跑驱动用例。
// An in-memory Cache used to exercise the driver without a Redis.
//
// 它刻意实现「不存在才写」的真实语义（而不是直接 Set），
// 否则并发收敛的用例会因为替身比真实实现更宽松而通过。
// It deliberately implements real set-if-absent semantics: a laxer double
// would let the convergence test pass for the wrong reason.
// ---------------------------------------------------------------------------

type fakeCache struct {
	mu      sync.Mutex
	data    map[string]string
	ttls    map[string]time.Duration
	failGet bool
	getN    int
	setN    int

	// failWriteFrom 让第 N 次（1 起数）及之后的写入失败。
	// Makes the Nth write onward fail.
	failWriteFrom int
}

func newFakeCache() *fakeCache {
	return &fakeCache{data: map[string]string{}, ttls: map[string]time.Duration{}}
}

// ttlOf 返回某个键写入时用的 TTL，供不变量断言使用。
func (c *fakeCache) ttlOf(key string) (time.Duration, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	d, ok := c.ttls[key]
	return d, ok
}

// keysWith 返回含某个中缀的键，用来分辨正向与反向映射。
func (c *fakeCache) keysWith(infix string) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	for k := range c.data {
		if strings.Contains(k, infix) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func (c *fakeCache) Get(_ context.Context, key string) (string, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.getN++
	if c.failGet {
		return "", false, errors.New("模拟的缓存故障 / simulated cache outage")
	}
	v, ok := c.data[key]
	return v, ok, nil
}

// FindOrCreate 实现 Cache。
//
// 整个方法在同一把锁下完成「查—建—取回」，这正是接口要求的原子性：
// 不存在任何时刻，别的调用方能观察到「键已被检查但尚未创建」。
// 真实实现（Redis）用 SET NX GET 一条命令或 Lua 脚本达到同样效果。
//
// 注意 ttl 只在创建时写入：键已存在时不得续期，否则一条被反复读到的映射
// 会永远不过期，而 TTL 正是 PII 的保留期。
//
// The whole method runs under one lock, which is the atomicity the interface
// demands. The TTL is applied only on creation: refreshing an existing mapping
// would make a frequently-read one immortal, and that TTL is PII retention.
func (c *fakeCache) FindOrCreate(_ context.Context, key, value string,
	ttl time.Duration) (string, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.setN++
	if c.failWriteFrom > 0 && c.setN >= c.failWriteFrom {
		return "", false, errors.New("模拟的写入故障 / simulated write failure")
	}
	if existing, ok := c.data[key]; ok {
		return existing, false, nil
	}
	c.data[key] = value
	c.ttls[key] = ttl
	return value, true, nil
}

func (c *fakeCache) DeleteByPrefix(_ context.Context, prefix string) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for k := range c.data {
		if strings.HasPrefix(k, prefix) {
			delete(c.data, k)
			// 只把反向映射计入条数，与其他驱动的口径保持一致：
			// 正向与反向是同一条令牌的两半，各计一次会让擦除回执翻倍，
			// 而这份回执是要拿去当合规证据的。
			// Only reverse mappings are counted, matching the other drivers:
			// forward and reverse are two halves of one token, and this count
			// is going into a compliance record.
			if strings.Contains(k, ":t:") {
				n++
			}
		}
	}
	return n, nil
}

// ---------------------------------------------------------------------------
// fakeDB 是 SQLExecutor 的内存实现，同时把每条 SQL 与参数记下来，
// 使「复合主键」「租户作用域的 DELETE」这类断言可以直接查语句本身。
// An in-memory SQLExecutor that records every statement and its arguments, so
// assertions about the composite key and the tenant-scoped DELETE can inspect
// the SQL itself.
// ---------------------------------------------------------------------------

type fakeRow struct {
	values []any
	err    error
}

func (r fakeRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	for i := range dest {
		switch d := dest[i].(type) {
		case *string:
			*d = r.values[i].(string)
		case *[]byte:
			*d = r.values[i].([]byte)
		default:
			return fmt.Errorf("fakeRow: 不支持的目标类型 %T", dest[i])
		}
	}
	return nil
}

type fakeResult struct{ n int64 }

func (r fakeResult) RowsAffected() (int64, error) { return r.n, nil }

type fakeRowRec struct {
	tenant, namespace, token, digest string
	cipher                           []byte
}

type fakeDB struct {
	mu         sync.Mutex
	rows       []fakeRowRec
	statements []string
}

func newFakeDB() *fakeDB { return &fakeDB{} }

func (d *fakeDB) ExecContext(_ context.Context, query string, args ...any) (SQLResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.statements = append(d.statements, query)

	switch {
	case strings.HasPrefix(strings.TrimSpace(query), "INSERT"):
		d.rows = append(d.rows, fakeRowRec{
			tenant: args[0].(string), namespace: args[1].(string),
			token: args[2].(string), digest: args[3].(string),
			cipher: args[4].([]byte),
		})
		return fakeResult{n: 1}, nil

	case strings.HasPrefix(strings.TrimSpace(query), "DELETE"):
		tenant := args[0].(string)
		kept := d.rows[:0]
		deleted := int64(0)
		for _, r := range d.rows {
			if r.tenant == tenant {
				deleted++
				continue
			}
			kept = append(kept, r)
		}
		d.rows = kept
		return fakeResult{n: deleted}, nil
	}
	return nil, fmt.Errorf("fakeDB: 未预期的语句 %q", query)
}

func (d *fakeDB) QueryRowContext(_ context.Context, query string, args ...any) SQLRow {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.statements = append(d.statements, query)

	tenant, namespace := args[0].(string), args[1].(string)
	switch {
	case strings.Contains(query, "value_digest = ?"):
		for _, r := range d.rows {
			if r.tenant == tenant && r.namespace == namespace && r.digest == args[2].(string) {
				return fakeRow{values: []any{r.token}}
			}
		}
	case strings.Contains(query, "token = ?"):
		for _, r := range d.rows {
			if r.tenant == tenant && r.namespace == namespace && r.token == args[2].(string) {
				return fakeRow{values: []any{r.cipher}}
			}
		}
	}
	return fakeRow{err: ErrSQLNoRows}
}
