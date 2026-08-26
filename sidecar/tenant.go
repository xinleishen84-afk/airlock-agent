package sidecar

import (
	"fmt"
	"net/http"

	"github.com/xinleishen84-afk/airlock-agent/pii/anonymize"
)

// # Tenant resolution
// # 租户解析
//
// The tenant must come from something the caller cannot choose freely. A
// request body field would let any caller declare itself to be any tenant,
// which is not isolation but a naming convention.
// 租户必须来自调用方不能随意选择的东西。
// 请求体里的一个字段会让任何调用方声称自己是任何租户——
// 那不是隔离，那是命名约定。
//
// Which of these is safe depends entirely on who can reach the port. A header
// resolver is safe behind a mesh that strips and re-stamps that header, and is
// no protection at all on a port anything can dial.
// 哪一种是安全的，完全取决于谁能连到这个端口。
// 头部解析器在「会剥离并重新盖章该头部」的服务网格后面是安全的，
// 而在任何东西都能拨通的端口上则毫无防护作用。

// TenantResolver derives the tenant from a request.
// 从请求推导租户。
type TenantResolver interface {
	// Name identifies the resolver in startup logs, so an operator can see
	// which isolation model is actually in effect.
	// 在启动日志中标识本解析器，使运维能看清实际生效的是哪种隔离模型。
	Name() string

	// Resolve returns the tenant, or an error if it cannot be established.
	// 返回租户；无法确定时返回错误。
	//
	// Returning an error must block the request. A resolver that falls back to
	// a default tenant on failure merges every unauthenticated caller into one
	// isolation domain — and that domain then holds real PII.
	// 返回错误必须阻断请求。失败时回退到默认租户的解析器，
	// 会把所有未认证的调用方合并进同一个隔离域——而那个域里装着真实 PII。
	Resolve(r *http.Request) (anonymize.Tenant, error)
}

// HeaderTenantResolver reads the tenant from a request header.
// 从请求头读取租户。
//
// Only safe where an upstream the caller cannot bypass sets that header: a
// service mesh, an authenticating gateway, an ingress with mTLS. On a port the
// caller can reach directly this is equivalent to letting them pick their own
// tenant.
// 只有当一个调用方绕不过去的上游来设置这个头部时才是安全的：
// 服务网格、做认证的网关、带 mTLS 的入口。
// 在调用方能直连的端口上，这等于让他们自己挑租户。
type HeaderTenantResolver struct {
	Header string
}

// NewHeaderTenantResolver builds a header-based resolver.
// 构造基于头部的解析器。
func NewHeaderTenantResolver(header string) (*HeaderTenantResolver, error) {
	if header == "" {
		return nil, fmt.Errorf("租户头部名不能为空 / tenant header name is required")
	}
	return &HeaderTenantResolver{Header: header}, nil
}

// Name implements TenantResolver.
func (h *HeaderTenantResolver) Name() string { return "header:" + h.Header }

// Resolve implements TenantResolver.
func (h *HeaderTenantResolver) Resolve(r *http.Request) (anonymize.Tenant, error) {
	raw := r.Header.Get(h.Header)
	if raw == "" {
		return "", fmt.Errorf("缺少 %s 头部——无法确定租户，请求已阻断 / missing %s header",
			h.Header, h.Header)
	}
	t := anonymize.Tenant(raw)
	if err := anonymize.ValidateTenant(t); err != nil {
		return "", err
	}
	return t, nil
}

// StaticTenantResolver assigns every request to one tenant.
// 把所有请求归入同一个租户。
//
// For genuinely single-tenant deployments. It exists as an explicit type rather
// than as "leave the resolver nil" so that running without isolation is a
// decision written down in the code and printed at startup, not the default
// that happens when nobody thought about it.
// 供确实是单租户的部署使用。它以显式类型存在，而不是「解析器留空」，
// 是为了让「不做隔离地运行」成为一个写在代码里、并在启动时打印出来的决定，
// 而不是没人想过时自然发生的默认值。
type StaticTenantResolver struct {
	tenant anonymize.Tenant
}

// NewStaticTenantResolver builds a single-tenant resolver.
// 构造单租户解析器。
func NewStaticTenantResolver(t anonymize.Tenant) (*StaticTenantResolver, error) {
	if err := anonymize.ValidateTenant(t); err != nil {
		return nil, err
	}
	return &StaticTenantResolver{tenant: t}, nil
}

// Name implements TenantResolver.
func (s *StaticTenantResolver) Name() string { return "static:" + string(s.tenant) }

// Resolve implements TenantResolver.
func (s *StaticTenantResolver) Resolve(*http.Request) (anonymize.Tenant, error) {
	return s.tenant, nil
}
