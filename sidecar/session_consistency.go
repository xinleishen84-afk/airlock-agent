package sidecar

import (
	"errors"
	"fmt"
)

// SessionConsistencyFlagUsage 是两个二进制共用的 flag 说明文本。
// Shared flag help text for both binaries.
const SessionConsistencyFlagUsage = "必填，取值 single-replica 或 session-affinity。\n" +
	"占位符（PHONE_0、PHONE_1……）是按本副本见过的文本顺序分配的递增序号，\n" +
	"多副本部署下同一会话的同一个占位符会在不同副本上指向不同的真实值——\n" +
	"用户会拿到别人的数据且不报错。声明 session-affinity 表示入口\n" +
	"已按 session id 做一致性哈希（nginx: hash $http_x_session_id consistent）"

// ValidateSessionConsistency 要求运维显式声明本部署如何保证会话跨轮一致。
// Requires an explicit declaration of how session consistency is guaranteed.
//
// # 为什么必填，而不是给一个默认值
// # Why this is required rather than defaulted
//
// 会话保险库把「真实值 -> 占位符」的映射存在进程内存里，占位符是按类型
// 递增的序号，编号取决于该副本见过的文本顺序。两个副本对同一会话会给出
// 不同的编号。
//
// 实测：同一会话下副本 A 把 13800138000 编成 PHONE_0，副本 B 把
// 13900139000 也编成 PHONE_0。上游回一句引用 PHONE_0 的话，A 复原成
// 13800138000，B 复原成 13900139000——用户拿到别人的号码，且不报错。
//
// 客户端每轮重发完整历史时看不出来：分配顺序由文本确定，两副本算得一样。
// 长会话普遍裁剪或摘要历史，一旦裁掉早先的轮次顺序就变了。也就是说
// **会话越长越容易出事**，而短会话怎么测都测不出来。
//
// 这条约束此前只写在 README 里，而出货的 deploy/core.yaml 是 replicas: 3。
// 一条没人执行的注记不是控制措施。两个取值都不能当默认：猜「单副本」会让
// 多副本部署静默串号，猜「有亲和」会替运维签下一个他没做的承诺。
//
// The vault holds the value→placeholder map in process memory as per-type
// ordinals numbered in whatever order that replica saw them, so two replicas
// number one session differently. Measured: a response citing PHONE_0 restored
// to a different real number on each replica — one user receiving another's
// data, silently. Resending full history hides it because ordering then follows
// the text; long sessions trim history and the divergence returns, so the
// failure grows more likely the longer a conversation runs.
//
// The constraint lived only in the README while the shipped manifest set
// replicas: 3. Neither value is safe as a default: assuming single-replica lets
// a multi-replica deployment cross-number sessions, and assuming affinity signs
// a guarantee the operator never made.
func ValidateSessionConsistency(mode string) error {
	switch mode {
	case "single-replica", "session-affinity":
		return nil
	case "":
		return errors.New("必须指定 --session-consistency=single-replica 或 " +
			"--session-consistency=session-affinity：占位符是副本本地的递增序号，" +
			"多副本且入口不做会话亲和时，同一会话的同一个占位符会在不同副本上" +
			"指向不同的真实值，用户会拿到别人的数据且不报错")
	default:
		return fmt.Errorf("未知取值 %q，只能是 single-replica 或 session-affinity", mode)
	}
}
