package detect

import "errors"

// ErrModelDegraded 标记一次「可以降级」的模型层故障。
// Marks a model-layer failure the caller may degrade past.
//
// # 为什么标记放在 detect 里，而不是判断放在传输层
// # Why the marker lives here rather than the decision living in transport
//
// 传输层知道的是「调用失败了，失败类别是什么」；它不知道这次请求能不能
// 少了模型结果还继续。后者取决于部署的取舍：一个只做内部工具的网关可以
// 接受降级，一个对外的合规网关不能。把这个判断塞进 NER 客户端，等于让
// 一个管网络通信的组件替安全策略拿主意。
//
// 所以传输层只负责标出「这次故障是可降级的那一类」（它知道自己被配成了
// fail-open），由级联层决定拿这个标记做什么。级联层同时是唯一持有前两层
// 结果的地方——降级的含义正是「用前两层的结果继续」。
//
// 这条错误必须被 %w 包装而不是直接返回：调用方要能同时拿到「可降级」这个
// 事实与底层的具体原因，后者是排障时唯一有用的东西。
//
// Transport knows a call failed and how; it does not know whether this request
// can proceed without model results. That depends on a deployment's tradeoff,
// so transport only marks the failure as belonging to the degradable class
// (it knows it was configured fail-open) and the cascade decides what to do —
// it is also the only layer holding the first two layers' results, which is
// exactly what degrading means.
var ErrModelDegraded = errors.New(
	"模型层不可用，本次按 fail-open 降级为前两层——" +
		"姓名、地址、机构名本次完全未检测 / model layer degraded")
