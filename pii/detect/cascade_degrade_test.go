package detect

import (
	"errors"
	"strings"
	"testing"
)

// failingModel 是一个总是失败的模型层，可选择是否标记为可降级。
type failingModel struct{ degradable bool }

func (m failingModel) Name() string { return "failing-model" }

func (m failingModel) CoveredTypes() []EntityType {
	return []EntityType{TypeName, TypeAddress, TypeOrg}
}

func (m failingModel) Detect(string) ([]Entity, error) {
	base := errors.New("connection refused")
	if m.degradable {
		return nil, errors.Join(ErrModelDegraded, base)
	}
	return nil, base
}

// TestCascadeDegradesToFastLayers 证明可降级故障会退回前两层的结果。
// Proves a degradable failure falls back to the first two layers.
//
// # fail-open 此前只是一句话
// # fail-open used to be only a sentence
//
// 传输层在 FailOpen=true 时返回的错误文本写着「已按 fail-open 放行」，而这里
// 无条件 return nil, err——请求整条失败。配了 fail-open 的部署在模型挂掉时与
// fail-closed 表现完全一样，这个开关没有改变任何行为。
//
// 降级的含义是「用前两层的结果继续」：正则、校验位、名册、复姓都还在，
// 只是姓名、地址、机构名这三类完全未检测。这个代价必须单独计数，
// 否则一次长时间宕机会表现为「触发率下降」，看起来像流量特征变了。
//
// The transport said it had let the request through while this propagated the
// error, so a fail-open deployment behaved exactly like a fail-closed one.
// Degrading means continuing with the first two layers' results at the cost of
// names, addresses and organizations going undetected — counted separately so
// an outage does not read as a shift in traffic composition.
func TestCascadeDegradesToFastLayers(t *testing.T) {
	gaz, err := NewGazetteerDetector(
		map[EntityType][]string{TypeName: {"张伟"}}, false, 2)
	if err != nil {
		t.Fatal(err)
	}
	var stats CascadeStats
	c := &Cascade{
		Fast:    NewCompositeDetector([]Detector{gaz}, 0),
		Model:   failingModel{degradable: true},
		OnStats: func(s CascadeStats) { stats = s },
	}

	const text = "联系张伟，手机 13800138000"
	got, err := c.Detect(text)
	if err != nil {
		t.Fatalf("可降级故障不应让整条请求失败——那样 fail-open 这个开关"+
			"就只改了错误文案：%v", err)
	}
	if len(got) == 0 {
		t.Fatal("降级后应保留前两层的结果，实际一个实体都没有——" +
			"那不是降级，是把整条链路一起丢了")
	}
	var names int
	for _, e := range got {
		if e.Type == TypeName && strings.Contains(text[e.Start:e.End], "张伟") {
			names++
		}
	}
	if names == 0 {
		t.Errorf("名册命中的姓名应当保留，实际结果: %+v", got)
	}
	if n := stats.ModelDegraded; n != 1 {
		t.Errorf("降级次数应为 1，实际 %d——降级必须单独计数，"+
			"与 ModelSkipped 混在一起会让一次宕机看起来像流量特征变了", n)
	}
}

// TestCascadeBlocksOnNonDegradableFailure 确认未标记的故障仍然阻断。
// Confirms an unmarked failure still blocks.
//
// 两种语义必须真的不同。fail-closed 下模型不可用意味着姓名类完全未检测，
// 此时放行等于把未脱敏的 PII 送出边界——那正是这个系统存在的理由所要防的。
func TestCascadeBlocksOnNonDegradableFailure(t *testing.T) {
	gaz, err := NewGazetteerDetector(
		map[EntityType][]string{TypeName: {"张伟"}}, false, 2)
	if err != nil {
		t.Fatal(err)
	}
	var stats CascadeStats
	c := &Cascade{
		Fast:    NewCompositeDetector([]Detector{gaz}, 0),
		Model:   failingModel{degradable: false},
		OnStats: func(s CascadeStats) { stats = s },
	}
	if _, err := c.Detect("联系张伟，手机 13800138000"); err == nil {
		t.Fatal("未标记为可降级的故障必须阻断——放行等于把未脱敏的 PII 送出边界")
	}
	if n := stats.ModelDegraded; n != 0 {
		t.Errorf("阻断不该计入降级次数，实际 %d", n)
	}
}
