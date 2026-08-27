package nerclient

import (
	"fmt"
	"unicode/utf8"
)

// # 字符偏移与字节偏移的对齐
// # Aligning character offsets with byte offsets
//
// 这是 Go + Python 联合架构里最容易出错的一处，也是最难发现的一处。
//
// Python 的 str 按 Unicode code point 索引，一个汉字是 1；
// Go 的 string 按字节索引，同一个汉字是 3。
// 文本「你好张三」里，Python 说「张三」在 [2:4]，Go 里它在 [6:12]。
//
// 拿 Python 的 [2:4] 直接去切 Go 的字符串，切出来的是「你」字的后两个
// 字节加「好」字的第一个字节——一段非法 UTF-8。后果有两层：
// 敏感值一个字都没被洗掉，而且报文被切成了下游解析器读不了的东西。
//
// Python indexes str by code point; Go indexes string by byte. In 你好张三,
// Python says 张三 is [2:4] while Go has it at [6:12]. Slicing Go's string
// with [2:4] yields the tail of 你 plus the head of 好 — invalid UTF-8. The
// sensitive value survives untouched, and the payload is now unparseable.
//
// # 为什么光有映射还不够
// # Why the mapping alone is not enough
//
// 映射表本身可能是对的，而两端看到的文本却不是同一份——中间做过 Unicode
// 归一化、去过 BOM、或者某一层把 \r\n 换成了 \n。这些都会让映射结果偏移，
// 而症状是「脱敏了错的几个字」，不是一个异常。
//
// 因此契约里带了 text 字段：映射完成后，切出来的字节必须与它逐字相同。
// 这一步把一类静默的数据损坏变成了一次显式的失败。
//
// The map can be correct while the two sides are not looking at the same text
// — Unicode normalization, a stripped BOM, or CRLF conversion anywhere in
// between shifts everything. The symptom is "the wrong characters were
// redacted", not an exception. The contract therefore carries the entity text,
// and the mapped bytes must equal it.

// offsetIndex maps Unicode code point positions to byte positions.
// 把 Unicode 码点位置映射到字节位置。
type offsetIndex struct {
	// runeToByte[i] 是第 i 个字符的起始字节偏移。
	// 长度为字符数 + 1，最后一项是哨兵，等于 len(text)，
	// 使「实体结束于文本末尾」这个边界情形不需要单独判断。
	//
	// Length is runeCount+1; the final sentinel equals len(text) so that an
	// entity ending at the end of the text needs no special case.
	runeToByte []int
	text       string
}

// newOffsetIndex builds the mapping for one text.
// 为一段文本建立映射。
//
// 用切片而非 map：查找是 O(1) 的数组索引而不是一次哈希，内存也连续。
// 这张表每个请求都要建一次，而它在 TTFT 关键路径上。
//
// A slice rather than a map: lookup is an array index, and the memory is
// contiguous. This table is built once per request, on the TTFT path.
func newOffsetIndex(text string) *offsetIndex {
	idx := &offsetIndex{
		runeToByte: make([]int, 0, utf8.RuneCountInString(text)+1),
		text:       text,
	}
	for byteOff := range text {
		idx.runeToByte = append(idx.runeToByte, byteOff)
	}
	idx.runeToByte = append(idx.runeToByte, len(text))
	return idx
}

// runeCount returns how many code points the text has.
// 返回文本的码点数。
func (i *offsetIndex) runeCount() int { return len(i.runeToByte) - 1 }

// toBytes converts a character span to a byte span and verifies it.
// 把字符区间转换为字节区间并加以验证。
//
// wantText 是服务端声称这个区间里的内容。映射后的切片必须与它逐字相同，
// 否则说明两端看到的不是同一份文本——这时候唯一安全的动作是失败，
// 而不是拿一个错位的区间去脱敏。
//
// wantText is what the server claims the span contains. A mismatch means the
// two sides are not looking at the same text, and the only safe action is to
// fail rather than redact a misaligned span.
func (i *offsetIndex) toBytes(startRune, endRune int, wantText string) (int, int, error) {
	if startRune < 0 || endRune < startRune {
		return 0, 0, fmt.Errorf(
			"字符区间非法 [%d,%d) / invalid rune span", startRune, endRune)
	}
	if endRune > i.runeCount() {
		return 0, 0, fmt.Errorf(
			"字符区间 [%d,%d) 越界，文本共 %d 个字符——"+
				"多半是两端看到的文本长度不同 / rune span out of range",
			startRune, endRune, i.runeCount())
	}

	startByte := i.runeToByte[startRune]
	endByte := i.runeToByte[endRune]

	if got := i.text[startByte:endByte]; got != wantText {
		return 0, 0, fmt.Errorf(
			"偏移映射后与服务端返回的文本不符：字符区间 [%d,%d) 映射为字节区间 "+
				"[%d,%d)，本端切出 %q，服务端声称 %q。"+
				"两端看到的不是同一份文本（Unicode 归一化、BOM、换行符转换都会造成这种情况）"+
				" / offset mismatch after mapping",
			startRune, endRune, startByte, endByte, got, wantText)
	}
	return startByte, endByte, nil
}
