package proxy

import "sync"

// 缓冲池。SSE 代理是每连接热路径，每条流若各自分配读写缓冲，
// 万级并发下仅缓冲本身就是数百 MB，且全部进入 GC 扫描范围。
//
// 池化的收益不只是省内存——更重要的是把 GC 的 STW 停顿次数压下来，
// 停顿直接表现为所有在途流的延迟尖刺。

// readBufSize 是单条流的读缓冲大小。
// 32KB 能容纳数十个典型 LLM chunk，减少 syscall 次数。
const readBufSize = 32 << 10

// writeBufSize 是单条流的写缓冲大小。
// 刻意设小：SSE 要求逐帧 Flush，大写缓冲没有意义，只是浪费。
const writeBufSize = 8 << 10

// readBufPool 复用读缓冲。
var readBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, readBufSize)
		return &b
	},
}

// getReadBuf 取一块读缓冲。
func getReadBuf() *[]byte { return readBufPool.Get().(*[]byte) }

// putReadBuf 归还读缓冲。
func putReadBuf(b *[]byte) { readBufPool.Put(b) }

// scannerPool 复用 SSE 解析器，避免每条流重建 bufio.Reader。
var scannerPool = sync.Pool{
	New: func() any { return NewScanner(nil, readBufSize, DefaultMaxEventSize) },
}
