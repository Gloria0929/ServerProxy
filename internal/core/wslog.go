package core

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
)

// logWS 是仅供读取 sing-box Clash API `/logs` 的最小 WebSocket 客户端。
// 只依赖标准库：处理握手、服务端→客户端文本帧、ping/pong 与 close。
type logWS struct {
	conn net.Conn
	br   *bufio.Reader
}

// dialLogWS 建立 WebSocket 连接并完成升级握手。
func dialLogWS(ctx context.Context, endpoint, secret string) (*logWS, error) {
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", endpoint)
	if err != nil {
		return nil, err
	}
	ws := &logWS{conn: conn, br: bufio.NewReader(conn)}

	keyRaw := make([]byte, 16)
	_, _ = rand.Read(keyRaw)
	key := base64.StdEncoding.EncodeToString(keyRaw)

	req := fmt.Sprintf("GET /logs HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n", endpoint, key)
	if secret != "" {
		req += "Authorization: Bearer " + secret + "\r\n"
	}
	req += "\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, err
	}

	resp, err := http.ReadResponse(ws.br, nil)
	if err != nil {
		conn.Close()
		return nil, err
	}
	// 握手响应体无需读取；帧数据由 ws.br 继续消费。
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		conn.Close()
		return nil, fmt.Errorf("日志通道升级失败：%s", resp.Status)
	}
	return ws, nil
}

// readFrame 返回一条文本帧；自动应答 ping/pong，遇到 close 返回 io.EOF。
func (w *logWS) readFrame() ([]byte, error) {
	for {
		opcode, payload, err := w.readOne()
		if err != nil {
			return nil, err
		}
		switch opcode {
		case 0x9: // ping → pong（客户端帧需 mask）
			_ = w.writeFrame(0xA, payload)
		case 0xA: // pong
			// 忽略
		case 0x8: // close
			return nil, io.EOF
		default:
			return payload, nil
		}
	}
}

func (w *logWS) readOne() (opcode byte, payload []byte, err error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(w.br, header); err != nil {
		return 0, nil, err
	}
	opcode = header[0] & 0x0f
	masked := header[1]&0x80 != 0
	length := uint64(header[1] & 0x7f)

	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(w.br, ext[:]); err != nil {
			return 0, nil, err
		}
		length = uint64(ext[0])<<8 | uint64(ext[1])
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(w.br, ext[:]); err != nil {
			return 0, nil, err
		}
		length = 0
		for _, b := range ext {
			length = length<<8 | uint64(b)
		}
	}

	var maskKey [4]byte
	if masked {
		if _, err := io.ReadFull(w.br, maskKey[:]); err != nil {
			return 0, nil, err
		}
	}

	if length > 4<<20 {
		return 0, nil, fmt.Errorf("日志帧过大：%d 字节", length)
	}
	payload = make([]byte, length)
	if _, err := io.ReadFull(w.br, payload); err != nil {
		return 0, nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}
	return opcode, payload, nil
}

// writeFrame 发送一个带 mask 的控制帧（客户端帧必须 mask）。
func (w *logWS) writeFrame(opcode byte, payload []byte) error {
	var maskKey [4]byte
	_, _ = rand.Read(maskKey[:])

	frame := make([]byte, 0, 2+len(payload)+4)
	frame = append(frame, 0x80|opcode)

	switch {
	case len(payload) < 126:
		frame = append(frame, byte(len(payload))|0x80)
	case len(payload) < 65536:
		frame = append(frame, 126|0x80, byte(len(payload)>>8), byte(len(payload)))
	default:
		frame = append(frame, 127|0x80)
		var ext [8]byte
		n := len(payload)
		for i := 7; i >= 0; i-- {
			ext[i] = byte(n)
			n >>= 8
		}
		frame = append(frame, ext[:]...)
	}
	frame = append(frame, maskKey[:]...)
	for i, b := range payload {
		frame = append(frame, b^maskKey[i%4])
	}
	_, err := w.conn.Write(frame)
	return err
}

func (w *logWS) close() error { return w.conn.Close() }
