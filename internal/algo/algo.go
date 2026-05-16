// Package lfsr реализует линейный регистр сдвига с обратной связью (LFSR).
// Вариант 1: степень 23, примитивный многочлен x^23 + x^5 + 1.
//
// Топология:
//   reg[0] — старший (выходной) бит, reg[22] — младший.
//   Отводы обратной связи: reg[0] XOR reg[18]  (x^23 и x^5).
//   Сдвиг влево: reg[i] = reg[i+1], в reg[22] записывается feedback.
package algo

import (
	"fmt"
	"strings"
)

const Size = 23

// FilterBits оставляет из строки только символы '0' и '1'.
func FilterBits(s string) string {
	var b strings.Builder
	for _, c := range s {
		if c == '0' || c == '1' {
			b.WriteRune(c)
		}
	}
	return b.String()
}

// Register — LFSR степени 23.
type Register struct {
	reg [Size]bool
}

// New создаёт регистр из строки начального состояния.
// Любые символы кроме '0'/'1' игнорируются.
// После фильтрации должно остаться ровно Size бит, не все нулевые.
func New(state string) (*Register, error) {
	bits := FilterBits(state)
	if len(bits) != Size {
		return nil, fmt.Errorf("требуется ровно %d бит, после фильтрации: %d", Size, len(bits))
	}
	allZero := true
	for _, c := range bits {
		if c == '1' {
			allZero = false
			break
		}
	}
	if allZero {
		return nil, fmt.Errorf("начальное состояние не может быть все нули")
	}
	r := &Register{}
	for i, c := range bits {
		r.reg[i] = c == '1'
	}
	return r, nil
}

// nextBit возвращает один выходной бит и сдвигает регистр влево.
// Выходной бит = reg[0].
// Обратная связь: reg[0] XOR reg[18] — пишется в reg[22].
func (r *Register) nextBit() bool {
	out := r.reg[0]
	fb := r.reg[0] != r.reg[18] // XOR
	copy(r.reg[:], r.reg[1:])
	r.reg[Size-1] = fb
	return out
}

// Process шифрует / дешифрует строку входных бит (XOR побитово).
// Любые символы кроме '0'/'1' во входе игнорируются.
// Возвращает результирующую строку битов и ключевой поток.
func (r *Register) Process(inputBits string) (result, keyStream string) {
	filtered := FilterBits(inputBits)
	res := make([]byte, len(filtered))
	key := make([]byte, len(filtered))
	for i, c := range filtered {
		kb := r.nextBit()
		if kb {
			key[i] = '1'
		} else {
			key[i] = '0'
		}
		in := c == '1'
		if in != kb {
			res[i] = '1'
		} else {
			res[i] = '0'
		}
	}
	return string(res), string(key)
}

// BitsToBytes конвертирует строку битов в срез байт (длина должна быть кратна 8).
func BitsToBytes(bits string) ([]byte, error) {
	if len(bits)%8 != 0 {
		return nil, fmt.Errorf("длина бит (%d) не кратна 8", len(bits))
	}
	out := make([]byte, len(bits)/8)
	for i := range out {
		b := byte(0)
		for j := 0; j < 8; j++ {
			if bits[i*8+j] == '1' {
				b |= 1 << uint(7-j)
			}
		}
		out[i] = b
	}
	return out, nil
}

// BytesToBits конвертирует байты в строку битов.
func BytesToBits(data []byte) string {
	buf := make([]byte, len(data)*8)
	for i, b := range data {
		for j := 0; j < 8; j++ {
			if (b>>(uint(7-j)))&1 == 1 {
				buf[i*8+j] = '1'
			} else {
				buf[i*8+j] = '0'
			}
		}
	}
	return string(buf)
}
