package main

import (
	"embed"
	"encoding/base64"
	"encoding/json"
	"io"
	"io/fs"
	"log"
	"net/http"
	"strings"

	"TI_LAB3/internal/algo"
)

//go:embed web/static
var webFS embed.FS

// ---------- API: /api/crypt ----------
// Обрабатывает текстовый ввод (биты как строка).

type cryptRequest struct {
	Seed      string `json:"seed"`      // начальное состояние регистра (любые символы, фильтруются)
	InputBits string `json:"inputBits"` // входные биты как строка '0'/'1'
	Mode      string `json:"mode"`      // "encrypt" | "decrypt"
}

type cryptResponse struct {
	KeyStream   string `json:"keyStream"`   // ключевой поток (полный)
	ResultBits  string `json:"resultBits"`  // результат (полный)
	InputCount  int    `json:"inputCount"`  // кол-во входных бит
	ResultCount int    `json:"resultCount"` // кол-во выходных бит
	// для отображения — первые DisplayLimit символов
	KeyStreamDisplay  string `json:"keyStreamDisplay"`
	ResultBitsDisplay string `json:"resultBitsDisplay"`
	InputBitsDisplay  string `json:"inputBitsDisplay"`
	Error             string `json:"error,omitempty"`
}

const DisplayLimit = 1000

func cryptHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if r.Method != http.MethodPost {
		writeErr(w, "method not allowed")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 32*1024*1024))
	if err != nil {
		writeErr(w, "ошибка чтения запроса")
		return
	}
	var req cryptRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeErr(w, "некорректный JSON")
		return
	}

	reg, err := lfsr.New(req.Seed)
	if err != nil {
		writeErr(w, err.Error())
		return
	}

	inputFiltered := lfsr.FilterBits(req.InputBits)
	if len(inputFiltered) == 0 {
		writeErr(w, "нет входных данных (нет битов 0/1)")
		return
	}

	result, keyStream := reg.Process(inputFiltered)

	resp := cryptResponse{
		KeyStream:   keyStream,
		ResultBits:  result,
		InputCount:  len(inputFiltered),
		ResultCount: len(result),
		InputBitsDisplay:  trunc(inputFiltered, DisplayLimit),
		KeyStreamDisplay:  trunc(keyStream, DisplayLimit),
		ResultBitsDisplay: trunc(result, DisplayLimit),
	}
	json.NewEncoder(w).Encode(resp)
}

// ---------- API: /api/file-to-bits ----------
// Принимает файл (base64), возвращает битовую строку.

type fileToBitsRequest struct {
	FileData string `json:"fileData"` // base64
}
type fileToBitsResponse struct {
	Bits  string `json:"bits"`
	Count int    `json:"count"`
	Error string `json:"error,omitempty"`
}

func fileToBitsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if r.Method != http.MethodPost {
		writeErrGeneric(w, "method not allowed")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 60*1024*1024))
	if err != nil {
		writeErrGeneric(w, "ошибка чтения")
		return
	}
	var req fileToBitsRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeErrGeneric(w, "некорректный JSON")
		return
	}
	data, err := base64.StdEncoding.DecodeString(req.FileData)
	if err != nil || len(data) == 0 {
		writeErrGeneric(w, "некорректные данные файла")
		return
	}
	bits := lfsr.BytesToBits(data)
	json.NewEncoder(w).Encode(fileToBitsResponse{Bits: bits, Count: len(bits)})
}

// ---------- API: /api/bits-to-file ----------
// Принимает строку битов, возвращает файл (base64).

type bitsToFileRequest struct {
	Bits string `json:"bits"`
}
type bitsToFileResponse struct {
	FileData string `json:"fileData"` // base64
	Size     int    `json:"size"`     // байт
	Error    string `json:"error,omitempty"`
}

func bitsToFileHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if r.Method != http.MethodPost {
		writeErrGeneric(w, "method not allowed")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 32*1024*1024))
	if err != nil {
		writeErrGeneric(w, "ошибка чтения")
		return
	}
	var req bitsToFileRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeErrGeneric(w, "некорректный JSON")
		return
	}
	bits := lfsr.FilterBits(req.Bits)
	if len(bits)%8 != 0 {
		writeErrGeneric(w, "длина бит не кратна 8 — невозможно сохранить как байты")
		return
	}
	data, err := lfsr.BitsToBytes(bits)
	if err != nil {
		writeErrGeneric(w, err.Error())
		return
	}
	json.NewEncoder(w).Encode(bitsToFileResponse{
		FileData: base64.StdEncoding.EncodeToString(data),
		Size:     len(data),
	})
}

// ---------- helpers ----------

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func writeErr(w http.ResponseWriter, msg string) {
	json.NewEncoder(w).Encode(cryptResponse{Error: msg})
}

func writeErrGeneric(w http.ResponseWriter, msg string) {
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func resultFileName(name, mode string) string {
	if mode == "encrypt" {
		return name + ".enc"
	}
	if t := strings.TrimSuffix(name, ".enc"); t != name {
		return t
	}
	return "decrypted_" + name
}

// ---------- main ----------

func main() {
	static, err := fs.Sub(webFS, "web/static")
	if err != nil {
		log.Fatalf("web/static не найден: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(static)))
	mux.HandleFunc("/api/crypt", cryptHandler)
	mux.HandleFunc("/api/file-to-bits", fileToBitsHandler)
	mux.HandleFunc("/api/bits-to-file", bitsToFileHandler)

	addr := ":8080"
	log.Printf("LFSR Web App (x^23 + x^5 + 1) → http://localhost%s\n", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
