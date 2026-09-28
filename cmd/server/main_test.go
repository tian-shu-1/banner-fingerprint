package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"bannerfp/internal/engine"
	"bannerfp/internal/model"
)

func newTestEngine(t *testing.T) *engine.Engine {
	t.Helper()
	eng, err := engine.LoadDir(filepath.Join("..", "..", "rules"), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	return eng
}

func TestFingerprintUnknownDoesNotFailBatch(t *testing.T) {
	eng := newTestEngine(t)
	body := `[{"ip":"1.2.3.23","port":12345,"banner":"QUIT\r\n"}]`
	req := httptest.NewRequest(http.MethodPost, "/fingerprint", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handleFingerprint(rec, req, eng, slog.New(slog.NewTextHandler(io.Discard, nil)), 8<<20, 10000)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var results []model.Result
	if err := json.Unmarshal(rec.Body.Bytes(), &results); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(results) != 1 || results[0].Protocol != "unknown" {
		t.Fatalf("results = %#v", results)
	}
}

func TestFingerprintLenientMySQLPayload(t *testing.T) {
	eng := newTestEngine(t)
	body := `[{"ip":"1.2.3.7","port":3306,"banner":"J\x00\x00\x00\n8.0.32\x00"}]`
	req := httptest.NewRequest(http.MethodPost, "/fingerprint", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handleFingerprint(rec, req, eng, slog.New(slog.NewTextHandler(io.Discard, nil)), 8<<20, 10000)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("X-Parse-Mode") != "lenient" {
		t.Fatalf("X-Parse-Mode = %q", rec.Header().Get("X-Parse-Mode"))
	}
	var results []model.Result
	if err := json.Unmarshal(rec.Body.Bytes(), &results); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(results) != 1 || results[0].Product != "MySQL" || results[0].Version != "8.0.32" {
		t.Fatalf("results = %#v", results)
	}
}

func TestFingerprintMalformedJSONReturns400(t *testing.T) {
	eng := newTestEngine(t)
	req := httptest.NewRequest(http.MethodPost, "/fingerprint", strings.NewReader("{not json"))
	rec := httptest.NewRecorder()

	handleFingerprint(rec, req, eng, slog.New(slog.NewTextHandler(io.Discard, nil)), 8<<20, 10000)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}
