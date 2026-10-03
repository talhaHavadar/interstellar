package jev

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/talhaHavadar/interstellar/internal/policy"
)

func TestEvaluateHappyPath(t *testing.T) {
	var gotReq request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer k" {
			t.Errorf("auth header = %q", got)
		}
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &gotReq); err != nil {
			t.Errorf("request body: %v", err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"model": "jev-9.9",
			"answers": map[string]any{
				"q0": map[string]any{"type": "noul", "noul": 0.8},
				"q1": map[string]any{"type": "noul", "noul": 0.1},
			},
		})
	}))
	defer srv.Close()

	c := New(srv.URL, "k", "jev-latest", time.Second)
	vs, err := c.Evaluate(context.Background(),
		policy.CallDescription{Wormhole: "mm", Tool: "post", Args: json.RawMessage(`{"a":1}`)},
		[]string{"rule A", "rule B"})
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 2 {
		t.Fatalf("want 2 verdicts, got %d", len(vs))
	}
	if vs[0].Probability != 0.8 || vs[1].Probability != 0.1 {
		t.Errorf("verdicts mapped by index wrong: %+v", vs)
	}
	if vs[0].Model != "jev-9.9" {
		t.Errorf("model not copied onto verdict: %q", vs[0].Model)
	}
	if gotReq.Model != "jev-latest" {
		t.Errorf("model not sent: %q", gotReq.Model)
	}
	if len(gotReq.Questions) != 2 {
		t.Errorf("want 2 questions in one request, got %d", len(gotReq.Questions))
	}
	if !strings.Contains(string(gotReq.State), `"post"`) {
		t.Errorf("state should carry the tool name, got %s", gotReq.State)
	}
	if !strings.Contains(string(gotReq.State), `"a":1`) {
		t.Errorf("state should carry the arguments, got %s", gotReq.State)
	}
}

func TestEvaluateResultCheckSendsOutput(t *testing.T) {
	var gotReq request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotReq)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"model":   "m",
			"answers": map[string]any{"q0": map[string]any{"type": "noul", "noul": 0.2}},
		})
	}))
	defer srv.Close()

	c := New(srv.URL, "k", "", time.Second)
	_, err := c.Evaluate(context.Background(),
		policy.CallDescription{Wormhole: "vault", Tool: "read", Result: json.RawMessage(`{"token":"abc"}`)},
		[]string{"output has a token"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(gotReq.State), `"output"`) || !strings.Contains(string(gotReq.State), `"token":"abc"`) {
		t.Errorf("state should carry the output, got %s", gotReq.State)
	}
	for _, q := range gotReq.Questions {
		if !strings.Contains(q.Instructions, "output") {
			t.Errorf("result-check instructions should mention the output, got %q", q.Instructions)
		}
	}
}

func TestEvaluateResultCheckWrapsNonJSON(t *testing.T) {
	var gotReq request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &gotReq); err != nil {
			t.Errorf("request body must stay valid JSON even for a plain-text result: %v", err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"model":   "m",
			"answers": map[string]any{"q0": map[string]any{"type": "noul", "noul": 0.1}},
		})
	}))
	defer srv.Close()

	c := New(srv.URL, "k", "", time.Second)
	_, err := c.Evaluate(context.Background(),
		policy.CallDescription{Tool: "t", Result: json.RawMessage(`not json`)},
		[]string{"r"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(gotReq.State), `"output"`) {
		t.Errorf("non-JSON output should still appear in state, got %s", gotReq.State)
	}
}

func TestEvaluateFailsClosedNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, "boom")
	}))
	defer srv.Close()
	c := New(srv.URL, "k", "", time.Second)
	if _, err := c.Evaluate(context.Background(), policy.CallDescription{}, []string{"r"}); err == nil {
		t.Fatal("non-200 must return an error so the caller fails closed")
	}
}

func TestEvaluateFailsClosedMissingAnswer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"model": "m", "answers": map[string]any{}})
	}))
	defer srv.Close()
	c := New(srv.URL, "k", "", time.Second)
	if _, err := c.Evaluate(context.Background(), policy.CallDescription{}, []string{"r"}); err == nil {
		t.Fatal("a missing answer must error")
	}
}

func TestEvaluateFailsClosedBadNoul(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"model":   "m",
			"answers": map[string]any{"q0": map[string]any{"type": "noul", "noul": 1.5}},
		})
	}))
	defer srv.Close()
	c := New(srv.URL, "k", "", time.Second)
	if _, err := c.Evaluate(context.Background(), policy.CallDescription{}, []string{"r"}); err == nil {
		t.Fatal("an out-of-range noul must error")
	}
}

func TestEvaluateFailsClosedOnTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"model":   "m",
			"answers": map[string]any{"q0": map[string]any{"type": "noul", "noul": 0.1}},
		})
	}))
	defer srv.Close()
	c := New(srv.URL, "k", "", 20*time.Millisecond)
	if _, err := c.Evaluate(context.Background(), policy.CallDescription{}, []string{"r"}); err == nil {
		t.Fatal("a timeout must error so the caller fails closed")
	}
}
