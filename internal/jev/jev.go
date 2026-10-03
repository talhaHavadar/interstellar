// Package jev implements policy.SemanticEngine against the TypeSafe "Jev"
// System One model (https://typesafe.ai). For a tool call it POSTs one "noul"
// (yes/no) question per rule to /v1/systemone and reports each rule's
// violation probability. The whole batch of rules for one call travels in a
// single request, so a semantically-checked tool call costs one round-trip.
//
// The same path serves result-time checks: when the CallDescription carries a
// Result, it is added to the state as "output" and the question is reworded to
// judge the output, so one engine can gate both a call's arguments and its
// returned output.
//
// Every failure path — non-200, transport/timeout, or a malformed answer —
// returns an error rather than a probability, so the caller (policy.CheckCall)
// fails closed and denies.
package jev

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/talhaHavadar/interstellar/internal/policy"
)

const (
	defaultBaseURL = "https://api.typesafe.ai"
	defaultModel   = "jev-latest"
	defaultTimeout = 5 * time.Second
	endpoint       = "/v1/systemone"
	maxResponse    = 1 << 20 // 1 MiB cap on the response body we read
)

// Client talks to the Jev HTTP API. It implements policy.SemanticEngine.
type Client struct {
	baseURL string
	apiKey  string
	model   string
	timeout time.Duration
	httpc   *http.Client
}

// New builds a client. Empty baseURL/model and a non-positive timeout fall
// back to defaults.
func New(baseURL, apiKey, model string, timeout time.Duration) *Client {
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	if model == "" {
		model = defaultModel
	}
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		model:   model,
		timeout: timeout,
		httpc:   &http.Client{},
	}
}

type request struct {
	State     json.RawMessage     `json:"state"`
	Model     string              `json:"model"`
	Questions map[string]question `json:"questions"`
}

type question struct {
	Type         string `json:"type"`
	Instructions string `json:"instructions"`
}

type response struct {
	Model   string            `json:"model"`
	Answers map[string]answer `json:"answers"`
}

type answer struct {
	Type string   `json:"type"`
	Noul *float64 `json:"noul"`
}

// Evaluate asks Jev, per rule, whether the call matches that rule's condition.
// Verdicts are returned in the same order as rules.
func (c *Client) Evaluate(ctx context.Context, call policy.CallDescription, rules []string) ([]policy.Verdict, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	args := call.Args
	if len(args) == 0 {
		args = json.RawMessage("null")
	}
	stateMap := map[string]any{
		"wormhole":  call.Wormhole,
		"tool":      call.Tool,
		"arguments": args,
	}
	// A result-time check carries the tool's output; add it to the state so the
	// question can judge the output rather than the arguments. ContentJson is
	// normally JSON, but guard against a plain-text payload: an invalid
	// fragment here would make the whole request body un-marshalable, which
	// fails closed and would wrongly deny every result.
	resultCheck := len(call.Result) > 0
	if resultCheck {
		out := call.Result
		if !json.Valid(out) {
			quoted, mErr := json.Marshal(string(out))
			if mErr != nil {
				return nil, fmt.Errorf("marshaling result: %w", mErr)
			}
			out = quoted
		}
		stateMap["output"] = out
	}
	state, err := json.Marshal(stateMap)
	if err != nil {
		return nil, fmt.Errorf("marshaling state: %w", err)
	}

	instructions := "The state describes a tool call (its wormhole, tool name, and " +
		"arguments). Answer yes if the tool call matches the following condition, " +
		"otherwise no. Condition: "
	if resultCheck {
		instructions = "The state describes a tool call (its wormhole, tool name, and " +
			"arguments) and the output it returned. Answer yes if the output (or the " +
			"call) matches the following condition, otherwise no. Condition: "
	}

	ids := make([]string, len(rules))
	questions := make(map[string]question, len(rules))
	for i, rule := range rules {
		id := fmt.Sprintf("q%d", i)
		ids[i] = id
		questions[id] = question{
			Type:         "noul",
			Instructions: instructions + rule,
		}
	}

	body, err := json.Marshal(request{State: state, Model: c.model, Questions: questions})
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("calling jev: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return nil, fmt.Errorf("reading jev response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jev returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}

	var parsed response
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, fmt.Errorf("decoding jev response: %w", err)
	}

	verdicts := make([]policy.Verdict, len(rules))
	for i, id := range ids {
		a, ok := parsed.Answers[id]
		if !ok {
			return nil, fmt.Errorf("jev response missing answer %q", id)
		}
		if a.Type != "noul" {
			return nil, fmt.Errorf("jev answer %q has type %q, want noul", id, a.Type)
		}
		if a.Noul == nil {
			return nil, fmt.Errorf("jev answer %q has no noul value", id)
		}
		if *a.Noul < 0 || *a.Noul > 1 {
			return nil, fmt.Errorf("jev answer %q noul %v out of [0,1]", id, *a.Noul)
		}
		verdicts[i] = policy.Verdict{Probability: *a.Noul, Model: parsed.Model}
	}
	return verdicts, nil
}
