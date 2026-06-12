package mcpserver

import (
	"github.com/talhaHavadar/interstellar/internal/policy"
	"github.com/talhaHavadar/interstellar/internal/registry"
	"github.com/talhaHavadar/interstellar/internal/session"
)

// statusPayload is the result of interstellar__status.
type statusPayload struct {
	Version   string           `json:"version"`
	Wormholes []wormholeStatus `json:"wormholes"`
	Targets   []targetStatus   `json:"targets"`
}

type wormholeStatus struct {
	Name        string       `json:"name"`
	Version     string       `json:"version"`
	Description string       `json:"description,omitempty"`
	Tools       []toolStatus `json:"tools"`
	Provides    []portStatus `json:"provides,omitempty"`
	Requires    []portStatus `json:"requires,omitempty"`
}

type toolStatus struct {
	Name string `json:"name"`
	// Exposed is false when the tool is hidden from agents.
	Exposed bool   `json:"exposed"`
	Reason  string `json:"reason,omitempty"`
}

type portStatus struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Optional bool   `json:"optional,omitempty"`
}

type targetStatus struct {
	Name     string            `json:"name"`
	Wormhole string            `json:"wormhole"`
	Port     string            `json:"port"`
	Type     string            `json:"type,omitempty"`
	Via      map[string]string `json:"via,omitempty"`
	Live     bool              `json:"live"`
}

func buildStatus(version string, reg *registry.Registry, pol *policy.Engine, sess *session.Manager, byType map[string][]string) statusPayload {
	payload := statusPayload{Version: version, Wormholes: []wormholeStatus{}, Targets: []targetStatus{}}

	for _, w := range reg.All() {
		ws := wormholeStatus{
			Name:        w.Manifest.Name,
			Version:     w.Manifest.Version,
			Description: w.Manifest.Description,
			Tools:       []toolStatus{},
		}
		for _, t := range w.Manifest.Tools {
			ts := toolStatus{Name: toolName(w.Manifest.Name, t.Name), Exposed: true}
			if dec := pol.CheckTool(w.Manifest.Name, t); !dec.Allow {
				ts.Exposed, ts.Reason = false, dec.Reason
			} else if _, reason := portArgsFor(w, t, byType); reason != "" {
				ts.Exposed, ts.Reason = false, reason
			}
			ws.Tools = append(ws.Tools, ts)
		}
		for _, p := range w.Manifest.Provides {
			ws.Provides = append(ws.Provides, portStatus{Name: p.Name, Type: p.Type, Optional: p.Optional})
		}
		for _, p := range w.Manifest.Requires {
			ws.Requires = append(ws.Requires, portStatus{Name: p.Name, Type: p.Type, Optional: p.Optional})
		}
		payload.Wormholes = append(payload.Wormholes, ws)
	}

	if sess != nil {
		for name, t := range sess.Targets() {
			ts := targetStatus{Name: name, Wormhole: t.Wormhole, Port: t.Port, Via: t.Via, Live: sess.IsLive(name)}
			if wh, ok := reg.Get(t.Wormhole); ok {
				if p := findPort(wh.Manifest.Provides, t.Port); p != nil {
					ts.Type = p.Type
				}
			}
			payload.Targets = append(payload.Targets, ts)
		}
	}
	return payload
}
