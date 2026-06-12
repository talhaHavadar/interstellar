// Command sysinfo is a purpose-built consumer wormhole. It exposes one
// agent-facing tool, get_system_info, which gathers a few specific facts
// about a target machine by running a fixed set of commands through an
// exec-endpoint it requires. The agent picks *which* target; it never
// supplies commands. This is the intended shape of a wormhole that needs
// remote execution: a scoped operation, not a shell.
package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/talhaHavadar/interstellar/pkg/wormhole"
)

type sysInfoInput struct {
	// IncludeDisk also reports filesystem usage.
	IncludeDisk bool `json:"include_disk,omitempty" jsonschema:"also report disk usage"`
}

type sysInfo struct {
	Hostname string            `json:"hostname"`
	Kernel   string            `json:"kernel"`
	Uptime   string            `json:"uptime"`
	Disk     string            `json:"disk,omitempty"`
	Errors   map[string]string `json:"errors,omitempty"`
}

// probe is one fact to gather: a label, the fixed argv to run, and where to
// store the trimmed stdout.
type probe struct {
	label string
	argv  []string
	store func(*sysInfo, string)
}

func main() {
	w := wormhole.New("sysinfo", "0.1.0",
		"Reports basic system information about a target machine.")

	w.Require(wormhole.Port{
		Name:        "shell",
		Type:        wormhole.PortTypeExecEndpoint,
		Description: "the machine to inspect",
	})

	wormhole.AddTool(w, wormhole.Tool[sysInfoInput]{
		Name:          "get_system_info",
		Description:   "Gather hostname, kernel, uptime (and optionally disk usage) from a target machine.",
		Capabilities:  []wormhole.Capability{wormhole.CapExecScoped},
		RequiresPorts: []string{"shell"},
		Handler:       getSystemInfo,
	})

	w.Serve()
}

func getSystemInfo(ctx context.Context, call *wormhole.Call, in sysInfoInput) (any, error) {
	link, ok := call.Link("shell")
	if !ok {
		return nil, fmt.Errorf("no exec endpoint linked")
	}
	var ep wormhole.ExecEndpointDescriptor
	if err := link.DecodeDescriptor(&ep); err != nil {
		return nil, fmt.Errorf("decoding exec endpoint: %w", err)
	}
	runner, err := wormhole.DialExecEndpoint(ep)
	if err != nil {
		return nil, err
	}
	defer runner.Close()

	probes := []probe{
		{"hostname", []string{"uname", "-n"}, func(s *sysInfo, v string) { s.Hostname = v }},
		{"kernel", []string{"uname", "-sr"}, func(s *sysInfo, v string) { s.Kernel = v }},
		{"uptime", []string{"uptime"}, func(s *sysInfo, v string) { s.Uptime = v }},
	}
	if in.IncludeDisk {
		probes = append(probes, probe{"disk", []string{"df", "-h", "/"}, func(s *sysInfo, v string) { s.Disk = v }})
	}

	info := &sysInfo{}
	for i, p := range probes {
		call.Progress(float64(i)/float64(len(probes)), "running "+p.label)
		res, err := runner.Run(ctx, wormhole.Command{Argv: p.argv, TimeoutMs: 10_000})
		if err != nil {
			recordErr(info, p.label, err.Error())
			continue
		}
		if res.ExitCode != 0 {
			recordErr(info, p.label, fmt.Sprintf("exit %d: %s", res.ExitCode, strings.TrimSpace(string(res.Stderr))))
			continue
		}
		p.store(info, strings.TrimSpace(string(res.Stdout)))
	}
	return info, nil
}

func recordErr(info *sysInfo, label, msg string) {
	if info.Errors == nil {
		info.Errors = map[string]string{}
	}
	info.Errors[label] = msg
}
