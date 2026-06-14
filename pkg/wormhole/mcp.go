package wormhole

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	mcpxv1 "github.com/talhaHavadar/interstellar/gen/mcpx/v1"
)

// MCPToolInfo is an upstream MCP tool as advertised by the server behind an
// mcp-endpoint.
type MCPToolInfo struct {
	Name        string
	Description string
	// InputSchemaJSON is the upstream tool's JSON Schema, as raw JSON.
	InputSchemaJSON []byte
}

// MCPCallResult is the outcome of calling an upstream MCP tool.
type MCPCallResult struct {
	// IsError reports a tool-level error reported by the upstream server (as
	// opposed to a transport failure, which surfaces as a returned error).
	IsError bool
	// ContentJSON is the JSON array of upstream content blocks.
	ContentJSON []byte
	// StructuredJSON is the upstream tool's structured output, if any.
	StructuredJSON []byte
}

// Text concatenates the text of every "text" content block in the result,
// ignoring non-text blocks. It is a convenience for the common case of an
// upstream tool that returns plain text.
func (r *MCPCallResult) Text() string {
	if len(r.ContentJSON) == 0 {
		return ""
	}
	var blocks []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(r.ContentJSON, &blocks); err != nil {
		return ""
	}
	var out string
	for _, b := range blocks {
		if b.Type == "text" {
			out += b.Text
		}
	}
	return out
}

// MCPBackend is the upstream an mcp-endpoint provider serves. A provider
// wormhole implements it (typically by wrapping a live client session to a
// third-party MCP server) and hands it to ServeMCPEndpoint.
type MCPBackend interface {
	// ListTools returns the upstream server's advertised tools.
	ListTools(ctx context.Context) ([]MCPToolInfo, error)
	// CallTool invokes one upstream tool. argsJSON is a JSON object matching
	// the upstream tool's input schema.
	CallTool(ctx context.Context, name string, argsJSON []byte) (*MCPCallResult, error)
}

// ServeMCPEndpoint starts an MCPProxyService backed by b on a freshly created
// unix socket under dir, and returns its descriptor plus a stop function.
// Provider wormholes call this from a LinkHandler:
//
//	desc, stop, err := wormhole.ServeMCPEndpoint(linkDir, backend)
//	return &wormhole.ActiveLink{Descriptor: desc, Close: stop}, err
func ServeMCPEndpoint(dir string, b MCPBackend) (MCPEndpointDescriptor, func() error, error) {
	if b == nil {
		return MCPEndpointDescriptor{}, nil, fmt.Errorf("mcp endpoint backend is nil")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return MCPEndpointDescriptor{}, nil, fmt.Errorf("creating link dir: %w", err)
	}
	sock := filepath.Join(dir, "mcp.sock")
	_ = os.Remove(sock)
	lis, err := net.Listen("unix", sock)
	if err != nil {
		return MCPEndpointDescriptor{}, nil, fmt.Errorf("listening on link socket: %w", err)
	}

	srv := grpc.NewServer()
	mcpxv1.RegisterMCPProxyServiceServer(srv, &mcpProxyServer{backend: b})

	go srv.Serve(lis)

	var once sync.Once
	stop := func() error {
		once.Do(func() {
			srv.GracefulStop()
			_ = os.Remove(sock)
		})
		return nil
	}
	return MCPEndpointDescriptor{Address: "unix://" + sock}, stop, nil
}

type mcpProxyServer struct {
	mcpxv1.UnimplementedMCPProxyServiceServer
	backend MCPBackend
}

func (s *mcpProxyServer) ListTools(ctx context.Context, _ *mcpxv1.ListToolsRequest) (*mcpxv1.ListToolsResponse, error) {
	tools, err := s.backend.ListTools(ctx)
	if err != nil {
		return nil, err
	}
	resp := &mcpxv1.ListToolsResponse{}
	for _, t := range tools {
		resp.Tools = append(resp.Tools, &mcpxv1.ToolInfo{
			Name:            t.Name,
			Description:     t.Description,
			InputSchemaJson: string(t.InputSchemaJSON),
		})
	}
	return resp, nil
}

func (s *mcpProxyServer) CallTool(ctx context.Context, req *mcpxv1.CallToolRequest) (*mcpxv1.CallToolResponse, error) {
	args := req.GetArgumentsJson()
	res, err := s.backend.CallTool(ctx, req.GetName(), []byte(args))
	if err != nil {
		return nil, err
	}
	return &mcpxv1.CallToolResponse{
		IsError:        res.IsError,
		ContentJson:    string(res.ContentJSON),
		StructuredJson: string(res.StructuredJSON),
	}, nil
}

// MCPProxy calls an upstream MCP server through an mcp-endpoint provided by
// another wormhole. Obtain one with DialMCPEndpoint, typically from the link a
// tool receives on a required mcp-endpoint port.
type MCPProxy struct {
	conn   *grpc.ClientConn
	client mcpxv1.MCPProxyServiceClient
}

// DialMCPEndpoint connects to an mcp-endpoint described by an
// MCPEndpointDescriptor (decoded from a link). Close it when done.
func DialMCPEndpoint(d MCPEndpointDescriptor) (*MCPProxy, error) {
	if d.Address == "" {
		return nil, fmt.Errorf("mcp endpoint descriptor has no address")
	}
	conn, err := grpc.NewClient(d.Address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("dialing mcp endpoint: %w", err)
	}
	return &MCPProxy{conn: conn, client: mcpxv1.NewMCPProxyServiceClient(conn)}, nil
}

// ListTools returns the upstream server's advertised tools.
func (p *MCPProxy) ListTools(ctx context.Context) ([]MCPToolInfo, error) {
	resp, err := p.client.ListTools(ctx, &mcpxv1.ListToolsRequest{})
	if err != nil {
		return nil, err
	}
	out := make([]MCPToolInfo, 0, len(resp.GetTools()))
	for _, t := range resp.GetTools() {
		out = append(out, MCPToolInfo{
			Name:            t.GetName(),
			Description:     t.GetDescription(),
			InputSchemaJSON: []byte(t.GetInputSchemaJson()),
		})
	}
	return out, nil
}

// CallTool invokes one upstream tool. args is marshaled to a JSON object; pass
// nil for no arguments. A non-nil error is a transport failure; a tool-level
// error is reported via MCPCallResult.IsError.
func (p *MCPProxy) CallTool(ctx context.Context, name string, args any) (*MCPCallResult, error) {
	var argsJSON []byte
	if args != nil {
		b, err := json.Marshal(args)
		if err != nil {
			return nil, fmt.Errorf("encoding arguments: %w", err)
		}
		argsJSON = b
	}
	resp, err := p.client.CallTool(ctx, &mcpxv1.CallToolRequest{
		Name:          name,
		ArgumentsJson: string(argsJSON),
	})
	if err != nil {
		return nil, err
	}
	return &MCPCallResult{
		IsError:        resp.GetIsError(),
		ContentJSON:    []byte(resp.GetContentJson()),
		StructuredJSON: []byte(resp.GetStructuredJson()),
	}, nil
}

// Close releases the connection.
func (p *MCPProxy) Close() error { return p.conn.Close() }
