package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// --- Config ---

type Config struct {
	URL            string `json:"url"`
	Token          string `json:"token"`
	AllowMutations bool   `json:"allow_mutations"`
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if cfg.URL == "" || cfg.Token == "" {
		return nil, fmt.Errorf("url and token are required")
	}
	cfg.URL = strings.TrimRight(cfg.URL, "/")
	return &cfg, nil
}

// --- HA API client ---

type HAClient struct {
	baseURL string
	token   string
	http    *http.Client
}

func NewHAClient(cfg *Config) *HAClient {
	return &HAClient{
		baseURL: cfg.URL,
		token:   cfg.Token,
		http:    &http.Client{Timeout: 15 * time.Second},
	}
}

func (c *HAClient) get(path string) (json.RawMessage, error) {
	req, err := http.NewRequest("GET", c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

func (c *HAClient) post(path string, payload any) (json.RawMessage, error) {
	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = strings.NewReader(string(data))
	}

	req, err := http.NewRequest("POST", c.baseURL+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

// --- JSON-RPC types ---

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type response struct {
	JSONRPC string  `json:"jsonrpc"`
	ID      any     `json:"id,omitempty"`
	Result  any     `json:"result,omitempty"`
	Error   *rpcErr `json:"error,omitempty"`
}

type rpcErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type textContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type callToolParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments,omitempty"`
}

type toolDef struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	InputSchema any    `json:"inputSchema"`
}

type prop struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	Default     any    `json:"default,omitempty"`
}

func schema(props map[string]any, required []string) map[string]any {
	s := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

// --- Tool definitions ---

func toolDefinitions(allowMutations bool) []toolDef {
	tools := []toolDef{
		{
			Name: "get_config", Description: "Get Home Assistant configuration info (location, units, version)",
			InputSchema: schema(map[string]any{}, nil),
		},
		{
			Name: "list_entities", Description: "List all entities or filter by domain (e.g. light, sensor, switch, automation)",
			InputSchema: schema(map[string]any{
				"domain": prop{Type: "string", Description: "Filter by domain (e.g. 'light', 'sensor', 'switch', 'climate', 'automation')"},
				"search": prop{Type: "string", Description: "Filter entities by name/id containing this text (case-insensitive)"},
			}, nil),
		},
		{
			Name: "get_state", Description: "Get the current state and attributes of a specific entity",
			InputSchema: schema(map[string]any{
				"entity_id": prop{Type: "string", Description: "Entity ID (e.g. 'light.living_room', 'sensor.temperature')"},
			}, []string{"entity_id"}),
		},
		{
			Name: "get_history", Description: "Get state history for an entity over a time period",
			InputSchema: schema(map[string]any{
				"entity_id": prop{Type: "string", Description: "Entity ID"},
				"hours":     prop{Type: "integer", Description: "Number of hours of history (default 24)", Default: 24},
			}, []string{"entity_id"}),
		},
		{
			Name: "list_services", Description: "List available services, optionally filtered by domain",
			InputSchema: schema(map[string]any{
				"domain": prop{Type: "string", Description: "Filter by domain (e.g. 'light', 'switch')"},
			}, nil),
		},
		{
			Name: "list_automations", Description: "List all automations with their state (on/off) and last triggered time",
			InputSchema: schema(map[string]any{}, nil),
		},
		{
			Name: "list_scenes", Description: "List all configured scenes",
			InputSchema: schema(map[string]any{}, nil),
		},
		{
			Name: "get_logbook", Description: "Get logbook entries for recent events",
			InputSchema: schema(map[string]any{
				"hours":     prop{Type: "integer", Description: "Number of hours to look back (default 24)", Default: 24},
				"entity_id": prop{Type: "string", Description: "Filter by entity ID (optional)"},
			}, nil),
		},
		{
			Name: "get_error_log", Description: "Get Home Assistant error log",
			InputSchema: schema(map[string]any{}, nil),
		},
	}

	if allowMutations {
		tools = append(tools,
			toolDef{
				Name: "call_service", Description: "Call a Home Assistant service (e.g. turn on a light, lock a door)",
				InputSchema: schema(map[string]any{
					"domain":    prop{Type: "string", Description: "Service domain (e.g. 'light', 'switch', 'climate')"},
					"service":   prop{Type: "string", Description: "Service name (e.g. 'turn_on', 'turn_off', 'toggle')"},
					"entity_id": prop{Type: "string", Description: "Target entity ID"},
					"data":      prop{Type: "string", Description: "Additional service data as JSON string (optional)"},
				}, []string{"domain", "service", "entity_id"}),
			},
			toolDef{
				Name: "trigger_automation", Description: "Trigger an automation manually",
				InputSchema: schema(map[string]any{
					"entity_id": prop{Type: "string", Description: "Automation entity ID (e.g. 'automation.morning_lights')"},
				}, []string{"entity_id"}),
			},
			toolDef{
				Name: "activate_scene", Description: "Activate a scene",
				InputSchema: schema(map[string]any{
					"entity_id": prop{Type: "string", Description: "Scene entity ID (e.g. 'scene.movie_night')"},
				}, []string{"entity_id"}),
			},
		)
	}

	return tools
}

// --- Tool dispatch ---

func callTool(ha *HAClient, cfg *Config, params callToolParams) (string, bool) {
	a := params.Arguments
	str := func(key string) string {
		if v, ok := a[key].(string); ok {
			return v
		}
		return ""
	}
	num := func(key string, def int) int {
		if v, ok := a[key].(float64); ok {
			return int(v)
		}
		return def
	}

	switch params.Name {
	case "get_config":
		data, err := ha.get("/api/config")
		if err != nil {
			return err.Error(), true
		}
		return prettyJSON(data), false

	case "list_entities":
		data, err := ha.get("/api/states")
		if err != nil {
			return err.Error(), true
		}
		domain := str("domain")
		search := strings.ToLower(str("search"))

		if domain == "" && search == "" {
			// Return summary: count per domain
			var states []struct {
				EntityID string `json:"entity_id"`
			}
			json.Unmarshal(data, &states)
			counts := map[string]int{}
			for _, s := range states {
				parts := strings.SplitN(s.EntityID, ".", 2)
				if len(parts) == 2 {
					counts[parts[0]]++
				}
			}
			return prettyJSON(counts), false
		}

		// Parse all states and filter
		var states []struct {
			EntityID   string         `json:"entity_id"`
			State      string         `json:"state"`
			Attributes map[string]any `json:"attributes"`
		}
		json.Unmarshal(data, &states)

		type compactEntity struct {
			EntityID     string `json:"entity_id"`
			State        string `json:"state"`
			FriendlyName string `json:"friendly_name,omitempty"`
			DeviceClass  string `json:"device_class,omitempty"`
			Unit         string `json:"unit,omitempty"`
		}

		var results []compactEntity
		for _, s := range states {
			if domain != "" && !strings.HasPrefix(s.EntityID, domain+".") {
				continue
			}
			friendlyName, _ := s.Attributes["friendly_name"].(string)
			if search != "" {
				if !strings.Contains(strings.ToLower(s.EntityID), search) &&
					!strings.Contains(strings.ToLower(friendlyName), search) {
					continue
				}
			}
			deviceClass, _ := s.Attributes["device_class"].(string)
			unit, _ := s.Attributes["unit_of_measurement"].(string)
			results = append(results, compactEntity{
				EntityID:     s.EntityID,
				State:        s.State,
				FriendlyName: friendlyName,
				DeviceClass:  deviceClass,
				Unit:         unit,
			})
		}
		return prettyJSON(results), false

	case "get_state":
		entityID := str("entity_id")
		data, err := ha.get("/api/states/" + entityID)
		if err != nil {
			return err.Error(), true
		}
		return prettyJSON(data), false

	case "get_history":
		entityID := str("entity_id")
		hours := num("hours", 24)
		ts := time.Now().Add(-time.Duration(hours) * time.Hour).Format(time.RFC3339)
		data, err := ha.get(fmt.Sprintf("/api/history/period/%s?filter_entity_id=%s&minimal_response&no_attributes", ts, entityID))
		if err != nil {
			return err.Error(), true
		}
		return prettyJSON(data), false

	case "list_services":
		data, err := ha.get("/api/services")
		if err != nil {
			return err.Error(), true
		}
		domain := str("domain")
		if domain == "" {
			// Return just domain names
			var services []struct {
				Domain string `json:"domain"`
			}
			json.Unmarshal(data, &services)
			var domains []string
			for _, s := range services {
				domains = append(domains, s.Domain)
			}
			return prettyJSON(domains), false
		}
		var services []json.RawMessage
		json.Unmarshal(data, &services)
		for _, s := range services {
			var svc struct {
				Domain string `json:"domain"`
			}
			json.Unmarshal(s, &svc)
			if svc.Domain == domain {
				return prettyJSON(s), false
			}
		}
		return fmt.Sprintf("domain '%s' not found", domain), true

	case "list_automations":
		data, err := ha.get("/api/states")
		if err != nil {
			return err.Error(), true
		}
		var states []json.RawMessage
		json.Unmarshal(data, &states)
		var automations []json.RawMessage
		for _, s := range states {
			var e struct {
				EntityID string `json:"entity_id"`
			}
			json.Unmarshal(s, &e)
			if strings.HasPrefix(e.EntityID, "automation.") {
				automations = append(automations, s)
			}
		}
		return prettyJSON(automations), false

	case "list_scenes":
		data, err := ha.get("/api/states")
		if err != nil {
			return err.Error(), true
		}
		var states []json.RawMessage
		json.Unmarshal(data, &states)
		var scenes []json.RawMessage
		for _, s := range states {
			var e struct {
				EntityID string `json:"entity_id"`
			}
			json.Unmarshal(s, &e)
			if strings.HasPrefix(e.EntityID, "scene.") {
				scenes = append(scenes, s)
			}
		}
		return prettyJSON(scenes), false

	case "get_logbook":
		hours := num("hours", 24)
		ts := time.Now().Add(-time.Duration(hours) * time.Hour).Format(time.RFC3339)
		path := fmt.Sprintf("/api/logbook/%s", ts)
		if eid := str("entity_id"); eid != "" {
			path += "?entity=" + eid
		}
		data, err := ha.get(path)
		if err != nil {
			return err.Error(), true
		}
		return prettyJSON(data), false

	case "get_error_log":
		data, err := ha.get("/api/error_log")
		if err != nil {
			return err.Error(), true
		}
		return string(data), false

	// Mutation tools
	case "call_service":
		if !cfg.AllowMutations {
			return "mutations disabled", true
		}
		domain := str("domain")
		service := str("service")
		entityID := str("entity_id")
		payload := map[string]any{"entity_id": entityID}
		if dataStr := str("data"); dataStr != "" {
			var extra map[string]any
			if err := json.Unmarshal([]byte(dataStr), &extra); err == nil {
				for k, v := range extra {
					payload[k] = v
				}
			}
		}
		result, err := ha.post(fmt.Sprintf("/api/services/%s/%s", domain, service), payload)
		if err != nil {
			return err.Error(), true
		}
		return prettyJSON(result), false

	case "trigger_automation":
		if !cfg.AllowMutations {
			return "mutations disabled", true
		}
		entityID := str("entity_id")
		payload := map[string]any{"entity_id": entityID}
		result, err := ha.post("/api/services/automation/trigger", payload)
		if err != nil {
			return err.Error(), true
		}
		return prettyJSON(result), false

	case "activate_scene":
		if !cfg.AllowMutations {
			return "mutations disabled", true
		}
		entityID := str("entity_id")
		payload := map[string]any{"entity_id": entityID}
		result, err := ha.post("/api/services/scene/turn_on", payload)
		if err != nil {
			return err.Error(), true
		}
		return prettyJSON(result), false

	default:
		return fmt.Sprintf("unknown tool: %s", params.Name), true
	}
}

func prettyJSON(v any) string {
	var raw json.RawMessage
	switch val := v.(type) {
	case json.RawMessage:
		raw = val
	case []byte:
		raw = val
	default:
		data, _ := json.MarshalIndent(v, "", "  ")
		return string(data)
	}
	var parsed any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return string(raw)
	}
	data, _ := json.MarshalIndent(parsed, "", "  ")
	return string(data)
}

// --- Server ---

func handleRequest(ha *HAClient, cfg *Config, req request) response {
	switch req.Method {
	case "initialize":
		return response{
			JSONRPC: "2.0", ID: req.ID,
			Result: map[string]any{
				"protocolVersion": "2024-11-05",
				"capabilities":   map[string]any{"tools": map[string]any{}},
				"serverInfo":     map[string]any{"name": "homeassistant-mcp", "version": "1.0.0"},
			},
		}
	case "notifications/initialized":
		return response{}
	case "tools/list":
		return response{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{"tools": toolDefinitions(cfg.AllowMutations)}}
	case "tools/call":
		var params callToolParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return response{JSONRPC: "2.0", ID: req.ID, Error: &rpcErr{Code: -32602, Message: "invalid params"}}
		}
		result, isErr := callTool(ha, cfg, params)
		return response{
			JSONRPC: "2.0", ID: req.ID,
			Result: map[string]any{
				"content": []textContent{{Type: "text", Text: result}},
				"isError": isErr,
			},
		}
	default:
		return response{JSONRPC: "2.0", ID: req.ID, Error: &rpcErr{Code: -32601, Message: "method not found"}}
	}
}

func writeResponse(w io.Writer, resp response) {
	if resp.JSONRPC == "" {
		return
	}
	data, _ := json.Marshal(resp)
	fmt.Fprintf(w, "%s\n", data)
}

func main() {
	defaultConfig := "config.json"
	if home, err := os.UserHomeDir(); err == nil {
		candidate := home + "/Development/homeassistant-mcp/config.json"
		if _, err := os.Stat(candidate); err == nil {
			defaultConfig = candidate
		}
	}
	configPath := flag.String("config", defaultConfig, "Path to config file")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	ha := NewHAClient(cfg)

	reader := bufio.NewReader(os.Stdin)
	writer := os.Stdout

	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				return
			}
			fmt.Fprintf(os.Stderr, "read error: %v\n", err)
			return
		}

		var req request
		if err := json.Unmarshal(line, &req); err != nil {
			writeResponse(writer, response{JSONRPC: "2.0", Error: &rpcErr{Code: -32700, Message: "parse error"}})
			continue
		}

		resp := handleRequest(ha, cfg, req)
		writeResponse(writer, resp)
	}
}
