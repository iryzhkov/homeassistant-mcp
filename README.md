# homeassistant-mcp

A Go MCP server for [Home Assistant](https://www.home-assistant.io) that exposes entities, services, automations, and history as tools for AI assistants via the [Model Context Protocol](https://modelcontextprotocol.io).

Communicates with the Home Assistant REST API using long-lived access tokens.

## Installation

```bash
go build -o homeassistant-mcp .
```

## Prerequisites

Create a long-lived access token in Home Assistant:

1. Go to your HA instance → **Profile** (bottom left)
2. Scroll to **Long-Lived Access Tokens**
3. Click **Create Token**, give it a name
4. Copy the token

## Configuration

Copy the example config and add your token:

```bash
cp config.example.json config.json
```

```json
{
  "url": "http://192.168.1.100:8123",
  "token": "your-long-lived-access-token",
  "allow_mutations": false
}
```

## Available Tools

### Read-only (always available)

| Tool | Description |
|---|---|
| `get_config` | HA configuration (version, location, units) |
| `list_entities` | All entities or filtered by domain |
| `get_state` | Current state and attributes of an entity |
| `get_history` | State history over a time period |
| `list_services` | Available services by domain |
| `list_automations` | All automations with state and last triggered |
| `list_scenes` | All configured scenes |
| `get_logbook` | Recent logbook entries |
| `get_error_log` | HA error log |

### Mutations (requires `allow_mutations: true`)

| Tool | Description |
|---|---|
| `call_service` | Call any HA service (turn on lights, etc.) |
| `trigger_automation` | Trigger an automation manually |
| `activate_scene` | Activate a scene |

## Claude Desktop Integration

```json
{
  "mcpServers": {
    "homeassistant": {
      "command": "/path/to/homeassistant-mcp",
      "args": ["--config", "/path/to/config.json"]
    }
  }
}
```

## License

MIT
