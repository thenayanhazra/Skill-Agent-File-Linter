/// Helpers for navigating MCP config JSON values.
use serde_json::Value;

/// Returns an iterator over (server_name, server_config) pairs from `mcpServers`.
pub fn mcp_servers(root: &Value) -> impl Iterator<Item = (&str, &Value)> {
    root.get("mcpServers")
        .and_then(|v| v.as_object())
        .into_iter()
        .flat_map(|obj| obj.iter().map(|(k, v)| (k.as_str(), v)))
}

/// Returns the string value at `key` in `obj`, if present.
pub fn str_field<'a>(obj: &'a Value, key: &str) -> Option<&'a str> {
    obj.get(key).and_then(|v| v.as_str())
}

/// Returns the array of string args from a server config.
pub fn args(server: &Value) -> Vec<&str> {
    server
        .get("args")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|a| a.as_str()).collect())
        .unwrap_or_default()
}

/// Returns the list of tool names from a server config.
pub fn tool_names(server: &Value) -> Vec<&str> {
    server
        .get("tools")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|t| {
                    t.as_str().or_else(|| t.get("name").and_then(|n| n.as_str()))
                })
                .collect()
        })
        .unwrap_or_default()
}
