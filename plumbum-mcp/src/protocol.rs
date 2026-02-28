//! MCP JSON-RPC protocol handler.

use serde_json::{json, Value};

/// Handle a single JSON-RPC request line.
pub fn handle_request(input: &str) -> String {
    let parsed: Value = match serde_json::from_str(input) {
        Ok(v) => v,
        Err(e) => return json_error(None, -32700, &format!("Parse error: {}", e)),
    };

    let id = parsed.get("id").cloned();
    let method = parsed.get("method").and_then(|m| m.as_str()).unwrap_or("");

    match method {
        "initialize" => {
            let result = json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "resources": { "subscribe": false, "listChanged": false },
                    "tools": {}
                },
                "serverInfo": {
                    "name": "plumbum",
                    "version": env!("CARGO_PKG_VERSION")
                }
            });
            json_result(id, result)
        }

        "resources/list" => {
            let result = json!({
                "resources": [
                    {
                        "uri": "plumbum://domains",
                        "name": "Scored Domains",
                        "description": "List of all scored domains from the latest run",
                        "mimeType": "application/json"
                    },
                    {
                        "uri": "plumbum://status",
                        "name": "Analysis Status",
                        "description": "Current analysis state and run summary",
                        "mimeType": "application/json"
                    }
                ]
            });
            json_result(id, result)
        }

        "tools/list" => {
            let result = json!({
                "tools": [
                    {
                        "name": "plumbum_explain",
                        "description": "Get detailed score decomposition for a domain",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "domain": { "type": "string", "description": "Domain name to explain" }
                            },
                            "required": ["domain"]
                        }
                    },
                    {
                        "name": "plumbum_query",
                        "description": "Query scored domains with filters",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "min_score": { "type": "number", "description": "Minimum composite score" },
                                "severity": { "type": "string", "description": "Filter by severity level" },
                                "limit": { "type": "integer", "description": "Max results to return" }
                            }
                        }
                    }
                ]
            });
            json_result(id, result)
        }

        "tools/call" => {
            let tool_name = parsed.pointer("/params/name")
                .and_then(|n| n.as_str())
                .unwrap_or("");

            match tool_name {
                "plumbum_explain" => {
                    let domain = parsed.pointer("/params/arguments/domain")
                        .and_then(|d| d.as_str())
                        .unwrap_or("unknown");
                    let result = json!({
                        "content": [{
                            "type": "text",
                            "text": format!("Score explanation for '{}' requires an active .plumbum/ database. Run 'plumbum apply' first.", domain)
                        }]
                    });
                    json_result(id, result)
                }
                "plumbum_query" => {
                    let result = json!({
                        "content": [{
                            "type": "text",
                            "text": "Query requires an active .plumbum/ database. Run 'plumbum apply' first."
                        }]
                    });
                    json_result(id, result)
                }
                _ => json_error(id, -32601, &format!("Unknown tool: {}", tool_name)),
            }
        }

        "notifications/initialized" | "ping" => {
            json_result(id, json!({}))
        }

        _ => json_error(id, -32601, &format!("Method not found: {}", method)),
    }
}

fn json_result(id: Option<Value>, result: Value) -> String {
    json!({
        "jsonrpc": "2.0",
        "id": id.unwrap_or(Value::Null),
        "result": result
    }).to_string()
}

fn json_error(id: Option<Value>, code: i64, message: &str) -> String {
    json!({
        "jsonrpc": "2.0",
        "id": id.unwrap_or(Value::Null),
        "error": { "code": code, "message": message }
    }).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initialize() {
        let req = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
        let resp: Value = serde_json::from_str(&handle_request(req)).unwrap();
        assert_eq!(resp["result"]["serverInfo"]["name"], "plumbum");
    }

    #[test]
    fn test_tools_list() {
        let req = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#;
        let resp: Value = serde_json::from_str(&handle_request(req)).unwrap();
        let tools = resp["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 2);
    }

    #[test]
    fn test_unknown_method() {
        let req = r#"{"jsonrpc":"2.0","id":3,"method":"nonexistent"}"#;
        let resp: Value = serde_json::from_str(&handle_request(req)).unwrap();
        assert!(resp.get("error").is_some());
    }
}
