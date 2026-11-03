//! opsguard-mcp —— AI 可控的 MCP stdio 服务器（开源版，零外部依赖）
//!
//! ## 接入方式（任一 MCP 客户端）
//!
//! ```json
//! { "mcpServers": { "opsguard": { "command": "opsguard-mcp", "args": ["--audit", "~/.opsguard/audit.jsonl"] } } }
//! ```
//!
//! ## 暴露的工具（4 个）
//!
//! | 工具 | 作用 | 读写 |
//! |---|---|---|
//! | `gate_check` | 评估操作是否被当前闸门策略放行（默认策略 = 全放行，可用参数选择维护窗口闸） | 只读 |
//! | `audit_append` | 向审计哈希链追加一条操作记录（AI 的每次操作都应记） | 追加 |
//! | `audit_verify` | 校验审计链完整性（返回总环数/断链位置/损坏行数） | 只读 |
//! | `update_status` | 查询自更新模块是否启用（透明度：AI/用户可确认本构建没有隐藏更新通道） | 只读 |
//!
//! ## 协议
//!
//! JSON-RPC 2.0 over stdio（MCP 规范 2024-11-05 的最小实现子集）：
//! `initialize` / `tools/list` / `tools/call` / `ping`，其余 method 回 `-32601`。
//! 无网络、无遥测；审计文件路径由 `--audit` 参数指定（缺省 `~/.opsguard/audit.jsonl`）。
//!
//! ## 闸门策略
//!
//! 默认 `AllowAllGate`（零硬闸门承诺）。`--maintenance <reason>` 参数可附加维护
//! 窗口闸（写操作拒绝、只读放行）——这是运行时显式选择，不是硬编码。

use std::io::{BufRead, Write};
use std::process::ExitCode;

use opsguard_gates::audit_store::AuditStore;
use opsguard_gates::{Action, ActionGate, AllowAllGate, ChainedGate, MaintenanceWindowGate};

fn main() -> ExitCode {
    let mut audit_path = home_audit_path();
    let mut maintenance: Option<String> = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--audit" => {
                if let Some(p) = args.next() {
                    audit_path = shellexpand_home(&p);
                }
            }
            "--maintenance" => {
                maintenance = Some(args.next().unwrap_or_else(|| "维护窗口内禁止写操作".into()));
            }
            "--help" | "-h" => {
                println!("opsguard-mcp —— OpsGuard MCP stdio 服务器");
                println!("  --audit <path>        审计 JSONL 路径（默认 ~/.opsguard/audit.jsonl）");
                println!("  --maintenance <text>  附加维护窗口闸（写操作拒绝）");
                eprintln!("见 --help");
                return ExitCode::SUCCESS;
            }
            _ => {}
        }
    }

    // 闸门装配：默认全放行；--maintenance 显式叠加（可插拔设计）
    let gate: Box<dyn ActionGate> = match &maintenance {
        Some(reason) => Box::new(
            ChainedGate::new()
                .push(Box::new(MaintenanceWindowGate {
                    in_window: true,
                    reason: reason.clone(),
                }))
                .push(Box::new(AllowAllGate)),
        ),
        None => Box::new(AllowAllGate),
    };

    let store = AuditStore::new(audit_path);
    let mut server = McpServer { gate, store };
    server.serve_stdio();
    ExitCode::SUCCESS
}

fn home_audit_path() -> std::path::PathBuf {
    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_else(|_| ".".into());
    std::path::PathBuf::from(home).join(".opsguard").join("audit.jsonl")
}

fn shellexpand_home(p: &str) -> std::path::PathBuf {
    if let Some(rest) = p.strip_prefix("~/") {
        let home = std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME")).unwrap_or_default();
        return std::path::PathBuf::from(home).join(rest);
    }
    std::path::PathBuf::from(p)
}

struct McpServer {
    gate: Box<dyn ActionGate>,
    store: AuditStore,
}

impl McpServer {
    fn serve_stdio(&mut self) {
        let stdin = std::io::stdin();
        let mut out = std::io::stdout();
        for line in stdin.lock().lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => break,
            };
            if line.trim().is_empty() {
                continue;
            }
            let resp = self.handle_line(&line);
            if let Some(r) = resp {
                writeln!(out, "{r}").ok();
                out.flush().ok();
            }
        }
    }

    /// 处理一条 JSON-RPC 请求；None = 不回复（如 notification）
    fn handle_line(&self, line: &str) -> Option<String> {
        let v: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => return Some(error_response(serde_json::Value::Null, -32700, "解析错误")),
        };
        let id = v.get("id").cloned().unwrap_or(serde_json::Value::Null);
        // notification（无 id）不回复
        if v.get("id").is_none() {
            return None;
        }
        let method = v.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let params = v.get("params").cloned().unwrap_or(serde_json::json!({}));
        match method {
            "initialize" => Some(ok_response(id, serde_json::json!({
                "protocolVersion": "2024-11-05",
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "opsguard-mcp", "version": env!("CARGO_PKG_VERSION") }
            }))),
            "ping" => Some(ok_response(id, serde_json::json!({}))),
            "tools/list" => Some(ok_response(id, serde_json::json!({ "tools": tool_defs() }))),
            "tools/call" => {
                let name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
                let args = params.get("arguments").cloned().unwrap_or(serde_json::json!({}));
                match self.call_tool(name, &args) {
                    Ok(text) => Some(ok_response(id, serde_json::json!({
                        "content": [{"type": "text", "text": text}],
                        "isError": false
                    }))),
                    Err(e) => Some(ok_response(id, serde_json::json!({
                        "content": [{"type": "text", "text": e}], "isError": true
                    }))),
                }
            }
            other => Some(error_response(id, -32601, &format!("未知方法: {other}"))),
        }
    }

    fn call_tool(&self, name: &str, args: &serde_json::Value) -> Result<String, String> {
        match name {
            "gate_check" => {
                let server = str_arg(args, "server").unwrap_or("");
                let intent = str_arg(args, "intent");
                let action = match intent {
                    Some(i) => Action::Write { server, intent: i },
                    None => Action::ReadOnly { server },
                };
                match self.gate.check(&action) {
                    None => Ok(format!("ALLOW：操作放行（{}）",
                        if intent.is_some() { "写操作" } else { "只读" })),
                    Some(reason) => Ok(format!("DENY：{reason}")),
                }
            }
            "audit_append" => {
                let row = match args.get("row") {
                    Some(serde_json::Value::String(s)) if !s.trim().is_empty() => s.clone(),
                    _ => {
                        // 支持结构化输入：自动规范化为稳定 JSON 作为 row
                        let obj = args.get("row_json").ok_or("缺少 row（字符串）或 row_json（对象）")?;
                        canonical_json(obj)?
                    }
                };
                let (n, mac) = self.store.append(&row).map_err(|e| format!("审计写入失败: {e}"))?;
                Ok(format!("已入链：#{n} mac={mac}"))
            }
            "audit_verify" => {
                if !self.store.path().exists() {
                    return Ok("审计链为空（文件不存在）：0 环，完整".into());
                }
                let (total, brk, bad) = self.store.verify().map_err(|e| format!("读取失败: {e}"))?;
                match brk {
                    None => Ok(format!("审计链完整：{total} 环，损坏行 {bad}")),
                    Some(i) => Ok(format!("⚠ 审计链已损坏：{total} 环中第 {} 环断链（0-based），损坏行 {bad}", i + 1)),
                }
            }
            "update_status" => {
                // 透明度：开源版更新模块默认关闭，只有显式配置才启用
                Ok("自更新模块：默认关闭（开源构建）。启用需显式提供 manifest_url 与 minisign 公钥；本进程未配置更新通道，不存在后台检查。".into())
            }
            _ => Err(format!("未知工具: {name}")),
        }
    }
}

fn str_arg<'a>(args: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    args.get(key).and_then(|v| v.as_str())
}

/// 规范化 JSON：键排序、无空白 —— 保证同一语义行哈希一致（审计链的 canonical 形态）。
fn canonical_json(v: &serde_json::Value) -> Result<String, String> {
    fn sort_value(v: &serde_json::Value) -> serde_json::Value {
        match v {
            serde_json::Value::Object(m) => {
                let mut keys: Vec<&String> = m.keys().collect();
                keys.sort();
                let mut out = serde_json::Map::new();
                for k in keys {
                    out.insert(k.clone(), sort_value(&m[k]));
                }
                serde_json::Value::Object(out)
            }
            serde_json::Value::Array(a) => serde_json::Value::Array(a.iter().map(sort_value).collect()),
            other => other.clone(),
        }
    }
    serde_json::to_string(&sort_value(v)).map_err(|e| format!("规范化失败: {e}"))
}

fn ok_response(id: serde_json::Value, result: serde_json::Value) -> String {
    serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": result }).to_string()
}

fn error_response(id: serde_json::Value, code: i64, message: &str) -> String {
    serde_json::json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } }).to_string()
}

/// 工具清单（JSON Schema 形态，MCP tools/list 返回）
fn tool_defs() -> Vec<serde_json::Value> {
    vec![
    serde_json::json!({
        "name": "gate_check",
        "description": "评估一个操作是否被 OpsGuard 闸门策略放行。写操作必须带 intent（一句话说明做什么、为什么）。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "server": { "type": "string", "description": "目标服务器别名" },
                "intent": { "type": "string", "description": "写操作时必填：一句话意图。缺省 = 只读操作" }
            },
            "required": ["server"]
        }
    }),
    serde_json::json!({
        "name": "audit_append",
        "description": "把一次操作写入审计哈希链（防篡改留痕）。每次执行命令/写文件后应调用。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "row": { "type": "string", "description": "规范化记录行（稳定 JSON 字符串）" },
                "row_json": { "type": "object", "description": "或传结构化对象（自动键序规范化后入链）" }
            }
        }
    }),
    serde_json::json!({
        "name": "audit_verify",
        "description": "校验审计哈希链完整性：返回总环数、断链位置、损坏行数。",
        "inputSchema": { "type": "object", "properties": {} }
    }),
    serde_json::json!({
        "name": "update_status",
        "description": "查询自更新模块状态（透明度工具）：本构建是否存在自动更新通道。",
        "inputSchema": { "type": "object", "properties": {} }
    }),
    ]
}
