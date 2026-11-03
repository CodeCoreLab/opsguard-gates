# OpsGuard Gates

OpsGuard 的闸门与审计模块 —— **彻底开源版**（v0.6.0）。

## 设计承诺

- **零硬闸门**：无许可、无激活、无设备指纹收集、无邀请码、无注册表访问
- **零联网**：构建与运行不需要任何账号、密钥或网络请求
- **可插拔**：操作闸门是 trait，默认实现为「全部放行」；策略由使用者装配

## 模块

| 模块 | 说明 |
|---|---|
| `ActionGate` trait | 可插拔操作闸门。`AllowAllGate`（默认）全放行；`ChainedGate` 叠加多策略；`MaintenanceWindowGate` 维护窗口示例 |
| `audit_chain` | 审计哈希链（SHA-256 链式 MAC，防篡改留痕），含 `verify_chain` 整链校验 |
| `audit_store` | 审计 JSONL 追加存储（主程序与 MCP 服务器共用） |
| `self_update` | 自更新（**默认关闭**）：仅当显式提供 manifest URL + minisign 公钥才启用，启用后签名验证不可绕过 |
| `opsguard-mcp` 二进制 | AI 可控的 MCP stdio 服务器（见下） |

## AI 可控：MCP 服务器

任意 MCP 客户端（Claude Code / Cursor / Codex / Cline…）接入：

```json
{
  "mcpServers": {
    "opsguard": {
      "command": "/path/to/opsguard-mcp",
      "args": ["--audit", "~/.opsguard/audit.jsonl"]
    }
  }
}
```

### 暴露的 4 个工具

| 工具 | 作用 | 读写 |
|---|---|---|
| `gate_check` | 评估操作是否放行（写操作须带 `intent`） | 只读 |
| `audit_append` | 把一次操作写入审计哈希链（传 `row` 字符串或 `row_json` 对象，自动规范化） | 追加 |
| `audit_verify` | 校验链完整性（总环数 / 断链位置 / 损坏行数） | 只读 |
| `update_status` | 自更新通道透明度查询（本构建是否存在后台更新） | 只读 |

### 运行时选项

```text
--audit <path>        审计 JSONL 路径（默认 ~/.opsguard/audit.jsonl）
--maintenance <text>  附加维护窗口闸：写操作拒绝、只读放行（显式选择，非硬编码）
```

### AI 操作纪律建议

MCP 服务器的工具说明里内置了使用建议：AI 每次执行命令/写文件后调用 `audit_append`
留痕；不确定操作先用 `gate_check` 评估。闸门默认全放行——信任边界由使用者的
装配策略决定，不由本 crate 强加。

## 构建

```bash
cargo build --release          # 含 opsguard-mcp 二进制
cargo build --no-default-features   # 纯库（不含 MCP 服务器）
cargo test                     # 8 个测试
```

## 许可

MIT OR Apache-2.0
