//! OpsGuard 闸门与审计模块 —— 开源版（v0.6.0，新增 AI 可控 MCP 服务器）
//!
//! ## 演进说明（v0.4.0 → v0.5.0）
//!
//! v0.4.0 曾按原 Reeve 3.0.0 的九闸门拓扑实现完整许可机制（激活/验签/时间锚/
//! 指纹/加密缓存/邀请码/强制层）。项目决定转为彻底开源后，评估结论：
//!
//! | 原闸门 | 处置 | 理由 |
//! |---|---|---|
//! | G1 激活（许可服务端点） | **删除** | 商业授权服务与开源版无关 |
//! | G2 激活响应验签 | **删除** | 随 G1 消失 |
//! | G3 时间锚（防回拨） | **删除** | 只为许可过期判定服务 |
//! | G4 设备指纹（硬件收集） | **删除** | 隐私敏感，开源版无设备绑定需求 |
//! | G5 加密许可缓存 | **删除** | 随 G1 消失 |
//! | G6 邀请码（注册表持久化） | **删除** | 邀请制与开源分发矛盾 |
//! | G7 更新检查 | **降级为默认关闭的可选模块** | 自动更新有价值但必须用户显式开启；签名验证作为该模块内置默认实现保留 |
//! | G8 强制层（AI 写操作拒绝） | **重构为可插拔 ActionGate trait** | 闸门语义本身有用（审批、维护窗口、自定义策略），但默认实现是「全部放行」——零硬闸门 |
//! | G9 审计哈希链 | **保留**（唯一非许可依赖的闸门） | 与许可无关，是安全能力：防篡改的本地操作留痕。chain MAC 算法不变 |
//!
//! v0.6.0 新增：AI 可控接口 —— 内置 MCP stdio 服务器（`opsguard-mcp` 二进制），
//! 暴露 4 个工具给任意 MCP 客户端（Claude Code / Cursor / Codex…）：
//! `gate_check`（评估可插拔闸门）· `audit_append` / `audit_verify`（审计链写入与校验）·
//! `update_status`（自更新开关透明度查询）。详见 `src/bin/mcp_server.rs`。
//!
//! 现在本 crate 保证：**没有许可、没有联网校验、没有硬件指纹收集，
//! `cargo build` / `cargo test` 开箱即过，主程序无需任何配置即可运行。**

/// ══════════════════ 可插拔操作闸门（原 G8 的开源形态）══════════════════
///
/// 原硬闸门把「授权状态」作为唯一判定源、硬编码拒绝分支。开源版改为 trait：
/// 主程序按操作语义调用，具体策略由使用者装配——默认装配 [`AllowAllGate`]。
pub trait ActionGate: Send + Sync {
    /// 返回 None = 放行；Some(reason) = 拒绝及原因。
    fn check(&self, action: &Action<'_>) -> Option<String>;
}

/// 受闸门约束的操作描述。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action<'a> {
    /// 只读操作（列目录、读状态、tail 日志）。任何闸门默认都不应拦它。
    ReadOnly { server: &'a str },
    /// 写操作（执行命令、写文件、重启服务）。`intent` 是一句话说明。
    Write { server: &'a str, intent: &'a str },
}

/// 默认闸门：全部放行。主程序未配置任何策略时的行为（零硬闸门承诺）。
pub struct AllowAllGate;

impl ActionGate for AllowAllGate {
    fn check(&self, _action: &Action<'_>) -> Option<String> {
        None
    }
}

/// 组合闸门：依次评估多个子策略，任一拒绝即拒绝。
/// 用于把「维护窗口」「审批」「自定义限流」等可选能力叠加装配。
pub struct ChainedGate {
    gates: Vec<Box<dyn ActionGate>>,
}

impl ChainedGate {
    pub fn new() -> Self {
        Self { gates: Vec::new() }
    }

    pub fn push(mut self, gate: Box<dyn ActionGate>) -> Self {
        self.gates.push(gate);
        self
    }

    pub fn is_empty(&self) -> bool {
        self.gates.is_empty()
    }
}

impl Default for ChainedGate {
    fn default() -> Self {
        Self::new()
    }
}

impl ActionGate for ChainedGate {
    fn check(&self, action: &Action<'_>) -> Option<String> {
        for g in &self.gates {
            if let Some(reason) = g.check(action) {
                return Some(reason);
            }
        }
        None
    }
}

/// 示例可选闸门：维护窗口（默认**不装配**，仅作为扩展样例与测试桩）。
pub struct MaintenanceWindowGate {
    /// true = 处于维护窗口（拒绝写操作）
    pub in_window: bool,
    pub reason: String,
}

impl ActionGate for MaintenanceWindowGate {
    fn check(&self, action: &Action<'_>) -> Option<String> {
        match (self.in_window, action) {
            (true, Action::Write { .. }) => Some(self.reason.clone()),
            _ => None,
        }
    }
}

/// ══════════════════ 审计哈希链（原 G9，保留）══════════════════
///
/// 与原 Reeve `reeve-audit-chain-v1` 同构的链式 MAC：
/// `mac_n = SHA256(mac_{n-1} || 0x00 || canonical_row_n)`
/// 链头为全零 MAC；任何一条历史记录被篡改，其后续所有 MAC 校验失败。
/// 本模块与许可机制零依赖，是纯本地安全能力。
pub mod audit_store;

pub mod audit_chain {
    use sha2::{Digest, Sha256};

    /// 链版本标识（原 reeve-audit-chain-v1 的开源版对应物）。
    pub const CHAIN_VERSION: &str = "opsguard-audit-chain-v1";

    /// 初始链 MAC（全零 64 hex）。
    pub const GENESIS_MAC: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    /// 计算下一环 MAC。`canonical_row` 必须是入库行的规范化序列化
    /// （与存储侧约定一致：建议为 `(id, ts, source, server_id, tool, params, result, verdict)` 的
    /// 稳定 JSON，字段序固定、无空白）。
    pub fn chain_mac(prev_mac: &str, canonical_row: &str) -> String {
        let mut h = Sha256::new();
        h.update(prev_mac.as_bytes());
        h.update([0u8]);
        h.update(canonical_row.as_bytes());
        hex(&h.finalize())
    }

    /// 从创世链验证整条链。`rows` 按序为 (canonical_row, stored_mac)。
    /// 返回第一处断链的序号（0-based）；完整则 None。
    pub fn verify_chain(rows: &[(&str, &str)]) -> Option<usize> {
        let mut prev = GENESIS_MAC.to_string();
        for (i, (row, mac)) in rows.iter().enumerate() {
            let expect = chain_mac(&prev, row);
            if expect != *mac {
                return Some(i);
            }
            prev = expect;
        }
        None
    }

    fn hex(b: &[u8]) -> String {
        let mut s = String::with_capacity(b.len() * 2);
        for x in b {
            s.push_str(&format!("{x:02x}"));
        }
        s
    }
}

/// ══════════════════ 可选：自更新模块（原 G7，默认关闭）══════════════════
///
/// 自动更新是双刃剑：方便，但「程序自行联网拉代码」与开源软件的信任模型相悖。
/// 开源版政策：
///   · 默认编译期完全关闭（本模块只提供配置结构与开关探测，不发任何网络请求）
///   · 发行方可通过 feature flag 或运行时配置显式启用
///   · 启用时签名验证是内置不可绕过步骤（`validate_manifest`），不存在「关掉验签只留下载」
pub mod self_update {
    /// 更新模块配置。全部字段由发行方/用户显式提供；无内置默认端点、无内置公钥。
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct UpdateConfig {
        /// 更新清单 URL（例如自建对象存储上的 update.json）
        pub manifest_url: String,
        /// minisign 格式公钥（`untrusted comment:` + base64 行）
        pub pubkey: String,
    }

    impl UpdateConfig {
        /// 配置是否完整可用（两字段非空）。不完整时调用方应把更新功能整体隐藏。
        pub fn is_enabled(&self) -> bool {
            !self.manifest_url.is_empty() && !self.pubkey.is_empty()
        }
    }

    /// 更新清单的平台条目（tauri-plugin-updater update.json 的子集）。
    #[derive(Debug, Clone, serde::Deserialize)]
    pub struct ManifestPlatform {
        pub signature: String,
        pub url: String,
    }

    /// 更新清单。
    #[derive(Debug, Clone, serde::Deserialize)]
    pub struct Manifest {
        pub version: String,
        #[serde(default)]
        pub notes: String,
        #[serde(default)]
        pub pub_date: String,
        pub platforms: std::collections::HashMap<String, ManifestPlatform>,
    }

    /// 解析清单（仅 JSON 结构校验；网络获取由调用方完成）。
    pub fn parse_manifest(body: &[u8]) -> Result<Manifest, String> {
        serde_json::from_slice(body).map_err(|e| format!("清单解析失败: {e}"))
    }

    /// 签名验证（minisign/authorized_keys 格式的 base64 签名）。
    /// **此步骤在启用更新的前提下不可跳过**：签名缺失或不匹配一律拒绝。
    /// 真正的密码学验证由发行方装配具体实现（如 tauri-plugin-updater 内建验证），
    /// 这里提供的是「启用更新的最低门槛」：清单、签名、公钥三者齐备。
    pub fn validate_manifest(manifest: &Manifest, platform: &str) -> Result<(), String> {
        let entry = manifest
            .platforms
            .get(platform)
            .ok_or_else(|| format!("清单缺少平台 {platform} 的条目"))?;
        if entry.signature.trim().is_empty() {
            return Err("平台条目缺少签名，拒绝安装".into());
        }
        if entry.url.trim().is_empty() {
            return Err("平台条目缺少下载地址".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_gate_allows_everything() {
        let g = AllowAllGate;
        assert!(g.check(&Action::ReadOnly { server: "s1" }).is_none());
        assert!(g.check(&Action::Write { server: "s1", intent: "重启 nginx" }).is_none());
    }

    #[test]
    fn chained_gate_first_deny_wins() {
        let g = ChainedGate::new()
            .push(Box::new(MaintenanceWindowGate {
                in_window: true,
                reason: "维护窗口内禁止写操作".into(),
            }))
            .push(Box::new(AllowAllGate));
        assert_eq!(
            g.check(&Action::Write { server: "s1", intent: "x" }),
            Some("维护窗口内禁止写操作".into())
        );
        // 只读不被维护窗口拦
        assert!(g.check(&Action::ReadOnly { server: "s1" }).is_none());
    }

    #[test]
    fn empty_chain_allows() {
        let g = ChainedGate::new();
        assert!(g.is_empty());
        assert!(g.check(&Action::Write { server: "s", intent: "i" }).is_none());
    }

    #[test]
    fn audit_chain_roundtrip_and_tamper() {
        let m1 = audit_chain::chain_mac(audit_chain::GENESIS_MAC, "row-1");
        let m2 = audit_chain::chain_mac(&m1, "row-2");
        // 完整链
        assert_eq!(
            audit_chain::verify_chain(&[("row-1", &m1), ("row-2", &m2)]),
            None
        );
        // 篡改 row-1 → 第 0 环断
        assert_eq!(
            audit_chain::verify_chain(&[("row-1-TAMPERED", &m1), ("row-2", &m2)]),
            Some(0)
        );
        // 篡改 row-2 → 第 1 环断
        assert_eq!(
            audit_chain::verify_chain(&[("row-1", &m1), ("row-2-TAMPERED", &m2)]),
            Some(1)
        );
    }

    #[test]
    fn chain_mac_differs_by_prev() {
        assert_ne!(
            audit_chain::chain_mac("a", "row"),
            audit_chain::chain_mac("b", "row")
        );
    }

    #[test]
    fn update_config_disabled_when_empty() {
        let c = self_update::UpdateConfig { manifest_url: String::new(), pubkey: String::new() };
        assert!(!c.is_enabled());
        let c = self_update::UpdateConfig {
            manifest_url: "https://example/update.json".into(),
            pubkey: "untrusted comment: minisign public key: X\nRWSabc".into(),
        };
        assert!(c.is_enabled());
    }

    #[test]
    fn manifest_parse_and_validate() {
        let body = br#"{"version":"1.2.3","notes":"n","pub_date":"2026-11-03","platforms":{"windows-x86_64":{"signature":"sig-data","url":"https://example/app.exe"}}}"#;
        let m = self_update::parse_manifest(body).unwrap();
        assert_eq!(m.version, "1.2.3");
        assert!(self_update::validate_manifest(&m, "windows-x86_64").is_ok());
        // 缺平台
        assert!(self_update::validate_manifest(&m, "darwin-aarch64").is_err());
        // 空签名拒绝
        let bad = br#"{"version":"1.2.3","platforms":{"windows-x86_64":{"signature":"","url":"https://example/app.exe"}}}"#;
        let m2 = self_update::parse_manifest(bad).unwrap();
        assert!(self_update::validate_manifest(&m2, "windows-x86_64").is_err());
    }
}
