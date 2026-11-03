//! 审计存储层（JSONL 追加文件 + 哈希链校验）—— MCP 服务器与主程序共用的持久化。
//!
//! 文件格式：每行一个 JSON 对象
//! `{"n":1,"row":"…canonical json…","mac":"…64hex…"}`
//! 追加写（append-only），损坏行（非 JSON）在校验时视为断链。

use std::fs::{OpenOptions, File};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

use crate::audit_chain;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuditEntry {
    /// 链序号（从 1 起）
    pub n: u64,
    /// 规范化行内容（入库行的稳定 JSON）
    pub row: String,
    /// 本环 MAC
    pub mac: String,
}

#[derive(Debug, Clone)]
pub struct AuditStore {
    path: PathBuf,
}

impl AuditStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// 追加一条记录：MAC 基于文件末环计算。返回 (序号, mac)。
    pub fn append(&self, row: &str) -> std::io::Result<(u64, String)> {
        let entries = self.load_all()?;
        let prev_mac = entries
            .last()
            .map(|e| e.mac.clone())
            .unwrap_or_else(|| audit_chain::GENESIS_MAC.to_string());
        let n = entries.last().map(|e| e.n + 1).unwrap_or(1);
        let mac = audit_chain::chain_mac(&prev_mac, row);
        let entry = AuditEntry { n, row: row.to_string(), mac: mac.clone() };
        let mut f = OpenOptions::new().create(true).append(true).open(&self.path)?;
        writeln!(f, "{}", serde_json::to_string(&entry).expect("serialize"))?;
        Ok((n, mac))
    }

    /// 读全量（损坏行跳过并记入 broken 计数——由 verify 报告）。
    pub fn load_all(&self) -> std::io::Result<Vec<AuditEntry>> {
        let mut out = Vec::new();
        if !self.path.exists() {
            return Ok(out);
        }
        let f = File::open(&self.path)?;
        for line in BufReader::new(f).lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(e) = serde_json::from_str::<AuditEntry>(&line) {
                out.push(e);
            }
        }
        Ok(out)
    }

    /// 整链校验。返回 (总环数, 首个断链序号(0-based, None=完整), 损坏行数)。
    pub fn verify(&self) -> std::io::Result<(usize, Option<usize>, usize)> {
        let f = File::open(&self.path)?;
        let mut rows: Vec<(&str, &str)> = Vec::new();
        let mut broken_lines = 0usize;
        let mut owned: Vec<AuditEntry> = Vec::new();
        for line in BufReader::new(f).lines() {
            let line = line?;
            if line.trim().is_empty() { continue; }
            match serde_json::from_str::<AuditEntry>(&line) {
                Ok(e) => owned.push(e),
                Err(_) => broken_lines += 1,
            }
        }
        for e in &owned {
            rows.push((e.row.as_str(), e.mac.as_str()));
        }
        let first_break = audit_chain::verify_chain(&rows);
        Ok((owned.len(), first_break, broken_lines))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_verify_roundtrip() {
        let dir = std::env::temp_dir().join(format!("og-audit-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("audit.jsonl");
        let _ = std::fs::remove_file(&p);
        let store = AuditStore::new(&p);
        store.append(r#"{"action":"exec","server":"s1","verdict":"ALLOW"}"#).unwrap();
        store.append(r#"{"action":"exec","server":"s2","verdict":"DENY"}"#).unwrap();
        let (total, brk, bad) = store.verify().unwrap();
        assert_eq!(total, 2);
        assert_eq!(brk, None);
        assert_eq!(bad, 0);
        // 篡改中间行 → 断链
        let mut lines: Vec<String> = std::fs::read_to_string(&p).unwrap().lines().map(String::from).collect();
        lines[0] = lines[0].replace("ALLOW", "TAMPERED");
        std::fs::write(&p, lines.join("\n") + "\n").unwrap();
        let (_, brk, _) = store.verify().unwrap();
        assert_eq!(brk, Some(0));
        let _ = std::fs::remove_file(&p);
        let _ = std::fs::remove_dir(dir);
    }
}
