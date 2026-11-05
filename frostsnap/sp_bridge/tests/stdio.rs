use serde_json::{json, Value};
use std::{
    io::Write,
    process::{Command, Stdio},
};

#[test]
fn stdio_has_correlated_responses_and_rejects_wrong_protocol() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let mut child = Command::new(env!("CARGO_BIN_EXE_frostsnap_sp_bridge"))
        .args([
            "--state",
            state.to_str().unwrap(),
            "--desktop-dev-key",
            "--offline",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let input = child.stdin.as_mut().unwrap();
        for request in [
            json!({"protocol":"bad","id":"bad","command":{"method":"wallets"}}),
            json!({"protocol":"frostsnap-sp-bridge/1","id":"ok","command":{"method":"wallets"}}),
        ] {
            writeln!(input, "{request}").unwrap();
        }
    }
    drop(child.stdin.take());
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    let messages: Vec<Value> = String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(messages[0]["event"], "ready");
    assert_eq!(messages[1]["id"], "bad");
    assert!(messages[1]["error"].is_string());
    assert_eq!(messages[2]["id"], "ok");
    assert_eq!(messages[2]["result"], json!([]));
}
