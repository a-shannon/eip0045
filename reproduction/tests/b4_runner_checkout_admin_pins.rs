use sha2::{Digest, Sha256};

const RUNNER: &str = include_str!("../b4-build/container-build.sh");
const RISC0_COMMIT: &str = "227229dc793c215c533cbc0e07911601974a4629";

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn unique_hash_literal(prefix: &str) -> &str {
    let values = RUNNER
        .lines()
        .filter_map(|line| line.trim().strip_prefix(prefix))
        .collect::<Vec<_>>();
    assert_eq!(values.len(), 1, "runner must contain exactly one {prefix}<sha256>");
    values[0]
}

#[test]
fn checkout_admin_hash_literals_match_cargo_generated_bytes() {
    let head = unique_hash_literal("require_hash \"$candidate/.git/HEAD\" ");
    let master =
        unique_hash_literal("require_hash \"$candidate/.git/refs/heads/master\" ");

    assert_eq!(head, sha256_hex(b"ref: refs/heads/master\n"));
    assert_eq!(master, sha256_hex(format!("{RISC0_COMMIT}\n").as_bytes()));
}
