//! Replay each verified node and claim edge from the saved public artifacts.
use anyhow::{bail, ensure, Context, Result};
use bincode::Options;
use risc0_zkvm::{
    sha::{Digest, Digestible},
    AssumptionReceipt, InnerReceipt, Receipt, ReceiptClaim, SegmentReceipt, SuccinctReceipt,
    VerifierContext,
};
use sha2::{Digest as _, Sha256};
use std::{env, fs, io::Read, path::Path};

const IMAGE: &str = "b574db28719df2261c18b5c5f0a52ad5ad96a290679df3223c1c3acacd0fca9c";
const STATEMENT_SHA: &str = "e8eb87bdd03c109a13f549e64ab5cd6597b890c024a3c39830726dc814676715";
const A_SHA: &str = "cacf94f766b12a62222050fee0b667c1d00cd7d53b082a9f63f864b24d932e96";
const MANIFEST_SHA: &str = "e52019540961bf1bd17f5354838c877f9539972421df2be9df7bb865a08976ec";
const PARAMS: &str = "f57f355f816d73b9c94cf5c63baa6c70a45fff10cfe3f298a9c2508dc4a06ae8";
type Succ = SuccinctReceipt<ReceiptClaim>;
const LIMIT: u64 = 32 * 1024 * 1024;
fn bytes(p: &Path) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    fs::File::open(p)
        .with_context(|| format!("open {}", p.display()))?
        .take(LIMIT + 1)
        .read_to_end(&mut data)?;
    ensure!(
        data.len() as u64 <= LIMIT,
        "oversized artifact {}",
        p.display()
    );
    Ok(data)
}
fn sha(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}
macro_rules! decode {
    ($data:expr) => {
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(LIMIT)
            .reject_trailing_bytes()
            .deserialize($data)?
    };
}

fn read_node(
    dir: &Path,
    name: &str,
    expected_control: &[u8],
    claim: Digest,
    ctx: &VerifierContext,
) -> Result<Succ> {
    let data = bytes(&dir.join(name))?;
    let node: Succ = decode!(&data);
    ensure!(
        node.hashfn == "poseidon2"
            && node.control_id.as_bytes() == expected_control
            && node.verifier_parameters.to_string() == PARAMS
            && node.seal.len() == 55667,
        "{name} control, hash suite, verifier parameters or seal size"
    );
    node.verify_integrity_with_context(ctx)
        .with_context(|| format!("verify {name}"))?;
    ensure!(
        node.claim.digest() == claim,
        "{name}: wrong parent-derived claim"
    );
    println!(
        "node={name} sha256={} control={} claim={}",
        sha(&data),
        node.control_id,
        claim
    );
    Ok(node)
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    ensure!(args.len() == 7, "usage: eip0045-recursive-replay CASE_8_9_10 VECTOR_DIR PUBLISHED_A_RECEIPT STATEMENT PROFILE_MANIFEST CHANGED_STATEMENT");
    let family: u8 = args[1].parse()?;
    ensure!((8..=10).contains(&family), "unknown family");
    let n = if family == 9 { 1 } else { 2 };
    let dir = Path::new(&args[2]);
    let a_bytes = bytes(Path::new(&args[3]))?;
    let statement = bytes(Path::new(&args[4]))?;
    let manifest = bytes(Path::new(&args[5]))?;
    ensure!(
        sha(&a_bytes) == A_SHA
            && sha(&statement) == STATEMENT_SHA
            && sha(&manifest) == MANIFEST_SHA,
        "public pinned input drift"
    );
    let control = |index: usize| &manifest[44 + 34 * index..76 + 34 * index];
    let explicit_root = Digest::try_from(&manifest[10..42])?;
    let image = Digest::try_from(hex::decode(IMAGE)?.as_slice())?;
    let expected = ReceiptClaim::ok(image, statement.clone()).digest();
    let ctx = VerifierContext::default();
    let a: Receipt = decode!(&a_bytes);
    a.verify_with_context(&ctx, image)?;
    let a_lift = a.inner.succinct()?;
    ensure!(
        a.journal.bytes == statement
            && a_lift.control_id.as_bytes() == control(0)
            && a_lift.claim.digest() == expected,
        "A must be the published unconditional lift15"
    );
    let composite_bytes = bytes(&dir.join("composite.bin"))?;
    let source: Receipt = decode!(&composite_bytes);
    source.verify_with_context(&ctx, image)?;
    ensure!(source.journal.bytes == statement, "source journal mismatch");
    let InnerReceipt::Composite(c) = &source.inner else {
        bail!("wrong source envelope")
    };
    ensure!(
        c.segments.len() == n && c.assumption_receipts.len() == usize::from(family != 8),
        "wrong graph source arity"
    );
    if family != 8 {
        let AssumptionReceipt::Proven(inner) = AssumptionReceipt::from(a.clone()) else {
            bail!("missing proven A")
        };
        ensure!(
            bincode::serialize(&inner)? == bincode::serialize(&c.assumption_receipts[0])?,
            "attached assumption receipt differs from the historical lift15 A"
        );
    }
    let mut lifts = Vec::new();
    for (i, original) in c.segments.iter().enumerate() {
        let label = format!("segment-{i}.bin");
        let data = bytes(&dir.join(&label))?;
        ensure!(
            data == bincode::serialize(original)?,
            "{label} differs from source composite"
        );
        let s: SegmentReceipt = decode!(&data);
        ensure!(
            s.index as usize == i && s.hashfn == "poseidon2",
            "{label} index/hash suite"
        );
        // 3.1.0 RV32IM seal version prefix followed by 91 circuit outputs then the exponent.
        let po2 = *s.seal.get(92).context("truncated RV32IM segment")?;
        ensure!(
            (15..=22).contains(&po2),
            "{label} unexpected RV32IM trace po2 {po2}"
        );
        if family == 8 {
            let nonce = s.povw_nonce()?;
            let mut h = Sha256::new();
            h.update(b"eip0045/b4/terminal-join/source-povw-job/v1\0");
            h.update(image.as_bytes());
            h.update(Sha256::digest(&statement));
            let job = u64::from_le_bytes(h.finalize()[..8].try_into()?).max(1);
            ensure!(
                nonce.log == 0u64 && nonce.job == job && nonce.segment == i as u32,
                "{label} source nonce"
            );
        }
        let name = format!("lift-{i}.bin");
        println!(
            "node={label} po2={po2} sha256={} claim={}",
            sha(&data),
            s.claim.digest()
        );
        lifts.push(read_node(
            dir,
            &name,
            control((po2 - 15) as usize),
            s.claim.digest(),
            &ctx,
        )?);
    }
    let terminal_segment = &c.segments[n - 1].claim;
    let output = terminal_segment
        .output
        .as_value()?
        .as_ref()
        .context("missing segment output")?;
    let last_claim = if family == 8 {
        ensure!(output.assumptions.is_empty(), "unexpected assumption");
        lifts[1].claim.clone()
    } else {
        let list = output.assumptions.as_value()?;
        ensure!(list.len() == 1, "want exactly one assumption");
        let head = list[0].as_value()?;
        let root = if family == 9 {
            explicit_root
        } else {
            Digest::ZERO
        };
        ensure!(
            head.claim == expected && head.control_root == root,
            "wrong assumption head or root"
        );
        let resolved_claim = lifts[n - 1].claim.resolve(&a_lift.claim)?.digest();
        println!(
            "assumptionClaim={} assumptionControlRoot={}",
            head.claim, head.control_root
        );
        read_node(dir, "resolve.bin", control(9), resolved_claim, &ctx)?.claim
    };
    let terminal_name;
    if n == 2 {
        let joined = lifts[0].claim.join(&last_claim)?.digest();
        read_node(dir, "join.bin", control(8), joined, &ctx)?;
        terminal_name = "join.bin";
    } else {
        terminal_name = "resolve.bin";
    }
    let mut r: Receipt = decode!(&bytes(&dir.join("receipt.bin"))?);
    let last = r.inner.succinct()?;
    ensure!(
        bytes(&dir.join(terminal_name))? == bincode::serialize(last)?,
        "final receipt substitution"
    );
    ensure!(
        last.get_seal_bytes() == bytes(&dir.join("raw-seal.bin"))?
            && r.journal.bytes == statement
            && last.claim.digest() == expected,
        "wrong final seal, journal or claim"
    );
    ensure!(
        last.claim
            .as_value()?
            .output
            .as_value()?
            .as_ref()
            .context("missing final output")?
            .assumptions
            .is_empty(),
        "final assumptions are not empty"
    );
    r.verify_with_context(&ctx, image)?;
    println!("GRAPH_PASS case={family} segments={n} final={terminal_name} emptyAssumptions=true");
    println!("Rust: ACCEPT case {family}");

    let changed = bytes(Path::new(&args[6]))?;
    ensure!(
        sha(&changed) == "3f16e6af09e001feb58611acd32d09d988258846cd260c2787a114af893a4287"
            && changed.len() == statement.len()
            && changed
                .iter()
                .zip(&statement)
                .map(|(a, b)| (a ^ b).count_ones())
                .sum::<u32>()
                == 1,
        "expected the published one-bit change in the application payload"
    );
    r.journal = risc0_zkvm::Journal::new(changed);
    match r.verify_with_context(&ctx, image) {
        Err(risc0_zkp::verify::VerificationError::ClaimDigestMismatch { .. }) => {
            println!("Rust: REJECT claim-digest-mismatch")
        }
        other => bail!("unexpected stock verifier result for the changed statement: {other:?}"),
    }
    Ok(())
}
