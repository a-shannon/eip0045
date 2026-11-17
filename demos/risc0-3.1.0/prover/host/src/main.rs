use anyhow::{bail, ensure, Context, Result};
use bincode::Options;
use eip_0045_methods::GuestInputHeader;
use risc0_binfmt::ProgramBinary;
use risc0_zkp::verify::VerificationError;
use risc0_zkvm::{sha::Digest, InnerReceipt, Journal, Receipt};
use std::{env, fs, io::{Read, Write}, process::ExitCode};

const LIFT_15: &str = "0ade565f320cba2d0b23003a6323424d3f3d3609bcdcca4c14ab492b15cae153";
const PARAMS: &str = "f57f355f816d73b9c94cf5c63baa6c70a45fff10cfe3f298a9c2508dc4a06ae8";
const RAW_BYTES: usize = 222_668;
const MAX_FILE: usize = 2 * 1024 * 1024;

fn read(path: &str, max: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    fs::File::open(path)?.take((max + 1) as u64).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= max, "input too large: {path}");
    Ok(bytes)
}

fn write_new(path: &str, bytes: &[u8]) -> Result<()> {
    fs::File::create_new(path)?.write_all(bytes)?;
    Ok(())
}

fn receipt(path: &str) -> Result<Receipt> {
    let bytes = read(path, MAX_FILE)?;
    let r: Receipt = bincode::DefaultOptions::new().with_fixint_encoding()
        .with_limit(MAX_FILE as u64).reject_trailing_bytes().deserialize(&bytes)
        .context("stock receipt decoding")?;
    Ok(r)
}

fn seal(r: &Receipt) -> Result<Vec<u8>> {
    let InnerReceipt::Succinct(s) = &r.inner else { bail!("expected a succinct receipt") };
    ensure!(s.hashfn == "poseidon2" && s.control_id.to_string() == LIFT_15,
        "unexpected terminal: {:?} {}", s.hashfn, s.control_id);
    ensure!(s.verifier_parameters.to_string() == PARAMS, "wrong verifier parameters");
    let bytes = s.get_seal_bytes();
    ensure!(bytes.len() == RAW_BYTES, "wrong raw seal size: {}", bytes.len());
    Ok(bytes)
}

fn image(value: &str) -> Result<Digest> {
    Ok(Digest::try_from(hex::decode(value)?.as_slice())?)
}

fn run(args: &[String]) -> Result<ExitCode> {
    match args {
        [cmd, user, out] if cmd == "pack" => {
            let user = read(user, MAX_FILE)?;
            let binary = ProgramBinary::new(&user, risc0_zkos_v1compat::V1COMPAT_ELF).encode();
            let id = risc0_binfmt::compute_image_id(&binary)?;
            write_new(out, &binary)?;
            println!("{id}");
        }
        [cmd, statement, out, iterations] if cmd == "guest-input" => {
            let statement = read(statement, eip_0045_methods::MAX_STATEMENT_BYTES)?;
            let header = GuestInputHeader::new(statement.len(), iterations.parse()?, 0x4549_5030_3034_3501)
                .map_err(|e| anyhow::anyhow!("guest input: {e}"))?;
            let mut bytes = header.encode().to_vec();
            bytes.extend(statement);
            write_new(out, &bytes)?;
        }
        [cmd, file, raw, id] if cmd == "extract" => {
            let r = receipt(file)?;
            r.verify(image(id)?).context("authenticating original stock receipt")?;
            write_new(raw, &seal(&r)?)?;
        }
        [cmd, file, raw, id, statement] if cmd == "verify" => {
            let mut r = receipt(file)?;
            let img = image(id)?;
            r.verify(img).context("invalid supplied stock receipt")?;
            ensure!(seal(&r)? == read(raw, RAW_BYTES)?, "raw seal and verified receipt differ");
            // Verify the journal requested by the caller against the unchanged
            // inner receipt, using the upstream cryptographic claim check.
            r.journal = Journal::new(read(statement, eip_0045_methods::MAX_STATEMENT_BYTES)?);
            match r.verify(img) {
                Ok(()) => println!("ACCEPT lift-po2-15"),
                Err(VerificationError::ClaimDigestMismatch { .. }) => {
                    println!("REJECT claim-digest-mismatch");
                    return Ok(ExitCode::from(1));
                }
                Err(e) => bail!("unexpected stock verifier error: {e}"),
            }
        }
        _ => bail!("usage: ergo310-receipt pack USER_ELF PROGRAM | guest-input STATEMENT OUT ITERATIONS | extract RECEIPT RAW IMAGE_ID | verify RECEIPT RAW IMAGE_ID EXPECTED_STATEMENT"),
    }
    Ok(ExitCode::SUCCESS)
}

fn main() -> ExitCode {
    match run(&env::args().skip(1).collect::<Vec<_>>()) {
        Ok(code) => code,
        Err(error) => { eprintln!("{error:#}"); ExitCode::from(2) }
    }
}
