// Copyright 2026 A. Shannon
// SPDX-License-Identifier: Apache-2.0

//! Authenticated negative adapter for the shared recursive-ancestry replay.
//!
//! The shared `recursive_ancestry` module owns the bounded V2 wire, family
//! graph, claim reconstruction, and upstream `ReceiptClaim::join`/`resolve`
//! semantics. This adapter adds subject framing, exact auxiliary-map decoding,
//! manifest authentication, and independent STARK verification of every
//! referenced producer seal before any typed rejection can be observed.

#[cfg(all(test, feature = "negative-materialization-set"))]
mod genuine_local_fifteen {
    use super::*;
    use crate::{
        b4_alternate_root_authority::genuine_alternate_root as alternate,
        b4_c2_alternate_root::reconstruct_genuine_alternate_root,
        b4_c2_ancestry::reconstruct_genuine_reusable_ancestry,
        b4_c2_negative_ancestry_witness::{LocalWitnessAncestryInput, reconstruct_genuine_witness_ancestry},
        b4_negative_ancestry_witness::compiled_negative_ancestry_witness_layout,
        b4_plan::{B4NegativeExecutionSurface, Eip0045B4NegativePlanV1},
        b4_subject_envelope::encode_subject_envelope,
        constants::MAX_STATEMENT_BYTES,
        receipt_oracle_codec::RECEIPT_ORACLE_MAX_BYTES,
        recursive_ancestry::RECURSIVE_ANCESTRY_MAX_BYTES,
    };
    use serde::Deserialize;
    use sha2::{Digest as _, Sha256};
    use std::{fs, io::Read, path::{Component, Path, PathBuf}};

    const MANIFEST: &[u8] = include_bytes!("../../../profiles/risc0-v3-succinct/manifest.bin");
    const DESCRIPTOR_MAX: usize = 64 * 1024;
    const TOTAL_MAX: u64 = 32 * 1024 * 1024;
    const GUEST_MAX: usize = 16 * 1024 * 1024;
    const REPRESENTATIVES: [usize; 7] = [141, 143, 145, 147, 148, 152, 154];
    const FAMILIES: [(&str, RecursiveAncestryFamily); 3] = [
        ("join", RecursiveAncestryFamily::TerminalJoin),
        ("resolve", RecursiveAncestryFamily::TerminalResolve),
        ("resolve-join", RecursiveAncestryFamily::ResolveThenJoin),
    ];

    #[derive(Clone, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct FilePin { role: String, path: PathBuf, bytes: u64, sha256: String }
    #[derive(Clone, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Descriptor { files: Vec<FilePin> }

    fn roles() -> Vec<(String, usize, usize)> {
        let mut result = Vec::new();
        for (prefix, family) in FAMILIES {
            result.extend([
                (format!("{prefix}.ancestry"), 1, RECURSIVE_ANCESTRY_MAX_BYTES),
                (format!("{prefix}.statement"), 159, MAX_STATEMENT_BYTES),
                (format!("{prefix}.final"), PROOF_BYTES, PROOF_BYTES),
            ]);
            for path in recursive_ancestry_expected_auxiliary_paths(family) {
                result.push((format!("{prefix}.aux.{path}"), PROOF_BYTES, PROOF_BYTES));
            }
        }
        for row in REPRESENTATIVES {
            result.push((format!("witness.{row}.raw"), PROOF_BYTES, PROOF_BYTES));
            result.push((format!("witness.{row}.oracle"), 1, RECEIPT_ORACLE_MAX_BYTES));
        }
        result.push(("alternate-guest".to_owned(), 1, GUEST_MAX));
        result
    }

    fn digest_shape(value: &str) -> bool {
        value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }

    fn validate_descriptor(value: &Descriptor) -> Result<()> {
        let expected = roles();
        ensure!(value.files.len() == expected.len(), "local ancestry input count differs");
        let mut total = 0u64;
        for (pin, (role, minimum, maximum)) in value.files.iter().zip(expected) {
            ensure!(pin.role == role, "local ancestry input role or order differs");
            ensure!(pin.bytes >= minimum as u64 && pin.bytes <= maximum as u64,
                "local ancestry input role bounds differ");
            ensure!(pin.path.is_absolute() && !pin.path.components().any(|p| p == Component::ParentDir),
                "local ancestry input path is not absolute and normalized");
            ensure!(digest_shape(&pin.sha256), "local ancestry input digest shape differs");
            total = total.checked_add(pin.bytes).context("local ancestry input total overflow")?;
            ensure!(total <= TOTAL_MAX, "local ancestry input total exceeds bound");
        }
        Ok(())
    }

    fn redirected(metadata: &fs::Metadata) -> bool {
        #[cfg(windows)]
        { use std::os::windows::fs::MetadataExt; metadata.file_attributes() & 0x400 != 0 }
        #[cfg(not(windows))]
        { let _ = metadata; false }
    }

    fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> Result<bool> {
        let common = left.is_file() && right.is_file() && left.len() == right.len()
            && left.modified()? == right.modified()? && !redirected(left) && !redirected(right);
        #[cfg(unix)]
        { use std::os::unix::fs::MetadataExt;
          Ok(common && left.dev() == right.dev() && left.ino() == right.ino()
            && left.nlink() == right.nlink() && left.ctime() == right.ctime()
            && left.ctime_nsec() == right.ctime_nsec()) }
        #[cfg(not(unix))]
        { Ok(common) }
    }

    fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>> {
        ensure!(path.is_absolute() && !path.components().any(|p| p == Component::ParentDir),
            "local ancestry reader requires absolute normalized path");
        for parent in path.ancestors().skip(1) {
            let metadata = fs::symlink_metadata(parent)?;
            ensure!(metadata.is_dir() && !metadata.file_type().is_symlink() && !redirected(&metadata),
                "local ancestry reader rejects parent redirect");
        }
        let before = fs::symlink_metadata(path)?;
        ensure!(before.is_file() && !before.file_type().is_symlink() && !redirected(&before)
            && before.len() <= maximum as u64, "local ancestry reader rejects file or bound");
        let mut file = fs::File::open(path)?;
        ensure!(same_file(&before, &file.metadata()?)?, "local ancestry opened file changed");
        let mut bytes = Vec::new();
        (&mut file).take(maximum as u64 + 1).read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= maximum && bytes.len() as u64 == before.len()
            && same_file(&before, &file.metadata()?)?
            && same_file(&before, &fs::symlink_metadata(path)?)?, "local ancestry read changed");
        Ok(bytes)
    }

    fn parse_descriptor(bytes: &[u8], digest: &str) -> Result<Descriptor> {
        ensure!(bytes.len() <= DESCRIPTOR_MAX && digest_shape(digest)
            && hex::encode(Sha256::digest(bytes)) == digest, "local ancestry descriptor pin differs");
        let descriptor: Descriptor = serde_json::from_slice(bytes)?;
        validate_descriptor(&descriptor)?;
        Ok(descriptor)
    }

    fn require_file_pin(pin: &FilePin, bytes: &[u8]) -> Result<()> {
        ensure!(bytes.len() as u64 == pin.bytes && hex::encode(Sha256::digest(bytes)) == pin.sha256,
            "local ancestry file pin differs");
        Ok(())
    }

    fn load() -> Result<BTreeMap<String, Vec<u8>>> {
        let path = std::env::var_os("EIP0045_B4_LOCAL_ANCESTRY_INPUTS").context("local ancestry descriptor required")?;
        let digest = std::env::var("EIP0045_B4_LOCAL_ANCESTRY_INPUTS_SHA256")
            .context("local ancestry descriptor SHA-256 required")?;
        let bytes = read_bounded(Path::new(&path), DESCRIPTOR_MAX)?;
        let descriptor = parse_descriptor(&bytes, &digest)?;
        // All roles and aggregate bounds have been checked before opening any payload.
        let mut result = BTreeMap::new();
        for (pin, (_, _, maximum)) in descriptor.files.iter().zip(roles()) {
            let bytes = read_bounded(&pin.path, maximum)?;
            require_file_pin(pin, &bytes)?;
            ensure!(result.insert(pin.role.clone(), bytes).is_none(), "local ancestry role duplicated");
        }
        Ok(result)
    }

    struct Positive<'a> {
        ancestry: &'a [u8], statement: &'a [u8], final_seal: &'a [u8], map: Vec<u8>,
    }

    impl Positive<'_> {
        fn subject(&self) -> Result<Vec<u8>> {
            Ok(encode_subject_envelope(&[self.ancestry, self.statement, self.final_seal, &self.map],
                ancestry_subject_envelope_contract())?)
        }
        fn witness_input<'a>(&'a self, guest: &'a [u8]) -> LocalWitnessAncestryInput<'a> {
            LocalWitnessAncestryInput { ancestry: self.ancestry, statement: self.statement,
                final_raw_seal: self.final_seal, auxiliary_map: &self.map, manifest: MANIFEST,
                alternate_guest: guest }
        }
    }

    fn positive<'a>(files: &'a BTreeMap<String, Vec<u8>>, prefix: &str,
        family: RecursiveAncestryFamily) -> Result<Positive<'a>> {
        let paths = recursive_ancestry_expected_auxiliary_paths(family);
        let entries = paths.iter().map(|path| (path.as_str(), files[&format!("{prefix}.aux.{path}")].as_slice()))
            .collect::<Vec<_>>();
        let map = encode_recursive_auxiliary_map(&B4RecursiveAuxiliaryMapV1::from_exact_entries(family, &entries)?)?;
        let input = Positive { ancestry: &files[&format!("{prefix}.ancestry")],
            statement: &files[&format!("{prefix}.statement")], final_seal: &files[&format!("{prefix}.final")], map };
        ensure!(parse_recursive_ancestry_jcs(input.ancestry)?.family == family,
            "local positive family differs from acquisition role");
        let prepared = prepare_ancestry(input.ancestry, input.statement, input.final_seal, &input.map, MANIFEST)?;
        ensure!(classify_semantics(&prepared)?.is_none(), "local positive ancestry did not accept");
        Ok(input)
    }

    fn expected(index: usize) -> Result<B4AncestryRejection> {
        match index {
            141..=143 => Ok(B4AncestryRejection::ClaimEdge),
            144..=148 => Ok(B4AncestryRejection::ResolveExplicit),
            149..=152 => Ok(B4AncestryRejection::ResolveZeroRoot),
            153..=155 => Ok(B4AncestryRejection::AssumptionInventory),
            _ => anyhow::bail!("local ancestry outcome row outside fixed fifteen"),
        }
    }

    fn require_outcome(index: usize, result: Result<B4AncestryRejection>) -> Result<()> {
        ensure!(result? == expected(index)?, "local ancestry consumer returned another typed boundary");
        Ok(())
    }

    #[test]
    fn local_input_contract_is_closed_before_payload_reads() {
        let value = Descriptor { files: roles().iter().map(|(role, minimum, _)| FilePin {
            role: role.clone(), path: std::env::current_dir().unwrap().join("not-opened"),
            bytes: *minimum as u64, sha256: "00".repeat(32),
        }).collect() };
        validate_descriptor(&value).unwrap();
        assert_eq!(value.files.len(), 32);
        let mut changed = value.clone(); changed.files.pop(); assert!(validate_descriptor(&changed).is_err());
        let mut changed = value.clone(); changed.files.push(value.files[0].clone()); assert!(validate_descriptor(&changed).is_err());
        let mut changed = value.clone(); changed.files.swap(0, 1); assert!(validate_descriptor(&changed).is_err());
        for index in 0..value.files.len() {
            let mut changed = value.clone(); changed.files[index].bytes = roles()[index].2 as u64 + 1;
            assert!(validate_descriptor(&changed).is_err());
            let mut changed = value.clone(); changed.files[index].sha256 = "00".repeat(31);
            assert!(validate_descriptor(&changed).is_err());
            let mut changed = value.clone(); changed.files[index].path = PathBuf::from("relative");
            assert!(validate_descriptor(&changed).is_err());
        }
        assert!(parse_descriptor(b"{}", &"00".repeat(32)).is_err());
        let pin = FilePin { role: "test".into(), path: PathBuf::new(), bytes: 3,
            sha256: hex::encode(Sha256::digest(b"abc")) };
        require_file_pin(&pin, b"abc").unwrap();
        assert!(require_file_pin(&pin, b"abd").is_err());
        assert!(require_file_pin(&pin, b"ab").is_err());
    }

    #[test]
    fn local_typed_outcomes_do_not_swallow_private_failures_or_wrong_boundaries() {
        for index in 141..=155 {
            require_outcome(index, Ok(expected(index).unwrap())).unwrap();
            assert!(require_outcome(index, Err(anyhow::anyhow!("private failure"))).is_err());
            for other in [B4AncestryRejection::ClaimEdge, B4AncestryRejection::ResolveExplicit,
                B4AncestryRejection::ResolveZeroRoot, B4AncestryRejection::AssumptionInventory] {
                if other != expected(index).unwrap() { assert!(require_outcome(index, Ok(other)).is_err()); }
            }
        }
        assert!(expected(140).is_err()); assert!(expected(156).is_err());
    }

    #[test]
    fn local_reader_accepts_exact_bytes_and_rejects_bounds_and_relative_paths() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("payload");
        fs::write(&path, b"abc").unwrap();
        assert_eq!(read_bounded(&path, 3).unwrap(), b"abc");
        assert!(read_bounded(&path, 2).is_err());
        assert!(read_bounded(root.path(), 3).is_err());
        assert!(read_bounded(Path::new("relative"), 3).is_err());
        assert!(read_bounded(&root.path().join("../payload"), 3).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn local_reader_rejects_leaf_and_parent_symlinks() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let physical = root.path().join("physical");
        fs::create_dir(&physical).unwrap();
        fs::write(physical.join("payload"), b"abc").unwrap();
        symlink(physical.join("payload"), root.path().join("leaf")).unwrap();
        symlink(&physical, root.path().join("parent")).unwrap();
        assert!(read_bounded(&root.path().join("leaf"), 3).is_err());
        assert!(read_bounded(&root.path().join("parent/payload"), 3).is_err());
        assert_eq!(read_bounded(&physical.join("payload"), 3).unwrap(), b"abc");
    }

    #[test]
    #[ignore = "requires externally pinned retained ancestry inputs and genuine alternate-root export; local diagnostics only"]
    fn retained_local_fifteen_producer_consumer_matrix() {
        retained_fifteen_matrix(|index, subject| {
            if let Some(index) = index {
                require_outcome(index, reject_ancestry_replay(subject, &[MANIFEST])).unwrap();
            } else {
                assert!(reject_ancestry_replay(subject, &[MANIFEST]).is_err());
            }
        });
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    #[ignore = "requires pinned retained inputs, alternate-root export, and Linux/x86_64 openat2 custody"]
    fn retained_physical_fifteen_dispatch_matrix() {
        let mut rows = Vec::new();
        let mut private = 0;
        retained_fifteen_matrix(|index, subject| {
            let (root, input, source) = physical::fixture(subject, MANIFEST);
            let result = super::super::negative::verify_negative_root(root.path());
            if let Some(index) = index {
                physical::require_observation(index, &input, &source, result.unwrap()).unwrap();
                if index == 141 { physical::isolated_custody_faults(subject); }
                rows.push(index);
                println!("physicalAncestryRow={index} exactObservation=PASS");
            } else {
                assert_eq!(result.unwrap_err().to_string(), physical::PRIVATE);
                private += 1;
            }
        });
        assert_eq!(rows, (141..=155).collect::<Vec<_>>());
        assert_eq!(private, 33); // Three valid positives, fifteen corrupt seals, fifteen malformed maps.
    }

    // Compiled on native hosts as well; execution is Linux-only and never skip-passes.
    #[allow(dead_code, reason = "physical fixture execution requires Linux/x86_64")]
    mod physical {
        use super::*;
        use crate::b4_negative_io::*;
        use crate::b4_plan::B4MaterializationDomain;

        pub(super) const PRIVATE: &str = "selected negative adapter VerifierAncestryReplay failed privately; no observation was produced";

        fn identity(role: &str, path: &str, bytes: &[u8]) -> B4NegativeNamedIdentityV1 {
            B4NegativeNamedIdentityV1 { role: role.into(), path: path.into(),
                byte_length: bytes.len() as u64, sha256: hex::encode(Sha256::digest(bytes)),
                encoding: B4NegativeFileEncoding::RawBytes }
        }

        pub(super) fn fixture(subject: &[u8], manifest: &[u8])
            -> (tempfile::TempDir, Eip0045B4NegativeVerifierInputV1, Vec<u8>) {
            let input = Eip0045B4NegativeVerifierInputV1 {
                format: B4_NEGATIVE_VERIFIER_INPUT_FORMAT.into(),
                format_version: B4_NEGATIVE_VERIFIER_INPUT_FORMAT_VERSION,
                materialization_domain: B4MaterializationDomain::VerifierInput,
                validation_surface: B4NegativeExecutionSurface::AncestryReplay,
                subject: identity("subject", "subject.bin", subject),
                context: vec![identity("context-00", "context/00.bin", manifest)],
            };
            input.validate_for_campaign_precommit().unwrap();
            let source = input.to_canonical_jcs().unwrap();
            let root = tempfile::tempdir().unwrap();
            fs::create_dir(root.path().join("context")).unwrap();
            fs::write(root.path().join("subject.bin"), subject).unwrap();
            fs::write(root.path().join("context/00.bin"), manifest).unwrap();
            fs::write(root.path().join("negative-input.json"), &source).unwrap();
            (root, input, source)
        }

        fn expected_observation_bytes(index: usize, input: &Eip0045B4NegativeVerifierInputV1,
            source: &[u8]) -> Vec<u8> {
            let stage = match expected(index).unwrap() {
                B4AncestryRejection::ClaimEdge => "claim-edge",
                B4AncestryRejection::ResolveExplicit => "resolve-explicit-semantics",
                B4AncestryRejection::ResolveZeroRoot => "resolve-zero-root-semantics",
                B4AncestryRejection::AssumptionInventory => "resolve-assumption-inventory",
            };
            // Independent literal wire oracle: no production observation serializer.
            format!(concat!("{{\"format\":\"Eip0045B4NegativeObservationV1\",\"formatVersion\":1,",
                "\"materializationDomain\":\"verifier-input\",\"negativeInputSha256\":\"{}\",",
                "\"rejection\":{{\"class\":\"ancestry-replay-mismatch\",\"stage\":\"{}\"}},",
                "\"subjectByteLength\":{},\"subjectSha256\":\"{}\",",
                "\"validationSurface\":\"ancestry-replay\",\"verdict\":\"reject\"}}"),
                hex::encode(Sha256::digest(source)), stage, input.subject.byte_length, input.subject.sha256).into_bytes()
        }

        pub(super) fn require_observation(index: usize, input: &Eip0045B4NegativeVerifierInputV1,
            source: &[u8], observation: Eip0045B4NegativeObservationV1) -> Result<()> {
            ensure!(observation.to_canonical_jcs()? == expected_observation_bytes(index, input, source),
                "physical ancestry observation differs from independent literal oracle");
            Ok(())
        }

        pub(super) fn isolated_custody_faults(subject: &[u8]) {
            use super::super::super::negative::verify_negative_root;
            for fault in 0..16 {
                let (root, mut input, source) = fixture(subject, MANIFEST);
                let link = tempfile::tempdir().unwrap();
                match fault {
                    0 => { let mut bytes = subject.to_vec(); bytes[0] ^= 1;
                        fs::write(root.path().join("subject.bin"), bytes).unwrap(); }
                    1 => { let mut bytes = MANIFEST.to_vec(); bytes[0] ^= 1;
                        fs::write(root.path().join("context/00.bin"), bytes).unwrap(); }
                    2 => fs::write(root.path().join("subject.bin"), &subject[..subject.len()-1]).unwrap(),
                    3 => fs::write(root.path().join("extra.bin"), b"extra").unwrap(),
                    4 => fs::write(root.path().join("context/01.bin"), MANIFEST).unwrap(),
                    5 => { let mut bytes = source; bytes.push(b'\n');
                        fs::write(root.path().join("negative-input.json"), bytes).unwrap(); }
                    6 => { fs::remove_file(root.path().join("subject.bin")).unwrap();
                        fs::create_dir(root.path().join("subject.bin")).unwrap(); }
                    7 => fs::remove_file(root.path().join("context/00.bin")).unwrap(),
                    8 => fs::hard_link(root.path().join("subject.bin"), link.path().join("alias")).unwrap(),
                    9 => fs::write(root.path().join("context/00.bin"), &MANIFEST[..MANIFEST.len()-1]).unwrap(),
                    10 => fs::hard_link(root.path().join("context/00.bin"), link.path().join("alias")).unwrap(),
                    11 => fs::remove_file(root.path().join("negative-input.json")).unwrap(),
                    12 => fs::remove_file(root.path().join("subject.bin")).unwrap(),
                    13 | 14 => {
                        let digest = if fault == 13 { &mut input.subject.sha256 } else { &mut input.context[0].sha256 };
                        let first = if digest.starts_with('0') { "1" } else { "0" };
                        digest.replace_range(..1, first);
                        fs::write(root.path().join("negative-input.json"), input.to_canonical_jcs().unwrap()).unwrap();
                    }
                    15 => { fs::remove_file(root.path().join("context/00.bin")).unwrap();
                        fs::remove_dir(root.path().join("context")).unwrap(); }
                    _ => unreachable!(),
                }
                let error = verify_negative_root(root.path()).unwrap_err().to_string();
                let expected = match fault {
                    0 | 13 => "negative verifier file subject.bin SHA-256 differs from its descriptor",
                    1 | 14 => "negative verifier file context/00.bin SHA-256 differs from its descriptor",
                    2 => "negative verifier file subject.bin length is outside its bound",
                    3 => "negative verifier root contains an unexpected or duplicate entry",
                    4 => "negative context entry lies outside the exact positional prefix",
                    5 => "B4 negative verifier input is not exact RFC 8785 JCS",
                    6 => "negative verifier path is not a regular file: subject.bin",
                    7 => "negative context directory is not the exact NN.bin positional prefix",
                    8 => "hard-linked negative verifier file is forbidden: subject.bin",
                    9 => "negative verifier file context/00.bin length is outside its bound",
                    10 => "hard-linked negative verifier file is forbidden: context/00.bin",
                    11 => "cannot pin negative verifier file negative-input.json",
                    12 => "negative verifier root does not contain the exact V1 inventory",
                    15 => "cannot pin negative context directory with the closed resolver policy",
                    _ => unreachable!(),
                };
                assert_eq!(error, expected, "custody fault {fault}");
            }
            #[cfg(unix)]
            for parent_redirect in [false, true] {
                let (root, _, _) = fixture(subject, MANIFEST);
                let external = tempfile::tempdir().unwrap();
                let path = if parent_redirect { "context" } else { "subject.bin" };
                fs::rename(root.path().join(path), external.path().join(path)).unwrap();
                std::os::unix::fs::symlink(external.path().join(path), root.path().join(path)).unwrap();
                let expected = if parent_redirect {
                    "cannot pin negative context directory with the closed resolver policy"
                } else { "negative verifier path is not a regular file: subject.bin" };
                assert_eq!(verify_negative_root(root.path()).unwrap_err().to_string(), expected);
            }
            // Re-pinned wrong manifest reaches the adapter but remains private.
            let mut manifest = MANIFEST.to_vec(); manifest[0] ^= 1;
            let (root, _, _) = fixture(subject, &manifest);
            assert_eq!(verify_negative_root(root.path()).unwrap_err().to_string(), PRIVATE);
        }

        #[test]
        fn physical_fixture_uses_exact_neutral_cardinality_and_boundaries() {
            let (root, input, source) = fixture(b"invalid envelope", MANIFEST);
            assert_eq!(input.context.len(), 1);
            assert_eq!(input.context[0].byte_length, 458);
            assert_eq!(fs::read(root.path().join("negative-input.json")).unwrap(), source);
            assert_eq!(Eip0045B4NegativeVerifierInputV1::from_canonical_jcs(&source).unwrap(), input);
        }

        #[test]
        fn literal_observation_oracle_rejects_isolated_field_drift() {
            let (_, input, source) = fixture(b"invalid envelope", MANIFEST);
            for index in 141..=155 {
                let bytes = expected_observation_bytes(index, &input, &source);
                let positive = Eip0045B4NegativeObservationV1::from_canonical_jcs(&bytes).unwrap();
                require_observation(index, &input, &source, positive.clone()).unwrap();
                for fault in 0..9 {
                    let mut changed = positive.clone();
                    match fault {
                        0 => changed.format.push('x'),
                        1 => changed.format_version += 1,
                        2 => changed.materialization_domain = B4MaterializationDomain::ArtifactValidator,
                        3 => changed.validation_surface = B4NegativeExecutionSurface::RawSealShape,
                        4 => changed.negative_input_sha256 = "00".repeat(32),
                        5 => changed.subject_byte_length += 1,
                        6 => changed.subject_sha256 = "00".repeat(32),
                        7 => changed.rejection.class = "raw-seal-shape-invalid".into(),
                        8 => changed.rejection.stage = if index < 144 { "resolve-explicit-semantics" } else { "claim-edge" }.into(),
                        _ => unreachable!(),
                    }
                    assert!(require_observation(index, &input, &source, changed).is_err(), "row {index} field {fault}");
                }
                // Verdict is a one-variant enum, so isolate its unknown wire value.
                let changed = String::from_utf8(bytes).unwrap().replace("\"verdict\":\"reject\"", "\"verdict\":\"accept\"");
                assert!(Eip0045B4NegativeObservationV1::from_canonical_jcs(changed.as_bytes()).is_err());
            }
        }
    }

    // One producer loop supplies both direct semantic and physical dispatch tests.
    // None denotes a positive acceptance or private adapter failure, never a rejection.
    fn retained_fifteen_matrix(mut consume: impl FnMut(Option<usize>, &[u8])) {
        let files = load().unwrap();
        let positives = FAMILIES.iter().map(|(prefix, family)| positive(&files, prefix, *family).unwrap())
            .collect::<Vec<_>>();
        assert!(positives.iter().all(|p| p.statement == positives[1].statement));
        for input in &positives {
            assert_eq!(reject_ancestry_replay(&input.subject().unwrap(), &[MANIFEST]).unwrap_err().to_string(),
                "ancestry subject was unexpectedly accepted");
            consume(None, &input.subject().unwrap());
        }
        let alternate_root = std::env::var_os("EIP0045_B4_ALTERNATE_VECTOR_ROOT").expect("alternate root required");
        let guest_path = std::env::var_os("EIP0045_B4_GUEST_FILE").expect("consumer guest required");
        let alternate = alternate::load_authenticated(Path::new(&alternate_root), positives[1].statement,
            Path::new(&guest_path)).unwrap();
        let layout = compiled_negative_ancestry_witness_layout().unwrap();
        let plan = Eip0045B4NegativePlanV1::canonical().unwrap();
        let rows = plan.groups.iter().flat_map(|group| group.executions.iter()).collect::<Vec<_>>();
        assert_eq!(rows.iter().enumerate().filter(|(_, row)| row.execution_surface == B4NegativeExecutionSurface::AncestryReplay)
            .map(|(index, _)| index).collect::<Vec<_>>(), (141..=155).collect::<Vec<_>>());
        // Exact seven-class inventory: repeated placements share the same borrowed input;
        // distinct classes may not substitute byte-identical receipts or raw seals.
        for (position, left) in REPRESENTATIVES.iter().enumerate() {
            for right in REPRESENTATIVES.iter().skip(position + 1) {
                for suffix in ["raw", "oracle"] {
                    assert_ne!(files[&format!("witness.{left}.{suffix}")], files[&format!("witness.{right}.{suffix}")]);
                }
            }
        }
        let resolve_projection = parse_recursive_ancestry_jcs(positives[1].ancestry).unwrap();
        let assumption_path = &resolve_projection.assumption_receipt.as_ref().unwrap().raw_seal.path;
        assert_eq!(files["witness.141.raw"], files[&format!("resolve.aux.{assumption_path}")]);
        assert_eq!(files["witness.143.raw"].as_slice(), positives[1].final_seal);
        let guest = &files["alternate-guest"];
        let mut observed = Vec::new();
        for index in 141..=155 {
            let family = if index == 141 { 0 } else if index == 143 || (149..=152).contains(&index) { 2 } else { 1 };
            let base = &positives[family];
            let subject = if let Some(selected) = layout.iter().find(|r| usize::from(r.expanded_row) == index) {
                let representative = match index { 142 | 153 => 141, 150 => 145, 151 => 147, _ => index };
                assert_eq!(selected.base_family, FAMILIES[family].1);
                assert_eq!(selected.witness_id, layout.iter().find(|r|
                    usize::from(r.expanded_row) == representative).unwrap().witness_id);
                let raw = &files[&format!("witness.{representative}.raw")];
                let oracle = &files[&format!("witness.{representative}.oracle")];
                let subject = reconstruct_genuine_witness_ancestry(index, base.witness_input(guest), raw, oracle).unwrap();
                let mut changed = raw.clone(); changed[0] ^= 1;
                assert!(reconstruct_genuine_witness_ancestry(index, base.witness_input(guest), &changed, oracle).is_err());
                let mut changed = oracle.clone(); changed[0] ^= 1;
                assert!(reconstruct_genuine_witness_ancestry(index, base.witness_input(guest), raw, &changed).is_err());
                // Another valid class is not evidence for the selected witness role.
                let other = if representative == 141 { 145 } else { 141 };
                assert!(reconstruct_genuine_witness_ancestry(index, base.witness_input(guest),
                    &files[&format!("witness.{other}.raw")],
                    &files[&format!("witness.{other}.oracle")]).is_err());
                subject
            } else if index == 146 {
                reconstruct_genuine_alternate_root(index, &alternate, base.ancestry, base.statement,
                    base.final_seal, &base.map, MANIFEST).unwrap().subject
            } else {
                reconstruct_genuine_reusable_ancestry(index, base.ancestry, base.statement,
                    base.final_seal, &base.map, MANIFEST).unwrap().subject
            };
            consume(Some(index), &subject);
            let decoded = decode_subject_envelope(&subject, ancestry_subject_envelope_contract()).unwrap();
            let [ancestry, statement, seal, map]: [&[u8]; 4] = decoded.parts().try_into().unwrap();
            assert_eq!(statement, base.statement);
            assert!(reject_ancestry_replay(&subject, &[]).is_err());
            let mut changed = seal.to_vec(); changed[0] ^= 1;
            let corrupt = encode_subject_envelope(&[ancestry, statement, &changed, map], ancestry_subject_envelope_contract()).unwrap();
            assert!(reject_ancestry_replay(&corrupt, &[MANIFEST]).is_err());
            consume(None, &corrupt);
            let mut bad_map = map.to_vec(); bad_map[..2].copy_from_slice(&0u16.to_le_bytes());
            let malformed = encode_subject_envelope(&[ancestry, statement, seal, &bad_map], ancestry_subject_envelope_contract()).unwrap();
            assert!(reject_ancestry_replay(&malformed, &[MANIFEST]).is_err());
            consume(None, &malformed);
            observed.push(index);
            println!("localAncestryRow={index} typedOutcome={:?}", expected(index).unwrap());
        }
        assert_eq!(observed, (141..=155).collect::<Vec<_>>());
    }
}

#[cfg(all(test, feature = "negative-materialization-set"))]
mod genuine_resolve_ancestry {
    use super::*;
    use crate::{
        b4::{B4AncestryInventoryOperation, B4AncestryInventoryTarget, B4ByteTarget,
            B4NegativeMaterialization, B4NegativeMutation},
        b4_c2_ancestry::reconstruct_genuine_resolve_ancestry,
        b4_plan::{B4NegativeQaResultCode, Eip0045B4NegativePlanV1},
        b4_subject_envelope::encode_subject_envelope,
        b4_terminal_byte_map::B4ByteMapError,
        b4_validator::negative_verifier::genuine_conditional_claim::load_authenticated,
        recursive_ancestry::{RecursiveAncestryInventoryEntry, recursive_ancestry_revealed_head_witness,
            recursive_ancestry_to_jcs},
    };

    fn envelope(ancestry: &[u8], statement: &[u8], final_seal: &[u8], map: &[u8]) -> Vec<u8> {
        encode_subject_envelope(&[ancestry, statement, final_seal, map],
            ancestry_subject_envelope_contract()).unwrap()
    }

    fn exact_error<T>(result: Result<T>, expected: &str) {
        assert_eq!(result.err().expect("private failure must not become a typed observation").to_string(), expected);
    }

    #[test]
    #[ignore = "requires genuine preserved TerminalResolve export; local diagnostic only"]
    fn genuine_resolve_ancestry_c2_producer_consumer_matrix() {
        let root = std::env::var_os("EIP0045_B4_RESOLVE_VECTOR_ROOT").expect("Resolve export root required");
        let (input, projection) = load_authenticated(std::path::Path::new(&root)).unwrap();
        let entries = input.auxiliary().iter().map(|(path, raw)| (path.as_str(), raw.as_slice())).collect::<Vec<_>>();
        let map = encode_recursive_auxiliary_map(&B4RecursiveAuxiliaryMapV1::from_exact_entries(
            RecursiveAncestryFamily::TerminalResolve, &entries).unwrap()).unwrap();
        let manifest = input.manifest();
        let positive = envelope(input.ancestry(), input.statement(), input.final_seal(), &map);
        // The real consumer verifies all three seals before its positive acceptance sentinel.
        exact_error(reject_ancestry_replay(&positive, &[manifest]), "ancestry subject was unexpectedly accepted");

        let plan = Eip0045B4NegativePlanV1::canonical().unwrap();
        let rows = plan.groups.iter().flat_map(|group| group.executions.iter()).collect::<Vec<_>>();
        let witness = recursive_ancestry_revealed_head_witness(&projection).unwrap();
        for (index, execution_id, qa, rejection) in [
            (144, "resolve-explicit-field-sweep--declared-explicit-root",
                B4NegativeQaResultCode::B4ResolveExplicitSemanticsMismatch, B4AncestryRejection::ResolveExplicit),
            (155, "resolve-assumption-inventory-sweep--pruned-assumption",
                B4NegativeQaResultCode::B4ResolveAssumptionInventoryInvalid, B4AncestryRejection::AssumptionInventory),
        ] {
            assert_eq!(rows[index].execution_id, execution_id);
            assert_eq!(rows[index].qa_result_code, qa);
            let closed = reconstruct_genuine_resolve_ancestry(index, input.ancestry(), input.statement(),
                input.final_seal(), &map, manifest).unwrap();
            assert_eq!(closed.derived_registry_row.execution_id, execution_id);
            assert_eq!(closed.derived_registry_row.base_selector_id, "case9-typed-ancestry-v1");
            assert_eq!(closed.base, input.ancestry());
            assert_eq!(closed.contexts, vec![manifest.to_vec()]);
            let decoded = decode_subject_envelope(&closed.subject, ancestry_subject_envelope_contract()).unwrap();
            let [ancestry, statement, final_seal, auxiliary]: [&[u8]; 4] = decoded.parts().try_into().unwrap();
            assert_eq!(statement, input.statement());
            assert_eq!(final_seal, input.final_seal());
            assert_eq!(auxiliary, map);
            let mut expected = projection.clone();
            if index == 144 {
                expected.assumption_receipt.as_mut().unwrap().requested_control_root = "00".repeat(DIGEST_BYTES);
                assert!(matches!(closed.derived_registry_row.materialization,
                    B4NegativeMaterialization::Mutation { mutation: B4NegativeMutation::ByteEdit {
                        target: B4ByteTarget::Ancestry, .. } }));
            } else {
                expected.assumption_receipt.as_mut().unwrap().source_inventory.entries =
                    vec![RecursiveAncestryInventoryEntry::Pruned { digest: hex::encode(witness.exact_digest) }];
                assert_eq!(closed.derived_registry_row.materialization,
                    B4NegativeMaterialization::Mutation { mutation: B4NegativeMutation::AncestryInventoryEdit {
                        edit: B4AncestryInventoryOperation::PruneRevealedHead {
                            before_claim_digest: hex::encode(witness.claim_digest),
                            before_control_root: hex::encode(witness.control_root),
                            exact_digest: hex::encode(witness.exact_digest),
                        }, target: B4AncestryInventoryTarget::AssumptionSourceInventoryHead } });
            }
            assert_eq!(parse_recursive_ancestry_jcs(ancestry).unwrap(), expected);
            assert_eq!(ancestry, recursive_ancestry_to_jcs(&expected).unwrap());
            let contexts = closed.contexts.iter().map(Vec::as_slice).collect::<Vec<_>>();
            assert_eq!(reject_ancestry_replay(&closed.subject, &contexts).unwrap(), rejection);
            exact_error(reconstruct_genuine_resolve_ancestry(index, ancestry, statement, final_seal, auxiliary, manifest),
                "genuine resolve ancestry base is not canonical positive evidence");

            // Each private failure preserves the actual mutation and every unselected part.
            exact_error(reject_ancestry_replay(&closed.subject, &[]),
                "ancestry replay requires exactly one manifest context");
            let mut corrupted_seal = final_seal.to_vec();
            corrupted_seal[0] ^= 1;
            let corrupted = envelope(ancestry, statement, &corrupted_seal, auxiliary);
            exact_error(reject_ancestry_replay(&corrupted, &contexts),
                "final raw seal SHA-256 differs from its binding");
            let mut wrong_map = auxiliary.to_vec();
            wrong_map[..2].copy_from_slice(&0u16.to_le_bytes());
            let malformed = envelope(ancestry, statement, final_seal, &wrong_map);
            let error = reject_ancestry_replay(&malformed, &contexts).unwrap_err();
            assert_eq!(error.to_string(), "cannot decode exact recursive auxiliary map");
            assert_eq!(error.downcast_ref::<B4ByteMapError>(), Some(&B4ByteMapError::CountNotAllowed { actual: 0 }));
        }
        exact_error(reconstruct_genuine_resolve_ancestry(149, input.ancestry(), input.statement(),
            input.final_seal(), &map, manifest), "genuine resolve ancestry seam permits only rows 144 and 155");
    }
}

#[cfg(all(test, feature = "negative-materialization-set"))]
mod genuine_alternate_root {
    use super::*;
    use crate::{
        b4::{B4NegativeMaterialization, B4NegativeMutation},
        b4_alternate_root_authority::genuine_alternate_root as alternate,
        b4_c2_alternate_root::reconstruct_genuine_alternate_root,
        b4_c2_opcode_sequence::{decode_producer_opcode_subject, encode_opcode_subject, split_raw_seal},
        b4_materialization_set::B4ClosedReconstructedExecutionV1,
        b4_plan::{B4NegativeQaResultCode, Eip0045B4NegativePlanV1},
        b4_subject_envelope::encode_subject_envelope,
        b4_terminal_byte_map::B4ByteMapError,
        b4_validator::negative_verifier::{genuine_conditional_claim::load_authenticated, reject_raw_seal_shape},
        recursive_ancestry::recursive_ancestry_to_jcs,
    };
    use sha2::{Digest as _, Sha256};
    use std::path::Path;

    fn envelope(ancestry: &[u8], statement: &[u8], seal: &[u8], map: &[u8]) -> Vec<u8> {
        encode_subject_envelope(&[ancestry, statement, seal, map], ancestry_subject_envelope_contract()).unwrap()
    }

    fn exact_error<T>(result: Result<T>, expected: &str) {
        assert_eq!(result.err().expect("private failure required").to_string(), expected);
    }

    fn require_resolve_rejection(result: Result<B4AncestryRejection>) -> Result<()> {
        ensure!(result? == B4AncestryRejection::ResolveExplicit, "alternate consumer returned another boundary");
        Ok(())
    }

    fn validate_splice(row: &B4ClosedReconstructedExecutionV1, original: &RecursiveAncestryProjection,
        ancestry: &[u8], statement: &[u8], final_seal: &[u8], map: &[u8], manifest: &[u8], alternate: &[u8]) -> Result<()> {
        ensure!(row.derived_registry_row.execution_id == "resolve-explicit-field-sweep--assumption-receipt-root"
            && row.derived_registry_row.base_selector_id == "case9-typed-ancestry-v1"
            && row.derived_registry_row.materialization == B4NegativeMaterialization::Mutation {
                mutation: B4NegativeMutation::AlternateRootAssumptionSubstitution {} }, "alternate row recipe differs");
        ensure!(row.base == ancestry && row.contexts == vec![manifest.to_vec()], "alternate row base or context differs");
        let decoded = decode_subject_envelope(&row.subject, ancestry_subject_envelope_contract())?;
        let [changed, actual_statement, actual_final, actual_map]: [&[u8]; 4] = decoded.parts().try_into().unwrap();
        ensure!(actual_statement == statement && actual_final == final_seal, "alternate row untouched envelope parts differ");
        let mut expected = original.clone();
        let assumption = expected.assumption_receipt.as_mut().unwrap();
        let assumption_path = assumption.raw_seal.path.clone();
        assumption.raw_seal.sha256 = hex::encode(Sha256::digest(alternate));
        ensure!(parse_recursive_ancestry_jcs(changed)? == expected && changed == recursive_ancestry_to_jcs(&expected)?,
            "alternate row projection changes more than the raw reference SHA");
        let profile = StarkProfileManifestV1::decode(manifest)?.profile_id()?;
        ensure!(classify_recursive_ancestry_semantics(&expected, statement, profile)? == RecursiveAncestrySemanticOutcome::Canonical,
            "alternate row is not structurally canonical");
        let before = decode_recursive_auxiliary_map(map, RecursiveAncestryFamily::TerminalResolve)?;
        let after = decode_recursive_auxiliary_map(actual_map, RecursiveAncestryFamily::TerminalResolve)?;
        for (path, bytes) in before.iter() {
            ensure!(after.get(path) == Some(if path == assumption_path { alternate } else { bytes }),
                "alternate row changed another auxiliary seal");
        }
        Ok(())
    }

    #[test]
    fn alternate_consumer_oracle_rejects_other_boundaries_and_private_failures() {
        require_resolve_rejection(Ok(B4AncestryRejection::ResolveExplicit)).unwrap();
        for boundary in [B4AncestryRejection::ResolveZeroRoot, B4AncestryRejection::ClaimEdge,
            B4AncestryRejection::AssumptionInventory] {
            exact_error(require_resolve_rejection(Ok(boundary)), "alternate consumer returned another boundary");
        }
        exact_error(require_resolve_rejection(Err(anyhow::anyhow!("ancestry subject was unexpectedly accepted"))),
            "ancestry subject was unexpectedly accepted");
    }

    #[test]
    #[ignore = "requires genuine current alternate-root and Resolve exports plus pinned guest; local diagnostic only"]
    fn genuine_alternate_root_c2_producer_consumer_matrix() {
        let resolve_root = std::env::var_os("EIP0045_B4_RESOLVE_VECTOR_ROOT").expect("Resolve root required");
        let alternate_root = std::env::var_os("EIP0045_B4_ALTERNATE_VECTOR_ROOT").expect("alternate root required");
        let guest = std::env::var_os("EIP0045_B4_GUEST_FILE").expect("pinned guest required");
        let (input, projection) = load_authenticated(Path::new(&resolve_root)).unwrap();
        assert_eq!(input.statement().len(), 160);
        assert_eq!(hex::encode(Sha256::digest(input.statement())),
            "da4f3d7483d082324d1d11a3df67fd0dbfb662e0091ad741400be32ac3c15ae1");
        let authority = alternate::load_authenticated(Path::new(&alternate_root), input.statement(), Path::new(&guest)).unwrap();
        assert_eq!(hex::encode(Sha256::digest(authority.raw_seal())),
            "c0ddfd89529fb0b3046808b6666018b66356a92826f7eab55deffff9036981a3");
        assert_eq!(authority.claim_digest(), recursive_ancestry_claim_digest(&projection.assumption_receipt.as_ref().unwrap().claim).unwrap());
        alternate::assert_single_faults(Path::new(&alternate_root), input.statement(), Path::new(&guest)).unwrap();
        let entries = input.auxiliary().iter().map(|(p, b)| (p.as_str(), b.as_slice())).collect::<Vec<_>>();
        let map = encode_recursive_auxiliary_map(&B4RecursiveAuxiliaryMapV1::from_exact_entries(
            RecursiveAncestryFamily::TerminalResolve, &entries).unwrap()).unwrap();
        let positive = envelope(input.ancestry(), input.statement(), input.final_seal(), &map);
        let contexts = [input.manifest()];
        // Actual positive consumer authenticates the final, conditional, and assumption seals.
        exact_error(reject_ancestry_replay(&positive, &contexts), "ancestry subject was unexpectedly accepted");
        let seam = |index, ancestry: &[u8], statement: &[u8], seal: &[u8], map: &[u8]| {
            reconstruct_genuine_alternate_root(index, &authority, ancestry, statement, seal, map, input.manifest())
        };
        let row = seam(146, input.ancestry(), input.statement(), input.final_seal(), &map).unwrap();
        let validate = |row: &B4ClosedReconstructedExecutionV1| validate_splice(row, &projection,
            input.ancestry(), input.statement(), input.final_seal(), &map, input.manifest(), authority.raw_seal());
        validate(&row).unwrap();
        let row_contexts = row.contexts.iter().map(Vec::as_slice).collect::<Vec<_>>();
        require_resolve_rejection(reject_ancestry_replay(&row.subject, &row_contexts)).unwrap();
        let decoded = decode_subject_envelope(&row.subject, ancestry_subject_envelope_contract()).unwrap();
        let [changed, statement, seal, changed_map]: [&[u8]; 4] = decoded.parts().try_into().unwrap();
        // Restoring exactly the original subject restores actual positive acceptance.
        exact_error(reject_ancestry_replay(&positive, &contexts), "ancestry subject was unexpectedly accepted");
        let mut mutant = row.clone();
        mutant.subject = positive.clone();
        exact_error(validate(&mutant), "alternate row projection changes more than the raw reference SHA");
        mutant = row.clone();
        mutant.derived_registry_row.execution_id.push('x');
        exact_error(validate(&mutant), "alternate row recipe differs");
        mutant = row.clone();
        mutant.contexts.clear();
        exact_error(validate(&mutant), "alternate row base or context differs");
        exact_error(reject_ancestry_replay(&row.subject, &[]), "ancestry replay requires exactly one manifest context");
        exact_error(reject_ancestry_replay(&row.subject, &[b"bad"]), "cannot decode ancestry manifest context");
        // Stale reference and changed auxiliary bytes isolate the artifact-binding gate.
        exact_error(reject_ancestry_replay(&envelope(input.ancestry(), statement, seal, changed_map), &contexts),
            "assumption raw seal SHA-256 differs from its binding");
        let mut corrupt = seal.to_vec();
        corrupt[0] ^= 1;
        exact_error(reject_ancestry_replay(&envelope(changed, statement, &corrupt, changed_map), &contexts),
            "final raw seal SHA-256 differs from its binding");
        let mut malformed = changed_map.to_vec();
        malformed[..2].copy_from_slice(&0u16.to_le_bytes());
        let error = reject_ancestry_replay(&envelope(changed, statement, seal, &malformed), &contexts).unwrap_err();
        assert_eq!(error.to_string(), "cannot decode exact recursive auxiliary map");
        assert_eq!(error.downcast_ref::<B4ByteMapError>(), Some(&B4ByteMapError::CountNotAllowed { actual: 0 }));
        let mut wrong_statement = statement.to_vec();
        wrong_statement[159] ^= 1;
        exact_error(reject_ancestry_replay(&envelope(changed, &wrong_statement, seal, changed_map), &contexts),
            "ancestry statement SHA-256 differs");
        let mut zero = projection.clone();
        zero.assumption_receipt.as_mut().unwrap().requested_control_root = "00".repeat(32);
        let zero_bytes = recursive_ancestry_to_jcs(&zero).unwrap();
        exact_error(seam(146, &zero_bytes, statement, seal, &map), "genuine alternate-root base is not canonical positive evidence");
        let mut wrong_claim = parse_recursive_ancestry_jcs(changed).unwrap();
        wrong_claim.assumption_receipt.as_mut().unwrap().claim.user_exit ^= 1;
        let wrong_claim_bytes = recursive_ancestry_to_jcs(&wrong_claim).unwrap();
        exact_error(reject_ancestry_replay(&envelope(&wrong_claim_bytes, statement, seal, changed_map), &contexts),
            "ancestry producer seal failed claim binding");
        // A requested-root change can yield the same public class; the splice oracle must reject it.
        let mut extra = parse_recursive_ancestry_jcs(changed).unwrap();
        extra.assumption_receipt.as_mut().unwrap().requested_control_root = "00".repeat(32);
        mutant = row.clone();
        mutant.subject = envelope(&recursive_ancestry_to_jcs(&extra).unwrap(), statement, seal, changed_map);
        exact_error(validate(&mutant), "alternate row projection changes more than the raw reference SHA");
        mutant = row.clone();
        mutant.subject = envelope(changed, &wrong_statement, seal, changed_map);
        exact_error(validate(&mutant), "alternate row untouched envelope parts differ");
        for index in [0, 107, 109, 144, 145, 147, 149, 155, usize::MAX] {
            exact_error(seam(index, &[], &[], &[], &[]), "genuine alternate-root seam permits only rows 108 and 146");
        }
        let plan = Eip0045B4NegativePlanV1::canonical().unwrap();
        let rows = plan.groups.iter().flat_map(|g| g.executions.iter()).collect::<Vec<_>>();
        assert_eq!(rows[146].qa_result_code, B4NegativeQaResultCode::B4ResolveExplicitSemanticsMismatch);
        assert_eq!(rows[108].qa_result_code, B4NegativeQaResultCode::RawSealInnerControlRootMismatch);
        let raw = seam(108, input.ancestry(), statement, seal, &map).unwrap();
        assert_eq!(raw.derived_registry_row.execution_id, "terminal-inner-root-mismatch--inner-control-root");
        assert_eq!(raw.derived_registry_row.base_selector_id, "alternate-root-lift-po2-15-v1");
        assert_eq!(raw.derived_registry_row.materialization, B4NegativeMaterialization::FixtureSelection {
            fixture_id: "alternate-root-lift-po2-15-v1".into() });
        assert_eq!(raw.base, authority.raw_seal());
        assert_eq!(raw.contexts, vec![input.manifest().to_vec()]);
        let opcode = decode_producer_opcode_subject(&raw.subject).unwrap();
        assert_eq!(opcode.proof_chunks().concat(), authority.raw_seal());
        let parsed = crate::ergo_statement::parse_ergo_statement_v1(statement).unwrap();
        assert_eq!(raw.subject, encode_opcode_subject(&split_raw_seal(authority.raw_seal()).unwrap(),
            parsed.application_payload(), &parsed.program_id(), &parsed.profile_id()).unwrap());
        let boundary = reject_raw_seal_shape(&raw.subject, &raw.contexts.iter().map(Vec::as_slice).collect::<Vec<_>>()).unwrap();
        assert_eq!((boundary.class(), boundary.stage()), ("inner-control-root-mismatch", "inner-control-root-binding"));
    }
}

use std::collections::BTreeMap;

use anyhow::{Context as _, Result, bail, ensure};
use risc0_zkp::field::baby_bear::{BabyBearElem, P as BABY_BEAR_MODULUS};

use crate::{
    b4_recursive_auxiliary_map::decode_recursive_auxiliary_map,
    b4_subject_envelope::{ancestry_subject_envelope_contract, decode_subject_envelope},
    canonical::validate_lower_hex_exact,
    constants::{
        B4_ALTERNATE_CONTROL_ROOT, DIGEST_BYTES, TERMINAL_CONTROL_KIND_JOIN,
        TERMINAL_CONTROL_KIND_LIFT, TERMINAL_CONTROL_KIND_RESOLVE,
    },
    profile_manifest::StarkProfileManifestV1,
    recursive_ancestry::{
        RecursiveAncestryArtifactReference, RecursiveAncestryClaim, RecursiveAncestryFamily,
        RecursiveAncestryOperation, RecursiveAncestryProjection, RecursiveAncestrySemanticOutcome,
        RecursiveAncestryTerminal, classify_recursive_ancestry_semantics,
        parse_recursive_ancestry_jcs, recursive_ancestry_claim_digest,
        recursive_ancestry_expected_auxiliary_paths, validate_recursive_ancestry_artifacts,
        validate_recursive_ancestry_structure,
    },
    seal::decode_seal_words,
};

#[cfg(test)]
use crate::b4_recursive_auxiliary_map::{
    B4RecursiveAuxiliaryMapV1, encode_recursive_auxiliary_map,
};
#[cfg(test)]
use crate::constants::PROOF_BYTES;

use super::{
    stark::verify_stark,
    terminal::{B4TerminalKind, B4VerifiedTerminal},
};

const OUTPUT_WORDS: usize = 32;
const INNER_ROOT_WORDS: usize = 16;
const OUTER_PO2_WORD_INDEX: usize = OUTPUT_WORDS;

/// Stable ancestry-policy rejection returned only after framing and producer
/// evidence have reached the selected consumer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum B4AncestryRejection {
    ClaimEdge,
    ResolveExplicit,
    ResolveZeroRoot,
    AssumptionInventory,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UntrustedSealOutput {
    inner_root: [u8; DIGEST_BYTES],
    claim_digest: [u8; DIGEST_BYTES],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AuthenticatedSealProducer {
    inner_root: [u8; DIGEST_BYTES],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SealProducerRole {
    AssumptionLift,
    Lift,
    Join,
    Resolve,
}

impl SealProducerRole {
    const fn from_operation(operation: &RecursiveAncestryOperation) -> Self {
        match operation {
            RecursiveAncestryOperation::Lift { .. } => Self::Lift,
            RecursiveAncestryOperation::Join { .. } => Self::Join,
            RecursiveAncestryOperation::Resolve { .. } => Self::Resolve,
        }
    }

    const fn terminal_kind(self) -> B4TerminalKind {
        match self {
            Self::AssumptionLift | Self::Lift => B4TerminalKind::Lift,
            Self::Join => B4TerminalKind::Join,
            Self::Resolve => B4TerminalKind::Resolve,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SealProducerRootBinding {
    InitialProfile,
    FixedAlternateAssumption,
}

struct PreparedAncestry<'a> {
    projection: RecursiveAncestryProjection,
    statement: &'a [u8],
    profile_id: [u8; DIGEST_BYTES],
    authenticated_assumption_root: Option<[u8; DIGEST_BYTES]>,
}

/// Exercise the authenticated ancestry projection and return a typed policy
/// rejection.
///
/// Framing, JCS, manifest, path, artifact, raw-seal, STARK, root, claim, and
/// terminal failures return `Err`; none can become public observations.
pub(super) fn reject_ancestry_replay(
    subject: &[u8],
    contexts: &[&[u8]],
) -> Result<B4AncestryRejection> {
    ensure!(
        contexts.len() == 1,
        "ancestry replay requires exactly one manifest context"
    );
    let decoded = decode_subject_envelope(subject, ancestry_subject_envelope_contract())
        .context("invalid ancestry subject envelope")?;
    let [ancestry, statement, final_seal, auxiliary_map]: [&[u8]; 4] =
        decoded
            .parts()
            .try_into()
            .map_err(|_| anyhow::anyhow!("ancestry envelope part count changed after decoding"))?;

    let prepared = prepare_ancestry(ancestry, statement, final_seal, auxiliary_map, contexts[0])?;
    classify_semantics(&prepared)?.context("ancestry subject was unexpectedly accepted")
}

#[allow(
    clippy::too_many_lines,
    reason = "producer framing and authentication remain in one fail-closed validation order"
)]
fn prepare_ancestry<'a>(
    ancestry: &[u8],
    statement: &'a [u8],
    final_seal: &[u8],
    auxiliary_map: &[u8],
    manifest_bytes: &[u8],
) -> Result<PreparedAncestry<'a>> {
    let projection = parse_recursive_ancestry_jcs(ancestry)?;
    let manifest = StarkProfileManifestV1::decode(manifest_bytes)
        .context("cannot decode ancestry manifest context")?;
    ensure!(
        manifest.encode()?.as_slice() == manifest_bytes,
        "ancestry manifest decode/re-encode changed bytes"
    );
    manifest
        .validate_initial_profile_target()
        .context("ancestry manifest differs from the frozen initial target")?;
    let profile_id = manifest.profile_id()?;

    validate_recursive_ancestry_structure(&projection, statement, profile_id)?;
    let borrowed_auxiliary = decode_recursive_auxiliary_map(auxiliary_map, projection.family)?;
    ensure!(
        borrowed_auxiliary.family() == projection.family,
        "decoded auxiliary family differs from parsed ancestry"
    );
    let auxiliary = borrowed_auxiliary
        .iter()
        .map(|(path, bytes)| (path.to_owned(), bytes))
        .collect::<BTreeMap<_, _>>();
    ensure!(
        auxiliary.len() == borrowed_auxiliary.len(),
        "decoded auxiliary inventory lost one compiled path"
    );
    validate_recursive_ancestry_artifacts(&projection, statement, final_seal, &auxiliary)?;

    let final_step = projection
        .steps
        .last()
        .context("ancestry projection has no final step")?;
    let _final_producer = authenticate_seal_producer(
        final_seal,
        &manifest,
        SealProducerRole::from_operation(&final_step.operation),
        &final_step.terminal,
        recursive_ancestry_claim_digest(&final_step.claim)?,
    )?;

    let mut authenticated_assumption_root = None;
    for path in recursive_ancestry_expected_auxiliary_paths(projection.family) {
        let bytes = borrowed_auxiliary
            .get(&path)
            .with_context(|| format!("missing parsed-family producer seal {path}"))?;
        let (role, terminal, claim, reference) = auxiliary_producer_contract(&projection, &path)?;
        ensure!(
            reference.path == path,
            "auxiliary producer reference changed after shared artifact validation"
        );
        let producer = authenticate_seal_producer(
            bytes,
            &manifest,
            role,
            terminal,
            recursive_ancestry_claim_digest(claim)?,
        )?;
        if role == SealProducerRole::AssumptionLift {
            ensure!(
                authenticated_assumption_root
                    .replace(producer.inner_root)
                    .is_none(),
                "ancestry authenticated more than one assumption receipt"
            );
        }
    }
    ensure!(
        authenticated_assumption_root.is_some() == projection.family.uses_assumption(),
        "authenticated assumption-root presence differs from the ancestry family"
    );

    Ok(PreparedAncestry {
        projection,
        statement,
        profile_id,
        authenticated_assumption_root,
    })
}

fn classify_semantics(prepared: &PreparedAncestry<'_>) -> Result<Option<B4AncestryRejection>> {
    let outcome = classify_recursive_ancestry_semantics(
        &prepared.projection,
        prepared.statement,
        prepared.profile_id,
    )?;
    if outcome != RecursiveAncestrySemanticOutcome::Canonical {
        return Ok(map_semantic_outcome(outcome));
    }
    let requested_assumption_root = prepared
        .projection
        .assumption_receipt
        .as_ref()
        .map(|assumption| {
            parse_digest(
                &assumption.requested_control_root,
                "assumption requested control root",
            )
        })
        .transpose()?;
    classify_authenticated_assumption_root(
        prepared.projection.family,
        requested_assumption_root,
        prepared.authenticated_assumption_root,
    )
}

fn classify_authenticated_assumption_root(
    family: RecursiveAncestryFamily,
    requested: Option<[u8; DIGEST_BYTES]>,
    authenticated: Option<[u8; DIGEST_BYTES]>,
) -> Result<Option<B4AncestryRejection>> {
    match family {
        RecursiveAncestryFamily::TerminalJoin => {
            ensure!(
                requested.is_none() && authenticated.is_none(),
                "terminal-join unexpectedly retained an assumption root"
            );
            Ok(None)
        }
        RecursiveAncestryFamily::TerminalResolve => {
            let requested =
                requested.context("explicit resolve lost its requested control root")?;
            let authenticated =
                authenticated.context("explicit resolve lost its authenticated receipt root")?;
            Ok((requested != authenticated).then_some(B4AncestryRejection::ResolveExplicit))
        }
        RecursiveAncestryFamily::ResolveThenJoin => {
            ensure!(
                requested == Some([0; DIGEST_BYTES]) && authenticated.is_some(),
                "zero-root resolve lost its requested or authenticated assumption root"
            );
            Ok(None)
        }
    }
}

const fn map_semantic_outcome(
    outcome: RecursiveAncestrySemanticOutcome,
) -> Option<B4AncestryRejection> {
    match outcome {
        RecursiveAncestrySemanticOutcome::Canonical => None,
        RecursiveAncestrySemanticOutcome::ClaimEdge => Some(B4AncestryRejection::ClaimEdge),
        RecursiveAncestrySemanticOutcome::ResolveExplicit => {
            Some(B4AncestryRejection::ResolveExplicit)
        }
        RecursiveAncestrySemanticOutcome::ResolveZeroRoot => {
            Some(B4AncestryRejection::ResolveZeroRoot)
        }
        RecursiveAncestrySemanticOutcome::AssumptionInventory(_) => {
            Some(B4AncestryRejection::AssumptionInventory)
        }
    }
}

fn auxiliary_producer_contract<'a>(
    projection: &'a RecursiveAncestryProjection,
    path: &str,
) -> Result<(
    SealProducerRole,
    &'a RecursiveAncestryTerminal,
    &'a RecursiveAncestryClaim,
    &'a RecursiveAncestryArtifactReference,
)> {
    if let Some(assumption) = projection
        .assumption_receipt
        .as_ref()
        .filter(|assumption| assumption.raw_seal.path == path)
    {
        return Ok((
            SealProducerRole::AssumptionLift,
            &assumption.terminal,
            &assumption.claim,
            &assumption.raw_seal,
        ));
    }
    let step = projection
        .steps
        .iter()
        .take(projection.steps.len() - 1)
        .find(|step| step.raw_seal.path == path)
        .context("parsed-family auxiliary path has no producer contract")?;
    Ok((
        SealProducerRole::from_operation(&step.operation),
        &step.terminal,
        &step.claim,
        &step.raw_seal,
    ))
}

fn authenticate_seal_producer(
    raw_seal: &[u8],
    manifest: &StarkProfileManifestV1,
    role: SealProducerRole,
    projected_terminal: &RecursiveAncestryTerminal,
    expected_claim: [u8; DIGEST_BYTES],
) -> Result<AuthenticatedSealProducer> {
    let output = decode_untrusted_seal_output(raw_seal, manifest)?;
    let verified = verify_stark(manifest, raw_seal)
        .context("ancestry producer seal failed pinned STARK verification")?;
    let root_binding = require_supported_producer_root(role, output.inner_root, manifest)?;
    let root_bound = match root_binding {
        SealProducerRootBinding::InitialProfile => verified.bind_inner_control_root(),
        SealProducerRootBinding::FixedAlternateAssumption => {
            verified.bind_fixed_alternate_inner_control_root()
        }
    }
    .context("ancestry producer seal failed closed root binding")?;
    let bound = root_bound
        .bind_claim(expected_claim)
        .context("ancestry producer seal failed claim binding")?;
    ensure!(
        bound.inner_control_root() == output.inner_root
            && bound.claim_digest() == output.claim_digest,
        "ancestry producer typestate differs from independently decoded output"
    );
    ensure!(
        bound.terminal().kind() == role.terminal_kind(),
        "ancestry producer terminal kind differs from its role"
    );
    validate_projected_terminal(projected_terminal, role, manifest)?;
    bind_projected_terminal(projected_terminal, bound.terminal())?;
    Ok(AuthenticatedSealProducer {
        inner_root: bound.inner_control_root(),
    })
}

// This gate is reached only after `verify_stark`. It selects either the
// authenticated initial profile root or the one fixed alternate assumption
// witness; no caller-selected root can reach the typestate transition.
fn require_supported_producer_root(
    role: SealProducerRole,
    actual: [u8; DIGEST_BYTES],
    manifest: &StarkProfileManifestV1,
) -> Result<SealProducerRootBinding> {
    if actual == manifest.inner_control_root() {
        return Ok(SealProducerRootBinding::InitialProfile);
    }
    if role == SealProducerRole::AssumptionLift && actual == B4_ALTERNATE_CONTROL_ROOT {
        return Ok(SealProducerRootBinding::FixedAlternateAssumption);
    }
    ensure!(
        role != SealProducerRole::AssumptionLift,
        "assumption receipt root is neither the initial profile root nor the fixed alternate witness"
    );
    bail!("ancestry step producer root differs from the authenticated profile")
}

fn decode_untrusted_seal_output(
    raw_seal: &[u8],
    manifest: &StarkProfileManifestV1,
) -> Result<UntrustedSealOutput> {
    let words = decode_seal_words(raw_seal).context("cannot decode ancestry producer seal")?;
    ensure!(
        words.iter().all(|word| *word < BABY_BEAR_MODULUS),
        "ancestry producer seal contains a non-reduced word"
    );
    ensure!(
        words[OUTER_PO2_WORD_INDEX] == u32::from(manifest.outer_po2()),
        "ancestry producer seal has the wrong outer exponent"
    );

    let mut inner_root = [0u8; DIGEST_BYTES];
    for (root_index, seal_index) in (0..INNER_ROOT_WORDS).step_by(2).enumerate() {
        ensure!(
            words[seal_index + 1] == 0,
            "ancestry producer seal has nonzero root padding"
        );
        let decoded = BabyBearElem::new_raw(words[seal_index]).as_u32();
        inner_root[root_index * 4..root_index * 4 + 4].copy_from_slice(&decoded.to_le_bytes());
    }
    let mut claim_digest = [0u8; DIGEST_BYTES];
    for (offset, raw_word) in words[INNER_ROOT_WORDS..OUTPUT_WORDS]
        .iter()
        .copied()
        .enumerate()
    {
        let decoded = BabyBearElem::new_raw(raw_word).as_u32();
        let halfword =
            u16::try_from(decoded).context("ancestry producer seal claim halfword exceeds u16")?;
        claim_digest[offset * 2..offset * 2 + 2].copy_from_slice(&halfword.to_le_bytes());
    }
    Ok(UntrustedSealOutput {
        inner_root,
        claim_digest,
    })
}

fn validate_projected_terminal(
    terminal: &RecursiveAncestryTerminal,
    role: SealProducerRole,
    manifest: &StarkProfileManifestV1,
) -> Result<()> {
    let (kind, parameter, control_id) = projected_terminal_fields(terminal)?;
    ensure!(
        kind == role.terminal_kind(),
        "ancestry projected terminal kind differs from its operation"
    );
    let manifest_kind = match kind {
        B4TerminalKind::Lift => TERMINAL_CONTROL_KIND_LIFT,
        B4TerminalKind::Join => TERMINAL_CONTROL_KIND_JOIN,
        B4TerminalKind::Resolve => TERMINAL_CONTROL_KIND_RESOLVE,
    };
    let control = manifest
        .terminal_controls()
        .iter()
        .find(|entry| entry.control_kind() == manifest_kind && entry.parameter() == parameter)
        .context("ancestry terminal key is absent from the manifest")?;
    ensure!(
        control_id == control.control_id(),
        "ancestry terminal control ID differs from the manifest"
    );
    Ok(())
}

fn bind_projected_terminal(
    projected: &RecursiveAncestryTerminal,
    actual: B4VerifiedTerminal,
) -> Result<()> {
    let (kind, parameter, control_id) = projected_terminal_fields(projected)?;
    ensure!(
        (kind, parameter, control_id) == (actual.kind(), actual.parameter(), actual.control_id()),
        "ancestry projection terminal differs from its cryptographically verified producer"
    );
    Ok(())
}

fn projected_terminal_fields(
    terminal: &RecursiveAncestryTerminal,
) -> Result<(B4TerminalKind, u8, [u8; DIGEST_BYTES])> {
    match terminal {
        RecursiveAncestryTerminal::Lift {
            segment_po2,
            control_id,
        } => Ok((
            B4TerminalKind::Lift,
            u8::try_from(*segment_po2).context("lift exponent does not fit u8")?,
            parse_digest(control_id, "ancestry lift control ID")?,
        )),
        RecursiveAncestryTerminal::Join { control_id } => Ok((
            B4TerminalKind::Join,
            0,
            parse_digest(control_id, "ancestry join control ID")?,
        )),
        RecursiveAncestryTerminal::Resolve { control_id } => Ok((
            B4TerminalKind::Resolve,
            0,
            parse_digest(control_id, "ancestry resolve control ID")?,
        )),
    }
}

fn parse_digest(value: &str, label: &str) -> Result<[u8; DIGEST_BYTES]> {
    validate_lower_hex_exact(value, DIGEST_BYTES)
        .with_context(|| format!("{label} is not exact lowercase hex"))?;
    let mut bytes = [0u8; DIGEST_BYTES];
    hex::decode_to_slice(value, &mut bytes).with_context(|| format!("cannot decode {label}"))?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use risc0_zkp::field::baby_bear::BabyBearElem;

    use super::*;
    use crate::recursive_ancestry::RecursiveAncestryInventoryDefect;

    const MANIFEST: &[u8] = include_bytes!("../../../profiles/risc0-v3-succinct/manifest.bin");

    #[test]
    fn shared_semantic_outcomes_have_one_closed_adapter_mapping() {
        assert_eq!(
            map_semantic_outcome(RecursiveAncestrySemanticOutcome::Canonical),
            None
        );
        assert_eq!(
            map_semantic_outcome(RecursiveAncestrySemanticOutcome::ClaimEdge),
            Some(B4AncestryRejection::ClaimEdge)
        );
        assert_eq!(
            map_semantic_outcome(RecursiveAncestrySemanticOutcome::ResolveExplicit),
            Some(B4AncestryRejection::ResolveExplicit)
        );
        assert_eq!(
            map_semantic_outcome(RecursiveAncestrySemanticOutcome::ResolveZeroRoot),
            Some(B4AncestryRejection::ResolveZeroRoot)
        );
        for defect in [
            RecursiveAncestryInventoryDefect::Missing,
            RecursiveAncestryInventoryDefect::Extra,
            RecursiveAncestryInventoryDefect::Pruned,
        ] {
            assert_eq!(
                map_semantic_outcome(RecursiveAncestrySemanticOutcome::AssumptionInventory(
                    defect
                )),
                Some(B4AncestryRejection::AssumptionInventory)
            );
        }
    }

    #[test]
    fn fabricated_producer_shape_cannot_cross_pinned_stark_verification() {
        let manifest = manifest();
        let terminal = RecursiveAncestryTerminal::Resolve {
            control_id: hex::encode(
                manifest
                    .terminal_controls()
                    .iter()
                    .find(|entry| {
                        entry.control_kind() == TERMINAL_CONTROL_KIND_RESOLVE
                            && entry.parameter() == 0
                    })
                    .unwrap()
                    .control_id(),
            ),
        };
        let claim = [0x42; DIGEST_BYTES];
        let error = authenticate_seal_producer(
            &seal_for(&manifest, claim),
            &manifest,
            SealProducerRole::Resolve,
            &terminal,
            claim,
        )
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("failed pinned STARK verification"),
            "fabricated producer failed outside pinned verification: {error:#}"
        );
    }

    #[test]
    fn auxiliary_map_is_family_exact_sorted_and_trailing_free() {
        let family = RecursiveAncestryFamily::TerminalResolve;
        let seal = vec![0u8; PROOF_BYTES];
        let paths = recursive_ancestry_expected_auxiliary_paths(family);
        let entries = paths
            .iter()
            .map(|path| (path.as_str(), seal.as_slice()))
            .collect::<Vec<_>>();
        let map = B4RecursiveAuxiliaryMapV1::from_exact_entries(family, &entries).unwrap();
        let encoded = encode_recursive_auxiliary_map(&map).unwrap();
        assert_eq!(
            decode_recursive_auxiliary_map(&encoded, family)
                .unwrap()
                .len(),
            2
        );

        let mut truncated = encoded.clone();
        truncated.pop();
        assert!(decode_recursive_auxiliary_map(&truncated, family).is_err());

        let mut trailing = encoded;
        trailing.push(0);
        assert!(decode_recursive_auxiliary_map(&trailing, family).is_err());
    }

    #[test]
    fn assumption_root_gate_admits_only_initial_and_fixed_alternate_roots() {
        let manifest = manifest();
        assert!(
            require_supported_producer_root(
                SealProducerRole::AssumptionLift,
                manifest.inner_control_root(),
                &manifest,
            )
            .is_ok()
        );
        assert_eq!(
            require_supported_producer_root(
                SealProducerRole::AssumptionLift,
                B4_ALTERNATE_CONTROL_ROOT,
                &manifest,
            )
            .unwrap(),
            SealProducerRootBinding::FixedAlternateAssumption
        );
        let error = require_supported_producer_root(
            SealProducerRole::AssumptionLift,
            [0xa5; DIGEST_BYTES],
            &manifest,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("neither the initial profile root nor the fixed alternate witness")
        );
    }

    #[test]
    fn explicit_resolve_compares_the_authenticated_assumption_root() {
        let stock = [0x11; DIGEST_BYTES];
        let alternate = [0x22; DIGEST_BYTES];
        assert_eq!(
            classify_authenticated_assumption_root(
                RecursiveAncestryFamily::TerminalResolve,
                Some(stock),
                Some(stock),
            )
            .unwrap(),
            None
        );
        assert_eq!(
            classify_authenticated_assumption_root(
                RecursiveAncestryFamily::TerminalResolve,
                Some(stock),
                Some(alternate),
            )
            .unwrap(),
            Some(B4AncestryRejection::ResolveExplicit)
        );
        assert_eq!(
            classify_authenticated_assumption_root(
                RecursiveAncestryFamily::ResolveThenJoin,
                Some([0; DIGEST_BYTES]),
                Some(alternate),
            )
            .unwrap(),
            None
        );
        assert_eq!(
            classify_authenticated_assumption_root(
                RecursiveAncestryFamily::TerminalJoin,
                None,
                None,
            )
            .unwrap(),
            None
        );
    }

    fn manifest() -> StarkProfileManifestV1 {
        let manifest = StarkProfileManifestV1::decode(MANIFEST).unwrap();
        manifest.validate_initial_profile_target().unwrap();
        manifest
    }

    fn seal_for(manifest: &StarkProfileManifestV1, claim_digest: [u8; DIGEST_BYTES]) -> Vec<u8> {
        let mut words = vec![0u32; PROOF_BYTES / 4];
        for (index, chunk) in manifest.inner_control_root().chunks_exact(4).enumerate() {
            let decoded = u32::from_le_bytes(chunk.try_into().unwrap());
            words[index * 2] = BabyBearElem::new(decoded).as_u32_montgomery();
        }
        for (index, chunk) in claim_digest.chunks_exact(2).enumerate() {
            let decoded = u32::from(u16::from_le_bytes(chunk.try_into().unwrap()));
            words[INNER_ROOT_WORDS + index] = BabyBearElem::new(decoded).as_u32_montgomery();
        }
        words[OUTER_PO2_WORD_INDEX] = u32::from(manifest.outer_po2());
        words.into_iter().flat_map(u32::to_le_bytes).collect()
    }
}
