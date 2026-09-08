//! Typed negative adapters for non-instrumented verifier-input surfaces.
//!
//! Framing or context failures are private adapter failures.  A returned
//! [`B4NegativeVerifierBoundary`] can come only from one selected production
//! consumer's structured error.  Case IDs, QA codes, expected results, and
//! diagnostic text are deliberately absent.

#![allow(
    dead_code,
    reason = "the single negative-handler table wires these reviewed adapters in the integration lot"
)]

#[cfg(all(test, feature = "validator", feature = "materializer-replay"))]
pub(super) mod genuine_conditional_claim {
    use super::*;
    use anyhow::{Context as _, Result, ensure};
    use std::{collections::BTreeMap, fs, io::Read, path::{Component, Path}};
    use crate::{
        b4::B4NegativeMaterialization,
        b4_c2_receipt_claim::reconstruct_genuine_case9,
        constants::MAX_STATEMENT_BYTES,
        recursive_ancestry::{
            RecursiveAncestryClaim, RecursiveAncestryFamily, RecursiveAncestryOperation,
            RecursiveAncestryProjection, RecursiveAncestryTerminal, RECURSIVE_ANCESTRY_MAX_BYTES,
            parse_recursive_ancestry_jcs, recursive_ancestry_claim_digest, recursive_ancestry_to_jcs,
            recursive_ancestry_expected_auxiliary_paths, validate_canonical_recursive_ancestry,
            validate_recursive_ancestry_artifacts,
        },
    };
    use super::super::terminal::B4TerminalKind;

    const MANIFEST: &[u8] = include_bytes!("../../../profiles/risc0-v3-succinct/manifest.bin");

    #[derive(Clone)]
    pub(in crate::b4_validator) struct Inputs {
        ancestry: Vec<u8>,
        statement: Vec<u8>,
        final_seal: Vec<u8>,
        auxiliary: BTreeMap<String, Vec<u8>>,
    }

    impl Inputs {
        pub(in crate::b4_validator) fn ancestry(&self) -> &[u8] { &self.ancestry }
        pub(in crate::b4_validator) fn statement(&self) -> &[u8] { &self.statement }
        pub(in crate::b4_validator) fn final_seal(&self) -> &[u8] { &self.final_seal }
        pub(in crate::b4_validator) fn auxiliary(&self) -> &BTreeMap<String, Vec<u8>> { &self.auxiliary }
        pub(in crate::b4_validator) fn manifest(&self) -> &'static [u8] { MANIFEST }
    }

    pub(in crate::b4_validator) fn load_authenticated(
        root: &Path,
    ) -> Result<(Inputs, RecursiveAncestryProjection)> {
        let input = load(root)?;
        let projection = authenticate(&input)?;
        Ok((input, projection))
    }

    fn redirected(metadata: &fs::Metadata) -> bool {
        #[cfg(windows)]
        { use std::os::windows::fs::MetadataExt; metadata.file_attributes() & 0x400 != 0 }
        #[cfg(not(windows))]
        { let _ = metadata; false }
    }

    fn directory(path: &Path) -> Result<()> {
        ensure!(path.is_absolute() && !path.components().any(|p| p == Component::ParentDir),
            "conditional directory path");
        for ancestor in path.ancestors() {
            let metadata = fs::symlink_metadata(ancestor)?;
            ensure!(metadata.is_dir() && !metadata.file_type().is_symlink() && !redirected(&metadata),
                "conditional directory redirect");
        }
        Ok(())
    }

    fn bounded(reader: &mut impl Read, minimum: usize, maximum: usize, length: u64) -> Result<Vec<u8>> {
        ensure!(length >= minimum as u64 && length <= maximum as u64, "conditional input bounds");
        let mut bytes = Vec::new();
        reader.take(maximum as u64 + 1).read_to_end(&mut bytes)?;
        ensure!(bytes.len() as u64 == length && bytes.len() <= maximum, "conditional input length drift");
        Ok(bytes)
    }

    fn read(path: &Path, minimum: usize, maximum: usize) -> Result<Vec<u8>> {
        directory(path.parent().context("conditional input parent")?)?;
        let before = fs::symlink_metadata(path)?;
        ensure!(before.is_file() && !before.file_type().is_symlink() && !redirected(&before),
            "conditional file redirect");
        let mut file = fs::File::open(path)?;
        ensure!(file.metadata()?.len() == before.len(), "conditional input length drift");
        let bytes = bounded(&mut file, minimum, maximum, before.len())?;
        let after = fs::symlink_metadata(path)?;
        ensure!(after.is_file() && !after.file_type().is_symlink() && !redirected(&after)
            && after.len() == before.len(), "conditional file changed");
        Ok(bytes)
    }

    fn load(root: &Path) -> Result<Inputs> {
        directory(root)?;
        let auxiliary = recursive_ancestry_expected_auxiliary_paths(RecursiveAncestryFamily::TerminalResolve)
            .into_iter().map(|path| {
                let bytes = read(&root.join("proof-output").join(&path), PROOF_BYTES, PROOF_BYTES)?;
                Ok((path, bytes))
            }).collect::<Result<BTreeMap<_, _>>>()?;
        Ok(Inputs {
            ancestry: read(&root.join("proof-output/candidate-ancestry.json"), 1, RECURSIVE_ANCESTRY_MAX_BYTES)?,
            statement: read(&root.join("proof-output/candidate-journal.bin"), 159, MAX_STATEMENT_BYTES)?,
            final_seal: read(&root.join("proof-output/candidate-raw-seal.bin"), PROOF_BYTES, PROOF_BYTES)?,
            auxiliary,
        })
    }

    fn bind_seal(raw: &[u8], claim: &RecursiveAncestryClaim, terminal: &RecursiveAncestryTerminal,
        manifest: &StarkProfileManifestV1) -> Result<()> {
        let verified = verify_stark(manifest, raw).context("conditional STARK")?
            .bind_inner_control_root().context("conditional root binding")?
            .bind_claim(recursive_ancestry_claim_digest(claim)?).context("conditional claim binding")?;
        let (kind, parameter, control) = match terminal {
            RecursiveAncestryTerminal::Lift { segment_po2, control_id } =>
                (B4TerminalKind::Lift, *segment_po2, control_id),
            RecursiveAncestryTerminal::Join { control_id } => (B4TerminalKind::Join, 0, control_id),
            RecursiveAncestryTerminal::Resolve { control_id } => (B4TerminalKind::Resolve, 0, control_id),
        };
        let actual = verified.terminal();
        ensure!(actual.kind() == kind && u32::from(actual.parameter()) == parameter
            && hex::encode(actual.control_id()) == *control, "conditional terminal binding");
        Ok(())
    }

    fn authenticate(input: &Inputs) -> Result<RecursiveAncestryProjection> {
        ensure!(!input.ancestry.is_empty() && input.ancestry.len() <= RECURSIVE_ANCESTRY_MAX_BYTES
            && (159..=MAX_STATEMENT_BYTES).contains(&input.statement.len())
            && input.final_seal.len() == PROOF_BYTES
            && input.auxiliary.values().all(|v| v.len() == PROOF_BYTES), "conditional input bounds");
        let mut paths = recursive_ancestry_expected_auxiliary_paths(RecursiveAncestryFamily::TerminalResolve);
        paths.sort();
        ensure!(input.auxiliary.keys().cloned().collect::<Vec<_>>() == paths, "conditional auxiliary inventory");
        let projection = parse_recursive_ancestry_jcs(&input.ancestry).context("conditional ancestry codec")?;
        ensure!(projection.family == RecursiveAncestryFamily::TerminalResolve && projection.steps.len() == 2
            && projection.steps[0].ordinal == 0
            && projection.steps[0].operation == (RecursiveAncestryOperation::Lift { segment_index: 0 }),
            "conditional step selection");
        let manifest = StarkProfileManifestV1::decode(MANIFEST)?;
        manifest.validate_initial_profile_target()?;
        validate_canonical_recursive_ancestry(&projection, &input.statement, manifest.profile_id()?)
            .context("conditional ancestry semantics")?;
        validate_recursive_ancestry_artifacts(&projection, &input.statement, &input.final_seal, &input.auxiliary)
            .context("conditional artifact binding")?;
        let assumption = projection.assumption_receipt.as_ref().context("conditional assumption")?;
        bind_seal(&input.auxiliary[&assumption.raw_seal.path], &assumption.claim, &assumption.terminal, &manifest)?;
        let step = &projection.steps[0];
        bind_seal(&input.auxiliary[&step.raw_seal.path], &step.claim, &step.terminal, &manifest)?;
        let final_step = &projection.steps[1];
        bind_seal(&input.final_seal, &final_step.claim, &final_step.terminal, &manifest)?;
        Ok(projection)
    }

    fn exact_error<T>(result: Result<T>, expected: &str) {
        assert_eq!(result.err().expect("negative must reject").to_string(), expected);
    }

    #[test]
    fn conditional_reader_bounds_and_relative_redirects_reject() {
        let mut exact = std::io::Cursor::new(b"abc");
        assert_eq!(bounded(&mut exact, 1, 3, 3).unwrap(), b"abc");
        let mut growing = std::io::Cursor::new(vec![0; 100]);
        exact_error(bounded(&mut growing, 1, 3, 3), "conditional input length drift");
        assert_eq!(growing.position(), 4);
        exact_error(bounded(&mut exact, 1, 3, 4), "conditional input bounds");
        exact_error(directory(Path::new("relative/../export")), "conditional directory path");
    }

    #[cfg(unix)]
    #[test]
    fn conditional_reader_rejects_file_and_parent_symlinks() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let physical = root.path().join("physical");
        fs::create_dir(&physical).unwrap();
        fs::write(physical.join("input"), b"abc").unwrap();
        symlink(physical.join("input"), root.path().join("leaf")).unwrap();
        exact_error(read(&root.path().join("leaf"), 1, 3), "conditional file redirect");
        symlink(&physical, root.path().join("parent")).unwrap();
        exact_error(read(&root.path().join("parent/input"), 1, 3), "conditional directory redirect");
        assert_eq!(read(&physical.join("input"), 1, 3).unwrap(), b"abc");
    }

    #[test]
    fn conditional_loader_uses_exact_export_proof_output_paths() {
        // Filesystem layout control only: these bytes are never authenticated as proofs.
        let root = tempfile::tempdir().unwrap();
        let output = root.path().join("proof-output");
        fs::create_dir(&output).unwrap();
        fs::write(output.join("candidate-ancestry.json"), b"{}").unwrap();
        fs::write(output.join("candidate-journal.bin"), vec![0; 160]).unwrap();
        fs::write(output.join("candidate-raw-seal.bin"), vec![0; PROOF_BYTES]).unwrap();
        let prefix = "reproduction/schema/b4-corpus-v1.candidate/positive/terminal-resolve-explicit-root/";
        let paths = [format!("{prefix}candidate-ancestry-assumption-raw-seal.bin"),
            format!("{prefix}candidate-ancestry-step-00-raw-seal.bin")];
        for (index, path) in paths.iter().enumerate() {
            let physical = output.join(path);
            fs::create_dir_all(physical.parent().unwrap()).unwrap();
            fs::write(physical, vec![index as u8 + 1; PROOF_BYTES]).unwrap();
        }
        let loaded = load(root.path()).unwrap();
        assert_eq!(loaded.auxiliary.keys().collect::<Vec<_>>(), paths.iter().collect::<Vec<_>>());
        assert_eq!(loaded.auxiliary[&paths[0]], vec![1; PROOF_BYTES]);
        assert_eq!(loaded.auxiliary[&paths[1]], vec![2; PROOF_BYTES]);
    }

    #[test]
    #[ignore = "requires authenticated genuine TerminalResolve export; local diagnostic only"]
    fn genuine_conditional_claim_c2_producer_consumer() {
        let root = std::env::var_os("EIP0045_B4_RESOLVE_VECTOR_ROOT").expect("Resolve export root required");
        let input = load(Path::new(&root)).unwrap();
        let projection = authenticate(&input).unwrap();
        let step = &projection.steps[0];
        let conditional = &input.auxiliary[&step.raw_seal.path];
        let contexts = [MANIFEST, input.statement.as_slice()];
        assert_eq!(reject_receipt_claim_policy(&input.final_seal, &contexts),
            Err(B4NegativeVerifierAdapterError::UnexpectedAcceptance));
        let expected = reject_receipt_claim_policy(conditional, &contexts).unwrap();
        assert_eq!(expected.class(), "receipt-claim-mismatch");
        assert_eq!(expected.stage(), "expected-claim-binding");

        let reconstructed = reconstruct_genuine_case9(conditional, MANIFEST, &input.statement).unwrap();
        assert_eq!(reconstructed.derived_registry_row.materialization,
            B4NegativeMaterialization::FixtureSelection { fixture_id: "case9-conditional-receipt-v1".to_owned() });
        assert_eq!(reconstructed.base, *conditional);
        assert_eq!(reconstructed.subject, *conditional);
        assert_eq!(reconstructed.contexts, vec![MANIFEST.to_vec(), input.statement.clone()]);
        let reconstructed_contexts = reconstructed.contexts.iter().map(Vec::as_slice).collect::<Vec<_>>();
        assert_eq!(reject_receipt_claim_policy(&reconstructed.subject, &reconstructed_contexts), Ok(expected));

        // Private single-input faults: none modifies any exported proof file.
        for replacement in [&input.final_seal,
            &input.auxiliary[&projection.assumption_receipt.as_ref().unwrap().raw_seal.path]] {
            let mut wrong = input.clone();
            assert_ne!(replacement, conditional);
            wrong.auxiliary.insert(step.raw_seal.path.clone(), replacement.clone());
            exact_error(authenticate(&wrong), "conditional artifact binding");
        }
        let mut corrupt = input.clone();
        corrupt.auxiliary.get_mut(&step.raw_seal.path).unwrap()[0] ^= 1;
        exact_error(authenticate(&corrupt), "conditional artifact binding");
        let mut missing = input.clone();
        missing.auxiliary.remove(&step.raw_seal.path);
        exact_error(authenticate(&missing), "conditional auxiliary inventory");
        let mut wrong_statement = input.clone();
        // A changed payload retains the statement codec shape but breaks the bound journal.
        *wrong_statement.statement.last_mut().unwrap() ^= 1;
        exact_error(authenticate(&wrong_statement), "conditional ancestry semantics");
        let mut wrong_selection = input.clone();
        let mut wrong_projection = projection.clone();
        wrong_projection.steps[0].ordinal = 1;
        wrong_selection.ancestry = recursive_ancestry_to_jcs(&wrong_projection).unwrap();
        exact_error(authenticate(&wrong_selection), "conditional step selection");
        let manifest = StarkProfileManifestV1::decode(MANIFEST).unwrap();
        let mut wrong_claim = step.claim.clone();
        let first = if wrong_claim.input_digest.starts_with('0') { "1" } else { "0" };
        wrong_claim.input_digest.replace_range(..1, first);
        exact_error(bind_seal(conditional, &wrong_claim, &step.terminal, &manifest), "conditional claim binding");
        exact_error(bind_seal(conditional, &step.claim, &projection.steps[1].terminal, &manifest),
            "conditional terminal binding");
        if let RecursiveAncestryTerminal::Lift { segment_po2, control_id } = &step.terminal {
            exact_error(bind_seal(conditional, &step.claim,
                &RecursiveAncestryTerminal::Lift { segment_po2: segment_po2 + 1, control_id: control_id.clone() },
                &manifest), "conditional terminal binding");
            let mut wrong_id = control_id.clone();
            wrong_id.replace_range(..1, if control_id.starts_with('0') { "1" } else { "0" });
            exact_error(bind_seal(conditional, &step.claim,
                &RecursiveAncestryTerminal::Lift { segment_po2: *segment_po2, control_id: wrong_id },
                &manifest), "conditional terminal binding");
        } else { panic!("authenticated step zero must be Lift"); }
        assert_eq!(reject_receipt_claim_policy(conditional, &[MANIFEST]),
            Err(B4NegativeVerifierAdapterError::ContextCardinality { actual: 1, expected: 2 }));
        assert_eq!(reject_receipt_claim_policy(conditional, &[input.statement.as_slice(), MANIFEST]),
            Err(B4NegativeVerifierAdapterError::ProfileContext));
    }
}

#[cfg(all(test, target_os = "linux", feature = "validator", feature = "materializer-replay"))]
mod genuine_terminal_policy {
    use super::*;
    use anyhow::{Result, ensure};
    use std::{collections::BTreeSet, fs, io::{Read, Write}, os::unix::fs::MetadataExt, path::{Path, PathBuf}};
    use crate::{
        b4::B4NegativeMaterialization,
        b4_c2_terminal_catalog::genuine_catalog_join::read_export,
        b4_c2_terminal_fixture::genuine_terminal_policy::{Joined, join},
        b4_materialization_set::B4ClosedReconstructedExecutionV1,
        b4_mutation::{canonical_materialization_recipe_jcs, Eip0045B4MaterializationIdentityV1},
        b4_negative_io::{B4NegativeFileEncoding, B4NegativeNamedIdentityV1, B4NegativeObservationRejectionV1,
            B4NegativeObservationVerdict, Eip0045B4NegativeObservationV1, Eip0045B4NegativeVerifierInputV1},
        b4_plan::{B4MaterializationDomain as D, B4NegativeExecutionSurface as S, B4NegativePlanFixture,
            B4NegativeQaResultCode, Eip0045B4NegativePlanV1},
        b4_terminal::B4_TERMINAL_FIXTURE_LAYOUT,
    };
    const MANIFEST: &[u8] = include_bytes!("../../../profiles/risc0-v3-succinct/manifest.bin");
    const PRIVATE: &str = "selected negative adapter VerifierTerminalPolicy failed privately; no observation was produced";
    fn sha(bytes: &[u8]) -> String { use sha2::{Digest, Sha256}; hex::encode(Sha256::digest(bytes)) }
    pub(super) fn physical(path: &Path) -> Result<()> {
        ensure!(path.is_absolute(), "terminal policy path must be absolute");
        for parent in path.ancestors() {
            let meta = fs::symlink_metadata(parent)?;
            ensure!(meta.is_dir() && !meta.file_type().is_symlink(), "terminal policy redirected parent");
        }
        ensure!(fs::canonicalize(path)? == path, "terminal policy redirected parent"); Ok(())
    }
    pub(super) fn read_pinned(path: &Path, size: usize, digest: &str) -> Result<Vec<u8>> {
        physical(path.parent().unwrap())?;
        let before = fs::symlink_metadata(path)?;
        ensure!(before.is_file() && !before.file_type().is_symlink() && before.nlink() == 1 && before.len() == size as u64,
            "terminal policy input physical identity");
        let file = fs::File::open(path)?; let opened = file.metadata()?;
        ensure!((before.dev(),before.ino()) == (opened.dev(),opened.ino()), "terminal policy input replaced");
        let mut bytes = Vec::with_capacity(size); file.take(size as u64 + 1).read_to_end(&mut bytes)?;
        let after = fs::symlink_metadata(path)?;
        ensure!(bytes.len() == size && sha(&bytes) == digest, "terminal policy input pin mismatch");
        ensure!((before.dev(),before.ino(),before.len(),before.nlink(),before.mtime(),before.mtime_nsec(),before.ctime(),before.ctime_nsec())
            == (after.dev(),after.ino(),after.len(),after.nlink(),after.mtime(),after.mtime_nsec(),after.ctime(),after.ctime_nsec()),
            "terminal policy input changed"); Ok(bytes)
    }
    fn load() -> Result<Joined> {
        let root = PathBuf::from(std::env::var_os("EIP0045_B4_TERMINAL_FIXTURE_REPOSITORY_ROOT")
            .ok_or_else(|| anyhow::anyhow!("explicit terminal fixture export root required"))?);
        physical(&root)?;
        let entries = read_export(&root)?;
        for (path, bytes) in &entries { read_pinned(&root.join(path),bytes.len(),&sha(bytes))?; }
        let joined = join(entries.clone())?; // All nine stock oracles replay before any C2 reconstruction.
        for (path, bytes) in &entries { read_pinned(&root.join(path),bytes.len(),&sha(bytes))?; }
        validate_rows(&joined.raw_seals,&joined.rows)?;
        Ok(joined)
    }
    fn identity(role: &str, path: &str, bytes: &[u8]) -> B4NegativeNamedIdentityV1 {
        B4NegativeNamedIdentityV1 { role:role.into(),path:path.into(),byte_length:bytes.len() as u64,
            sha256:sha(bytes),encoding:B4NegativeFileEncoding::RawBytes }
    }
    fn neutral(subject: &[u8], contexts: &[Vec<u8>]) -> Result<Vec<u8>> {
        Eip0045B4NegativeVerifierInputV1 { format:"Eip0045B4NegativeVerifierInputV1".into(),format_version:1,
            materialization_domain:D::VerifierInput,validation_surface:S::TerminalPolicy,
            subject:identity("subject","subject.bin",subject),
            context:contexts.iter().enumerate().map(|(i,b)| identity(&format!("context-{i:02}"),&format!("context/{i:02}.bin"),b)).collect(),
        }.to_canonical_jcs()
    }
    fn expected(input: &[u8], subject: &[u8]) -> Eip0045B4NegativeObservationV1 {
        Eip0045B4NegativeObservationV1 { format:"Eip0045B4NegativeObservationV1".into(),format_version:1,
            materialization_domain:D::VerifierInput,validation_surface:S::TerminalPolicy,
            negative_input_sha256:sha(input),subject_byte_length:subject.len() as u64,subject_sha256:sha(subject),
            verdict:B4NegativeObservationVerdict::Reject,rejection:B4NegativeObservationRejectionV1 {
                class:"terminal-policy-mismatch".into(),stage:"terminal-control-id".into() } }
    }
    fn observation(actual: &Eip0045B4NegativeObservationV1, input: &[u8], subject: &[u8]) -> Result<()> {
        ensure!(*actual == expected(input,subject), "terminal policy observation mismatch");
        let literal = format!(concat!("{{\"format\":\"Eip0045B4NegativeObservationV1\",\"formatVersion\":1,",
            "\"materializationDomain\":\"verifier-input\",\"negativeInputSha256\":\"{}\",",
            "\"rejection\":{{\"class\":\"terminal-policy-mismatch\",\"stage\":\"terminal-control-id\"}},",
            "\"subjectByteLength\":{},\"subjectSha256\":\"{}\",\"validationSurface\":\"terminal-policy\",\"verdict\":\"reject\"}}"),
            sha(input),subject.len(),sha(subject));
        ensure!(actual.to_canonical_jcs()? == literal.as_bytes(), "terminal policy observation JCS mismatch"); Ok(())
    }
    fn validate_rows(raw: &[Vec<u8>], rows: &[B4ClosedReconstructedExecutionV1]) -> Result<()> {
        ensure!(raw.len() == 9 && rows.len() == 8, "ordered terminal policy coverage");
        let plan = Eip0045B4NegativePlanV1::canonical()?; let plan_jcs = plan.to_canonical_jcs()?;
        for (slot,row) in rows.iter().enumerate() {
            let fixture = B4_TERMINAL_FIXTURE_LAYOUT[slot].fixture_id;
            let id = format!("terminal-excluded-shipping-family-sweep--{fixture}");
            let planned = plan.groups.iter().flat_map(|g| &g.executions).nth(131+slot).unwrap();
            ensure!(planned.execution_id == id && planned.variant_id == fixture && planned.base_selector_id == fixture
                && planned.fixture == B4NegativePlanFixture::ExcludedFamilyReceiptsV1
                && planned.materialization_domain == D::VerifierInput && planned.execution_surface == S::TerminalPolicy
                && planned.qa_result_code == B4NegativeQaResultCode::RawSealControlIdNotAllowed
                && planned.parser_truncation_words.is_none()
                && row.derived_registry_row.execution_id == id && row.derived_registry_row.base_selector_id == fixture
                && row.derived_registry_row.materialization_domain == D::VerifierInput, "terminal policy canonical row mismatch");
            ensure!(row.base == raw[slot] && row.subject == raw[slot] && row.contexts == vec![MANIFEST.to_vec()],
                "terminal policy selected source mismatch");
            ensure!(row.derived_registry_row.materialization == (B4NegativeMaterialization::FixtureSelection { fixture_id:fixture.into() }),
                "terminal policy fixture recipe mismatch");
            ensure!(row.negative_input_jcs == neutral(&row.subject,&row.contexts)?, "terminal policy neutral input mismatch");
            let recipe = canonical_materialization_recipe_jcs(&row.derived_registry_row.materialization)?;
            let identity = Eip0045B4MaterializationIdentityV1::from_canonical_jcs(&row.materialization_identity_jcs)?;
            ensure!(identity.execution_id == id && identity.base_selector_id == fixture && identity.materialization_domain == D::VerifierInput
                && identity.base_byte_length == row.base.len() as u64 && identity.base_sha256 == sha(&row.base)
                && identity.output_byte_length == row.subject.len() as u64 && identity.output_sha256 == sha(&row.subject)
                && identity.materialization_recipe_byte_length == recipe.len() as u64 && identity.materialization_recipe_sha256 == sha(&recipe)
                && identity.negative_plan_byte_length == plan_jcs.len() as u64 && identity.negative_plan_sha256 == sha(&plan_jcs),
                "terminal policy materialization identity mismatch");
        } Ok(())
    }
    pub(super) fn fresh(path: &Path) -> Result<()> {
        physical(path.parent().ok_or_else(||anyhow::anyhow!("terminal policy output parent"))?)?;
        match fs::symlink_metadata(path) { Err(e) if e.kind()==std::io::ErrorKind::NotFound => Ok(()),
            _ => anyhow::bail!("terminal policy output exists") }
    }
    pub(super) fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
        physical(path.parent().unwrap())?;
        let mut f=fs::OpenOptions::new().write(true).create_new(true).open(path)?; f.write_all(bytes)?; f.sync_all()?;
        ensure!(fs::read(path)? == bytes,"terminal policy writeback mismatch"); Ok(())
    }
    fn package(path: &Path, subject: &[u8], contexts: &[Vec<u8>]) -> Result<()> {
        fresh(path)?;fs::create_dir(path)?;fs::create_dir(path.join("context"))?;
        write_new(&path.join("subject.bin"),subject)?;write_new(&path.join("negative-input.json"),&neutral(subject,contexts)?)?;
        for (i,b) in contexts.iter().enumerate(){write_new(&path.join(format!("context/{i:02}.bin")),b)?;} Ok(())
    }
    fn dispatch(path: &Path,row: &B4ClosedReconstructedExecutionV1) -> Result<()> {
        ensure!(fs::read(path.join("subject.bin"))? == row.subject && fs::read(path.join("negative-input.json"))? == row.negative_input_jcs
            && fs::read(path.join("context/00.bin"))? == row.contexts[0], "terminal policy physical row mismatch");
        observation(&crate::b4_validator::verify_negative_root(path)?,&row.negative_input_jcs,&row.subject)
    }
    fn deny(path: &Path,message: &str) {
        assert_eq!(crate::b4_validator::verify_negative_root(path).expect_err("private fault yielded observation").to_string(),message);
    }
    fn inventory(root: &Path) -> Result<()> {
        let expected=BTreeSet::from_iter((131..139).flat_map(|i|
            ["materialization-identity.json","materialization-recipe.json","input/negative-input.json","input/subject.bin","input/context/00.bin"]
                .into_iter().map(move |p|format!("{i}/{p}"))));
        let dirs=BTreeSet::from_iter((131..139).flat_map(|i|[i.to_string(),format!("{i}/input"),format!("{i}/input/context")]));
        let mut files=BTreeSet::new();let mut found_dirs=BTreeSet::new();let mut pending=vec![root.to_path_buf()];
        while let Some(dir)=pending.pop(){physical(&dir)?;for entry in fs::read_dir(dir)?{let p=entry?.path();let meta=fs::symlink_metadata(&p)?;
            let name=p.strip_prefix(root)?.to_str().unwrap().to_owned();ensure!(!meta.file_type().is_symlink(),"terminal policy output redirect");
            if meta.is_dir(){found_dirs.insert(name);pending.push(p);}else{ensure!(meta.is_file()&&meta.nlink()==1,"terminal policy output non-private file");files.insert(name);}}}
        ensure!(files==expected && found_dirs==dirs,"terminal policy output inventory mismatch");Ok(())
    }
    #[test]
    fn terminal_policy_observation_and_reader_are_closed() {
        let subject=vec![0u8;PROOF_BYTES]; // Serialization fixture, not a cryptographic proof.
        let original=expected(b"input",&subject); observation(&original,b"input",&subject).unwrap();
        for field in 0..7 {observation(&original,b"input",&subject).unwrap();let mut fault=original.clone();match field {
            0=>fault.subject_sha256="00".repeat(32),1=>fault.negative_input_sha256="00".repeat(32),2=>fault.subject_byte_length+=1,
            3=>fault.rejection.class="wrong".into(),4=>fault.rejection.stage="wrong".into(),5=>fault.validation_surface=S::RawSealShape,
            _=>fault.materialization_domain=D::ArtifactValidator}
            assert_eq!(observation(&fault,b"input",&subject).unwrap_err().to_string(),"terminal policy observation mismatch");}
        let temp=tempfile::tempdir().unwrap();let p=temp.path().join("input");write_new(&p,b"valid").unwrap();
        assert_eq!(read_pinned(&p,5,&sha(b"valid")).unwrap(),b"valid");
        assert_eq!(read_pinned(&p,4,&sha(b"valid")).unwrap_err().to_string(),"terminal policy input physical identity");
        assert_eq!(read_pinned(&p,5,&sha(b"other")).unwrap_err().to_string(),"terminal policy input pin mismatch");
        assert!(write_new(&p,b"replace").is_err());assert_eq!(fs::read(&p).unwrap(),b"valid");
        for hard in [false,true] {let alias=temp.path().join(if hard {"hard"} else {"symbolic"});
            if hard{fs::hard_link(&p,&alias).unwrap();}else{std::os::unix::fs::symlink(&p,&alias).unwrap();}
            assert_eq!(read_pinned(&alias,5,&sha(b"valid")).unwrap_err().to_string(),"terminal policy input physical identity");
            fs::remove_file(alias).unwrap();assert_eq!(read_pinned(&p,5,&sha(b"valid")).unwrap(),b"valid");}
    }
    #[test]
    #[ignore="requires nineteen authentic terminal files and a fresh explicit output root"]
    fn genuine_terminal_policy_public_matrix() {
        let output=PathBuf::from(std::env::var_os("EIP0045_B4_TERMINAL_POLICY_OUTPUT_ROOT").unwrap());fresh(&output).unwrap();
        let joined=load().unwrap();
        // The ninth proof is valid for the terminal-only predicate despite its non-OK receipt claim.
        assert_eq!(reject_terminal_policy(&joined.raw_seals[8],&[MANIFEST]),Err(B4NegativeVerifierAdapterError::UnexpectedAcceptance));
        for row in &joined.rows {let boundary=reject_terminal_policy(&row.subject,&[MANIFEST]).unwrap();
            assert_eq!((boundary.class(),boundary.stage()),("terminal-policy-mismatch","terminal-control-id"));}
        fs::create_dir(&output).unwrap();
        for (slot,row) in joined.rows.iter().enumerate(){let dir=output.join((131+slot).to_string());fs::create_dir(&dir).unwrap();
            write_new(&dir.join("materialization-identity.json"),&row.materialization_identity_jcs).unwrap();
            write_new(&dir.join("materialization-recipe.json"),&canonical_materialization_recipe_jcs(&row.derived_registry_row.materialization).unwrap()).unwrap();
            package(&dir.join("input"),&row.subject,&row.contexts).unwrap();dispatch(&dir.join("input"),row).unwrap();}
        inventory(&output).unwrap();fs::File::open(&output).unwrap().sync_all().unwrap();
        assert!(package(&output.join("131/input"),&joined.rows[0].subject,&joined.rows[0].contexts).is_err());
        dispatch(&output.join("131/input"),&joined.rows[0]).unwrap();
        assert_eq!(validate_rows(&joined.raw_seals,&joined.rows[..7]).unwrap_err().to_string(),"ordered terminal policy coverage");
        let mut changed=joined.rows.clone();changed.swap(0,1);
        assert_eq!(validate_rows(&joined.raw_seals,&changed).unwrap_err().to_string(),"terminal policy canonical row mismatch");
        changed=joined.rows.clone();changed[7]=changed[6].clone();
        assert_eq!(validate_rows(&joined.raw_seals,&changed).unwrap_err().to_string(),"terminal policy canonical row mismatch");
        for fault in 0..8 {validate_rows(&joined.raw_seals,&joined.rows).unwrap();let mut changed=joined.rows.clone();
            let message=match fault {
                0=>{changed[0].subject=joined.raw_seals[1].clone();"terminal policy selected source mismatch"},
                1=>{changed[0].negative_input_jcs.push(b'\n');"terminal policy neutral input mismatch"},
                2=>{changed[0].contexts[0][0]^=1;"terminal policy selected source mismatch"},
                3=>{changed[0].materialization_identity_jcs=joined.rows[1].materialization_identity_jcs.clone();"terminal policy materialization identity mismatch"},
                4=>{changed[0].derived_registry_row.base_selector_id.push_str("-wrong");"terminal policy canonical row mismatch"},
                5=>{changed[0].derived_registry_row.materialization_domain=D::ArtifactValidator;"terminal policy canonical row mismatch"},
                6=>{changed[0].derived_registry_row.execution_id.push_str("-wrong");"terminal policy canonical row mismatch"},
                _=>{changed[0].derived_registry_row.materialization=B4NegativeMaterialization::FixtureSelection {fixture_id:"wrong".into()};"terminal policy fixture recipe mismatch"},
            };assert_eq!(validate_rows(&joined.raw_seals,&changed).unwrap_err().to_string(),message);}
    }
    #[test]
    #[ignore="requires nineteen authentic terminal files; private faults never become observations"]
    fn genuine_terminal_policy_private_and_custody_failures() {
        use crate::{
            b4_c2_terminal_catalog::genuine_catalog_join::CATALOG_PATH,
            b4_terminal::{terminal_fixture_raw_seal_path, terminal_fixture_receipt_oracle_path},
            b4_terminal_oracle::{B4TerminalOracleReplayError, B4TerminalOracleReplayErrorKind as K, B4TerminalOracleSlot},
            canonical::canonical_json_bytes,
        };
        let joined=load().unwrap();let row=&joined.rows[0];let allowed=&joined.raw_seals[8];
        let root=PathBuf::from(std::env::var_os("EIP0045_B4_TERMINAL_FIXTURE_REPOSITORY_ROOT").unwrap());
        let entries=read_export(&root).unwrap();
        // These faults enter the actual new nineteen-file join, not the older catalogue join.
        // Each mutation changes exactly one source while its paired bytes remain unchanged.
        for fault in 0..3 {
            let positive=join(entries.clone()).unwrap();validate_rows(&positive.raw_seals,&positive.rows).unwrap();
            let mut changed=entries.clone();
            let (target,kind,slot)=match fault {
                0=>(terminal_fixture_receipt_oracle_path(B4_TERMINAL_FIXTURE_LAYOUT[8].fixture_id).unwrap(),
                    K::ReceiptDecode,Some(B4TerminalOracleSlot::AllowedTerminalNonOk)),
                1=>(terminal_fixture_raw_seal_path(B4_TERMINAL_FIXTURE_LAYOUT[0].fixture_id).unwrap(),
                    K::ReceiptProfileShape,Some(B4TerminalOracleSlot::LiftPo214)),
                _=>(CATALOG_PATH.to_owned(),K::CandidateCatalogueBindingMismatch,None),
            };
            let (_,bytes)=changed.iter_mut().find(|(path,_)| path==&target).unwrap();
            match fault {
                // The frozen codec forbids a trailing byte even on the ninth receipt.
                0=>bytes.push(0),
                1=>{bytes[0]^=1;assert!(u32::from_le_bytes(bytes[..4].try_into().unwrap()) < 2_013_265_921);},
                _=>{let mut catalog:serde_json::Value=serde_json::from_slice(bytes).unwrap();
                    let digest=catalog["fixtures"][0]["claimDigest"].as_str().unwrap();
                    let replacement=format!("{}{}",if digest.starts_with('0'){"1"}else{"0"},&digest[1..]);
                    catalog["fixtures"][0]["claimDigest"]=replacement.into();
                    *bytes=canonical_json_bytes(&catalog).unwrap();},
            }
            assert_eq!(changed.len(),19);
            for ((before_path,before),(after_path,after)) in entries.iter().zip(&changed) {
                assert_eq!(before_path,after_path);
                if before_path==&target{assert_ne!(before,after);}else{assert_eq!(before,after);}
            }
            let error=join(changed).err().expect("changed source produced Joined rows");
            let replay=error.downcast_ref::<B4TerminalOracleReplayError>().expect("fault missed the oracle replay/binding stage");
            assert_eq!(replay.kind(),kind);assert_eq!(replay.slot(),slot);
            let restored=join(entries.clone()).unwrap();validate_rows(&restored.raw_seals,&restored.rows).unwrap();
        }
        let contexts=vec![MANIFEST.to_vec()];
        assert_eq!(reject_terminal_policy(allowed,&[MANIFEST]),Err(B4NegativeVerifierAdapterError::UnexpectedAcceptance));
        let temp=tempfile::tempdir().unwrap();let path=temp.path().join("allowed");package(&path,allowed,&contexts).unwrap();deny(&path,PRIVATE);
        let mut wrong_manifest=MANIFEST.to_vec();wrong_manifest[0]^=1;
        assert_eq!(reject_terminal_policy(&row.subject,&[&wrong_manifest]),Err(B4NegativeVerifierAdapterError::ProfileContext));
        let path=temp.path().join("wrong-manifest");package(&path,&row.subject,&[wrong_manifest]).unwrap();deny(&path,PRIVATE);
        assert_eq!(reject_terminal_policy(&row.subject,&[]),Err(B4NegativeVerifierAdapterError::ContextCardinality {actual:0,expected:1}));
        let path=temp.path().join("missing-context");package(&path,&row.subject,&[]).unwrap();
        deny(&path,"negative input context cardinality differs from the frozen handler contract");
        let mut damaged=allowed.clone();damaged[0]^=1;
        assert!(u32::from_le_bytes(damaged[..4].try_into().unwrap()) < 2_013_265_921);
        assert_eq!(&damaged[1..],&allowed[1..]);
        assert_eq!(reject_terminal_policy(&damaged,&[MANIFEST]),Err(B4NegativeVerifierAdapterError::UnexpectedStarkBoundary(
            B4StarkRejectionBoundary {class:B4StarkErrorClass::Risc0CryptographicVerifier,stage:B4StarkErrorStage::Risc0ProofVerification})));
        let path=temp.path().join("crypto");package(&path,&damaged,&contexts).unwrap();deny(&path,PRIVATE);
        for fault in 0..12 {
            let case=tempfile::tempdir().unwrap();let path=case.path().join("input");package(&path,&row.subject,&row.contexts).unwrap();dispatch(&path,row).unwrap();
            let message=match fault {
                0=>{let mut input=row.negative_input_jcs.clone();input.push(b'\n');fs::write(path.join("negative-input.json"),input).unwrap();"B4 negative verifier input is not exact RFC 8785 JCS"},
                1=>{let mut b=row.subject.clone();b[0]^=1;fs::write(path.join("subject.bin"),b).unwrap();"negative verifier file subject.bin SHA-256 differs from its descriptor"},
                2=>{let mut b=row.subject.clone();b.pop();fs::write(path.join("subject.bin"),b).unwrap();"negative verifier file subject.bin length is outside its bound"},
                3=>{fs::remove_file(path.join("context/00.bin")).unwrap();"negative context directory is not the exact NN.bin positional prefix"},
                4=>{fs::write(path.join("extra"),b"x").unwrap();"negative verifier root contains an unexpected or duplicate entry"},
                5|6=>{let backing=case.path().join("backing");fs::rename(path.join("subject.bin"),&backing).unwrap();if fault==5{std::os::unix::fs::symlink(&backing,path.join("subject.bin")).unwrap();"negative verifier path is not a regular file: subject.bin"}else{fs::hard_link(&backing,path.join("subject.bin")).unwrap();"hard-linked negative verifier file is forbidden: subject.bin"}},
                7=>{let mut b=row.contexts[0].clone();b[0]^=1;fs::write(path.join("context/00.bin"),b).unwrap();"negative verifier file context/00.bin SHA-256 differs from its descriptor"},
                8=>{let mut b=row.contexts[0].clone();b.pop();fs::write(path.join("context/00.bin"),b).unwrap();"negative verifier file context/00.bin length is outside its bound"},
                9|10=>{let backing=case.path().join("backing");fs::rename(path.join("context/00.bin"),&backing).unwrap();if fault==9{std::os::unix::fs::symlink(&backing,path.join("context/00.bin")).unwrap();"negative verifier path is not a regular file: context/00.bin"}else{fs::hard_link(&backing,path.join("context/00.bin")).unwrap();"hard-linked negative verifier file is forbidden: context/00.bin"}},
                _=>{fs::write(path.join("context/01.bin"),MANIFEST).unwrap();"negative context entry lies outside the exact positional prefix"},
            };deny(&path,message);
        }
        assert_eq!(reject_terminal_policy(allowed,&[MANIFEST]),Err(B4NegativeVerifierAdapterError::UnexpectedAcceptance));
    }
}


#[cfg(all(test, target_os = "linux", feature = "validator", feature = "materializer-replay"))]
mod genuine_receipt_claim {
    use super::*;
    use super::genuine_conditional_claim::{Inputs, load_authenticated};
    use super::genuine_terminal_policy::{fresh, physical, read_pinned, write_new};
    use anyhow::{Context as _, Result, ensure};
    use std::{collections::BTreeSet, fs, os::unix::fs::MetadataExt, path::{Path, PathBuf}};
    use crate::{
        b4::B4NegativeMaterialization,
        b4_c2_receipt_claim::reconstruct_genuine_case9,
        b4_c2_terminal_catalog::genuine_catalog_join::{CATALOG_PATH, read_export},
        b4_c2_terminal_fixture::genuine_terminal_policy::join_receipt_claim,
        b4_materialization_set::B4ClosedReconstructedExecutionV1 as Row,
        b4_mutation::{canonical_materialization_recipe_jcs, Eip0045B4MaterializationIdentityV1},
        b4_negative_io::{B4NegativeFileEncoding, B4NegativeNamedIdentityV1, B4NegativeObservationRejectionV1,
            B4NegativeObservationVerdict, Eip0045B4NegativeObservationV1, Eip0045B4NegativeVerifierInputV1},
        b4_plan::{B4MaterializationDomain as D, B4NegativeExecutionSurface as S, B4NegativePlanFixture as F,
            B4NegativeQaResultCode, Eip0045B4NegativePlanV1},
        b4_terminal::{B4_TERMINAL_FIXTURE_LAYOUT, terminal_fixture_raw_seal_path, terminal_fixture_receipt_oracle_path},
        b4_terminal_oracle::{B4TerminalOracleReplayError, B4TerminalOracleReplayErrorKind as K, B4TerminalOracleSlot},
        canonical::canonical_json_bytes,
        recursive_ancestry::{parse_recursive_ancestry_jcs, recursive_ancestry_to_jcs},
    };
    const MANIFEST: &[u8] = include_bytes!("../../../profiles/risc0-v3-succinct/manifest.bin");
    const STATEMENT_SHA: &str = "da4f3d7483d082324d1d11a3df67fd0dbfb662e0091ad741400be32ac3c15ae1";
    const PRIVATE: &str = "selected negative adapter VerifierReceiptClaimPolicy failed privately; no observation was produced";
    const SELECTORS: [&str;2] = ["allowed-terminal-non-ok-v1","case9-conditional-receipt-v1"];
    const IDS: [&str;2] = ["claim-final-status-non-ok--non-ok-status","claim-final-assumptions-nonempty--nonempty-assumptions"];
    struct Joined { rows: Vec<Row>, subjects: [Vec<u8>;2], statements: [Vec<u8>;2], final_seal: Vec<u8> }
    fn sha(bytes: &[u8]) -> String { use sha2::{Digest,Sha256}; hex::encode(Sha256::digest(bytes)) }
    fn env(name: &str) -> PathBuf { PathBuf::from(std::env::var_os(name).expect("explicit receipt-claim input/output path required")) }
    fn resolve_entries(input: &Inputs) -> Vec<(String,Vec<u8>)> {
        let mut entries=vec![("proof-output/candidate-ancestry.json".into(),input.ancestry().to_vec()),
            ("proof-output/candidate-journal.bin".into(),input.statement().to_vec()),
            ("proof-output/candidate-raw-seal.bin".into(),input.final_seal().to_vec())];
        entries.extend(input.auxiliary().iter().map(|(p,b)|(format!("proof-output/{p}"),b.clone()))); entries
    }
    fn join_conditional(root: &Path) -> Result<(Row,Inputs)> {
        physical(root)?;
        let (input,projection)=load_authenticated(root)?;
        let entries=resolve_entries(&input);
        for (p,b) in &entries { read_pinned(&root.join(p),b.len(),&sha(b))?; }
        let conditional=&input.auxiliary()[&projection.steps[0].raw_seal.path];
        let row=reconstruct_genuine_case9(conditional,MANIFEST,input.statement())?;
        for (p,b) in &entries { read_pinned(&root.join(p),b.len(),&sha(b))?; }
        Ok((row,input))
    }
    fn load() -> Result<Joined> {
        let root=env("EIP0045_B4_TERMINAL_FIXTURE_REPOSITORY_ROOT"); physical(&root)?;
        let statement_path=env("EIP0045_B4_TERMINAL_REFERENCE_STATEMENT");
        let statement=read_pinned(&statement_path,160,STATEMENT_SHA)?;
        let entries=read_export(&root)?;
        for (p,b) in &entries { read_pinned(&root.join(p),b.len(),&sha(b))?; }
        let raw_path=terminal_fixture_raw_seal_path(B4_TERMINAL_FIXTURE_LAYOUT[8].fixture_id)?;
        let raw=entries.iter().find(|(p,_)|p==&raw_path).context("allowed terminal fixture absent")?.1.clone();
        let first=join_receipt_claim(entries.clone(),&statement)?;
        for (p,b) in &entries { read_pinned(&root.join(p),b.len(),&sha(b))?; }
        read_pinned(&statement_path,160,STATEMENT_SHA)?;
        let (second,input)=join_conditional(&env("EIP0045_B4_RESOLVE_VECTOR_ROOT"))?;
        let projection=parse_recursive_ancestry_jcs(input.ancestry())?;
        let conditional=input.auxiliary()[&projection.steps[0].raw_seal.path].clone();
        let joined=Joined { rows:vec![first,second], subjects:[raw,conditional],
            statements:[statement,input.statement().to_vec()], final_seal:input.final_seal().to_vec() };
        validate_rows(&joined,&joined.rows)?; Ok(joined)
    }
    fn identity(role: &str,path: &str,bytes: &[u8]) -> B4NegativeNamedIdentityV1 {
        B4NegativeNamedIdentityV1 { role:role.into(),path:path.into(),byte_length:bytes.len() as u64,sha256:sha(bytes),encoding:B4NegativeFileEncoding::RawBytes }
    }
    fn neutral(subject: &[u8],contexts: &[Vec<u8>]) -> Result<Vec<u8>> {
        Eip0045B4NegativeVerifierInputV1 { format:"Eip0045B4NegativeVerifierInputV1".into(),format_version:1,
            materialization_domain:D::VerifierInput,validation_surface:S::ReceiptClaimPolicy,
            subject:identity("subject","subject.bin",subject),
            context:contexts.iter().enumerate().map(|(i,b)|identity(&format!("context-{i:02}"),&format!("context/{i:02}.bin"),b)).collect() }.to_canonical_jcs()
    }
    fn expected(input: &[u8],subject: &[u8]) -> Eip0045B4NegativeObservationV1 {
        Eip0045B4NegativeObservationV1 { format:"Eip0045B4NegativeObservationV1".into(),format_version:1,
            materialization_domain:D::VerifierInput,validation_surface:S::ReceiptClaimPolicy,
            negative_input_sha256:sha(input),subject_byte_length:subject.len() as u64,subject_sha256:sha(subject),
            verdict:B4NegativeObservationVerdict::Reject,rejection:B4NegativeObservationRejectionV1 {
                class:"receipt-claim-mismatch".into(),stage:"expected-claim-binding".into() } }
    }
    fn observation(actual: &Eip0045B4NegativeObservationV1,input: &[u8],subject: &[u8]) -> Result<()> {
        ensure!(*actual==expected(input,subject),"receipt-claim observation mismatch");
        let literal=format!(concat!("{{\"format\":\"Eip0045B4NegativeObservationV1\",\"formatVersion\":1,",
            "\"materializationDomain\":\"verifier-input\",\"negativeInputSha256\":\"{}\",",
            "\"rejection\":{{\"class\":\"receipt-claim-mismatch\",\"stage\":\"expected-claim-binding\"}},",
            "\"subjectByteLength\":{},\"subjectSha256\":\"{}\",\"validationSurface\":\"receipt-claim-policy\",\"verdict\":\"reject\"}}"),
            sha(input),subject.len(),sha(subject));
        ensure!(actual.to_canonical_jcs()?==literal.as_bytes(),"receipt-claim observation JCS mismatch"); Ok(())
    }
    fn validate_rows(joined: &Joined,rows: &[Row]) -> Result<()> {
        ensure!(rows.len()==2,"ordered receipt-claim coverage");
        let plan=Eip0045B4NegativePlanV1::canonical()?; let plan_jcs=plan.to_canonical_jcs()?;
        ensure!(plan_jcs.len()==89547 && sha(&plan_jcs)=="3d13dc5abfe07711e5c4dcaf7f84ce6c7e26411ff4cb58d4480f3acafaac6100","receipt-claim independent plan pin");
        for (slot,row) in rows.iter().enumerate() {
            let planned=plan.groups.iter().flat_map(|g|&g.executions).nth(139+slot).unwrap();
            ensure!(planned.execution_id==IDS[slot] && planned.variant_id==["non-ok-status","nonempty-assumptions"][slot]
                && planned.base_selector_id==SELECTORS[slot] && planned.fixture==if slot==0{F::AllowedTerminalNonOkV1}else{F::Case9ConditionalReceiptV1}
                && planned.materialization_domain==D::VerifierInput && planned.execution_surface==S::ReceiptClaimPolicy
                && planned.qa_result_code==B4NegativeQaResultCode::RawSealClaimMismatch && planned.parser_truncation_words.is_none()
                && row.derived_registry_row.execution_id==IDS[slot] && row.derived_registry_row.base_selector_id==SELECTORS[slot]
                && row.derived_registry_row.materialization_domain==D::VerifierInput,"receipt-claim canonical row mismatch");
            ensure!(row.base==joined.subjects[slot] && row.subject==joined.subjects[slot]
                && row.contexts==vec![MANIFEST.to_vec(),joined.statements[slot].clone()],"receipt-claim selected source mismatch");
            ensure!(row.derived_registry_row.materialization==(B4NegativeMaterialization::FixtureSelection {fixture_id:SELECTORS[slot].into()}),"receipt-claim fixture recipe mismatch");
            ensure!(row.negative_input_jcs==neutral(&row.subject,&row.contexts)?,"receipt-claim neutral input mismatch");
            let recipe=canonical_materialization_recipe_jcs(&row.derived_registry_row.materialization)?;
            let id=Eip0045B4MaterializationIdentityV1::from_canonical_jcs(&row.materialization_identity_jcs)?;
            ensure!(id.execution_id==IDS[slot] && id.base_selector_id==SELECTORS[slot] && id.materialization_domain==D::VerifierInput
                && id.base_byte_length==row.base.len() as u64 && id.base_sha256==sha(&row.base)
                && id.output_byte_length==row.subject.len() as u64 && id.output_sha256==sha(&row.subject)
                && id.materialization_recipe_byte_length==recipe.len() as u64 && id.materialization_recipe_sha256==sha(&recipe)
                && id.negative_plan_byte_length==89547 && id.negative_plan_sha256=="3d13dc5abfe07711e5c4dcaf7f84ce6c7e26411ff4cb58d4480f3acafaac6100",
                "receipt-claim materialization identity mismatch");
        } Ok(())
    }
    fn package(root: &Path,subject: &[u8],contexts: &[Vec<u8>]) -> Result<()> {
        fresh(root)?;fs::create_dir(root)?;fs::create_dir(root.join("context"))?;
        write_new(&root.join("subject.bin"),subject)?;write_new(&root.join("negative-input.json"),&neutral(subject,contexts)?)?;
        for(i,b)in contexts.iter().enumerate(){write_new(&root.join(format!("context/{i:02}.bin")),b)?;} Ok(())
    }
    fn dispatch(root: &Path,row: &Row) -> Result<()> {
        ensure!(fs::read(root.join("subject.bin"))?==row.subject && fs::read(root.join("negative-input.json"))?==row.negative_input_jcs
            && fs::read(root.join("context/00.bin"))?==row.contexts[0] && fs::read(root.join("context/01.bin"))?==row.contexts[1],"receipt-claim physical row mismatch");
        observation(&crate::b4_validator::verify_negative_root(root)?,&row.negative_input_jcs,&row.subject)
    }
    fn deny(root: &Path,message: &str) {
        assert_eq!(crate::b4_validator::verify_negative_root(root).expect_err("private fault yielded observation").to_string(),message);
    }
    fn boundary(row: &Row) {
        let contexts=row.contexts.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let result=reject_receipt_claim_policy(&row.subject,&contexts).unwrap();
        assert_eq!((result.class(),result.stage()),("receipt-claim-mismatch","expected-claim-binding"));
    }
    fn write_resolve(root: &Path,input: &Inputs) {
        fresh(root).unwrap();fs::create_dir(root).unwrap();
        for(p,b)in resolve_entries(input){let path=root.join(p);fs::create_dir_all(path.parent().unwrap()).unwrap();write_new(&path,&b).unwrap();}
    }
    #[test]
    fn receipt_claim_observation_and_reader_are_closed() {
        let subject=vec![0u8;PROOF_BYTES]; // Serializer fixture, never accepted as a proof.
        let original=expected(b"input",&subject);observation(&original,b"input",&subject).unwrap();
        for field in 0..7 {let mut wrong=original.clone();match field {
            0=>wrong.subject_sha256="00".repeat(32),1=>wrong.negative_input_sha256="00".repeat(32),2=>wrong.subject_byte_length+=1,
            3=>wrong.rejection.class="wrong".into(),4=>wrong.rejection.stage="wrong".into(),5=>wrong.validation_surface=S::TerminalPolicy,
            _=>wrong.materialization_domain=D::ArtifactValidator}
            assert_eq!(observation(&wrong,b"input",&subject).unwrap_err().to_string(),"receipt-claim observation mismatch");
        }
        let temp=tempfile::tempdir().unwrap();let path=temp.path().join("pinned");write_new(&path,b"valid").unwrap();
        assert_eq!(read_pinned(&path,5,&sha(b"valid")).unwrap(),b"valid");
        assert!(read_pinned(&path,4,&sha(b"valid")).is_err());assert!(read_pinned(&path,5,&sha(b"other")).is_err());
        assert!(write_new(&path,b"other").is_err());assert_eq!(fs::read(&path).unwrap(),b"valid");
        // A replaced inode with changed bytes cannot inherit the retained digest.
        let old=temp.path().join("old");fs::rename(&path,&old).unwrap();write_new(&path,b"other").unwrap();
        assert_ne!(fs::metadata(&path).unwrap().ino(),fs::metadata(&old).unwrap().ino());
        assert!(read_pinned(&path,5,&sha(b"valid")).is_err());
    }
    #[test]
    #[ignore="requires authentic terminal export, original terminal statement and TerminalResolve export"]
    fn genuine_receipt_claim_producer_consumer() {
        let joined=load().unwrap();for row in &joined.rows {boundary(row);}
        let entries=read_export(&env("EIP0045_B4_TERMINAL_FIXTURE_REPOSITORY_ROOT")).unwrap();
        let statement=&joined.statements[0];
        for fault in 0..3 {
            boundary(&join_receipt_claim(entries.clone(),statement).unwrap());
            let mut changed=entries.clone();
            let(target,kind,slot)=match fault {
                0=>(terminal_fixture_receipt_oracle_path(B4_TERMINAL_FIXTURE_LAYOUT[8].fixture_id).unwrap(),K::ReceiptDecode,Some(B4TerminalOracleSlot::AllowedTerminalNonOk)),
                1=>(terminal_fixture_raw_seal_path(B4_TERMINAL_FIXTURE_LAYOUT[0].fixture_id).unwrap(),K::ReceiptProfileShape,Some(B4TerminalOracleSlot::LiftPo214)),
                _=>(CATALOG_PATH.to_owned(),K::CandidateCatalogueBindingMismatch,None),
            };
            let(_,bytes)=changed.iter_mut().find(|(p,_)|p==&target).unwrap();
            match fault {0=>bytes.push(0),1=>{bytes[0]^=1;assert!(u32::from_le_bytes(bytes[..4].try_into().unwrap())<2_013_265_921);},_=>{
                let mut catalog:serde_json::Value=serde_json::from_slice(bytes).unwrap();
                let old=catalog["fixtures"][0]["claimDigest"].as_str().unwrap();
                catalog["fixtures"][0]["claimDigest"]=format!("{}{}",if old.starts_with('0'){"1"}else{"0"},&old[1..]).into();
                *bytes=canonical_json_bytes(&catalog).unwrap();
            }}
            for((p,b),(q,c))in entries.iter().zip(&changed){assert_eq!(p,q);if p==&target{assert_ne!(b,c);}else{assert_eq!(b,c);}}
            let error=join_receipt_claim(changed,statement).err().expect("unauthenticated terminal inputs reached C2");
            let replay=error.downcast_ref::<B4TerminalOracleReplayError>().expect("fault missed terminal authentication");
            assert_eq!(replay.kind(),kind);assert_eq!(replay.slot(),slot);
            boundary(&join_receipt_claim(entries.clone(),statement).unwrap());
        }
        let mut changed_statement=statement.to_vec();*changed_statement.last_mut().unwrap()^=1;
        assert_eq!(join_receipt_claim(entries.clone(),&changed_statement).err().unwrap().to_string(),"terminal receipt-claim reference statement pin");
        boundary(&join_receipt_claim(entries.clone(),statement).unwrap());
        assert!(join_receipt_claim(entries[..18].to_vec(),statement).is_err());
        boundary(&join_receipt_claim(entries,statement).unwrap());

        let root=env("EIP0045_B4_RESOLVE_VECTOR_ROOT");let(_,input)=join_conditional(&root).unwrap();
        let projection=parse_recursive_ancestry_jcs(input.ancestry()).unwrap();
        let step_path=format!("proof-output/{}",projection.steps[0].raw_seal.path);
        let assumption_path=format!("proof-output/{}",projection.assumption_receipt.as_ref().unwrap().raw_seal.path);
        for fault in 0..10 {
            let temp=tempfile::tempdir().unwrap();let copy=temp.path().join("resolve");write_resolve(&copy,&input);
            boundary(&join_conditional(&copy).unwrap().0);
            let(target,bytes,expected_error)=match fault {
                0=>(step_path.clone(),Some(input.final_seal().to_vec()),"conditional artifact binding"),
                1=>(step_path.clone(),Some(input.auxiliary()[&projection.assumption_receipt.as_ref().unwrap().raw_seal.path].clone()),"conditional artifact binding"),
                2|3|4=>{let name=if fault==2{step_path.clone()}else if fault==3{assumption_path.clone()}else{"proof-output/candidate-raw-seal.bin".into()};
                    let mut bytes=fs::read(copy.join(&name)).unwrap();bytes[0]^=1;(name,Some(bytes),"conditional artifact binding")},
                5=>{let mut bytes=input.statement().to_vec();*bytes.last_mut().unwrap()^=1;("proof-output/candidate-journal.bin".into(),Some(bytes),"conditional ancestry semantics")},
                6|7=>{let mut p=projection.clone();if fault==6{p.steps[0].ordinal=1;}else{
                    let old=p.steps[0].claim.input_digest.clone();p.steps[0].claim.input_digest=format!("{}{}",if old.starts_with('0'){"1"}else{"0"},&old[1..]);}
                    ("proof-output/candidate-ancestry.json".into(),Some(recursive_ancestry_to_jcs(&p).unwrap()),if fault==6{"conditional step selection"}else{"conditional ancestry semantics"})},
                8=>(step_path.clone(),None,""),
                _=>{let mut bytes=input.ancestry().to_vec();bytes.push(b'\n');("proof-output/candidate-ancestry.json".into(),Some(bytes),"conditional ancestry codec")},
            };
            let original=fs::read(copy.join(&target)).unwrap();
            if let Some(bytes)=bytes {fs::write(copy.join(&target),bytes).unwrap();}else{fs::remove_file(copy.join(&target)).unwrap();}
            for(p,b)in resolve_entries(&input){if p!=target{assert_eq!(fs::read(copy.join(p)).unwrap(),b);}}
            let error=join_conditional(&copy).err().expect("unauthenticated conditional inputs reached C2");
            if !expected_error.is_empty(){assert_eq!(error.to_string(),expected_error);}else{
                assert_eq!(error.downcast_ref::<std::io::Error>().expect("missing step did not fail at file loading").kind(),std::io::ErrorKind::NotFound);
                assert!(!copy.join(&target).exists());
            }
            fs::write(copy.join(&target),original).unwrap();boundary(&join_conditional(&copy).unwrap().0);
        }
    }
    #[test]
    #[ignore="requires authentic receipt-claim inputs; faults must remain private"]
    fn genuine_receipt_claim_private_and_custody_failures() {
        let joined=load().unwrap();let temp=tempfile::tempdir().unwrap();
        let final_contexts=vec![MANIFEST.to_vec(),joined.statements[1].clone()];
        assert_eq!(reject_receipt_claim_policy(&joined.final_seal,&[MANIFEST,&joined.statements[1]]),Err(B4NegativeVerifierAdapterError::UnexpectedAcceptance));
        let accepted=temp.path().join("accepted");package(&accepted,&joined.final_seal,&final_contexts).unwrap();
        assert_eq!(crate::b4_validator::verify_negative_root(&accepted).unwrap_err().to_string(),PRIVATE);
        for (slot,row) in joined.rows.iter().enumerate() {
            boundary(row);
            for fault in 0..5 {
                let mut subject=row.subject.clone();let mut contexts=row.contexts.clone();
                match fault {0=>contexts[0][0]^=1,1=>contexts[1][0]^=1,2=>{subject[0]^=1;assert!(u32::from_le_bytes(subject[..4].try_into().unwrap())<2_013_265_921);},
                    3=>contexts.swap(0,1),_=>{contexts.pop();}}
                let refs=contexts.iter().map(Vec::as_slice).collect::<Vec<_>>();
                let error=reject_receipt_claim_policy(&subject,&refs).unwrap_err();
                match fault {0|3=>assert_eq!(error,B4NegativeVerifierAdapterError::ProfileContext),
                    1=>assert_eq!(error,B4NegativeVerifierAdapterError::StatementEnvelope),
                    2=>assert_eq!(error,B4NegativeVerifierAdapterError::UnexpectedStarkBoundary(B4StarkRejectionBoundary {class:B4StarkErrorClass::Risc0CryptographicVerifier,stage:B4StarkErrorStage::Risc0ProofVerification})),
                    _=>assert_eq!(error,B4NegativeVerifierAdapterError::ContextCardinality {actual:1,expected:2})}
                let path=temp.path().join(format!("private-{slot}-{fault}"));package(&path,&subject,&contexts).unwrap();
                let message=match fault {
                    3=>"negative context 00 declared length is outside its handler custody bound",
                    4=>"negative input context cardinality differs from the frozen handler contract",
                    _=>PRIVATE,
                };deny(&path,message);
            }
            for fault in 0..16 {
                let case=tempfile::tempdir().unwrap();let path=case.path().join("input");package(&path,&row.subject,&row.contexts).unwrap();dispatch(&path,row).unwrap();
                match fault {
                    0=>{let mut b=row.negative_input_jcs.clone();b.push(b'\n');fs::write(path.join("negative-input.json"),b).unwrap();},
                    1|2=>{let mut b=row.subject.clone();if fault==1{b[0]^=1;}else{b.pop();}fs::write(path.join("subject.bin"),b).unwrap();},
                    3=>{fs::remove_file(path.join("context/01.bin")).unwrap();},
                    4=>{fs::write(path.join("extra"),b"x").unwrap();},
                    5|6=>{let backing=case.path().join("backing");fs::rename(path.join("subject.bin"),&backing).unwrap();
                        if fault==5{std::os::unix::fs::symlink(&backing,path.join("subject.bin")).unwrap();}else{fs::hard_link(&backing,path.join("subject.bin")).unwrap();}},
                    7..=14=>{let index=(fault-7)/4;let kind=(fault-7)%4;let leaf=path.join(format!("context/{index:02}.bin"));
                        if kind<2{let mut b=row.contexts[index].clone();if kind==0{b[0]^=1;}else{b.pop();}fs::write(leaf,b).unwrap();}
                        else{let backing=case.path().join("backing");fs::rename(&leaf,&backing).unwrap();if kind==2{std::os::unix::fs::symlink(&backing,leaf).unwrap();}else{fs::hard_link(&backing,leaf).unwrap();}}},
                    _=>{fs::write(path.join("context/02.bin"),MANIFEST).unwrap();},
                };
                let message=match fault {
                    0=>"B4 negative verifier input is not exact RFC 8785 JCS".to_owned(),
                    1=>"negative verifier file subject.bin SHA-256 differs from its descriptor".into(),
                    2=>"negative verifier file subject.bin length is outside its bound".into(),
                    3=>"negative context directory is not the exact NN.bin positional prefix".into(),
                    4=>"negative verifier root contains an unexpected or duplicate entry".into(),
                    5=>"negative verifier path is not a regular file: subject.bin".into(),
                    6=>"hard-linked negative verifier file is forbidden: subject.bin".into(),
                    7..=14=>{let index=(fault-7)/4;match (fault-7)%4 {
                        0=>format!("negative verifier file context/{index:02}.bin SHA-256 differs from its descriptor"),
                        1=>format!("negative verifier file context/{index:02}.bin length is outside its bound"),
                        2=>format!("negative verifier path is not a regular file: context/{index:02}.bin"),
                        _=>format!("hard-linked negative verifier file is forbidden: context/{index:02}.bin"),
                    }},
                    _=>"negative context entry lies outside the exact positional prefix".into(),
                };deny(&path,&message);
            }
        }
    }
    #[test]
    #[ignore="requires authentic receipt-claim inputs and a fresh explicit output root"]
    fn genuine_receipt_claim_public_matrix() {
        let output=env("EIP0045_B4_RECEIPT_CLAIM_OUTPUT_ROOT");fresh(&output).unwrap();
        let joined=load().unwrap();for row in &joined.rows{boundary(row);}
        for fault in 0..9 {
            validate_rows(&joined,&joined.rows).unwrap();let mut rows=joined.rows.clone();
            match fault {0=>{rows.pop();},1=>rows.swap(0,1),2=>rows[1]=rows[0].clone(),
                3=>rows[0].subject=joined.subjects[1].clone(),4=>rows[0].contexts.swap(0,1),
                5=>rows[0].negative_input_jcs.push(b'\n'),6=>rows[0].materialization_identity_jcs=rows[1].materialization_identity_jcs.clone(),
                7=>rows[0].derived_registry_row.base_selector_id="wrong".into(),
                _=>rows[0].derived_registry_row.materialization=B4NegativeMaterialization::FixtureSelection {fixture_id:"wrong".into()}}
            assert!(validate_rows(&joined,&rows).is_err(),"changed C2 binding accepted");
        }
        fs::create_dir(&output).unwrap();
        for(slot,row)in joined.rows.iter().enumerate(){let dir=output.join((139+slot).to_string());fs::create_dir(&dir).unwrap();
            write_new(&dir.join("materialization-identity.json"),&row.materialization_identity_jcs).unwrap();
            write_new(&dir.join("materialization-recipe.json"),&canonical_materialization_recipe_jcs(&row.derived_registry_row.materialization).unwrap()).unwrap();
            package(&dir.join("input"),&row.subject,&row.contexts).unwrap();dispatch(&dir.join("input"),row).unwrap();
            assert!(package(&dir.join("input"),&row.subject,&row.contexts).is_err());dispatch(&dir.join("input"),row).unwrap();
        }
        let expected=BTreeSet::from_iter((139..141).flat_map(|i|["materialization-identity.json","materialization-recipe.json","input/negative-input.json","input/subject.bin","input/context/00.bin","input/context/01.bin"].into_iter().map(move|p|format!("{i}/{p}"))));
        let dirs=BTreeSet::from_iter((139..141).flat_map(|i|[i.to_string(),format!("{i}/input"),format!("{i}/input/context")]));
        let mut files=BTreeSet::new();let mut seen=BTreeSet::new();let mut pending=vec![output.clone()];
        while let Some(dir)=pending.pop(){physical(&dir).unwrap();for entry in fs::read_dir(dir).unwrap(){let p=entry.unwrap().path();let meta=fs::symlink_metadata(&p).unwrap();
            let name=p.strip_prefix(&output).unwrap().to_str().unwrap().to_owned();assert!(!meta.file_type().is_symlink());
            if meta.is_dir(){seen.insert(name);pending.push(p);}else{assert!(meta.is_file()&&meta.nlink()==1);files.insert(name);}}}
        assert_eq!(files,expected);assert_eq!(seen,dirs);fs::File::open(&output).unwrap().sync_all().unwrap();
    }
}
use core::fmt;

use crate::{
    b4_subject_envelope::{
        B4SubjectEnvelopeContract, B4SubjectEnvelopeError, B4SubjectEnvelopeKind,
        B4SubjectPartBounds, decode_subject_envelope,
    },
    claim::{ClaimConstructionError, ok_receipt_claim_digests},
    constants::{DIGEST_BYTES, MAX_APPLICATION_PAYLOAD_BYTES, PROOF_BYTES, PROOF_CHUNK_LENGTHS},
    ergo_statement::parse_ergo_statement_v1,
    profile_manifest::StarkProfileManifestV1,
};

use super::{
    errors::{B4StarkError, B4StarkErrorClass, B4StarkErrorStage, B4StarkRejectionBoundary},
    stark::verify_stark,
};

const OPCODE_PROOF_VECTOR_MIN_BYTES: usize = 2 + 3 * 4;
const OPCODE_PROOF_VECTOR_MAX_BYTES: usize = 2 + 5 * 4 + PROOF_BYTES + 4;
const OPCODE_PROOF_VECTOR_MIN_CHUNKS: usize = 3;
const OPCODE_PROOF_VECTOR_MAX_CHUNKS: usize = 5;
const OPCODE_PROOF_CHUNK_MAX_BYTES: usize = 65_536;
const OPCODE_PROOF_VECTOR_MAX_PAYLOAD_BYTES: usize = PROOF_BYTES + 4;
const OPCODE_ID_MIN_BYTES: usize = DIGEST_BYTES - 1;
const OPCODE_ID_MAX_BYTES: usize = DIGEST_BYTES + 1;

const OPCODE_PART_BOUNDS: [B4SubjectPartBounds; 4] = [
    B4SubjectPartBounds::new(OPCODE_PROOF_VECTOR_MIN_BYTES, OPCODE_PROOF_VECTOR_MAX_BYTES),
    B4SubjectPartBounds::new(0, MAX_APPLICATION_PAYLOAD_BYTES + 1),
    B4SubjectPartBounds::new(OPCODE_ID_MIN_BYTES, OPCODE_ID_MAX_BYTES),
    B4SubjectPartBounds::new(OPCODE_ID_MIN_BYTES, OPCODE_ID_MAX_BYTES),
];

/// Closed non-instrumented verifier rejection boundaries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum B4NegativeVerifierBoundary {
    /// The opcode profile ID is not exactly one digest.
    OpcodeProfileIdLength,
    /// The opcode program ID is not exactly one digest.
    OpcodeProgramIdLength,
    /// The opcode application payload exceeds the authenticated profile bound.
    OpcodeApplicationPayloadLength,
    /// The opcode proof vector does not contain the canonical four chunks.
    OpcodeProofChunkCount,
    /// One opcode proof chunk differs from its canonical positional length.
    OpcodeProofChunkLength,
    /// A structured STARK-core failure admitted by the selected surface.
    Stark(B4StarkRejectionBoundary),
}

impl B4NegativeVerifierBoundary {
    /// Stable class identifier for the future pathless observation.
    pub(super) const fn class(self) -> &'static str {
        match self {
            Self::OpcodeProfileIdLength
            | Self::OpcodeProgramIdLength
            | Self::OpcodeApplicationPayloadLength
            | Self::OpcodeProofChunkCount
            | Self::OpcodeProofChunkLength => "opcode-input-shape-invalid",
            Self::Stark(boundary) => boundary.class.as_str(),
        }
    }

    /// Stable first-stage identifier for the future pathless observation.
    pub(super) const fn stage(self) -> &'static str {
        match self {
            Self::OpcodeProfileIdLength => "opcode-profile-id-byte-length",
            Self::OpcodeProgramIdLength => "opcode-program-id-byte-length",
            Self::OpcodeApplicationPayloadLength => "opcode-application-payload-byte-length",
            Self::OpcodeProofChunkCount => "opcode-proof-chunk-count",
            Self::OpcodeProofChunkLength => "opcode-proof-chunk-byte-length",
            Self::Stark(boundary) => boundary.stage.as_str(),
        }
    }
}

/// Private failures which are forbidden from becoming campaign observations.
#[derive(Debug, Eq, PartialEq)]
pub(super) enum B4NegativeVerifierAdapterError {
    /// The selected handler received the wrong number of positional contexts.
    ContextCardinality { actual: usize, expected: usize },
    /// The outer composite subject is not the exact selected-handler grammar.
    SubjectEnvelope(B4SubjectEnvelopeError),
    /// The nested proof-vector transport is malformed rather than a valid
    /// mutation reaching opcode policy.
    ProofVectorEnvelope(B4ProofVectorEnvelopeError),
    /// The manifest context is not a byte-exact frozen initial-profile value.
    ProfileContext,
    /// A nominally unmutated opcode field differs from the authenticated base.
    OpcodeBaseBinding,
    /// A raw statement is malformed rather than a valid claim mutation.
    StatementEnvelope,
    /// Expected-claim derivation failed before the selected policy boundary.
    ClaimConstruction(ClaimConstructionError),
    /// A bounded allocation could not be reserved.
    AllocationFailure,
    /// The selected negative subject was unexpectedly accepted.
    UnexpectedAcceptance,
    /// A structured consumer failure occurred outside the selected surface.
    UnexpectedStarkBoundary(B4StarkRejectionBoundary),
    /// A valid opcode envelope reached an opcode-policy rejection while a
    /// deeper raw-seal surface was selected.
    UnexpectedOpcodeBoundary(B4NegativeVerifierBoundary),
}

impl fmt::Display for B4NegativeVerifierAdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for B4NegativeVerifierAdapterError {}

/// Private nested proof-vector framing failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum B4ProofVectorEnvelopeError {
    TruncatedCount,
    FramingChunkCount,
    TruncatedLength { index: usize },
    ChunkTooLarge { index: usize, actual: usize },
    CumulativePayloadTooLarge,
    ArithmeticOverflow,
    TruncatedChunk { index: usize },
    TrailingBytes,
}

/// Exercise the exact opcode-input preflight.
pub(super) fn reject_opcode_preflight(
    subject: &[u8],
    contexts: &[&[u8]],
) -> Result<B4NegativeVerifierBoundary, B4NegativeVerifierAdapterError> {
    let manifest = decode_manifest_context(contexts, 1)?;
    let opcode = decode_opcode_subject(subject)?;
    match preflight_opcode_inputs(&manifest, &opcode)? {
        Some(boundary) => Ok(boundary),
        None => Err(B4NegativeVerifierAdapterError::UnexpectedAcceptance),
    }
}

/// Exercise raw statement parsing, a known-good STARK, late root binding, and
/// the independently derived expected-claim binding.
pub(super) fn reject_raw_statement_claim_binding(
    subject: &[u8],
    contexts: &[&[u8]],
) -> Result<B4NegativeVerifierBoundary, B4NegativeVerifierAdapterError> {
    let manifest = decode_manifest_context(contexts, 2)?;
    let statement = parse_ergo_statement_v1(subject)
        .map_err(|_| B4NegativeVerifierAdapterError::StatementEnvelope)?;
    let expected_claim = ok_receipt_claim_digests(&statement.program_id(), subject)
        .map_err(B4NegativeVerifierAdapterError::ClaimConstruction)?
        .expected_claim;
    let seal = contexts[1];

    let verified = verify_stark(&manifest, seal).map_err(unexpected_stark)?;
    let root_bound = verified
        .bind_inner_control_root()
        .map_err(unexpected_stark)?;
    match root_bound.bind_claim(expected_claim) {
        Err(error) if error.rejection_boundary().class == B4StarkErrorClass::ReceiptClaim => Ok(
            B4NegativeVerifierBoundary::Stark(error.rejection_boundary()),
        ),
        Err(error) => Err(unexpected_stark(error)),
        Ok(_) => Err(B4NegativeVerifierAdapterError::UnexpectedAcceptance),
    }
}

/// Exercise the opcode transport followed by raw-seal shape and, only after a
/// cryptographically valid proof, the late inner-control-root binding.
///
/// This is the only non-instrumented route capable of reporting
/// `inner-control-root-binding`.  Mutating output bytes cannot reach that
/// boundary: the pinned verifier must first return a `VerifiedStarkEnvelope`.
pub(super) fn reject_raw_seal_shape(
    subject: &[u8],
    contexts: &[&[u8]],
) -> Result<B4NegativeVerifierBoundary, B4NegativeVerifierAdapterError> {
    let manifest = decode_manifest_context(contexts, 1)?;
    let opcode = decode_opcode_subject(subject)?;
    if let Some(boundary) = preflight_opcode_inputs(&manifest, &opcode)? {
        return Err(B4NegativeVerifierAdapterError::UnexpectedOpcodeBoundary(
            boundary,
        ));
    }
    let seal = concatenate_proof_chunks(&opcode.proof_chunks)?;

    let verified = match verify_stark(&manifest, &seal) {
        Err(error) if error.rejection_boundary().class == B4StarkErrorClass::RawSealShape => {
            return Ok(B4NegativeVerifierBoundary::Stark(
                error.rejection_boundary(),
            ));
        }
        Err(error) => return Err(unexpected_stark(error)),
        Ok(verified) => verified,
    };
    match verified.bind_inner_control_root() {
        Err(error) if error.rejection_boundary().class == B4StarkErrorClass::InnerControlRoot => {
            Ok(B4NegativeVerifierBoundary::Stark(
                error.rejection_boundary(),
            ))
        }
        Err(error) => Err(unexpected_stark(error)),
        Ok(_) => Err(B4NegativeVerifierAdapterError::UnexpectedAcceptance),
    }
}

/// Exercise the pinned STARK verifier's exactly-once terminal policy.
pub(super) fn reject_terminal_policy(
    subject: &[u8],
    contexts: &[&[u8]],
) -> Result<B4NegativeVerifierBoundary, B4NegativeVerifierAdapterError> {
    let manifest = decode_manifest_context(contexts, 1)?;
    match verify_stark(&manifest, subject) {
        Err(error) => select_terminal_policy_boundary(error),
        Ok(_) => Err(B4NegativeVerifierAdapterError::UnexpectedAcceptance),
    }
}

fn select_terminal_policy_boundary(
    error: B4StarkError,
) -> Result<B4NegativeVerifierBoundary, B4NegativeVerifierAdapterError> {
    let boundary = error.rejection_boundary();
    if boundary.class == B4StarkErrorClass::TerminalPolicy
        && boundary.stage == B4StarkErrorStage::TerminalControlId
    {
        Ok(B4NegativeVerifierBoundary::Stark(boundary))
    } else {
        Err(unexpected_stark(error))
    }
}

/// Exercise a raw receipt seal against the exact expected successful,
/// empty-assumptions claim derived from the positional statement context.
pub(super) fn reject_receipt_claim_policy(
    subject: &[u8],
    contexts: &[&[u8]],
) -> Result<B4NegativeVerifierBoundary, B4NegativeVerifierAdapterError> {
    let manifest = decode_manifest_context(contexts, 2)?;
    let statement_bytes = contexts[1];
    let statement = parse_ergo_statement_v1(statement_bytes)
        .map_err(|_| B4NegativeVerifierAdapterError::StatementEnvelope)?;
    let expected_claim = ok_receipt_claim_digests(&statement.program_id(), statement_bytes)
        .map_err(B4NegativeVerifierAdapterError::ClaimConstruction)?
        .expected_claim;

    let verified = verify_stark(&manifest, subject).map_err(unexpected_stark)?;
    let root_bound = verified
        .bind_inner_control_root()
        .map_err(unexpected_stark)?;
    match root_bound.bind_claim(expected_claim) {
        Err(error) if error.rejection_boundary().class == B4StarkErrorClass::ReceiptClaim => Ok(
            B4NegativeVerifierBoundary::Stark(error.rejection_boundary()),
        ),
        Err(error) => Err(unexpected_stark(error)),
        Ok(_) => Err(B4NegativeVerifierAdapterError::UnexpectedAcceptance),
    }
}

struct B4OpcodeInputs<'a> {
    proof_chunks: Vec<&'a [u8]>,
    application_payload: &'a [u8],
    program_id: &'a [u8],
    profile_id: &'a [u8],
}

fn decode_opcode_subject(
    subject: &[u8],
) -> Result<B4OpcodeInputs<'_>, B4NegativeVerifierAdapterError> {
    let envelope = decode_subject_envelope(
        subject,
        B4SubjectEnvelopeContract::new(B4SubjectEnvelopeKind::OpcodeInputs, &OPCODE_PART_BOUNDS),
    )
    .map_err(B4NegativeVerifierAdapterError::SubjectEnvelope)?;
    let parts = envelope.parts();
    let proof_chunks = decode_proof_vector(parts[0])
        .map_err(B4NegativeVerifierAdapterError::ProofVectorEnvelope)?;
    Ok(B4OpcodeInputs {
        proof_chunks,
        application_payload: parts[1],
        program_id: parts[2],
        profile_id: parts[3],
    })
}

fn preflight_opcode_inputs(
    manifest: &StarkProfileManifestV1,
    opcode: &B4OpcodeInputs<'_>,
) -> Result<Option<B4NegativeVerifierBoundary>, B4NegativeVerifierAdapterError> {
    if opcode.profile_id.len() != DIGEST_BYTES {
        return Ok(Some(B4NegativeVerifierBoundary::OpcodeProfileIdLength));
    }
    if opcode.program_id.len() != DIGEST_BYTES {
        return Ok(Some(B4NegativeVerifierBoundary::OpcodeProgramIdLength));
    }
    let maximum_payload = usize::try_from(manifest.max_application_payload_bytes())
        .map_err(|_| B4NegativeVerifierAdapterError::ProfileContext)?;
    if opcode.application_payload.len() > maximum_payload {
        return Ok(Some(
            B4NegativeVerifierBoundary::OpcodeApplicationPayloadLength,
        ));
    }
    if opcode.proof_chunks.len() != PROOF_CHUNK_LENGTHS.len() {
        return Ok(Some(B4NegativeVerifierBoundary::OpcodeProofChunkCount));
    }
    if opcode
        .proof_chunks
        .iter()
        .map(|chunk| chunk.len())
        .ne(PROOF_CHUNK_LENGTHS)
    {
        return Ok(Some(B4NegativeVerifierBoundary::OpcodeProofChunkLength));
    }
    let profile_id = manifest
        .profile_id()
        .map_err(|_| B4NegativeVerifierAdapterError::ProfileContext)?;
    if opcode.profile_id != profile_id {
        return Err(B4NegativeVerifierAdapterError::OpcodeBaseBinding);
    }
    Ok(None)
}

fn decode_proof_vector(source: &[u8]) -> Result<Vec<&[u8]>, B4ProofVectorEnvelopeError> {
    let count_bytes = source
        .get(..2)
        .ok_or(B4ProofVectorEnvelopeError::TruncatedCount)?;
    let count = usize::from(u16::from_le_bytes(
        count_bytes
            .try_into()
            .map_err(|_| B4ProofVectorEnvelopeError::TruncatedCount)?,
    ));
    if !(OPCODE_PROOF_VECTOR_MIN_CHUNKS..=OPCODE_PROOF_VECTOR_MAX_CHUNKS).contains(&count) {
        return Err(B4ProofVectorEnvelopeError::FramingChunkCount);
    }
    let mut chunks = Vec::new();
    chunks
        .try_reserve_exact(count)
        .map_err(|_| B4ProofVectorEnvelopeError::ArithmeticOverflow)?;
    let mut cursor = 2_usize;
    let mut cumulative = 0_usize;
    for index in 0..count {
        let length_end = cursor
            .checked_add(4)
            .ok_or(B4ProofVectorEnvelopeError::ArithmeticOverflow)?;
        let length_bytes = source
            .get(cursor..length_end)
            .ok_or(B4ProofVectorEnvelopeError::TruncatedLength { index })?;
        let length = usize::try_from(u32::from_le_bytes(
            length_bytes
                .try_into()
                .map_err(|_| B4ProofVectorEnvelopeError::TruncatedLength { index })?,
        ))
        .map_err(|_| B4ProofVectorEnvelopeError::ArithmeticOverflow)?;
        if length > OPCODE_PROOF_CHUNK_MAX_BYTES {
            return Err(B4ProofVectorEnvelopeError::ChunkTooLarge {
                index,
                actual: length,
            });
        }
        cumulative = cumulative
            .checked_add(length)
            .ok_or(B4ProofVectorEnvelopeError::ArithmeticOverflow)?;
        if cumulative > OPCODE_PROOF_VECTOR_MAX_PAYLOAD_BYTES {
            return Err(B4ProofVectorEnvelopeError::CumulativePayloadTooLarge);
        }
        cursor = length_end;
        let chunk_end = cursor
            .checked_add(length)
            .ok_or(B4ProofVectorEnvelopeError::ArithmeticOverflow)?;
        let chunk = source
            .get(cursor..chunk_end)
            .ok_or(B4ProofVectorEnvelopeError::TruncatedChunk { index })?;
        chunks.push(chunk);
        cursor = chunk_end;
    }
    if cursor != source.len() {
        return Err(B4ProofVectorEnvelopeError::TrailingBytes);
    }
    Ok(chunks)
}

fn concatenate_proof_chunks(chunks: &[&[u8]]) -> Result<Vec<u8>, B4NegativeVerifierAdapterError> {
    let mut raw = Vec::new();
    raw.try_reserve_exact(PROOF_BYTES)
        .map_err(|_| B4NegativeVerifierAdapterError::AllocationFailure)?;
    for chunk in chunks {
        raw.extend_from_slice(chunk);
    }
    if raw.len() != PROOF_BYTES {
        return Err(B4NegativeVerifierAdapterError::OpcodeBaseBinding);
    }
    Ok(raw)
}

fn decode_manifest_context(
    contexts: &[&[u8]],
    expected_contexts: usize,
) -> Result<StarkProfileManifestV1, B4NegativeVerifierAdapterError> {
    if contexts.len() != expected_contexts {
        return Err(B4NegativeVerifierAdapterError::ContextCardinality {
            actual: contexts.len(),
            expected: expected_contexts,
        });
    }
    let manifest = StarkProfileManifestV1::decode(contexts[0])
        .map_err(|_| B4NegativeVerifierAdapterError::ProfileContext)?;
    if manifest
        .encode()
        .map_err(|_| B4NegativeVerifierAdapterError::ProfileContext)?
        .as_slice()
        != contexts[0]
        || manifest.validate_initial_profile_target().is_err()
    {
        return Err(B4NegativeVerifierAdapterError::ProfileContext);
    }
    Ok(manifest)
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "Result::map_err supplies an owned error and this adapter retains only its closed projection"
)]
fn unexpected_stark(error: B4StarkError) -> B4NegativeVerifierAdapterError {
    B4NegativeVerifierAdapterError::UnexpectedStarkBoundary(error.rejection_boundary())
}

#[cfg(test)]
mod tests {
    use std::{env, fs, path::PathBuf};

    use risc0_zkp::field::baby_bear::BabyBearElem;

    use super::*;
    use crate::{
        constants::{ERGO_STATEMENT_DOMAIN, RISC0_OUTER_PO2, STATEMENT_PREFIX_BYTES},
        ergo_statement::ErgoStatementV1,
    };

    const MANIFEST: &[u8] = include_bytes!("../../../profiles/risc0-v3-succinct/manifest.bin");
    const SUBJECT_MAGIC: &[u8] = b"EIP45B4S";

    fn manifest() -> StarkProfileManifestV1 {
        let manifest = StarkProfileManifestV1::decode(MANIFEST).unwrap();
        manifest.validate_initial_profile_target().unwrap();
        manifest
    }

    fn proof_vector(chunks: &[&[u8]]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&u16::try_from(chunks.len()).unwrap().to_le_bytes());
        for chunk in chunks {
            bytes.extend_from_slice(&u32::try_from(chunk.len()).unwrap().to_le_bytes());
            bytes.extend_from_slice(chunk);
        }
        bytes
    }

    fn subject_envelope(kind: u8, parts: &[&[u8]]) -> Vec<u8> {
        let mut bytes = SUBJECT_MAGIC.to_vec();
        bytes.push(1);
        bytes.push(kind);
        bytes.extend_from_slice(&u16::try_from(parts.len()).unwrap().to_le_bytes());
        for part in parts {
            bytes.extend_from_slice(&u32::try_from(part.len()).unwrap().to_le_bytes());
            bytes.extend_from_slice(part);
        }
        bytes
    }

    fn canonical_chunks(raw: &[u8]) -> Vec<&[u8]> {
        let mut offset = 0;
        PROOF_CHUNK_LENGTHS
            .iter()
            .map(|length| {
                let start = offset;
                offset += length;
                &raw[start..offset]
            })
            .collect()
    }

    fn opcode_subject(raw: &[u8], payload: &[u8], program: &[u8], profile: &[u8]) -> Vec<u8> {
        let chunks = canonical_chunks(raw);
        let proof = proof_vector(&chunks);
        subject_envelope(1, &[&proof, payload, program, profile])
    }

    fn zero_preflight_seal() -> Vec<u8> {
        let mut raw = vec![0_u8; PROOF_BYTES];
        raw[32 * 4..33 * 4].copy_from_slice(&u32::from(RISC0_OUTER_PO2).to_le_bytes());
        raw
    }

    fn set_word(raw: &mut [u8], index: usize, value: u32) {
        raw[index * 4..index * 4 + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn base_opcode_subject(raw: &[u8]) -> Vec<u8> {
        let manifest = manifest();
        opcode_subject(raw, b"", &[0x44; 32], &manifest.profile_id().unwrap())
    }

    #[test]
    fn opcode_exact_length_recipes_reach_only_their_typed_boundaries() {
        let raw = zero_preflight_seal();
        let manifest = manifest();
        let profile = manifest.profile_id().unwrap();
        for length in [31, 33] {
            let profile_mutation = opcode_subject(&raw, b"", &[0x44; 32], &vec![0; length]);
            assert_eq!(
                reject_opcode_preflight(&profile_mutation, &[MANIFEST]).unwrap(),
                B4NegativeVerifierBoundary::OpcodeProfileIdLength
            );
            let program_mutation = opcode_subject(&raw, b"", &vec![0; length], &profile);
            assert_eq!(
                reject_opcode_preflight(&program_mutation, &[MANIFEST]).unwrap(),
                B4NegativeVerifierBoundary::OpcodeProgramIdLength
            );
        }

        let payload = vec![0; MAX_APPLICATION_PAYLOAD_BYTES + 1];
        let payload_mutation = opcode_subject(&raw, &payload, &[0x44; 32], &profile);
        assert_eq!(
            reject_opcode_preflight(&payload_mutation, &[MANIFEST]).unwrap(),
            B4NegativeVerifierBoundary::OpcodeApplicationPayloadLength
        );
    }

    #[test]
    fn opcode_count_empty_boundary_and_total_length_recipes_are_exact() {
        let raw = zero_preflight_seal();
        let manifest = manifest();
        let profile = manifest.profile_id().unwrap();
        let canonical = canonical_chunks(&raw);

        for selected in [&canonical[..3], &canonical[..]] {
            let chunks = if selected.len() == 3 {
                selected.to_vec()
            } else {
                let mut five = selected.to_vec();
                five.push(&[]);
                five
            };
            let proof = proof_vector(&chunks);
            let subject = subject_envelope(1, &[&proof, b"", &[0x44; 32], &profile]);
            assert_eq!(
                reject_opcode_preflight(&subject, &[MANIFEST]).unwrap(),
                B4NegativeVerifierBoundary::OpcodeProofChunkCount
            );
        }

        let mut empty_fourth = canonical.clone();
        empty_fourth[3] = &[];
        let proof = proof_vector(&empty_fourth);
        let subject = subject_envelope(1, &[&proof, b"", &[0x44; 32], &profile]);
        assert_eq!(
            reject_opcode_preflight(&subject, &[MANIFEST]).unwrap(),
            B4NegativeVerifierBoundary::OpcodeProofChunkLength
        );

        for boundary in 0..3 {
            for delta in [-1_isize, 1] {
                let mut lengths = PROOF_CHUNK_LENGTHS;
                lengths[boundary] = lengths[boundary].checked_add_signed(delta).unwrap();
                lengths[boundary + 1] = lengths[boundary + 1].checked_add_signed(-delta).unwrap();
                let mut offset = 0;
                let shifted = lengths
                    .iter()
                    .map(|length| {
                        let start = offset;
                        offset += length;
                        &raw[start..offset]
                    })
                    .collect::<Vec<_>>();
                let proof = proof_vector(&shifted);
                let subject = subject_envelope(1, &[&proof, b"", &[0x44; 32], &profile]);
                assert_eq!(
                    reject_opcode_preflight(&subject, &[MANIFEST]).unwrap(),
                    B4NegativeVerifierBoundary::OpcodeProofChunkLength
                );
            }
        }
    }

    #[test]
    fn raw_shape_recipes_project_only_structured_stark_errors() {
        let base = zero_preflight_seal();
        let cases = [
            (
                1,
                1,
                B4StarkError::NonzeroInnerRootPadding { index: 1 }.rejection_boundary(),
            ),
            (
                16,
                BabyBearElem::new(65_536).as_u32_montgomery(),
                B4StarkError::ClaimHalfwordOutOfRange {
                    index: 16,
                    value: 65_536,
                }
                .rejection_boundary(),
            ),
            (
                33,
                risc0_zkp::field::baby_bear::P,
                B4StarkError::RawSealWordNotReduced {
                    index: 33,
                    word: risc0_zkp::field::baby_bear::P,
                }
                .rejection_boundary(),
            ),
            (
                32,
                u32::from(RISC0_OUTER_PO2) - 1,
                B4StarkError::OuterPo2Mismatch {
                    actual: u32::from(RISC0_OUTER_PO2) - 1,
                    expected: u32::from(RISC0_OUTER_PO2),
                }
                .rejection_boundary(),
            ),
        ];
        for (index, value, expected) in cases {
            let mut raw = base.clone();
            set_word(&mut raw, index, value);
            assert_eq!(
                reject_raw_seal_shape(&base_opcode_subject(&raw), &[MANIFEST]).unwrap(),
                B4NegativeVerifierBoundary::Stark(expected)
            );
        }
    }

    #[test]
    fn framing_and_context_failures_never_become_rejection_boundaries() {
        let raw = zero_preflight_seal();
        let valid = base_opcode_subject(&raw);

        assert!(matches!(
            reject_opcode_preflight(&valid[..valid.len() - 1], &[MANIFEST]),
            Err(B4NegativeVerifierAdapterError::SubjectEnvelope(_))
        ));
        assert_eq!(
            reject_opcode_preflight(&valid, &[]),
            Err(B4NegativeVerifierAdapterError::ContextCardinality {
                actual: 0,
                expected: 1
            })
        );
        assert_eq!(
            reject_terminal_policy(&raw, &[MANIFEST, MANIFEST]),
            Err(B4NegativeVerifierAdapterError::ContextCardinality {
                actual: 2,
                expected: 1
            })
        );
        let mut wrong_kind = valid.clone();
        wrong_kind[SUBJECT_MAGIC.len() + 1] = 2;
        assert!(matches!(
            reject_opcode_preflight(&wrong_kind, &[MANIFEST]),
            Err(B4NegativeVerifierAdapterError::SubjectEnvelope(
                B4SubjectEnvelopeError::UnexpectedKind { .. }
            ))
        ));
        let mut manifest = MANIFEST.to_vec();
        manifest[0] ^= 1;
        assert_eq!(
            reject_opcode_preflight(&valid, &[&manifest]),
            Err(B4NegativeVerifierAdapterError::ProfileContext)
        );
        assert_eq!(
            reject_raw_statement_claim_binding(&raw, &[&raw, MANIFEST]),
            Err(B4NegativeVerifierAdapterError::ProfileContext)
        );
    }

    #[test]
    fn terminal_handler_exposes_only_the_planned_control_id_boundary() {
        let allowed = B4StarkError::TerminalControlIdNotAllowed { actual: [1; 32] };
        assert_eq!(
            select_terminal_policy_boundary(allowed.clone()),
            Ok(B4NegativeVerifierBoundary::Stark(
                allowed.rejection_boundary()
            ))
        );

        for private in [
            B4StarkError::TerminalOuterPo2Mismatch {
                actual: 17,
                expected: 18,
            },
            B4StarkError::TerminalCallbackMissing,
            B4StarkError::TerminalCallbackRepeated,
        ] {
            let boundary = private.rejection_boundary();
            assert_eq!(
                select_terminal_policy_boundary(private),
                Err(B4NegativeVerifierAdapterError::UnexpectedStarkBoundary(
                    boundary
                ))
            );
        }
    }

    #[test]
    fn statement_recipe_mutations_remain_valid_distinct_claim_preimages() {
        let manifest = manifest();
        let statement = ErgoStatementV1::new(
            [0x11; 32],
            manifest.profile_id().unwrap(),
            [0x22; 32],
            [0x33; 32],
            b"payload",
        )
        .unwrap()
        .encode()
        .unwrap();
        let original = parse_ergo_statement_v1(&statement).unwrap();
        let original_claim = ok_receipt_claim_digests(&original.program_id(), &statement).unwrap();

        for index in [
            ERGO_STATEMENT_DOMAIN.len() + 1,
            ERGO_STATEMENT_DOMAIN.len() + 1 + DIGEST_BYTES,
            ERGO_STATEMENT_DOMAIN.len() + 1 + 2 * DIGEST_BYTES,
            ERGO_STATEMENT_DOMAIN.len() + 1 + 3 * DIGEST_BYTES,
            statement.len() - 1,
        ] {
            let mut mutated = statement.clone();
            mutated[index] ^= 1;
            let decoded = parse_ergo_statement_v1(&mutated).unwrap();
            assert_ne!(
                ok_receipt_claim_digests(&decoded.program_id(), &mutated).unwrap(),
                original_claim
            );
        }
    }

    #[test]
    fn closed_boundary_identifiers_are_nonplaceholder_lower_kebab() {
        let boundaries = [
            B4NegativeVerifierBoundary::OpcodeProfileIdLength,
            B4NegativeVerifierBoundary::OpcodeProgramIdLength,
            B4NegativeVerifierBoundary::OpcodeApplicationPayloadLength,
            B4NegativeVerifierBoundary::OpcodeProofChunkCount,
            B4NegativeVerifierBoundary::OpcodeProofChunkLength,
            B4NegativeVerifierBoundary::Stark(
                B4StarkError::ClaimDigestMismatch {
                    expected: [0; 32],
                    actual: [1; 32],
                }
                .rejection_boundary(),
            ),
        ];
        for boundary in boundaries {
            for value in [boundary.class(), boundary.stage()] {
                assert!(!value.is_empty());
                assert!(value.bytes().all(|byte| {
                    byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                }));
                assert!(!value.contains("unknown"));
                assert!(!value.contains("placeholder"));
            }
        }
    }

    /// This test is deliberately environment-fed: the repository does not
    /// freeze candidate proof bytes before the materialization authority does.
    /// It must be run against an authenticated generated lift-po2-15 vector.
    #[test]
    #[ignore = "requires EIP0045_B4_REAL_VECTOR_ROOT with statement and proof outputs"]
    fn real_vector_reaches_every_noninstrumented_consumer_and_root_mutation_stays_crypto_early() {
        let root = PathBuf::from(env::var_os("EIP0045_B4_REAL_VECTOR_ROOT").unwrap());
        let seal =
            fs::read(root.join("proof/candidate-proof-export/proof-output/candidate-raw-seal.bin"))
                .unwrap();
        let statement = fs::read(root.join("statement/candidate-statement.bin")).unwrap();
        let parsed = parse_ergo_statement_v1(&statement).unwrap();
        let opcode = opcode_subject(
            &seal,
            &statement[STATEMENT_PREFIX_BYTES..],
            &parsed.program_id(),
            &parsed.profile_id(),
        );

        assert_eq!(
            reject_opcode_preflight(&opcode, &[MANIFEST]),
            Err(B4NegativeVerifierAdapterError::UnexpectedAcceptance)
        );
        assert_eq!(
            reject_raw_seal_shape(&opcode, &[MANIFEST]),
            Err(B4NegativeVerifierAdapterError::UnexpectedAcceptance)
        );
        assert_eq!(
            reject_terminal_policy(&seal, &[MANIFEST]),
            Err(B4NegativeVerifierAdapterError::UnexpectedAcceptance)
        );
        assert_eq!(
            reject_receipt_claim_policy(&seal, &[MANIFEST, &statement]),
            Err(B4NegativeVerifierAdapterError::UnexpectedAcceptance)
        );

        let mut reordered_chunks = canonical_chunks(&seal);
        reordered_chunks.swap(0, 1);
        let reordered_proof = proof_vector(&reordered_chunks);
        let reordered = subject_envelope(
            1,
            &[
                &reordered_proof,
                &statement[STATEMENT_PREFIX_BYTES..],
                &parsed.program_id(),
                &parsed.profile_id(),
            ],
        );
        let reordered_result = reject_raw_seal_shape(&reordered, &[MANIFEST]);
        assert_eq!(
            reordered_result,
            Ok(B4NegativeVerifierBoundary::Stark(
                B4StarkError::RawSealWordNotReduced { index: 0, word: 0 }.rejection_boundary()
            ))
        );

        let mut mutated_statement = statement.clone();
        mutated_statement[ERGO_STATEMENT_DOMAIN.len() + 1] ^= 1;
        assert_eq!(
            reject_raw_statement_claim_binding(&mutated_statement, &[MANIFEST, &seal])
                .unwrap()
                .class(),
            B4StarkErrorClass::ReceiptClaim.as_str()
        );

        let mut mutated_root = seal.clone();
        mutated_root[0] ^= 1;
        assert!(matches!(
            reject_raw_seal_shape(&base_opcode_subject(&mutated_root), &[MANIFEST]),
            Err(B4NegativeVerifierAdapterError::UnexpectedStarkBoundary(
                B4StarkRejectionBoundary {
                    class: B4StarkErrorClass::Risc0CryptographicVerifier,
                    ..
                }
            ))
        ));
    }

    /// Seven-row statement-claim joins, not H0 or campaign authority.
    #[cfg(feature = "positive-gate")]
    mod genuine_statement_claim {
        use anyhow::{Context as _, Result, ensure};
        use sha2::{Digest as _, Sha256};

        use super::*;
        use crate::{
            b4::{B4ByteOperation, B4ByteTarget, B4NegativeMaterialization, B4NegativeMutation},
            b4_c2_raw::reconstruct_statement_claim_for_test,
            b4_materialization_set::B4ClosedReconstructedExecutionV1,
            b4_plan::{B4MaterializationDomain, B4NegativePlanExecutionV1, Eip0045B4NegativePlanV1},
            ergo_statement::ErgoStatementFieldV1,
        };

        // Kept fail-closed until the distinct nonempty-payload proof is pinned.
        const CLAIM_SEAL_SHA: Option<&str> = Some("d6fa2514cd2a642665cd8e746ae6ae0474c2f5604bf2a90852eec9f8c27c7bfc");
        const CLAIM_STATEMENT_SHA: Option<&str> = Some("da4f3d7483d082324d1d11a3df67fd0dbfb662e0091ad741400be32ac3c15ae1");
        const CLAIM_ROWS: [usize; 7] = [0, 1, 2, 3, 4, 5, 6];
        const CLAIM_IDS: [&str; 7] = [
            "statement-field-byte-sweep--chain-domain-byte-order-reversed",
            "statement-field-byte-sweep--profile-id",
            "statement-field-byte-sweep--program-id",
            "statement-field-byte-sweep--contract-id-byte-order-reversed",
            "statement-field-byte-sweep--application-payload",
            "statement-profile-id-byte-order--profile-id",
            "statement-program-id-byte-order--program-id",
        ];
        // Independent table checked against the typed layout, not copied from
        // any returned materialization recipe or earlier empty-payload vector.
        const EDITS: [(ErgoStatementFieldV1, usize, usize, bool); 7] = [
            (ErgoStatementFieldV1::ChainDomainId, 27, 32, true),
            (ErgoStatementFieldV1::ProfileId, 59, 1, false),
            (ErgoStatementFieldV1::ProgramId, 91, 1, false),
            (ErgoStatementFieldV1::ContractId, 123, 32, true),
            (ErgoStatementFieldV1::ApplicationPayload, 159, 1, false),
            (ErgoStatementFieldV1::ProfileId, 59, 32, true),
            (ErgoStatementFieldV1::ProgramId, 91, 32, true),
        ];

        struct ClaimVector {
            seal: Vec<u8>,
            statement: Vec<u8>,
            planned: Vec<B4NegativePlanExecutionV1>,
            plan_jcs: Vec<u8>,
        }

        fn pinned_file(root: &std::path::Path, relative: &str, length: usize, digest: &str) -> Result<Vec<u8>> {
            let path = root.join(relative);
            ensure!(fs::canonicalize(&path)? == path, "redirected claim diagnostic input");
            let metadata = fs::metadata(&path)?;
            ensure!(metadata.is_file() && metadata.len() == u64::try_from(length)?, "claim diagnostic input size/type");
            let bytes = fs::read(path)?;
            ensure!(bytes.len() == length && hex::encode(Sha256::digest(&bytes)) == digest, "claim diagnostic input pin");
            Ok(bytes)
        }

        fn load_claim_vector() -> Result<ClaimVector> {
            let seal_sha = CLAIM_SEAL_SHA.context("claim seal pin is pending")?;
            let statement_sha = CLAIM_STATEMENT_SHA.context("claim statement pin is pending")?;
            let root = PathBuf::from(env::var_os("EIP0045_B4_CLAIM_VECTOR_ROOT")
                .context("EIP0045_B4_CLAIM_VECTOR_ROOT is required")?);
            ensure!(root.is_absolute() && fs::canonicalize(&root)? == root, "physical claim diagnostic root required");
            let seal = pinned_file(&root, "proof/candidate-proof-export/proof-output/candidate-raw-seal.bin", PROOF_BYTES, seal_sha)?;
            let statement = pinned_file(&root, "statement/candidate-statement.bin", 160, statement_sha)?;
            let parsed = parse_ergo_statement_v1(&statement)?;
            ensure!(parsed.encode()? == statement && parsed.application_payload() == [1], "claim vector nonempty payload/encoding");
            ensure!(parsed.profile_id() == manifest().profile_id()?, "claim vector positive profile");
            ensure!(statement[155..159] == [1, 0, 0, 0], "claim vector payload-length prefix");
            let plan = Eip0045B4NegativePlanV1::canonical()?;
            let plan_jcs = plan.to_canonical_jcs()?;
            let planned = plan.groups.into_iter().flat_map(|group| group.executions).collect();
            Ok(ClaimVector { seal, statement, planned, plan_jcs })
        }

        fn reconstruct(vector: &ClaimVector) -> Result<Vec<(usize, B4ClosedReconstructedExecutionV1)>> {
            CLAIM_ROWS.into_iter().map(|index| {
                let row = reconstruct_statement_claim_for_test(index, &vector.planned[index],
                    &vector.plan_jcs, &vector.seal, &vector.statement)?;
                Ok((index, row))
            }).collect()
        }

        fn expected_edit(vector: &ClaimVector, index: usize) -> Result<(ErgoStatementFieldV1, usize, Vec<u8>, Vec<u8>)> {
            let &(field, offset, width, reverse) = EDITS.get(index).context("unexpected claim row")?;
            let parsed = parse_ergo_statement_v1(&vector.statement)?;
            let span = parsed.layout()?.span(field);
            ensure!(span.start() == offset && span.len() >= width, "independent claim table/layout mismatch");
            let before = vector.statement.get(offset..offset + width).context("claim field absent")?.to_vec();
            let replacement = if reverse {
                before.iter().rev().copied().collect::<Vec<_>>()
            } else {
                vec![before[0] ^ 1]
            };
            ensure!(before != replacement, "claim edit would be a no-op");
            Ok((field, offset, before, replacement))
        }

        fn validate_claim_observation(observed: std::result::Result<
            B4NegativeVerifierBoundary, B4NegativeVerifierAdapterError,
        >) -> Result<()> {
            let boundary = observed.context("claim consumer did not return a structured rejection")?;
            ensure!(boundary.class() == "receipt-claim-mismatch"
                && boundary.stage() == "expected-claim-binding", "exact claim class/stage mismatch");
            Ok(())
        }

        fn validate_row(vector: &ClaimVector, index: usize, row: &B4ClosedReconstructedExecutionV1) -> Result<()> {
            ensure!(CLAIM_ROWS.contains(&index), "unexpected claim row");
            let selector = if index <= 4 { "lift-po2-15-reference-statement-v1" } else { "lift-po2-15" };
            let registry = &row.derived_registry_row;
            ensure!(registry.execution_id == CLAIM_IDS[index]
                && registry.execution_id == vector.planned[index].execution_id
                && registry.base_selector_id == selector
                && registry.materialization_domain == B4MaterializationDomain::VerifierInput, "claim row identity mismatch");
            ensure!(row.base == vector.statement, "claim base mismatch");
            ensure!(row.contexts.len() == 2 && row.contexts[0] == MANIFEST
                && row.contexts[1] == vector.seal, "claim positional context mismatch");
            let (field, offset, before, replacement) = expected_edit(vector, index)?;
            let end = offset + before.len();
            ensure!(row.subject.len() == vector.statement.len()
                && row.subject.get(..offset) == vector.statement.get(..offset)
                && row.subject.get(offset..end) == Some(replacement.as_slice())
                && row.subject.get(end..) == vector.statement.get(end..), "exact claim splice mismatch");
            let expected = B4NegativeMaterialization::Mutation {
                mutation: B4NegativeMutation::ByteEdit {
                    target: B4ByteTarget::Statement,
                    edit: B4ByteOperation::Replace {
                        before_hex: hex::encode(&before), replacement_hex: hex::encode(&replacement),
                        offset: u64::try_from(offset)?,
                    },
                },
            };
            ensure!(registry.materialization == expected, "claim recipe mismatch");
            let original = parse_ergo_statement_v1(&vector.statement)?;
            let mutated = parse_ergo_statement_v1(&row.subject)?;
            let layout = original.layout()?;
            ensure!(mutated.encode()? == row.subject && mutated.layout()? == layout, "claim statement grammar/layout mismatch");
            for candidate in ErgoStatementFieldV1::ALL {
                let span = layout.span(candidate);
                let changed = span.bytes(&vector.statement)? != span.bytes(&row.subject)?;
                ensure!(changed == (candidate == field), "claim unrelated field mismatch");
            }
            ensure!(row.subject[155..159] == vector.statement[155..159], "claim payload-length drift");
            let original_claim = ok_receipt_claim_digests(&original.program_id(), &vector.statement)?;
            let changed_claim = ok_receipt_claim_digests(&mutated.program_id(), &row.subject)?;
            ensure!(original_claim != changed_claim, "claim mutation has unchanged claim preimage");
            let contexts = row.contexts.iter().map(Vec::as_slice).collect::<Vec<_>>();
            // No profile/program prefilter: mutated program and complete subject
            // must reach the real consumer's own expected-claim construction.
            validate_claim_observation(reject_raw_statement_claim_binding(&row.subject, &contexts))
        }

        fn validate_matrix(vector: &ClaimVector, rows: &[(usize, B4ClosedReconstructedExecutionV1)]) -> Result<()> {
            ensure!(rows.iter().map(|(index, _)| *index).eq(CLAIM_ROWS), "ordered seven-row claim coverage mismatch");
            for (index, row) in rows { validate_row(vector, *index, row)?; }
            Ok(())
        }

        fn require_failure(result: Result<()>, guard: &str) {
            let error = result.expect_err("claim single-fault mutant bypassed oracle");
            assert!(format!("{error:#}").contains(guard), "wrong claim mutant guard: {error:#}");
        }

        #[test]
        #[ignore = "requires pinned EIP0045_B4_CLAIM_VECTOR_ROOT; local diagnostic only"]
        fn genuine_statement_claim_matrix() {
            let vector = load_claim_vector().unwrap();
            validate_matrix(&vector, &reconstruct(&vector).unwrap()).unwrap();
        }

        #[test]
        #[ignore = "requires pinned EIP0045_B4_CLAIM_VECTOR_ROOT; local diagnostic only"]
        fn genuine_statement_claim_preconditions() {
            let vector = load_claim_vector().unwrap();
            assert_eq!(reject_raw_statement_claim_binding(&vector.statement, &[MANIFEST, &vector.seal]),
                Err(B4NegativeVerifierAdapterError::UnexpectedAcceptance));
            let parsed = parse_ergo_statement_v1(&vector.statement).unwrap();
            let opcode = opcode_subject(&vector.seal, parsed.application_payload(), &parsed.program_id(), &parsed.profile_id());
            assert_eq!(reject_raw_seal_shape(&opcode, &[MANIFEST]),
                Err(B4NegativeVerifierAdapterError::UnexpectedAcceptance));
            for index in CLAIM_ROWS { expected_edit(&vector, index).unwrap(); }
            let (_, offset, before, after) = expected_edit(&vector, 4).unwrap();
            assert_eq!((offset, before, after), (159, vec![1], vec![0]));
            for index in [7, 29, 33, 71, 109] {
                let error = reconstruct_statement_claim_for_test(index, &vector.planned[index],
                    &vector.plan_jcs, &vector.seal, &vector.statement).unwrap_err();
                assert!(error.to_string().contains("closed statement row"));
            }
        }

        #[test]
        #[ignore = "requires pinned EIP0045_B4_CLAIM_VECTOR_ROOT; local diagnostic only"]
        fn genuine_statement_claim_bypass_mutants() {
            let vector = load_claim_vector().unwrap();
            let rows = reconstruct(&vector).unwrap();
            validate_matrix(&vector, &rows).unwrap();
            let mut omitted = rows.clone();
            omitted.remove(4);
            require_failure(validate_matrix(&vector, &omitted), "ordered seven-row claim coverage");
            let mut duplicated = rows.clone();
            duplicated[4] = duplicated[3].clone();
            require_failure(validate_matrix(&vector, &duplicated), "ordered seven-row claim coverage");
            let base = &rows[1].1;
            let mut unmutated = base.clone();
            unmutated.subject.clone_from(&vector.statement);
            require_failure(validate_row(&vector, 1, &unmutated), "exact claim splice");
            require_failure(validate_claim_observation(reject_raw_statement_claim_binding(
                &vector.statement, &[MANIFEST, &vector.seal])), "claim consumer did not return a structured rejection");

            let wrong_stage = B4NegativeVerifierBoundary::Stark(B4StarkRejectionBoundary {
                class: B4StarkErrorClass::ReceiptClaim, stage: B4StarkErrorStage::InnerControlRootBinding,
            });
            require_failure(validate_claim_observation(Ok(wrong_stage)), "exact claim class/stage");

            let mut wrong_context = base.clone();
            wrong_context.contexts.swap(0, 1);
            require_failure(validate_row(&vector, 1, &wrong_context), "claim positional context");
            let contexts = wrong_context.contexts.iter().map(Vec::as_slice).collect::<Vec<_>>();
            let rejected_context = reject_raw_statement_claim_binding(&wrong_context.subject, &contexts);
            assert_eq!(rejected_context, Err(B4NegativeVerifierAdapterError::ProfileContext));
            require_failure(validate_claim_observation(rejected_context), "claim consumer did not return a structured rejection");
            let mut changed_seal = base.clone();
            changed_seal.contexts[1][0] ^= 1;
            require_failure(validate_row(&vector, 1, &changed_seal), "claim positional context");

            let mut malformed = base.clone();
            malformed.subject[0] ^= 1;
            let rejected_envelope = reject_raw_statement_claim_binding(&malformed.subject, &[MANIFEST, &vector.seal]);
            assert_eq!(rejected_envelope, Err(B4NegativeVerifierAdapterError::StatementEnvelope));
            require_failure(validate_claim_observation(rejected_envelope), "claim consumer did not return a structured rejection");

            let mut unrelated = base.clone();
            unrelated.subject[27] ^= 1;
            // A second valid field change still reaches the expected consumer
            // rejection; the exact splice oracle must independently catch it.
            validate_claim_observation(reject_raw_statement_claim_binding(&unrelated.subject, &[MANIFEST, &vector.seal])).unwrap();
            require_failure(validate_row(&vector, 1, &unrelated), "exact claim splice");
            let mut wrong_recipe = base.clone();
            if let B4NegativeMaterialization::Mutation { mutation: B4NegativeMutation::ByteEdit {
                edit: B4ByteOperation::Replace { offset, .. }, ..
            }} = &mut wrong_recipe.derived_registry_row.materialization { *offset += 1; }
            require_failure(validate_row(&vector, 1, &wrong_recipe), "claim recipe mismatch");
            let mut wrong_identity = base.clone();
            wrong_identity.derived_registry_row.base_selector_id = "lift-po2-15".to_owned();
            require_failure(validate_row(&vector, 1, &wrong_identity), "claim row identity mismatch");
        }

        /// Production descriptor custody and dispatch, using unchanged real C2
        /// outputs. No CLI-process or complete campaign closure is asserted.
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        mod production_dispatch {
            use std::{io::Write as _, path::Path};

            use super::*;
            use crate::{
                b4_negative_io::{
                    B4NegativeFileEncoding, B4NegativeNamedIdentityV1,
                    B4NegativeObservationRejectionV1, B4NegativeObservationVerdict,
                    Eip0045B4NegativeObservationV1, Eip0045B4NegativeVerifierInputV1,
                },
                b4_plan::B4NegativeExecutionSurface,
            };

            const PRIVATE_FAILURE: &str = "selected negative adapter VerifierRawStatementClaimBinding failed privately; no observation was produced";

            struct Package {
                temporary: tempfile::TempDir,
                root: PathBuf,
                input: Eip0045B4NegativeVerifierInputV1,
                input_jcs: Vec<u8>,
            }

            fn digest(bytes: &[u8]) -> String {
                hex::encode(Sha256::digest(bytes))
            }

            fn identity(role: &str, path: &str, bytes: &[u8]) -> B4NegativeNamedIdentityV1 {
                B4NegativeNamedIdentityV1 {
                    role: role.to_owned(), path: path.to_owned(),
                    byte_length: u64::try_from(bytes.len()).unwrap(),
                    sha256: digest(bytes), encoding: B4NegativeFileEncoding::RawBytes,
                }
            }

            fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
                let mut file = fs::OpenOptions::new().write(true).create_new(true).open(path)?;
                file.write_all(bytes)?;
                file.sync_all()?;
                Ok(())
            }

            fn package(subject: &[u8], contexts: &[Vec<u8>]) -> Result<Package> {
                ensure!(subject.len() == 160 && contexts.len() == 2, "closed claim package dimensions");
                let temporary = tempfile::tempdir()?;
                let root = temporary.path().join("negative");
                fs::create_dir(&root)?;
                fs::create_dir(root.join("context"))?;
                write_new(&root.join("subject.bin"), subject)?;
                let mut context = Vec::new();
                for (index, bytes) in contexts.iter().enumerate() {
                    let path = format!("context/{index:02}.bin");
                    write_new(&root.join(&path), bytes)?;
                    context.push(identity(&format!("context-{index:02}"), &path, bytes));
                }
                let input = Eip0045B4NegativeVerifierInputV1 {
                    format: "Eip0045B4NegativeVerifierInputV1".to_owned(), format_version: 1,
                    materialization_domain: B4MaterializationDomain::VerifierInput,
                    validation_surface: B4NegativeExecutionSurface::RawStatementClaimBinding,
                    subject: identity("subject", "subject.bin", subject), context,
                };
                let input_jcs = input.to_canonical_jcs()?;
                write_new(&root.join("negative-input.json"), &input_jcs)?;
                ensure!(fs::canonicalize(&root)? == root, "physical claim package root");
                Ok(Package { temporary, root, input, input_jcs })
            }

            fn closed_real_package(row: &B4ClosedReconstructedExecutionV1) -> Result<Package> {
                let physical = package(&row.subject, &row.contexts)?;
                ensure!(physical.input_jcs == row.negative_input_jcs,
                    "C2 neutral input differs from the physical claim package");
                Ok(physical)
            }

            fn expected_observation(input_jcs: &[u8], subject: &[u8]) -> Eip0045B4NegativeObservationV1 {
                Eip0045B4NegativeObservationV1 {
                    format: "Eip0045B4NegativeObservationV1".to_owned(), format_version: 1,
                    materialization_domain: B4MaterializationDomain::VerifierInput,
                    validation_surface: B4NegativeExecutionSurface::RawStatementClaimBinding,
                    negative_input_sha256: digest(input_jcs),
                    subject_byte_length: u64::try_from(subject.len()).unwrap(),
                    subject_sha256: digest(subject), verdict: B4NegativeObservationVerdict::Reject,
                    rejection: B4NegativeObservationRejectionV1 {
                        class: "receipt-claim-mismatch".to_owned(),
                        stage: "expected-claim-binding".to_owned(),
                    },
                }
            }

            fn validate_dispatch_observation(observation: &Eip0045B4NegativeObservationV1,
                input_jcs: &[u8], subject: &[u8]) -> Result<()> {
                ensure!(*observation == expected_observation(input_jcs, subject),
                    "dispatch observation identity/boundary mismatch");
                let jcs = observation.to_canonical_jcs()?;
                // Literal independent field set/order: no execution ID, recipe,
                // expectation, path, or diagnostic may leak into the response.
                let exact = format!(concat!(
                    "{{\"format\":\"Eip0045B4NegativeObservationV1\",\"formatVersion\":1,",
                    "\"materializationDomain\":\"verifier-input\",\"negativeInputSha256\":\"{}\",",
                    "\"rejection\":{{\"class\":\"receipt-claim-mismatch\",\"stage\":\"expected-claim-binding\"}},",
                    "\"subjectByteLength\":{},\"subjectSha256\":\"{}\",",
                    "\"validationSurface\":\"raw-statement-claim-binding\",\"verdict\":\"reject\"}}"
                ), digest(input_jcs), subject.len(), digest(subject));
                ensure!(jcs == exact.as_bytes(), "dispatch observation exact JCS mismatch");
                ensure!(Eip0045B4NegativeObservationV1::from_canonical_jcs(&jcs)? == *observation,
                    "dispatch observation round-trip mismatch");
                Ok(())
            }

            fn dispatch(package: &Package, subject: &[u8]) -> Result<()> {
                // The only production call receives a root, never an expected
                // outcome, injected contract, retained view, or adapter callback.
                let observation = crate::b4_validator::verify_negative_root(&package.root)?;
                validate_dispatch_observation(&observation, &package.input_jcs, subject)
            }

            fn deny(package: &Package, exact: &str) {
                let error = crate::b4_validator::verify_negative_root(&package.root)
                    .expect_err("physical claim fault produced an observation");
                assert_eq!(error.to_string(), exact, "wrong physical claim failure: {error:#}");
            }

            fn authenticate_positive(vector: &ClaimVector) {
                // This exercises complete stock proof, terminal, initial root
                // and exact program/statement-derived claim before any negative.
                assert_eq!(reject_raw_statement_claim_binding(&vector.statement, &[MANIFEST, &vector.seal]),
                    Err(B4NegativeVerifierAdapterError::UnexpectedAcceptance));
            }

            #[test]
            fn production_statement_claim_observation_oracle_and_entry_are_exact() {
                // Identity-only fixture; not a proof, C2 row, or authority.
                let subject = [0_u8; 160];
                let expected = expected_observation(b"input", &subject);
                validate_dispatch_observation(&expected, b"input", &subject).unwrap();
                for fault in 0..7 {
                    let mut changed = expected.clone();
                    match fault {
                        0 => changed.negative_input_sha256 = "00".repeat(32),
                        1 => changed.subject_sha256 = "00".repeat(32),
                        2 => changed.subject_byte_length += 1,
                        3 => changed.validation_surface = B4NegativeExecutionSurface::RawSealShape,
                        4 => changed.materialization_domain = B4MaterializationDomain::ArtifactValidator,
                        5 => changed.rejection.class = "raw-seal-shape-invalid".to_owned(),
                        6 => changed.rejection.stage = "inner-control-root-binding".to_owned(),
                        _ => unreachable!(),
                    }
                    require_failure(validate_dispatch_observation(&changed, b"input", &subject),
                        "dispatch observation identity/boundary mismatch");
                }
                let helpers = include_str!("negative_verifier.rs").split("mod production_dispatch {")
                    .nth(1).unwrap().split("#[test]").next().unwrap();
                assert!(helpers.contains("crate::b4_validator::verify_negative_root("));
                for forbidden in ["ContractAuthority::Test", "verify_authenticated_parts", "load_for_test"] {
                    assert!(!helpers.contains(forbidden), "test authority bypass: {forbidden}");
                }
            }

            #[test]
            #[ignore = "requires pinned EIP0045_B4_CLAIM_VECTOR_ROOT and Linux physical custody"]
            fn production_statement_claim_frozen_dispatch_matrix() {
                let vector = load_claim_vector().unwrap();
                authenticate_positive(&vector);
                let rows = reconstruct(&vector).unwrap();
                assert!(rows.iter().map(|(index, _)| *index).eq([0, 1, 2, 3, 4, 5, 6]));
                for (index, row) in &rows {
                    validate_row(&vector, *index, row).unwrap();
                    let physical = closed_real_package(row).unwrap();
                    assert_eq!(fs::read(physical.root.join("subject.bin")).unwrap(), row.subject);
                    for (position, bytes) in row.contexts.iter().enumerate() {
                        assert_eq!(fs::read(physical.root.join(format!("context/{position:02}.bin"))).unwrap(), *bytes);
                    }
                    dispatch(&physical, &row.subject).unwrap();
                }
                // Only the producer's neutral JSON drifts. The physical files
                // remain the authentic C2 subject/contexts; reject this broken
                // producer-to-consumer binding before production dispatch.
                let original = &rows[1].1;
                let mut changed = original.clone();
                let mut input = Eip0045B4NegativeVerifierInputV1::from_canonical_jcs(
                    &changed.negative_input_jcs).unwrap();
                let replacement = if &input.subject.sha256[..1] == "0" { "1" } else { "0" };
                input.subject.sha256.replace_range(0..1, replacement);
                changed.negative_input_jcs = input.to_canonical_jcs().unwrap();
                assert_eq!(changed.subject, original.subject);
                assert_eq!(changed.contexts, original.contexts);
                assert_ne!(changed.negative_input_jcs, original.negative_input_jcs);
                require_failure(closed_real_package(&changed).map(|_| ()),
                    "C2 neutral input differs from the physical claim package");
            }

            #[test]
            #[ignore = "requires pinned EIP0045_B4_CLAIM_VECTOR_ROOT and Linux physical custody"]
            fn production_statement_claim_frozen_custody_faults() {
                let vector = load_claim_vector().unwrap();
                authenticate_positive(&vector);
                let rows = reconstruct(&vector).unwrap();
                let row = &rows[1].1;
                validate_row(&vector, 1, row).unwrap();
                let control = closed_real_package(row).unwrap();
                dispatch(&control, &row.subject).unwrap();

                // A changed canonical descriptor digest is distinct from a
                // changed physical subject and from either context's drift.
                let mut input_digest = package(&row.subject, &row.contexts).unwrap();
                let replacement = if &input_digest.input.subject.sha256[..1] == "0" { "1" } else { "0" };
                input_digest.input.subject.sha256.replace_range(0..1, replacement);
                fs::write(input_digest.root.join("negative-input.json"), input_digest.input.to_canonical_jcs().unwrap()).unwrap();
                deny(&input_digest, "negative verifier file subject.bin SHA-256 differs from its descriptor");

                for (relative, original) in [
                    ("subject.bin", row.subject.as_slice()),
                    ("context/00.bin", row.contexts[0].as_slice()),
                    ("context/01.bin", row.contexts[1].as_slice()),
                ] {
                    let physical = package(&row.subject, &row.contexts).unwrap();
                    let mut changed = original.to_vec();
                    changed[0] ^= 1;
                    fs::write(physical.root.join(relative), changed).unwrap();
                    deny(&physical, &format!("negative verifier file {relative} SHA-256 differs from its descriptor"));
                }
                let framing = package(&row.subject, &row.contexts).unwrap();
                let mut framed = framing.input_jcs.clone();
                framed.push(b'\n');
                fs::write(framing.root.join("negative-input.json"), framed).unwrap();
                deny(&framing, "B4 negative verifier input is not exact RFC 8785 JCS");

                let mut absent = package(&row.subject, &row.contexts).unwrap();
                absent.input.context.pop();
                fs::write(absent.root.join("negative-input.json"), absent.input.to_canonical_jcs().unwrap()).unwrap();
                deny(&absent, "negative input context cardinality differs from the frozen handler contract");
                let swapped = package(&row.subject, &[row.contexts[1].clone(), row.contexts[0].clone()]).unwrap();
                deny(&swapped, "negative context 00 declared length is outside its handler custody bound");

                let missing_context = package(&row.subject, &row.contexts).unwrap();
                fs::remove_file(missing_context.root.join("context/01.bin")).unwrap();
                deny(&missing_context, "negative context directory is not the exact NN.bin positional prefix");
                let extra = package(&row.subject, &row.contexts).unwrap();
                write_new(&extra.root.join("extra.bin"), b"extra").unwrap();
                deny(&extra, "negative verifier root contains an unexpected or duplicate entry");
                let missing = package(&row.subject, &row.contexts).unwrap();
                fs::remove_file(missing.root.join("subject.bin")).unwrap();
                deny(&missing, "negative verifier root does not contain the exact V1 inventory");

                for hard_link in [false, true] {
                    let physical = package(&row.subject, &row.contexts).unwrap();
                    dispatch(&physical, &row.subject).unwrap();
                    let subject = physical.root.join("subject.bin");
                    // Keep the backing file outside the watched negative tree,
                    // so an inventory error cannot mask the link guard.
                    let backing = physical.temporary.path().join("backing.bin");
                    fs::rename(&subject, &backing).unwrap();
                    if hard_link {
                        fs::hard_link(&backing, &subject).unwrap();
                        deny(&physical, "hard-linked negative verifier file is forbidden: subject.bin");
                    } else {
                        std::os::unix::fs::symlink(&backing, &subject).unwrap();
                        assert!(fs::symlink_metadata(&subject).unwrap().file_type().is_symlink());
                        deny(&physical, "negative verifier path is not a regular file: subject.bin");
                    }
                }
                dispatch(&control, &row.subject).unwrap();
            }

            #[test]
            #[ignore = "requires pinned EIP0045_B4_CLAIM_VECTOR_ROOT and Linux physical custody"]
            fn production_statement_claim_frozen_private_failures() {
                let vector = load_claim_vector().unwrap();
                authenticate_positive(&vector);
                let rows = reconstruct(&vector).unwrap();
                let row = &rows[1].1;
                validate_row(&vector, 1, row).unwrap();
                let control = closed_real_package(row).unwrap();
                dispatch(&control, &row.subject).unwrap();

                let accepted = package(&vector.statement, &row.contexts).unwrap();
                deny(&accepted, PRIVATE_FAILURE);
                let mut malformed = row.subject.clone();
                malformed[155..159].copy_from_slice(&2_u32.to_le_bytes());
                assert_eq!(reject_raw_statement_claim_binding(&malformed, &[MANIFEST, &vector.seal]),
                    Err(B4NegativeVerifierAdapterError::StatementEnvelope));
                deny(&package(&malformed, &row.contexts).unwrap(), PRIVATE_FAILURE);

                // A reduced inner-root limb changes the proof transcript, not
                // the raw framing. Stock verification must fail before claim
                // binding; even consistently rehashed input files cannot turn
                // that unrelated error into a claim observation.
                let mut changed_seal = vector.seal.clone();
                changed_seal[0] ^= 1;
                let before = u32::from_le_bytes(vector.seal[..4].try_into().unwrap());
                let after = u32::from_le_bytes(changed_seal[..4].try_into().unwrap());
                assert!(before < 2_013_265_921 && after < 2_013_265_921 && before != after);
                assert_eq!(&changed_seal[1..], &vector.seal[1..]);
                assert_eq!(reject_raw_statement_claim_binding(&row.subject, &[MANIFEST, &changed_seal]),
                    Err(B4NegativeVerifierAdapterError::UnexpectedStarkBoundary(B4StarkRejectionBoundary {
                        class: B4StarkErrorClass::Risc0CryptographicVerifier,
                        stage: B4StarkErrorStage::Risc0ProofVerification,
                    })));
                let crypto = package(&row.subject, &[row.contexts[0].clone(), changed_seal]).unwrap();
                deny(&crypto, PRIVATE_FAILURE);
                dispatch(&control, &row.subject).unwrap();
                authenticate_positive(&vector);
            }
        }
    }

    /// Local diagnostic coverage of genuine-byte producer/consumer joins. These
    /// tests do not create cryptographic or campaign authority from a fixture.
    #[cfg(feature = "positive-gate")]
    mod genuine_raw_shape {
        use anyhow::{Context as _, Result, bail, ensure};
        use sha2::{Digest as _, Sha256};

        use super::*;
        use crate::{
            b4::{B4ByteOperation, B4ByteTarget, B4NegativeMaterialization,
                 B4NegativeMutation, B4SequenceOperation, B4SequenceTarget},
            b4_c2_raw::reconstruct_raw_shape_for_test,
            b4_materialization_set::B4ClosedReconstructedExecutionV1,
            b4_plan::{B4MaterializationDomain, B4NegativePlanExecutionV1,
                      Eip0045B4NegativePlanV1},
            seal::{SealSemanticProjection, SealSemanticRole, decode_seal_words,
                   derive_seal_semantic_projection, first_byte_order_candidate,
                   fixed_semantic_representative},
        };

        const CONSTANTS: &[u8] = include_bytes!("../../../profiles/risc0-v3-succinct/constants.bin");
        const SEAL_SHA: &str = "9580a6d7f9dd4d8314a3c16202eec86fdd0c511f61e4374f433015aec493765f";
        const STATEMENT_SHA: &str = "a7e2cb867db1881b6784786ba0821717c8259cc179be1cad123d9b5127329128";
        const ROWS: [usize; 41] = [
            29, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46,
            47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61,
            62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 109,
        ];
        const FIRST_BYTE_ORDER_WORDS: [usize; 7] = [0, 17, 33, 1057, 4461, 4720, 4729];
        const FIXED_MODULUS_WORDS: [usize; 7] = [0, 16, 33, 1057, 4461, 4717, 4729];

        struct Vector {
            seal: Vec<u8>,
            statement: Vec<u8>,
            words: Vec<u32>,
            semantic: SealSemanticProjection,
            planned: Vec<B4NegativePlanExecutionV1>,
            plan_jcs: Vec<u8>,
        }

        fn read_pinned(root: &std::path::Path, relative: &str, length: usize, digest: &str) -> Result<Vec<u8>> {
            let path = root.join(relative);
            ensure!(fs::canonicalize(&path)? == path, "redirected diagnostic input");
            let metadata = fs::metadata(&path)?;
            ensure!(metadata.is_file() && metadata.len() == u64::try_from(length)?, "diagnostic input size/type");
            let bytes = fs::read(path)?;
            ensure!(bytes.len() == length && hex::encode(Sha256::digest(&bytes)) == digest, "diagnostic input pin");
            Ok(bytes)
        }

        fn load_vector() -> Result<Vector> {
            let root = PathBuf::from(env::var_os("EIP0045_B4_REAL_VECTOR_ROOT")
                .context("EIP0045_B4_REAL_VECTOR_ROOT is required")?);
            ensure!(root.is_absolute() && fs::canonicalize(&root)? == root, "physical diagnostic root required");
            let seal = read_pinned(&root, "proof/candidate-proof-export/proof-output/candidate-raw-seal.bin", PROOF_BYTES, SEAL_SHA)?;
            let statement = read_pinned(&root, "statement/candidate-statement.bin", 159, STATEMENT_SHA)?;
            let parsed = parse_ergo_statement_v1(&statement)?;
            ensure!(parsed.profile_id() == manifest().profile_id()?, "diagnostic statement profile");
            let words = decode_seal_words(&seal)?;
            let semantic = derive_seal_semantic_projection(CONSTANTS)?;
            let plan = Eip0045B4NegativePlanV1::canonical()?;
            let plan_jcs = plan.to_canonical_jcs()?;
            let planned = plan.groups.into_iter().flat_map(|group| group.executions).collect();
            Ok(Vector { seal, statement, words, semantic, planned, plan_jcs })
        }

        fn honest_opcode(vector: &Vector) -> Result<Vec<u8>> {
            let parsed = parse_ergo_statement_v1(&vector.statement)?;
            Ok(opcode_subject(&vector.seal, parsed.application_payload(), &parsed.program_id(), &parsed.profile_id()))
        }

        fn reconstruct(vector: &Vector) -> Result<Vec<(usize, B4ClosedReconstructedExecutionV1)>> {
            ROWS.into_iter().map(|index| {
                let row = reconstruct_raw_shape_for_test(index, &vector.planned[index],
                    &vector.plan_jcs, &vector.seal, &vector.statement)?;
                Ok((index, row))
            }).collect()
        }

        fn expected_stage(index: usize) -> Result<&'static str> {
            match index {
                29 | 57..=70 => Ok("babybear-word-reduction"),
                33..=40 => Ok("inner-root-padding"),
                41..=56 => Ok("claim-halfword-decoding"),
                71 | 109 => Ok("outer-po2-preflight"),
                _ => bail!("unexpected matrix row"),
            }
        }

        fn validate_observation(index: usize, observed: std::result::Result<
            B4NegativeVerifierBoundary, B4NegativeVerifierAdapterError,
        >) -> Result<()> {
            let boundary = observed.context("consumer did not return a structured rejection")?;
            ensure!(boundary.class() == "raw-seal-shape-invalid"
                && boundary.stage() == expected_stage(index)?, "exact class/stage mismatch");
            Ok(())
        }

        fn first_reversal_word(vector: &Vector, role: SealSemanticRole) -> Result<usize> {
            // Scan the B2-derived role in serialization order independently of
            // the producer helper, then compare its first-candidate witness.
            let index = vector.semantic.words(role).iter().copied().find(|index| {
                let before = vector.words[*index];
                before.swap_bytes() != before && before.swap_bytes() >= vector.semantic.modulus()
            }).context("role has no byte-order candidate")?;
            let candidate = first_byte_order_candidate(&vector.seal, &vector.semantic, role)?;
            ensure!(candidate.word_index() == index
                && candidate.original_word() == vector.words[index]
                && candidate.reversed_word() == vector.words[index].swap_bytes(), "first candidate witness drift");
            Ok(index)
        }

        fn expected_word(vector: &Vector, index: usize) -> Result<(usize, u32)> {
            let modulus = vector.semantic.modulus();
            let montgomery = |value: u32| -> Result<u32> {
                Ok(u32::try_from((u64::from(value) * ((1_u64 << 32) % u64::from(modulus))) % u64::from(modulus))?)
            };
            match index {
                33..=40 => Ok((1 + 2 * (index - 33), 1)),
                41..=56 => Ok((16 + index - 41, montgomery(65_536)?)),
                57..=63 => Ok((fixed_semantic_representative(&vector.semantic, SealSemanticRole::ALL[index - 57])?, modulus)),
                64..=70 => {
                    let word = first_reversal_word(vector, SealSemanticRole::ALL[index - 64])?;
                    Ok((word, vector.words[word].swap_bytes()))
                }
                71 => Ok((32, montgomery(u32::from(manifest().outer_po2()))?)),
                109 => Ok((32, u32::from(manifest().outer_po2()) + 1)),
                _ => bail!("row has no one-word splice"),
            }
        }

        fn validate_row(vector: &Vector, index: usize, row: &B4ClosedReconstructedExecutionV1) -> Result<()> {
            ensure!(ROWS.contains(&index), "unexpected matrix row");
            let registry = &row.derived_registry_row;
            ensure!(registry.execution_id == vector.planned[index].execution_id
                && registry.base_selector_id == "lift-po2-15"
                && registry.materialization_domain == B4MaterializationDomain::VerifierInput, "row identity mismatch");
            ensure!(row.contexts.len() == 1 && row.contexts[0] == MANIFEST, "context mismatch");
            let opcode = decode_opcode_subject(&row.subject).context("opcode envelope mismatch")?;
            let statement = parse_ergo_statement_v1(&vector.statement)?;
            ensure!(opcode.application_payload == statement.application_payload()
                && opcode.profile_id == statement.profile_id()
                && opcode.program_id == statement.program_id(), "unmutated opcode field mismatch");
            ensure!(opcode.proof_chunks.len() == 4
                && opcode.proof_chunks.iter().map(|chunk| chunk.len()).eq(PROOF_CHUNK_LENGTHS), "proof chunk framing mismatch");
            if index == 29 {
                let original = canonical_chunks(&vector.seal);
                ensure!(opcode.proof_chunks.iter().copied().eq([original[1], original[0], original[2], original[3]]), "chunk permutation mismatch");
                let expected = B4NegativeMaterialization::Mutation {
                    mutation: B4NegativeMutation::SequenceEdit {
                        target: B4SequenceTarget::ProofChunks,
                        edit: B4SequenceOperation::Move {
                            before_element_id: "chunk-00".to_owned(),
                            before_element_sha256: hex::encode(Sha256::digest(original[0])),
                            from_index: 0, to_index: 1,
                        },
                    },
                };
                ensure!(registry.materialization == expected, "sequence recipe mismatch");
            } else {
                let (word, replacement) = expected_word(vector, index)?;
                let offset = word.checked_mul(4).context("word offset overflow")?;
                let mutated = concatenate_proof_chunks(&opcode.proof_chunks)?;
                ensure!(row.base == vector.seal, "raw base mismatch");
                ensure!(vector.words[word] != replacement, "splice became a no-op");
                ensure!(mutated[..offset] == vector.seal[..offset]
                    && mutated[offset + 4..] == vector.seal[offset + 4..]
                    && mutated[offset..offset + 4] == replacement.to_le_bytes(), "exact one-word splice mismatch");
                let expected = B4NegativeMaterialization::Mutation {
                    mutation: B4NegativeMutation::ByteEdit {
                        target: B4ByteTarget::RawSeal,
                        edit: B4ByteOperation::Replace {
                            before_hex: hex::encode(&vector.seal[offset..offset + 4]),
                            replacement_hex: hex::encode(replacement.to_le_bytes()),
                            offset: u64::try_from(offset)?,
                        },
                    },
                };
                ensure!(registry.materialization == expected, "byte recipe mismatch");
            }
            // Pass the producer's actual bytes and positional contexts unchanged.
            let contexts = row.contexts.iter().map(Vec::as_slice).collect::<Vec<_>>();
            validate_observation(index, reject_raw_seal_shape(&row.subject, &contexts))
        }

        fn validate_matrix(vector: &Vector, rows: &[(usize, B4ClosedReconstructedExecutionV1)]) -> Result<()> {
            ensure!(rows.iter().map(|(index, _)| *index).eq(ROWS), "ordered 41-row coverage mismatch");
            for (index, row) in rows {
                validate_row(vector, *index, row)?;
            }
            Ok(())
        }

        fn require_oracle_failure(result: Result<()>, guard: &str) {
            let failure = result.expect_err("single-fault mutant bypassed the oracle");
            assert!(format!("{failure:#}").contains(guard), "wrong mutant guard: {failure:#}");
        }

        #[test]
        #[ignore = "requires pinned EIP0045_B4_REAL_VECTOR_ROOT; local diagnostic only"]
        fn genuine_raw_shape_matrix() {
            let vector = load_vector().unwrap();
            let rows = reconstruct(&vector).unwrap();
            validate_matrix(&vector, &rows).unwrap();
        }

        #[test]
        #[ignore = "requires pinned EIP0045_B4_REAL_VECTOR_ROOT; local diagnostic only"]
        fn genuine_raw_shape_preconditions() {
            let vector = load_vector().unwrap();
            let opcode = honest_opcode(&vector).unwrap();
            assert_eq!(reject_raw_seal_shape(&opcode, &[MANIFEST]),
                Err(B4NegativeVerifierAdapterError::UnexpectedAcceptance));
            assert_eq!(reject_raw_statement_claim_binding(&vector.statement, &[MANIFEST, &vector.seal]),
                Err(B4NegativeVerifierAdapterError::UnexpectedAcceptance));
            let mut first = [0; 7];
            let mut fixed = [0; 7];
            for (index, role) in SealSemanticRole::ALL.into_iter().enumerate() {
                first[index] = first_reversal_word(&vector, role).unwrap();
                fixed[index] = fixed_semantic_representative(&vector.semantic, role).unwrap();
            }
            assert_eq!(first, FIRST_BYTE_ORDER_WORDS);
            assert_eq!(fixed, FIXED_MODULUS_WORDS);
            assert_ne!(first[1], fixed[1]);
            assert_ne!(first[5], fixed[5]);
            for index in [0, 28, 30, 32, 72, 108] {
                let error = reconstruct_raw_shape_for_test(index, &vector.planned[index],
                    &vector.plan_jcs, &vector.seal, &vector.statement).unwrap_err();
                assert!(error.to_string().contains("closed proof-order or raw-seal row"));
            }
        }

        #[test]
        #[ignore = "requires pinned EIP0045_B4_REAL_VECTOR_ROOT; local diagnostic only"]
        fn genuine_raw_shape_bypass_mutants() {
            let vector = load_vector().unwrap();
            let rows = reconstruct(&vector).unwrap();
            validate_matrix(&vector, &rows).unwrap();
            let mut omitted = rows.clone();
            omitted.remove(1);
            require_oracle_failure(validate_matrix(&vector, &omitted), "ordered 41-row coverage");
            let mut duplicated = rows.clone();
            duplicated[1] = duplicated[0].clone();
            require_oracle_failure(validate_matrix(&vector, &duplicated), "ordered 41-row coverage");

            let base = &rows[1].1; // exact row 33: padding word 1
            let mut unmutated = base.clone();
            unmutated.subject = honest_opcode(&vector).unwrap();
            require_oracle_failure(validate_row(&vector, 33, &unmutated), "exact one-word splice");

            let other_stage = B4NegativeVerifierBoundary::Stark(
                B4StarkError::OuterPo2Mismatch { actual: 1, expected: 18 }.rejection_boundary());
            assert_eq!(other_stage.class(), "raw-seal-shape-invalid");
            require_oracle_failure(validate_observation(33, Ok(other_stage)), "exact class/stage");

            let mut unrelated_raw = vector.seal.clone();
            set_word(&mut unrelated_raw, 1, 1);
            unrelated_raw[1000 * 4] ^= 1;
            let parsed = parse_ergo_statement_v1(&vector.statement).unwrap();
            let mut unrelated = base.clone();
            unrelated.subject = opcode_subject(&unrelated_raw, parsed.application_payload(), &parsed.program_id(), &parsed.profile_id());
            // The real consumer still returns the expected stage; only exact
            // splice closure detects this unrelated second alteration.
            validate_observation(33, reject_raw_seal_shape(&unrelated.subject, &[MANIFEST])).unwrap();
            require_oracle_failure(validate_row(&vector, 33, &unrelated), "exact one-word splice");

            let mut wrong_context = base.clone();
            wrong_context.contexts[0][0] ^= 1;
            require_oracle_failure(validate_row(&vector, 33, &wrong_context), "context mismatch");
            let mut wrong_envelope = base.clone();
            wrong_envelope.subject[SUBJECT_MAGIC.len() + 1] = 2;
            require_oracle_failure(validate_row(&vector, 33, &wrong_envelope), "opcode envelope mismatch");
            let mut wrong_identity = base.clone();
            wrong_identity.derived_registry_row.execution_id.push_str("-unrelated");
            require_oracle_failure(validate_row(&vector, 33, &wrong_identity), "row identity mismatch");
            let mut wrong_recipe = base.clone();
            if let B4NegativeMaterialization::Mutation { mutation: B4NegativeMutation::ByteEdit {
                edit: B4ByteOperation::Replace { offset, .. }, ..
            }} = &mut wrong_recipe.derived_registry_row.materialization { *offset += 4; }
            require_oracle_failure(validate_row(&vector, 33, &wrong_recipe), "byte recipe mismatch");

            let mut later_candidates = 0;
            for (role_index, role) in SealSemanticRole::ALL.into_iter().enumerate() {
                let first = first_reversal_word(&vector, role).unwrap();
                let later = vector.semantic.words(role).iter().copied().find(|word| {
                    *word > first && vector.words[*word].swap_bytes() != vector.words[*word]
                        && vector.words[*word].swap_bytes() >= vector.semantic.modulus()
                });
                if let Some(later) = later {
                    later_candidates += 1;
                    let index = 64 + role_index;
                    let mut mutant = rows.iter().find(|(candidate, _)| *candidate == index).unwrap().1.clone();
                    let mut raw = vector.seal.clone();
                    set_word(&mut raw, later, vector.words[later].swap_bytes());
                    mutant.subject = opcode_subject(&raw, parsed.application_payload(), &parsed.program_id(), &parsed.profile_id());
                    validate_observation(index, reject_raw_seal_shape(&mutant.subject, &[MANIFEST])).unwrap();
                    require_oracle_failure(validate_row(&vector, index, &mutant), "exact one-word splice");
                }
            }
            assert!(later_candidates > 0, "genuine vector must exercise a later qualifying candidate");
        }

        /// Separate authentic input closures: case0 supplies 41 mutations;
        /// Resolve plus ALT supplies row 108. This is not one campaign cohort.
        #[cfg(all(target_os = "linux", target_arch = "x86_64", feature = "negative-materialization-set"))]
        mod production_dispatch {
            use std::{io::Write as _, path::Path};

            use super::*;
            use crate::{
                b4_alternate_root_authority::genuine_alternate_root as alternate,
                b4_c2_alternate_root::reconstruct_genuine_alternate_root,
                b4_c2_opcode_sequence::{decode_producer_opcode_subject, encode_opcode_subject, split_raw_seal},
                b4_negative_io::{B4NegativeFileEncoding, B4NegativeNamedIdentityV1,
                    B4NegativeObservationRejectionV1, B4NegativeObservationVerdict,
                    Eip0045B4NegativeObservationV1, Eip0045B4NegativeVerifierInputV1},
                b4_plan::B4NegativeExecutionSurface,
                b4_recursive_auxiliary_map::{B4RecursiveAuxiliaryMapV1, encode_recursive_auxiliary_map},
                b4_validator::negative_verifier::genuine_conditional_claim::load_authenticated,
                recursive_ancestry::{RecursiveAncestryFamily, recursive_ancestry_claim_digest},
            };

            const PRIVATE_FAILURE: &str = "selected negative adapter VerifierRawSealShape failed privately; no observation was produced";

            struct Package {
                temporary: tempfile::TempDir,
                root: PathBuf,
                input: Eip0045B4NegativeVerifierInputV1,
                input_jcs: Vec<u8>,
            }

            fn digest(bytes: &[u8]) -> String { hex::encode(Sha256::digest(bytes)) }

            fn identity(role: &str, path: &str, bytes: &[u8]) -> B4NegativeNamedIdentityV1 {
                B4NegativeNamedIdentityV1 { role: role.to_owned(), path: path.to_owned(),
                    byte_length: u64::try_from(bytes.len()).unwrap(), sha256: digest(bytes),
                    encoding: B4NegativeFileEncoding::RawBytes }
            }

            fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
                let mut file = fs::OpenOptions::new().write(true).create_new(true).open(path)?;
                file.write_all(bytes)?;
                file.sync_all()?;
                Ok(())
            }

            fn package(subject: &[u8], context: &[u8]) -> Result<Package> {
                ensure!((1..=262_144).contains(&subject.len()) && context.len() == 458,
                    "closed raw-shape package dimensions");
                let temporary = tempfile::tempdir()?;
                let root = temporary.path().join("negative");
                fs::create_dir(&root)?;
                fs::create_dir(root.join("context"))?;
                write_new(&root.join("subject.bin"), subject)?;
                write_new(&root.join("context/00.bin"), context)?;
                let input = Eip0045B4NegativeVerifierInputV1 {
                    format: "Eip0045B4NegativeVerifierInputV1".to_owned(), format_version: 1,
                    materialization_domain: B4MaterializationDomain::VerifierInput,
                    validation_surface: B4NegativeExecutionSurface::RawSealShape,
                    subject: identity("subject", "subject.bin", subject),
                    context: vec![identity("context-00", "context/00.bin", context)],
                };
                let input_jcs = input.to_canonical_jcs()?;
                write_new(&root.join("negative-input.json"), &input_jcs)?;
                ensure!(fs::canonicalize(&root)? == root, "physical raw-shape package root");
                Ok(Package { temporary, root, input, input_jcs })
            }

            fn closed_package(row: &B4ClosedReconstructedExecutionV1) -> Result<Package> {
                ensure!(row.contexts.len() == 1 && row.contexts[0] == MANIFEST,
                    "C2 raw-shape context differs from the initial manifest");
                let physical = package(&row.subject, &row.contexts[0])?;
                ensure!(physical.input_jcs == row.negative_input_jcs,
                    "C2 neutral input differs from the physical raw-shape package");
                Ok(physical)
            }

            fn boundary(index: usize) -> Result<(&'static str, &'static str)> {
                if index == 108 { Ok(("inner-control-root-mismatch", "inner-control-root-binding")) }
                else { Ok(("raw-seal-shape-invalid", expected_stage(index)?)) }
            }

            fn expected_observation(index: usize, input: &[u8], subject: &[u8]) -> Result<Eip0045B4NegativeObservationV1> {
                let (class, stage) = boundary(index)?;
                Ok(Eip0045B4NegativeObservationV1 {
                    format: "Eip0045B4NegativeObservationV1".to_owned(), format_version: 1,
                    materialization_domain: B4MaterializationDomain::VerifierInput,
                    validation_surface: B4NegativeExecutionSurface::RawSealShape,
                    negative_input_sha256: digest(input), subject_byte_length: u64::try_from(subject.len())?,
                    subject_sha256: digest(subject), verdict: B4NegativeObservationVerdict::Reject,
                    rejection: B4NegativeObservationRejectionV1 { class: class.to_owned(), stage: stage.to_owned() },
                })
            }

            fn check_observation(index: usize, observed: &Eip0045B4NegativeObservationV1,
                input: &[u8], subject: &[u8]) -> Result<()> {
                ensure!(*observed == expected_observation(index, input, subject)?,
                    "raw-shape observation identity/boundary mismatch");
                let (class, stage) = boundary(index)?;
                let exact = format!(concat!(
                    "{{\"format\":\"Eip0045B4NegativeObservationV1\",\"formatVersion\":1,",
                    "\"materializationDomain\":\"verifier-input\",\"negativeInputSha256\":\"{}\",",
                    "\"rejection\":{{\"class\":\"{}\",\"stage\":\"{}\"}},",
                    "\"subjectByteLength\":{},\"subjectSha256\":\"{}\",",
                    "\"validationSurface\":\"raw-seal-shape\",\"verdict\":\"reject\"}}"
                ), digest(input), class, stage, subject.len(), digest(subject));
                let jcs = observed.to_canonical_jcs()?;
                ensure!(jcs == exact.as_bytes(), "raw-shape observation exact JCS mismatch");
                ensure!(Eip0045B4NegativeObservationV1::from_canonical_jcs(&jcs)? == *observed,
                    "raw-shape observation round-trip mismatch");
                Ok(())
            }

            fn dispatch(physical: &Package, index: usize, subject: &[u8]) -> Result<()> {
                let observed = crate::b4_validator::verify_negative_root(&physical.root)?;
                check_observation(index, &observed, &physical.input_jcs, subject)
            }

            fn deny(physical: &Package, exact: &str) {
                let error = crate::b4_validator::verify_negative_root(&physical.root)
                    .expect_err("raw-shape fault produced an observation");
                assert_eq!(error.to_string(), exact, "wrong physical raw-shape failure: {error:#}");
            }

            fn case0() -> Result<Vector> {
                let vector = load_vector()?;
                ensure!(vector.statement.len() == 159, "case0 is the separate empty-payload input");
                assert_eq!(reject_raw_statement_claim_binding(&vector.statement, &[MANIFEST, &vector.seal]),
                    Err(B4NegativeVerifierAdapterError::UnexpectedAcceptance));
                assert_eq!(reject_raw_seal_shape(&honest_opcode(&vector)?, &[MANIFEST]),
                    Err(B4NegativeVerifierAdapterError::UnexpectedAcceptance));
                Ok(vector)
            }

            fn case0_indices(indices: &[usize]) -> Result<()> {
                ensure!(indices == ROWS.as_slice() && indices.len() == 41 && !indices.contains(&108),
                    "exact case0-only 41-row coverage differs");
                Ok(())
            }

            #[test]
            fn production_raw_shape_observation_oracle_and_entry_are_exact() {
                // Identity-only objects, never proofs or materialization authority.
                let expected = expected_observation(33, b"input", b"subject").unwrap();
                check_observation(33, &expected, b"input", b"subject").unwrap();
                let alt = expected_observation(108, b"input", b"subject").unwrap();
                check_observation(108, &alt, b"input", b"subject").unwrap();
                for fault in 0..7 {
                    let mut changed = expected.clone();
                    match fault {
                        0 => changed.negative_input_sha256 = "00".repeat(32),
                        1 => changed.subject_sha256 = "00".repeat(32),
                        2 => changed.subject_byte_length += 1,
                        3 => changed.validation_surface = B4NegativeExecutionSurface::RawStatementClaimBinding,
                        4 => changed.materialization_domain = B4MaterializationDomain::ArtifactValidator,
                        5 => changed.rejection.class = "inner-control-root-mismatch".to_owned(),
                        6 => changed.rejection.stage = "outer-po2-preflight".to_owned(),
                        _ => unreachable!(),
                    }
                    require_oracle_failure(check_observation(33, &changed, b"input", b"subject"),
                        "raw-shape observation identity/boundary mismatch");
                }
                case0_indices(&ROWS).unwrap();
                require_oracle_failure(case0_indices(&ROWS[1..]), "exact case0-only 41-row coverage");
                let mut duplicated = ROWS;
                duplicated[1] = duplicated[0];
                require_oracle_failure(case0_indices(&duplicated), "exact case0-only 41-row coverage");
                let helpers = include_str!("negative_verifier.rs").split("mod genuine_raw_shape {")
                    .nth(1).unwrap().split("mod production_dispatch {")
                    .nth(1).unwrap().split("#[test]").next().unwrap();
                assert!(helpers.contains("crate::b4_validator::verify_negative_root("));
                for forbidden in ["ContractAuthority::Test", "verify_authenticated_parts", "load_for_test"] {
                    assert!(!helpers.contains(forbidden), "test authority bypass: {forbidden}");
                }
            }

            #[test]
            #[ignore = "requires pinned case0 EIP0045_B4_REAL_VECTOR_ROOT and Linux physical custody"]
            fn production_raw_shape_frozen_dispatch_matrix() {
                let vector = case0().unwrap();
                let rows = reconstruct(&vector).unwrap();
                case0_indices(&rows.iter().map(|(index, _)| *index).collect::<Vec<_>>()).unwrap();
                for (index, row) in &rows {
                    validate_row(&vector, *index, row).unwrap();
                    let physical = closed_package(row).unwrap();
                    assert_eq!(fs::read(physical.root.join("subject.bin")).unwrap(), row.subject);
                    assert_eq!(fs::read(physical.root.join("context/00.bin")).unwrap(), row.contexts[0]);
                    dispatch(&physical, *index, &row.subject).unwrap();
                }
                let original = &rows[1].1;
                let mut changed = original.clone();
                let mut input = Eip0045B4NegativeVerifierInputV1::from_canonical_jcs(&changed.negative_input_jcs).unwrap();
                let replacement = if &input.subject.sha256[..1] == "0" { "1" } else { "0" };
                input.subject.sha256.replace_range(0..1, replacement);
                changed.negative_input_jcs = input.to_canonical_jcs().unwrap();
                assert_eq!(changed.subject, original.subject);
                assert_eq!(changed.contexts, original.contexts);
                assert_ne!(changed.negative_input_jcs, original.negative_input_jcs);
                require_oracle_failure(closed_package(&changed).map(|_| ()),
                    "C2 neutral input differs from the physical raw-shape package");
            }

            #[test]
            #[ignore = "requires preserved Resolve and ALT exports plus pinned guest; distinct nonempty input"]
            fn production_raw_shape_alternate_frozen_dispatch() {
                let resolve = PathBuf::from(env::var_os("EIP0045_B4_RESOLVE_VECTOR_ROOT").expect("Resolve root required"));
                let alt_root = PathBuf::from(env::var_os("EIP0045_B4_ALTERNATE_VECTOR_ROOT").expect("ALT root required"));
                let guest = PathBuf::from(env::var_os("EIP0045_B4_GUEST_FILE").expect("pinned guest required"));
                let (input, projection) = load_authenticated(&resolve).unwrap();
                assert_eq!(input.manifest(), MANIFEST);
                assert_eq!(input.statement().len(), 160);
                assert_eq!(digest(input.statement()), "da4f3d7483d082324d1d11a3df67fd0dbfb662e0091ad741400be32ac3c15ae1");
                let authority = alternate::load_authenticated(&alt_root, input.statement(), &guest).unwrap();
                assert_eq!(digest(authority.raw_seal()), "c0ddfd89529fb0b3046808b6666018b66356a92826f7eab55deffff9036981a3");
                let assumption = projection.assumption_receipt.as_ref().unwrap();
                assert_eq!(authority.claim_digest(), recursive_ancestry_claim_digest(&assumption.claim).unwrap());
                let parsed = parse_ergo_statement_v1(input.statement()).unwrap();
                assert_eq!(parsed.application_payload(), [1]);
                let original_seal = input.auxiliary().get(&assumption.raw_seal.path).unwrap();
                let honest = opcode_subject(original_seal, parsed.application_payload(), &parsed.program_id(), &parsed.profile_id());
                assert_eq!(reject_raw_statement_claim_binding(input.statement(), &[MANIFEST, original_seal]),
                    Err(B4NegativeVerifierAdapterError::UnexpectedAcceptance));
                assert_eq!(reject_raw_seal_shape(&honest, &[MANIFEST]),
                    Err(B4NegativeVerifierAdapterError::UnexpectedAcceptance));
                let entries = input.auxiliary().iter().map(|(path, bytes)| (path.as_str(), bytes.as_slice())).collect::<Vec<_>>();
                let map = encode_recursive_auxiliary_map(&B4RecursiveAuxiliaryMapV1::from_exact_entries(
                    RecursiveAncestryFamily::TerminalResolve, &entries).unwrap()).unwrap();
                let row = reconstruct_genuine_alternate_root(108, &authority, input.ancestry(),
                    input.statement(), input.final_seal(), &map, input.manifest()).unwrap();
                assert_eq!(row.derived_registry_row.execution_id, "terminal-inner-root-mismatch--inner-control-root");
                assert_eq!(row.derived_registry_row.base_selector_id, "alternate-root-lift-po2-15-v1");
                assert_eq!(row.derived_registry_row.materialization_domain, B4MaterializationDomain::VerifierInput);
                assert_eq!(row.derived_registry_row.materialization, B4NegativeMaterialization::FixtureSelection {
                    fixture_id: "alternate-root-lift-po2-15-v1".into() });
                assert_eq!(row.base, authority.raw_seal());
                assert_eq!(row.contexts, vec![MANIFEST.to_vec()]);
                assert_eq!(decode_producer_opcode_subject(&row.subject).unwrap().proof_chunks().concat(), authority.raw_seal());
                assert_eq!(row.subject, encode_opcode_subject(&split_raw_seal(authority.raw_seal()).unwrap(),
                    parsed.application_payload(), &parsed.program_id(), &parsed.profile_id()).unwrap());
                let physical = closed_package(&row).unwrap();
                dispatch(&physical, 108, &row.subject).unwrap();
                // Restoring the matched, initial-root seal is acceptance, not
                // a late-root rejection; a canned observation must fail here.
                deny(&package(&honest, MANIFEST).unwrap(), PRIVATE_FAILURE);
                dispatch(&physical, 108, &row.subject).unwrap();
            }

            #[test]
            #[ignore = "requires pinned case0 EIP0045_B4_REAL_VECTOR_ROOT and Linux physical custody"]
            fn production_raw_shape_frozen_custody_faults() {
                let vector = case0().unwrap();
                let rows = reconstruct(&vector).unwrap();
                let row = &rows[1].1;
                validate_row(&vector, 33, row).unwrap();
                let control = closed_package(row).unwrap();
                dispatch(&control, 33, &row.subject).unwrap();
                let mut declared = package(&row.subject, MANIFEST).unwrap();
                let replacement = if &declared.input.subject.sha256[..1] == "0" { "1" } else { "0" };
                declared.input.subject.sha256.replace_range(0..1, replacement);
                fs::write(declared.root.join("negative-input.json"), declared.input.to_canonical_jcs().unwrap()).unwrap();
                deny(&declared, "negative verifier file subject.bin SHA-256 differs from its descriptor");
                for (relative, bytes) in [("subject.bin", row.subject.as_slice()), ("context/00.bin", MANIFEST)] {
                    let physical = package(&row.subject, MANIFEST).unwrap();
                    let mut changed = bytes.to_vec(); changed[0] ^= 1;
                    fs::write(physical.root.join(relative), changed).unwrap();
                    deny(&physical, &format!("negative verifier file {relative} SHA-256 differs from its descriptor"));
                }
                let framing = package(&row.subject, MANIFEST).unwrap();
                let mut bytes = framing.input_jcs.clone(); bytes.push(b'\n');
                fs::write(framing.root.join("negative-input.json"), bytes).unwrap();
                deny(&framing, "B4 negative verifier input is not exact RFC 8785 JCS");
                let mut absent = package(&row.subject, MANIFEST).unwrap(); absent.input.context.clear();
                fs::write(absent.root.join("negative-input.json"), absent.input.to_canonical_jcs().unwrap()).unwrap();
                deny(&absent, "negative input context cardinality differs from the frozen handler contract");
                let mut oversized = package(&row.subject, MANIFEST).unwrap(); oversized.input.subject.byte_length = 262_145;
                fs::write(oversized.root.join("negative-input.json"), oversized.input.to_canonical_jcs().unwrap()).unwrap();
                deny(&oversized, "negative subject declared length is outside the handler custody bound");
                let missing = package(&row.subject, MANIFEST).unwrap();
                fs::remove_file(missing.root.join("context/00.bin")).unwrap();
                deny(&missing, "negative context directory is not the exact NN.bin positional prefix");
                let extra = package(&row.subject, MANIFEST).unwrap(); write_new(&extra.root.join("extra.bin"), b"extra").unwrap();
                deny(&extra, "negative verifier root contains an unexpected or duplicate entry");
                for hard_link in [false, true] {
                    let physical = package(&row.subject, MANIFEST).unwrap();
                    dispatch(&physical, 33, &row.subject).unwrap();
                    let subject = physical.root.join("subject.bin");
                    let backing = physical.temporary.path().join("backing.bin");
                    fs::rename(&subject, &backing).unwrap();
                    if hard_link {
                        fs::hard_link(&backing, &subject).unwrap();
                        deny(&physical, "hard-linked negative verifier file is forbidden: subject.bin");
                    } else {
                        std::os::unix::fs::symlink(&backing, &subject).unwrap();
                        assert!(fs::symlink_metadata(&subject).unwrap().file_type().is_symlink());
                        deny(&physical, "negative verifier path is not a regular file: subject.bin");
                    }
                }
                dispatch(&control, 33, &row.subject).unwrap();
            }

            #[test]
            #[ignore = "requires pinned case0 EIP0045_B4_REAL_VECTOR_ROOT and Linux physical custody"]
            fn production_raw_shape_frozen_private_failures() {
                let vector = case0().unwrap();
                let rows = reconstruct(&vector).unwrap();
                let row = &rows[1].1;
                validate_row(&vector, 33, row).unwrap();
                let control = closed_package(row).unwrap(); dispatch(&control, 33, &row.subject).unwrap();
                deny(&package(&honest_opcode(&vector).unwrap(), MANIFEST).unwrap(), PRIVATE_FAILURE);
                let mut malformed = row.subject.clone(); malformed[0] ^= 1;
                assert_eq!(reject_raw_seal_shape(&malformed, &[MANIFEST]),
                    Err(B4NegativeVerifierAdapterError::SubjectEnvelope(B4SubjectEnvelopeError::MagicMismatch)));
                deny(&package(&malformed, MANIFEST).unwrap(), PRIVATE_FAILURE);
                let parsed = parse_ergo_statement_v1(&vector.statement).unwrap();
                let short_profile = opcode_subject(&vector.seal, parsed.application_payload(), &parsed.program_id(), &[0; 31]);
                assert_eq!(reject_raw_seal_shape(&short_profile, &[MANIFEST]),
                    Err(B4NegativeVerifierAdapterError::UnexpectedOpcodeBoundary(B4NegativeVerifierBoundary::OpcodeProfileIdLength)));
                deny(&package(&short_profile, MANIFEST).unwrap(), PRIVATE_FAILURE);
                let mut wrong_manifest = MANIFEST.to_vec(); wrong_manifest[0] ^= 1;
                assert_eq!(reject_raw_seal_shape(&row.subject, &[&wrong_manifest]), Err(B4NegativeVerifierAdapterError::ProfileContext));
                deny(&package(&row.subject, &wrong_manifest).unwrap(), PRIVATE_FAILURE);
                let mut changed = vector.seal.clone(); changed[0] ^= 1;
                assert!(u32::from_le_bytes(changed[..4].try_into().unwrap()) < 2_013_265_921);
                assert_eq!(&changed[1..], &vector.seal[1..]);
                let crypto = opcode_subject(&changed, parsed.application_payload(), &parsed.program_id(), &parsed.profile_id());
                assert_eq!(reject_raw_seal_shape(&crypto, &[MANIFEST]),
                    Err(B4NegativeVerifierAdapterError::UnexpectedStarkBoundary(B4StarkRejectionBoundary {
                        class: B4StarkErrorClass::Risc0CryptographicVerifier, stage: B4StarkErrorStage::Risc0ProofVerification,
                    })));
                deny(&package(&crypto, MANIFEST).unwrap(), PRIVATE_FAILURE);
                dispatch(&control, 33, &row.subject).unwrap();
            }
        }
    }

    /// The proof is cryptographically valid under a deliberately different,
    /// fixed recursion control root.  Ergo's pinned verifier must therefore
    /// reach—and reject at—the late inner-control-root binding, rather than
    /// misclassifying the witness as a malformed seal or cryptographic failure.
    #[test]
    #[ignore = "requires EIP0045_B4_ALTERNATE_ROOT with an alternate-root proof export"]
    fn alternate_root_vector_reaches_exact_late_ergo_root_rejection() {
        let root = PathBuf::from(env::var_os("EIP0045_B4_ALTERNATE_ROOT").unwrap());
        let proof_output = root.join("candidate-proof-export/proof-output");
        let seal = fs::read(proof_output.join("candidate-raw-seal.bin")).unwrap();
        let statement = fs::read(proof_output.join("candidate-journal.bin")).unwrap();
        let parsed = parse_ergo_statement_v1(&statement).unwrap();
        let opcode = opcode_subject(
            &seal,
            &statement[STATEMENT_PREFIX_BYTES..],
            &parsed.program_id(),
            &parsed.profile_id(),
        );
        let expected = B4StarkError::InnerControlRootMismatch {
            expected: [0; 32],
            actual: [1; 32],
        }
        .rejection_boundary();

        assert_eq!(
            reject_raw_seal_shape(&opcode, &[MANIFEST]),
            Ok(B4NegativeVerifierBoundary::Stark(expected))
        );
        assert_eq!(
            reject_terminal_policy(&seal, &[MANIFEST]),
            Err(B4NegativeVerifierAdapterError::UnexpectedAcceptance)
        );
        assert_eq!(
            reject_receipt_claim_policy(&seal, &[MANIFEST, &statement]),
            Err(B4NegativeVerifierAdapterError::UnexpectedStarkBoundary(
                expected
            ))
        );
    }
}
