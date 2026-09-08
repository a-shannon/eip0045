//! Typed negative adapters for catalog, registry, and corpus surfaces.
//!
//! Each adapter is selected by the external `(domain, surface)` pair before
//! entering this module.  Subject framing carries no dispatch authority, and
//! no adapter receives a case ID, variant ID, QA code, or expected rejection.
//! A returned rejection is therefore derived only by invoking the selected
//! production consumer on the authenticated subject.

use std::collections::BTreeMap;

#[cfg(all(test, feature = "materializer-replay", target_os = "linux", target_arch = "x86_64"))]
mod genuine_terminal_metadata_tests {
    use super::*;
    use anyhow::{Result, ensure};
    use std::{collections::BTreeSet, fs, io::{Read, Write}, os::unix::fs::MetadataExt, path::{Path, PathBuf}};
    use crate::{
        b4::{B4ByteTarget, B4NegativeMaterialization, B4NegativeMutation},
        b4_case8_terminal_join_root::{B4Case8TerminalJoinPacketSourcesV1, B4OwnedCase8TerminalJoinRootV1, B4VerifiedCase8TerminalJoinReplayV1},
        b4_c2_terminal_metadata::reconstruct_terminal_metadata_execution,
        b4_materialization_set::B4ClosedReconstructedExecutionV1,
        b4_mutation::{canonical_materialization_recipe_jcs, reconstruct_byte_edit, Eip0045B4MaterializationIdentityV1},
        b4_negative_io::{B4NegativeFileEncoding, B4NegativeNamedIdentityV1, B4NegativeObservationRejectionV1,
            B4NegativeObservationVerdict, Eip0045B4NegativeObservationV1, Eip0045B4NegativeVerifierInputV1},
        b4_plan::{B4MaterializationDomain as D, B4NegativeExecutionSurface as S},
        b4_subject_envelope::encode_subject_envelope,
    };
    const INPUTS: [(&str, usize, &str); 6] = [
        ("manifest.bin",458,"deffb2cb231f98a348cbd166d5f1c43315661ccd8bd212099f16f238d0fe8946"),
        ("algorithm.txt",29773,"90a884da420a09f2c1108d7388c2ac74db8dbdb195de704206e2bf8ec1ad0bee"),
        ("constants.bin",65119,"8c4a92b7d354890481eefdef233d4ca43f6bcd9f7cb00e4dd9e709da47789ef3"),
        ("guest.bin",129704,"88c72323c0831de4f7e4a234df65cf84e2723621fbed855c57f329a091f90542"),
        ("statement.bin",160,"da4f3d7483d082324d1d11a3df67fd0dbfb662e0091ad741400be32ac3c15ae1"),
        ("join-raw-seal.bin",222668,"41686d2c29149f311395f172472b5617022e359c36ef31ca1683544edc216ded"),
    ];
    const PRIVATE: &str = "selected negative adapter ArtifactTerminalMetadata failed privately; no observation was produced";
    const VARIANTS: [&str; 3] = ["kind", "parameter", "control-id"];
    fn sha(bytes: &[u8]) -> String { use sha2::{Digest, Sha256}; hex::encode(Sha256::digest(bytes)) }
    fn physical(path: &Path) -> Result<()> {
        ensure!(path.is_absolute(), "metadata path must be absolute");
        for parent in path.ancestors() {
            let meta = fs::symlink_metadata(parent)?;
            ensure!(meta.is_dir() && !meta.file_type().is_symlink(), "metadata redirected parent");
        }
        ensure!(fs::canonicalize(path)? == path, "metadata redirected parent"); Ok(())
    }
    fn read_pinned(path: &Path, size: usize, digest: &str) -> Result<Vec<u8>> {
        physical(path.parent().unwrap())?;
        let before = fs::symlink_metadata(path)?;
        ensure!(before.is_file() && !before.file_type().is_symlink() && before.nlink() == 1 && before.len() == size as u64,
            "metadata input physical identity");
        let file = fs::File::open(path)?;
        let opened = file.metadata()?;
        ensure!((before.dev(),before.ino()) == (opened.dev(),opened.ino()), "metadata input replaced");
        let mut bytes = Vec::with_capacity(size);
        file.take(size as u64 + 1).read_to_end(&mut bytes)?;
        let after = fs::symlink_metadata(path)?;
        ensure!(bytes.len() == size && sha(&bytes) == digest, "metadata input pin mismatch");
        ensure!((before.dev(),before.ino(),before.len(),before.nlink(),before.mtime(),before.mtime_nsec(),before.ctime(),before.ctime_nsec())
            == (after.dev(),after.ino(),after.len(),after.nlink(),after.mtime(),after.mtime_nsec(),after.ctime(),after.ctime_nsec()), "metadata input changed");
        Ok(bytes)
    }
    fn load() -> Result<B4VerifiedCase8TerminalJoinReplayV1> {
        let root = PathBuf::from(std::env::var_os("EIP0045_B4_TERMINAL_METADATA_INPUT_ROOT").ok_or_else(|| anyhow::anyhow!("explicit metadata input root required"))?);
        physical(&root)?;
        let names = fs::read_dir(&root)?.map(|entry| entry.map(|e| e.file_name())).collect::<std::io::Result<BTreeSet<_>>>()?;
        ensure!(names == INPUTS.iter().map(|(name,_,_)| std::ffi::OsString::from(*name)).collect(), "metadata six-file inventory");
        let bytes = INPUTS.iter().map(|(name,size,digest)| read_pinned(&root.join(name),*size,digest)).collect::<Result<Vec<_>>>()?;
        let replay = B4OwnedCase8TerminalJoinRootV1::from_packet_sources(B4Case8TerminalJoinPacketSourcesV1 {
            profile_manifest: &bytes[0], profile_algorithm: &bytes[1], profile_constants: &bytes[2],
            guest_elf: &bytes[3], statement: &bytes[4], raw_seal: &bytes[5],
        })?.replay()?; // the sole positive owner is produced by the actual verifier
        for ((name,size,digest), original) in INPUTS.iter().zip(&bytes) {
            ensure!(read_pinned(&root.join(name),*size,digest)? == *original, "metadata replay input drift");
        }
        Ok(replay)
    }
    fn frame(manifest: &[u8], record: &[u8]) -> Vec<u8> {
        encode_subject_envelope(&[manifest,record], terminal_metadata_subject_envelope_contract()).unwrap()
    }
    fn identity(role: String, path: String, bytes: &[u8]) -> B4NegativeNamedIdentityV1 {
        B4NegativeNamedIdentityV1 { role,path,byte_length:bytes.len() as u64,sha256:sha(bytes),encoding:B4NegativeFileEncoding::RawBytes }
    }
    fn neutral(subject: &[u8], contexts: &[Vec<u8>]) -> Result<Vec<u8>> {
        Eip0045B4NegativeVerifierInputV1 { format:"Eip0045B4NegativeVerifierInputV1".into(),format_version:1,
            materialization_domain:D::ArtifactValidator,validation_surface:S::TerminalMetadata,
            subject:identity("subject".into(),"subject.bin".into(),subject),
            context:contexts.iter().enumerate().map(|(i,b)| identity(format!("context-{i:02}"),format!("context/{i:02}.bin"),b)).collect(),
        }.to_canonical_jcs()
    }
    fn expected(input: &[u8], subject: &[u8]) -> Eip0045B4NegativeObservationV1 {
        Eip0045B4NegativeObservationV1 { format:"Eip0045B4NegativeObservationV1".into(),format_version:1,
            materialization_domain:D::ArtifactValidator,validation_surface:S::TerminalMetadata,
            negative_input_sha256:sha(input),subject_byte_length:subject.len() as u64,subject_sha256:sha(subject),
            verdict:B4NegativeObservationVerdict::Reject,rejection:B4NegativeObservationRejectionV1 {
                class:"terminal-metadata-mismatch".into(),stage:"terminal-metadata-binding".into() }, }
    }
    fn observation(actual: &Eip0045B4NegativeObservationV1, input: &[u8], subject: &[u8]) -> Result<()> {
        ensure!(*actual == expected(input,subject), "metadata observation mismatch");
        let literal = format!(concat!("{{\"format\":\"Eip0045B4NegativeObservationV1\",\"formatVersion\":1,",
            "\"materializationDomain\":\"artifact-validator\",\"negativeInputSha256\":\"{}\",",
            "\"rejection\":{{\"class\":\"terminal-metadata-mismatch\",\"stage\":\"terminal-metadata-binding\"}},",
            "\"subjectByteLength\":{},\"subjectSha256\":\"{}\",\"validationSurface\":\"terminal-metadata\",\"verdict\":\"reject\"}}"),sha(input),subject.len(),sha(subject));
        ensure!(actual.to_canonical_jcs()? == literal.as_bytes(), "metadata observation JCS mismatch"); Ok(())
    }
    fn validate_rows(replay: &B4VerifiedCase8TerminalJoinReplayV1, rows: &[B4ClosedReconstructedExecutionV1]) -> Result<()> {
        ensure!(rows.len() == 3, "ordered metadata coverage");
        let contexts = replay.contexts().map(<[u8]>::to_vec);
        let plan = Eip0045B4NegativePlanV1::canonical()?; let plan_jcs = plan.to_canonical_jcs()?;
        for (slot,row) in rows.iter().enumerate() {
            let id = format!("terminal-metadata-field-sweep--{}",VARIANTS[slot]);
            let planned = plan.groups.iter().flat_map(|g| &g.executions).nth(110+slot).unwrap();
            ensure!(row.derived_registry_row.execution_id == id && planned.execution_id == id
                && planned.execution_surface == S::TerminalMetadata && planned.materialization_domain == D::ArtifactValidator
                && row.derived_registry_row.base_selector_id == "terminal-join"
                && row.derived_registry_row.materialization_domain == D::ArtifactValidator, "metadata canonical row mismatch");
            ensure!(row.base.as_slice() == replay.terminal_metadata_record().as_slice() && row.contexts.as_slice() == contexts.as_slice(), "metadata source/context mismatch");
            ensure!(row.negative_input_jcs == neutral(&row.subject,&row.contexts)?, "metadata neutral input mismatch");
            let (manifest,record) = decode_terminal_metadata_subject(&row.subject).map_err(|e|anyhow::anyhow!("metadata subject: {e:?}"))?;
            ensure!(manifest == contexts[1], "metadata subject manifest mismatch");
            let mut projected = *replay.terminal_metadata_record();
            match slot { 0 => projected[0]=3, 1 => projected[1]=1, _ => projected[2]^=1 }
            ensure!(record == projected, "metadata single-field projection mismatch");
            let B4NegativeMaterialization::Mutation { mutation:B4NegativeMutation::ByteEdit { target:B4ByteTarget::TerminalMetadataRecord,edit } }
                = &row.derived_registry_row.materialization else { anyhow::bail!("metadata recipe target mismatch") };
            ensure!(reconstruct_byte_edit(&row.base,edit)? == record, "metadata recipe replay mismatch");
            let recipe = canonical_materialization_recipe_jcs(&row.derived_registry_row.materialization)?;
            let identity = Eip0045B4MaterializationIdentityV1::from_canonical_jcs(&row.materialization_identity_jcs)?;
            ensure!(identity.execution_id == id && identity.base_selector_id == "terminal-join"
                && identity.materialization_domain == D::ArtifactValidator
                && identity.base_byte_length == row.base.len() as u64 && identity.base_sha256 == sha(&row.base)
                && identity.output_byte_length == row.subject.len() as u64 && identity.output_sha256 == sha(&row.subject)
                && identity.materialization_recipe_byte_length == recipe.len() as u64 && identity.materialization_recipe_sha256 == sha(&recipe)
                && identity.negative_plan_byte_length == plan_jcs.len() as u64 && identity.negative_plan_sha256 == sha(&plan_jcs), "metadata materialization identity mismatch");
        } Ok(())
    }
    fn rows(replay: &B4VerifiedCase8TerminalJoinReplayV1) -> Vec<B4ClosedReconstructedExecutionV1> {
        let plan = Eip0045B4NegativePlanV1::canonical().unwrap(); let jcs=plan.to_canonical_jcs().unwrap();
        let rows=(110..113).map(|index| reconstruct_terminal_metadata_execution(index,
            plan.groups.iter().flat_map(|g| &g.executions).nth(index).unwrap(),&jcs,replay).unwrap().unwrap()).collect::<Vec<_>>();
        validate_rows(replay,&rows).unwrap(); rows
    }
    fn fresh(path: &Path) -> Result<()> {
        physical(path.parent().ok_or_else(||anyhow::anyhow!("metadata output parent"))?)?;
        match fs::symlink_metadata(path) { Err(e) if e.kind()==std::io::ErrorKind::NotFound => Ok(()), _ => anyhow::bail!("metadata output exists") }
    }
    fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
        physical(path.parent().unwrap())?;
        let mut f=fs::OpenOptions::new().write(true).create_new(true).open(path)?; f.write_all(bytes)?; f.sync_all()?;
        ensure!(fs::read(path)? == bytes,"metadata writeback mismatch"); Ok(())
    }
    fn package(path: &Path, subject: &[u8], contexts: &[Vec<u8>]) -> Result<()> {
        fresh(path)?;fs::create_dir(path)?;fs::create_dir(path.join("context"))?;
        write_new(&path.join("subject.bin"),subject)?;write_new(&path.join("negative-input.json"),&neutral(subject,contexts)?)?;
        for (i,b) in contexts.iter().enumerate(){write_new(&path.join(format!("context/{i:02}.bin")),b)?;}
        Ok(())
    }
    fn dispatch(path: &Path,row: &B4ClosedReconstructedExecutionV1) -> Result<()> {
        ensure!(fs::read(path.join("subject.bin"))? == row.subject && fs::read(path.join("negative-input.json"))? == row.negative_input_jcs,"metadata physical row mismatch");
        for (i,b) in row.contexts.iter().enumerate(){ensure!(fs::read(path.join(format!("context/{i:02}.bin")))? == *b,"metadata physical context mismatch");}
        observation(&crate::b4_validator::verify_negative_root(path)?,&row.negative_input_jcs,&row.subject)
    }
    fn inventory(root: &Path) -> Result<()> {
        let expected=BTreeSet::from_iter(std::iter::once("base-record.bin".to_owned()).chain((110..113).flat_map(|i|
            ["materialization-identity.json","materialization-recipe.json","input/negative-input.json","input/subject.bin"].into_iter().map(move |p|format!("{i}/{p}"))
            .chain((0..7).map(move |c|format!("{i}/input/context/{c:02}.bin"))))));
        let dirs=BTreeSet::from_iter((110..113).flat_map(|i|[i.to_string(),format!("{i}/input"),format!("{i}/input/context")]));
        let mut files=BTreeSet::new();let mut found_dirs=BTreeSet::new();let mut pending=vec![root.to_path_buf()];
        while let Some(dir)=pending.pop(){physical(&dir)?;for entry in fs::read_dir(dir)?{let p=entry?.path();let meta=fs::symlink_metadata(&p)?;
            let name=p.strip_prefix(root)?.to_str().unwrap().to_owned();ensure!(!meta.file_type().is_symlink(),"metadata output redirect");
            if meta.is_dir(){found_dirs.insert(name);pending.push(p);}else{ensure!(meta.is_file()&&meta.nlink()==1,"metadata output non-private file");files.insert(name);}}}
        ensure!(files==expected && found_dirs==dirs,"metadata output inventory mismatch");Ok(())
    }
    fn private(subject: &[u8],contexts: &[Vec<u8>],kind:B4TerminalMetadataProducerErrorKind) {
        let refs=contexts.iter().map(Vec::as_slice).collect::<Vec<_>>();
        assert_eq!(reject_terminal_metadata(subject,&refs),Err(B4ArtifactCatalogAdapterError::TerminalMetadataProducer(kind)));
    }
    fn deny(path:&Path,message:&str){assert_eq!(crate::b4_validator::verify_negative_root(path).expect_err("private fault yielded observation").to_string(),message);}
    #[test]
    fn terminal_metadata_observation_and_reader_are_closed() {
        let subject=[0u8;512]; // synthetic observation fixture, not a cryptographic subject
        let original=expected(b"input",&subject);
        observation(&original,b"input",&subject).unwrap();
        let mut malformed_size=original.clone();malformed_size.subject_byte_length=7;
        assert_eq!(malformed_size.to_canonical_jcs().unwrap_err().to_string(),"negative subject byte length is outside the selected handler bound");
        for field in 0..7 {observation(&original,b"input",&subject).unwrap();let mut fault=original.clone();match field {
            0=>fault.subject_sha256="00".repeat(32),1=>fault.negative_input_sha256="00".repeat(32),2=>fault.subject_byte_length+=1,
            3=>fault.rejection.class="wrong".into(),4=>fault.rejection.stage="wrong".into(),5=>fault.validation_surface=S::RawSealShape,_=>fault.materialization_domain=D::VerifierInput}
            assert_eq!(observation(&fault,b"input",&subject).unwrap_err().to_string(),"metadata observation mismatch");}
        let temp=tempfile::tempdir().unwrap();let p=temp.path().join("input");write_new(&p,b"valid").unwrap();
        assert_eq!(read_pinned(&p,5,&sha(b"valid")).unwrap(),b"valid");
        assert_eq!(read_pinned(&p,4,&sha(b"valid")).unwrap_err().to_string(),"metadata input physical identity");
        assert_eq!(read_pinned(&p,5,&sha(b"other")).unwrap_err().to_string(),"metadata input pin mismatch");
        assert!(write_new(&p,b"replace").is_err());assert_eq!(fs::read(&p).unwrap(),b"valid");
        for hard in [false,true] {
            assert_eq!(read_pinned(&p,5,&sha(b"valid")).unwrap(),b"valid");
            let alias=temp.path().join(if hard {"hard"} else {"symbolic"});
            if hard {fs::hard_link(&p,&alias).unwrap();}else{std::os::unix::fs::symlink(&p,&alias).unwrap();}
            assert_eq!(read_pinned(&alias,5,&sha(b"valid")).unwrap_err().to_string(),"metadata input physical identity");
            fs::remove_file(alias).unwrap();
        }
    }
    #[test]
    #[ignore="requires six pinned metadata inputs and fresh explicit metadata output root"]
    fn genuine_terminal_metadata_public_matrix() {
        let output=PathBuf::from(std::env::var_os("EIP0045_B4_TERMINAL_METADATA_OUTPUT_ROOT").unwrap());fresh(&output).unwrap();
        let replay=load().unwrap();let contexts=replay.contexts().map(<[u8]>::to_vec);
        let honest=frame(&contexts[1],replay.terminal_metadata_record());
        private(&honest,&contexts,B4TerminalMetadataProducerErrorKind::UnexpectedAcceptance);
        let rows=rows(&replay);fs::create_dir(&output).unwrap();write_new(&output.join("base-record.bin"),replay.terminal_metadata_record()).unwrap();
        for (slot,row) in rows.iter().enumerate(){let dir=output.join((110+slot).to_string());fs::create_dir(&dir).unwrap();
            write_new(&dir.join("materialization-identity.json"),&row.materialization_identity_jcs).unwrap();
            write_new(&dir.join("materialization-recipe.json"),&canonical_materialization_recipe_jcs(&row.derived_registry_row.materialization).unwrap()).unwrap();
            package(&dir.join("input"),&row.subject,&row.contexts).unwrap();dispatch(&dir.join("input"),row).unwrap();}
        inventory(&output).unwrap();fs::File::open(&output).unwrap().sync_all().unwrap();
        assert_eq!(validate_rows(&replay,&rows[..2]).unwrap_err().to_string(),"ordered metadata coverage");
        let mut changed=rows.clone();changed.swap(0,1);assert_eq!(validate_rows(&replay,&changed).unwrap_err().to_string(),"metadata canonical row mismatch");
        changed=rows.clone();changed[2]=changed[1].clone();assert_eq!(validate_rows(&replay,&changed).unwrap_err().to_string(),"metadata canonical row mismatch");
        for fault in 0..3 {
            validate_rows(&replay,&rows).unwrap();
            let mut changed=rows.clone();
            let message=match fault {
                0=>{changed[0].negative_input_jcs.push(b'\n');"metadata neutral input mismatch"},
                1=>{changed[0].contexts[0][0]^=1;"metadata source/context mismatch"},
                _=>{changed[0].materialization_identity_jcs=rows[1].materialization_identity_jcs.clone();"metadata materialization identity mismatch"},
            };
            assert_eq!(validate_rows(&replay,&changed).unwrap_err().to_string(),message);
        }
    }
    #[test]
    #[ignore="requires six pinned metadata inputs; private and custody faults never become observations"]
    fn genuine_terminal_metadata_private_and_custody_failures() {
        let replay=load().unwrap();let contexts=replay.contexts().map(<[u8]>::to_vec);let honest=frame(&contexts[1],replay.terminal_metadata_record());
        private(&honest,&contexts,B4TerminalMetadataProducerErrorKind::UnexpectedAcceptance);
        let rows=rows(&replay);let row=&rows[0];
        for fault in 0..3 {
            private(&honest,&contexts,B4TerminalMetadataProducerErrorKind::UnexpectedAcceptance);
            let mut candidate=honest.clone();let mut changed=contexts.to_vec();
            let kind=match fault {
                0=>B4TerminalMetadataProducerErrorKind::UnexpectedAcceptance,
                1=>{let mut record=*replay.terminal_metadata_record();record[0]=3;record[1]=1;candidate=frame(&contexts[1],&record);B4TerminalMetadataProducerErrorKind::CandidateRecordMutationShape},
                _=>{changed[6][0]^=1;changed[0]=crate::b4_validator::synthesize_positive_verifier_input_v1(&changed[1],&changed[2],&changed[3],&changed[4],&changed[5],&changed[6]).unwrap();B4TerminalMetadataProducerErrorKind::PositiveRoot},
            };
            private(&candidate,&changed,kind);
            let temp=tempfile::tempdir().unwrap();let path=temp.path().join("input");package(&path,&candidate,&changed).unwrap();deny(&path,PRIVATE);
        }
        for fault in 0..9 {
            let temp=tempfile::tempdir().unwrap();let path=temp.path().join("input");package(&path,&row.subject,&row.contexts).unwrap();dispatch(&path,row).unwrap();
            let message=match fault {
                0=>{let mut input=row.negative_input_jcs.clone();input.push(b'\n');fs::write(path.join("negative-input.json"),input).unwrap();"B4 negative verifier input is not exact RFC 8785 JCS"},
                1=>{let mut subject=row.subject.clone();subject[0]^=1;fs::write(path.join("subject.bin"),subject).unwrap();"negative verifier file subject.bin SHA-256 differs from its descriptor"},
                2=>{let mut subject=row.subject.clone();subject.pop();fs::write(path.join("subject.bin"),subject).unwrap();"negative verifier file subject.bin length is outside its bound"},
                3=>{fs::remove_file(path.join("context/06.bin")).unwrap();"negative context directory is not the exact NN.bin positional prefix"},
                4=>{fs::write(path.join("extra"),b"x").unwrap();"negative verifier root contains an unexpected or duplicate entry"},
                5|6=>{let backing=temp.path().join("backing");fs::rename(path.join("subject.bin"),&backing).unwrap();if fault==5{std::os::unix::fs::symlink(&backing,path.join("subject.bin")).unwrap();"negative verifier path is not a regular file: subject.bin"}else{fs::hard_link(&backing,path.join("subject.bin")).unwrap();"hard-linked negative verifier file is forbidden: subject.bin"}},
                7=>{let mut input=Eip0045B4NegativeVerifierInputV1::from_canonical_jcs(&row.negative_input_jcs).unwrap();input.context.pop();fs::remove_file(path.join("context/06.bin")).unwrap();fs::write(path.join("negative-input.json"),input.to_canonical_jcs().unwrap()).unwrap();"negative input context cardinality differs from the frozen handler contract"},
                _=>{let mut b=row.contexts[5].clone();b[0]^=1;fs::write(path.join("context/05.bin"),b).unwrap();"negative verifier file context/05.bin SHA-256 differs from its descriptor"},
            };deny(&path,message);
        }
        for index in 0..7 {
            let temp=tempfile::tempdir().unwrap();let path=temp.path().join("input");
            package(&path,&row.subject,&row.contexts).unwrap();dispatch(&path,row).unwrap();
            let mut changed=row.contexts[index].clone();changed[0]^=1;
            fs::write(path.join(format!("context/{index:02}.bin")),changed).unwrap();
            deny(&path,&format!("negative verifier file context/{index:02}.bin SHA-256 differs from its descriptor"));
        }
    }
}

#[cfg(all(test, feature = "materializer-replay"))]
mod genuine_catalog_join_tests {
    use super::*;
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    mod production_dispatch {
        use super::*;
        use anyhow::{Result, ensure};
        use std::{fs, io::Write, path::{Path, PathBuf}};
        use crate::{
            b4::{B4NegativeMaterialization, B4NegativeMutation, B4ByteTarget},
            b4_materialization_set::B4ClosedReconstructedExecutionV1,
            b4_mutation::{canonical_materialization_recipe_jcs, reconstruct_byte_edit,
                Eip0045B4MaterializationIdentityV1},
            b4_negative_io::{B4NegativeFileEncoding, B4NegativeNamedIdentityV1,
                B4NegativeObservationRejectionV1, B4NegativeObservationVerdict,
                Eip0045B4NegativeObservationV1, Eip0045B4NegativeVerifierInputV1},
            b4_plan::{B4MaterializationDomain as D, B4NegativeExecutionSurface as S},
        };

        const PRIVATE: &str = "selected negative adapter ArtifactTerminalFixtureCatalog failed privately; no observation was produced";
        const VARIANTS: [&str; 3] = ["program-id", "claim-digest", "control-id"];
        fn sha(bytes: &[u8]) -> String { use sha2::{Digest, Sha256}; hex::encode(Sha256::digest(bytes)) }
        fn neutral(subject: &[u8]) -> Result<Vec<u8>> {
            Eip0045B4NegativeVerifierInputV1 {
                format: "Eip0045B4NegativeVerifierInputV1".into(), format_version: 1,
                materialization_domain: D::ArtifactValidator, validation_surface: S::TerminalFixtureCatalog,
                subject: B4NegativeNamedIdentityV1 { role: "subject".into(), path: "subject.bin".into(),
                    byte_length: subject.len() as u64, sha256: sha(subject), encoding: B4NegativeFileEncoding::RawBytes },
                context: vec![],
            }.to_canonical_jcs()
        }
        fn expected(input: &[u8], subject: &[u8]) -> Eip0045B4NegativeObservationV1 {
            Eip0045B4NegativeObservationV1 {
                format: "Eip0045B4NegativeObservationV1".into(), format_version: 1,
                materialization_domain: D::ArtifactValidator, validation_surface: S::TerminalFixtureCatalog,
                negative_input_sha256: sha(input), subject_byte_length: subject.len() as u64,
                subject_sha256: sha(subject), verdict: B4NegativeObservationVerdict::Reject,
                rejection: B4NegativeObservationRejectionV1 { class: "terminal-fixture-catalog-mismatch".into(),
                    stage: "terminal-fixture-catalog-binding".into() },
            }
        }
        fn observation(actual: &Eip0045B4NegativeObservationV1, input: &[u8], subject: &[u8]) -> Result<()> {
            ensure!(*actual == expected(input, subject), "catalog observation identity/boundary mismatch");
            let literal = format!(concat!("{{\"format\":\"Eip0045B4NegativeObservationV1\",\"formatVersion\":1,",
                "\"materializationDomain\":\"artifact-validator\",\"negativeInputSha256\":\"{}\",",
                "\"rejection\":{{\"class\":\"terminal-fixture-catalog-mismatch\",\"stage\":\"terminal-fixture-catalog-binding\"}},",
                "\"subjectByteLength\":{},\"subjectSha256\":\"{}\",",
                "\"validationSurface\":\"terminal-fixture-catalog\",\"verdict\":\"reject\"}}"), sha(input), subject.len(), sha(subject));
            ensure!(actual.to_canonical_jcs()? == literal.as_bytes(), "catalog observation exact JCS mismatch");
            Ok(())
        }
        fn validate_rows(positive: &[u8], rows: &[B4ClosedReconstructedExecutionV1]) -> Result<()> {
            ensure!(rows.len() == 3, "ordered three-row catalog coverage");
            let honest = decode_subject_envelope(positive, terminal_catalog_subject_envelope_contract())?;
            let plan = Eip0045B4NegativePlanV1::canonical()?;
            let plan_jcs = plan.to_canonical_jcs()?;
            for (slot, row) in rows.iter().enumerate() {
                let id = format!("terminal-fixture-catalog-binding-sweep--{}", VARIANTS[slot]);
                ensure!(row.derived_registry_row.execution_id == id, "ordered three-row catalog coverage");
                let planned = plan.groups.iter().flat_map(|group| &group.executions).nth(11 + slot).unwrap();
                ensure!(planned.execution_id == id && planned.execution_surface == S::TerminalFixtureCatalog
                    && planned.materialization_domain == D::ArtifactValidator
                    && row.derived_registry_row.materialization_domain == D::ArtifactValidator
                    && row.derived_registry_row.base_selector_id == "terminal-fixture-catalog-v1", "catalog plan/row mismatch");
                ensure!(row.base == honest.parts()[0] && row.contexts.is_empty(), "catalog base/context mismatch");
                ensure!(row.negative_input_jcs == neutral(&row.subject)?, "catalog neutral input mismatch");
                let subject = decode_subject_envelope(&row.subject, terminal_catalog_subject_envelope_contract())?;
                ensure!(subject.parts()[1..] == honest.parts()[1..], "catalog proof maps changed");
                let B4NegativeMaterialization::Mutation { mutation: B4NegativeMutation::ByteEdit {
                    target: B4ByteTarget::TerminalFixtureCatalogEntry, edit,
                }} = &row.derived_registry_row.materialization else { anyhow::bail!("catalog recipe target mismatch") };
                ensure!(reconstruct_byte_edit(&row.base, edit)? == subject.parts()[0], "catalog recipe output mismatch");
                let recipe = canonical_materialization_recipe_jcs(&row.derived_registry_row.materialization)?;
                let identity = Eip0045B4MaterializationIdentityV1::from_canonical_jcs(&row.materialization_identity_jcs)?;
                // The final identity binds the framed consumer subject; the recipe edits only its catalogue part.
                ensure!(identity.execution_id == id && identity.base_selector_id == "terminal-fixture-catalog-v1"
                    && identity.materialization_domain == D::ArtifactValidator
                    && identity.base_byte_length == row.base.len() as u64 && identity.base_sha256 == sha(&row.base)
                    && identity.output_byte_length == row.subject.len() as u64
                    && identity.output_sha256 == sha(&row.subject)
                    && identity.materialization_recipe_byte_length == recipe.len() as u64
                    && identity.materialization_recipe_sha256 == sha(&recipe)
                    && identity.negative_plan_byte_length == plan_jcs.len() as u64
                    && identity.negative_plan_sha256 == sha(&plan_jcs), "catalog materialization identity mismatch");
            }
            Ok(())
        }
        fn physical(path: &Path) -> Result<()> {
            ensure!(path.is_absolute(), "catalog output must be absolute");
            for parent in path.ancestors() {
                let meta = fs::symlink_metadata(parent)?;
                ensure!(meta.is_dir() && !meta.file_type().is_symlink(), "catalog redirected parent");
            }
            ensure!(fs::canonicalize(path)? == path, "catalog redirected parent"); Ok(())
        }
        fn fresh(path: &Path) -> Result<()> {
            physical(path.parent().ok_or_else(|| anyhow::anyhow!("catalog output parent"))?)?;
            match fs::symlink_metadata(path) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                _ => anyhow::bail!("catalog output already exists"),
            }
        }
        fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
            physical(path.parent().unwrap())?;
            let mut file = fs::OpenOptions::new().write(true).create_new(true).open(path)?;
            file.write_all(bytes)?; file.sync_all()?;
            ensure!(fs::read(path)? == bytes, "catalog output readback mismatch"); Ok(())
        }
        fn package(path: &Path, subject: &[u8], input: &[u8]) -> Result<()> {
            fresh(path)?; fs::create_dir(path)?;
            write_new(&path.join("subject.bin"), subject)?;
            write_new(&path.join("negative-input.json"), input)?;
            fs::File::open(path)?.sync_all()?; Ok(())
        }
        fn dispatch(path: &Path, row: &B4ClosedReconstructedExecutionV1) -> Result<()> {
            ensure!(fs::read(path.join("subject.bin"))? == row.subject
                && fs::read(path.join("negative-input.json"))? == row.negative_input_jcs, "catalog physical bytes mismatch");
            observation(&crate::b4_validator::verify_negative_root(path)?, &row.negative_input_jcs, &row.subject)
        }
        fn export_inventory(root: &Path) -> Result<()> {
            use std::{collections::BTreeSet, os::unix::fs::MetadataExt};
            let mut expected = BTreeSet::from(["base.bin".to_owned()]);
            let mut directories = BTreeSet::new();
            for index in 11..14 {
                directories.extend([index.to_string(), format!("{index}/input")]);
                for leaf in ["materialization-identity.json", "materialization-recipe.json",
                    "input/negative-input.json", "input/subject.bin"] {
                    expected.insert(format!("{index}/{leaf}"));
                }
            }
            let mut files = BTreeSet::new(); let mut found_dirs = BTreeSet::new();
            let mut pending = vec![root.to_path_buf()];
            while let Some(directory) = pending.pop() {
                physical(&directory)?;
                for entry in fs::read_dir(directory)? {
                    let path = entry?.path(); let meta = fs::symlink_metadata(&path)?;
                    let name = path.strip_prefix(root)?.to_str().unwrap().to_owned();
                    ensure!(!meta.file_type().is_symlink(), "catalog export redirected entry");
                    if meta.is_dir() { found_dirs.insert(name); pending.push(path); }
                    else { ensure!(meta.is_file() && meta.nlink() == 1, "catalog export non-private file"); files.insert(name); }
                }
            }
            ensure!(files == expected && found_dirs == directories, "catalog export inventory mismatch"); Ok(())
        }
        fn deny(path: &Path, expected: &str) {
            assert_eq!(crate::b4_validator::verify_negative_root(path)
                .expect_err("private/custody failure produced an observation").to_string(), expected);
        }
        fn load() -> crate::b4_c2_terminal_catalog::genuine_catalog_join::Joined {
            let root = PathBuf::from(std::env::var_os("EIP0045_B4_TERMINAL_FIXTURE_REPOSITORY_ROOT").unwrap());
            join(read_export(&root).unwrap()).unwrap()
        }
        #[test]
        fn production_terminal_catalog_observation_is_exact() {
            // Schema oracle only, not synthetic fixture authority.
            let value = expected(b"input", b"subject");
            for fault in 0..7 {
                observation(&value, b"input", b"subject").unwrap();
                let mut changed = value.clone();
                match fault {
                    0 => changed.negative_input_sha256 = "00".repeat(32),
                    1 => changed.subject_sha256 = "00".repeat(32),
                    2 => changed.subject_byte_length += 1,
                    3 => changed.rejection.class = "wrong".into(),
                    4 => changed.rejection.stage = "wrong".into(),
                    5 => changed.materialization_domain = D::VerifierInput,
                    _ => changed.validation_surface = S::RawSealShape,
                }
                assert_eq!(observation(&changed, b"input", b"subject").unwrap_err().to_string(),
                    "catalog observation identity/boundary mismatch");
            }
        }
        #[test]
        #[ignore = "requires authenticated nineteen-file export and a fresh explicit dispatch output root"]
        fn genuine_terminal_catalog_public_matrix() {
            let output = PathBuf::from(std::env::var_os("EIP0045_B4_TERMINAL_DISPATCH_OUTPUT_ROOT").unwrap());
            fresh(&output).unwrap(); // fail before expensive authenticated replay
            let joined = load();
            validate_rows(&joined.positive, &joined.rows).unwrap();
            assert_eq!(reject_terminal_fixture_catalog(&joined.positive), Err(B4ArtifactCatalogAdapterError::UnexpectedAcceptance));
            fs::create_dir(&output).unwrap();
            write_new(&output.join("base.bin"), &joined.rows[0].base).unwrap();
            for (slot, row) in joined.rows.iter().enumerate() {
                let directory = output.join((11 + slot).to_string()); fs::create_dir(&directory).unwrap();
                write_new(&directory.join("materialization-identity.json"), &row.materialization_identity_jcs).unwrap();
                write_new(&directory.join("materialization-recipe.json"),
                    &canonical_materialization_recipe_jcs(&row.derived_registry_row.materialization).unwrap()).unwrap();
                package(&directory.join("input"), &row.subject, &row.negative_input_jcs).unwrap();
                dispatch(&directory.join("input"), row).unwrap();
            }
            export_inventory(&output).unwrap();
            fs::File::open(&output).unwrap().sync_all().unwrap();
            assert_eq!(validate_rows(&joined.positive, &joined.rows[..2]).unwrap_err().to_string(), "ordered three-row catalog coverage");
            let mut changed = joined.rows.clone(); changed.swap(0, 1);
            assert_eq!(validate_rows(&joined.positive, &changed).unwrap_err().to_string(), "ordered three-row catalog coverage");
            changed = joined.rows.clone(); changed[2] = changed[1].clone();
            assert_eq!(validate_rows(&joined.positive, &changed).unwrap_err().to_string(), "ordered three-row catalog coverage");
            for fault in 0..3 {
                validate_rows(&joined.positive, &joined.rows).unwrap();
                let mut changed = joined.rows.clone();
                let message = match fault {
                    0 => { changed[0].negative_input_jcs.push(b'\n'); "catalog neutral input mismatch" },
                    1 => { changed[0].materialization_identity_jcs = joined.rows[1].materialization_identity_jcs.clone(); "catalog materialization identity mismatch" },
                    _ => { changed[0].base[0] ^= 1; "catalog base/context mismatch" },
                };
                assert_eq!(validate_rows(&joined.positive, &changed).unwrap_err().to_string(), message);
            }
        }
        #[test]
        #[ignore = "requires authenticated nineteen-file export; physical private and custody single faults"]
        fn genuine_terminal_catalog_public_private_and_custody_failures() {
            let joined = load(); validate_rows(&joined.positive, &joined.rows).unwrap();
            let row = &joined.rows[0];
            // Private faults start at the honest accepted bundle, not at an
            // already-mutated catalogue row. The row is only the public control.
            let decoded = decode_subject_envelope(&joined.positive, terminal_catalog_subject_envelope_contract()).unwrap();
            let parts = decoded.parts();
            let frame = |a: &[u8], b: &[u8], c: &[u8]| encode_subject_envelope(&[a,b,c], terminal_catalog_subject_envelope_contract()).unwrap();
            let mut invalid: serde_json::Value = serde_json::from_slice(parts[0]).unwrap();
            invalid["fixtures"][0]["claimDigest"] = "invalid-digest".into();
            let raw = decode_terminal_byte_map(B4TerminalByteMapKind::RawSeal, parts[1]).unwrap();
            let mut damaged = raw.entries()[0].payload().to_vec(); damaged[0] ^= 1;
            let entries = raw.entries().iter().enumerate().map(|(i,e)|
                B4TerminalByteMapEntry::new(e.path(), if i == 0 { &damaged } else { e.payload() })).collect::<Vec<_>>();
            let bad_raw = encode_terminal_byte_map(B4TerminalByteMapKind::RawSeal, &entries).unwrap();
            // Encode the swapped bytes with explicit test-only lengths, then let the
            // real closed consumer enforce its original positional bounds.
            let swapped_bounds = [B4SubjectPartBounds::new(parts[0].len(), parts[0].len()),
                B4SubjectPartBounds::new(parts[2].len(), parts[2].len()),
                B4SubjectPartBounds::new(parts[1].len(), parts[1].len())];
            let swapped = encode_subject_envelope(&[parts[0], parts[2], parts[1]],
                B4SubjectEnvelopeContract::new(B4SubjectEnvelopeKind::TerminalCatalogBundle, &swapped_bounds)).unwrap();
            let subjects = [joined.positive.clone(), frame(&canonical_json_bytes(&invalid).unwrap(), parts[1], parts[2]),
                frame(&serde_json::to_vec_pretty(&serde_json::from_slice::<serde_json::Value>(parts[0]).unwrap()).unwrap(), parts[1], parts[2]),
                frame(parts[0], &bad_raw, parts[2]), swapped];
            for (index, subject) in subjects.into_iter().enumerate() {
                assert_eq!(reject_terminal_fixture_catalog(&joined.positive), Err(B4ArtifactCatalogAdapterError::UnexpectedAcceptance));
                let private = reject_terminal_fixture_catalog(&subject);
                match index {
                    0 => assert_eq!(private, Err(B4ArtifactCatalogAdapterError::UnexpectedAcceptance)),
                    1 | 2 => assert!(exact_private_failure(private, B4ArtifactCatalogAdapterError::TerminalOracleReplay(B4TerminalOracleReplayErrorKind::CandidateCatalogueInvalid))),
                    3 => assert!(exact_private_failure(private, B4ArtifactCatalogAdapterError::TerminalOracleReplay(B4TerminalOracleReplayErrorKind::ReceiptProfileShape))),
                    _ => {
                        // A swapped oversized map is rejected by the closed envelope
                        // before replay; otherwise its first named path is wrong.
                        let maximum = terminal_byte_map_maximum_encoded_bytes(B4TerminalByteMapKind::RawSeal);
                        if parts[2].len() > maximum {
                            assert_eq!(private, Err(B4ArtifactCatalogAdapterError::SubjectEnvelope(
                                B4SubjectEnvelopeError::PartLengthOutOfBounds { index: 1, actual: parts[2].len(), minimum: 1, maximum })));
                        } else { assert_eq!(private, Err(B4ArtifactCatalogAdapterError::ByteMap(B4ByteMapError::ExpectedPathMismatch { index: 0 }))); }
                    },
                }
                let temp = tempfile::tempdir().unwrap(); let path = temp.path().join("input");
                package(&path, &row.subject, &row.negative_input_jcs).unwrap(); dispatch(&path, row).unwrap();
                fs::write(path.join("subject.bin"), &subject).unwrap();
                fs::write(path.join("negative-input.json"), neutral(&subject).unwrap()).unwrap();
                deny(&path, PRIVATE); // recalculated custody cannot mask a private adapter error
            }
            for fault in 0..10 {
                let temp = tempfile::tempdir().unwrap(); let path = temp.path().join("input");
                package(&path, &row.subject, &row.negative_input_jcs).unwrap(); dispatch(&path, row).unwrap();
                let message = match fault {
                    0 => { let mut input = row.negative_input_jcs.clone(); input.push(b'\n'); fs::write(path.join("negative-input.json"), input).unwrap(); "B4 negative verifier input is not exact RFC 8785 JCS" },
                    1 => { let mut subject = row.subject.clone(); subject[0] ^= 1; fs::write(path.join("subject.bin"), subject).unwrap(); "negative verifier file subject.bin SHA-256 differs from its descriptor" },
                    2 => { let mut subject = row.subject.clone(); subject.pop(); fs::write(path.join("subject.bin"), subject).unwrap(); "negative verifier file subject.bin length is outside its bound" },
                    3 => { fs::remove_file(path.join("subject.bin")).unwrap(); "negative verifier root does not contain the exact V1 inventory" },
                    4 => { fs::write(path.join("extra"), b"x").unwrap(); "negative verifier root contains an unexpected or duplicate entry" },
                    5 | 6 => {
                        let backing = temp.path().join("backing"); fs::rename(path.join("subject.bin"), &backing).unwrap();
                        if fault == 5 { std::os::unix::fs::symlink(&backing, path.join("subject.bin")).unwrap(); "negative verifier path is not a regular file: subject.bin" }
                        else { fs::hard_link(&backing, path.join("subject.bin")).unwrap(); "hard-linked negative verifier file is forbidden: subject.bin" }
                    },
                    7 => { let mut input = Eip0045B4NegativeVerifierInputV1::from_canonical_jcs(&row.negative_input_jcs).unwrap(); input.subject.sha256 = "00".repeat(32); fs::write(path.join("negative-input.json"), input.to_canonical_jcs().unwrap()).unwrap(); "negative verifier file subject.bin SHA-256 differs from its descriptor" },
                    8 => { fs::write(path.join("negative-input.json"), b"{").unwrap(); "B4 negative verifier input is not exact RFC 8785 JCS" },
                    _ => {
                        let bytes = b"x";
                        let mut input = Eip0045B4NegativeVerifierInputV1::from_canonical_jcs(&row.negative_input_jcs).unwrap();
                        input.context.push(B4NegativeNamedIdentityV1 {
                            role: "context-00".into(), path: "context/00.bin".into(),
                            byte_length: 1, sha256: sha(bytes), encoding: B4NegativeFileEncoding::RawBytes,
                        });
                        fs::create_dir(path.join("context")).unwrap();
                        write_new(&path.join("context/00.bin"), bytes).unwrap();
                        fs::write(path.join("negative-input.json"), input.to_canonical_jcs().unwrap()).unwrap();
                        "negative input context cardinality differs from the frozen handler contract"
                    },
                }; deny(&path, message);
            }
        }
    }
    use crate::{
        b4_c2_terminal_catalog::genuine_catalog_join::{join, read_export},
        b4_negative_handler_contract::validate_negative_rejection_boundary,
        b4_plan::{B4MaterializationDomain, B4NegativeExecutionSurface},
        b4_subject_envelope::encode_subject_envelope,
        b4_terminal_byte_map::{B4TerminalByteMapEntry, encode_terminal_byte_map,
            terminal_byte_map_maximum_encoded_bytes},
        canonical::canonical_json_bytes,
    };

    type Outcome = Result<B4ArtifactCatalogRejection, B4ArtifactCatalogAdapterError>;

    fn exact_private_failure(actual: Outcome, expected: B4ArtifactCatalogAdapterError) -> bool {
        let allowed = matches!(&expected,
            B4ArtifactCatalogAdapterError::TerminalOracleReplay(
                B4TerminalOracleReplayErrorKind::CandidateCatalogueInvalid
                | B4TerminalOracleReplayErrorKind::ReceiptProfileShape)
            | B4ArtifactCatalogAdapterError::ByteMap(_));
        allowed && actual == Err(expected)
    }

    #[test]
    fn terminal_catalog_private_oracle_rejects_unexpected_acceptance_and_wrong_errors() {
        use B4ArtifactCatalogAdapterError as E;
        let expected = [
            E::TerminalOracleReplay(B4TerminalOracleReplayErrorKind::CandidateCatalogueInvalid),
            E::TerminalOracleReplay(B4TerminalOracleReplayErrorKind::ReceiptProfileShape),
            E::ByteMap(B4ByteMapError::ExpectedPathMismatch { index: 0 }),
        ];
        for error in &expected {
            assert!(exact_private_failure(Err(error.clone()), error.clone()));
            for unexpected in [E::UnexpectedAcceptance, E::UnexpectedConsumerRejection] {
                assert!(!exact_private_failure(Err(unexpected.clone()), error.clone()));
                assert!(!exact_private_failure(Err(unexpected.clone()), unexpected));
            }
            assert!(!exact_private_failure(Ok(B4ArtifactCatalogRejection::TerminalFixtureCatalogBinding), error.clone()));
            for other in expected.iter().filter(|other| *other != error) {
                assert!(!exact_private_failure(Err(other.clone()), error.clone()));
            }
        }
    }

    fn exact_matrix(positive: Outcome, rows: &[(usize, Outcome)]) -> bool {
        positive == Err(B4ArtifactCatalogAdapterError::UnexpectedAcceptance)
            && rows.len() == 3
            && rows.iter().map(|(index, _)| *index).eq(11..14)
            && rows.iter().all(|(_, result)| {
                *result == Ok(B4ArtifactCatalogRejection::TerminalFixtureCatalogBinding)
            })
    }

    #[test]
    fn terminal_catalog_matrix_oracle_rejects_missing_duplicate_and_fake_observations() {
        let bound = Ok(B4ArtifactCatalogRejection::TerminalFixtureCatalogBinding);
        let accepted = Err(B4ArtifactCatalogAdapterError::UnexpectedAcceptance);
        let rows = vec![(11, bound.clone()), (12, bound.clone()), (13, bound.clone())];
        assert!(exact_matrix(accepted.clone(), &rows)); // test-oracle truth table only
        assert!(!exact_matrix(bound.clone(), &rows)); // canned negative observer
        assert!(!exact_matrix(accepted.clone(), &rows[..2]));
        let mut duplicate = rows.clone();
        duplicate[2].0 = 12;
        assert!(!exact_matrix(accepted.clone(), &duplicate));
        let mut restored = rows;
        restored[1].1 = accepted.clone();
        assert!(!exact_matrix(accepted, &restored));
        validate_negative_rejection_boundary(
            B4MaterializationDomain::ArtifactValidator,
            B4NegativeExecutionSurface::TerminalFixtureCatalog,
            "terminal-fixture-catalog-mismatch",
            "terminal-fixture-catalog-binding",
        ).unwrap();
    }

    #[test]
    #[ignore = "requires genuine nineteen-file EIP0045_B4_TERMINAL_FIXTURE_REPOSITORY_ROOT export"]
    fn genuine_terminal_catalog_c2_producer_consumer_matrix() {
        let root = std::path::PathBuf::from(std::env::var_os(
            "EIP0045_B4_TERMINAL_FIXTURE_REPOSITORY_ROOT",
        ).expect("explicit genuine fixture export root"));
        let joined = join(read_export(&root).unwrap()).unwrap();
        let positive = reject_terminal_fixture_catalog(&joined.positive);
        assert_eq!(positive, Err(B4ArtifactCatalogAdapterError::UnexpectedAcceptance));
        let rows = joined.rows.iter().enumerate().map(|(slot, row)| {
            assert!(row.contexts.is_empty());
            assert_eq!(row.derived_registry_row.base_selector_id, "terminal-fixture-catalog-v1");
            let variant = ["program-id", "claim-digest", "control-id"][slot];
            assert_eq!(row.derived_registry_row.execution_id,
                format!("terminal-fixture-catalog-binding-sweep--{variant}"));
            (11 + slot, reject_terminal_fixture_catalog(&row.subject))
        }).collect::<Vec<_>>();
        assert!(exact_matrix(positive, &rows));
    }

    #[test]
    #[ignore = "requires genuine nineteen-file EIP0045_B4_TERMINAL_FIXTURE_REPOSITORY_ROOT export"]
    fn genuine_terminal_catalog_private_failures_are_not_binding_observations() {
        let root = std::path::PathBuf::from(std::env::var_os(
            "EIP0045_B4_TERMINAL_FIXTURE_REPOSITORY_ROOT",
        ).expect("explicit genuine fixture export root"));
        let entries = read_export(&root).unwrap();
        let joined = join(entries.clone()).unwrap();
        assert_eq!(reject_terminal_fixture_catalog(&joined.positive),
            Err(B4ArtifactCatalogAdapterError::UnexpectedAcceptance));
        let decoded = decode_subject_envelope(&joined.rows[0].subject,
            terminal_catalog_subject_envelope_contract()).unwrap();
        let parts = decoded.parts();
        let frame = |catalog: &[u8], raw: &[u8], oracle: &[u8]| {
            encode_subject_envelope(&[catalog, raw, oracle],
                terminal_catalog_subject_envelope_contract()).unwrap()
        };
        let mut extra: serde_json::Value = serde_json::from_slice(parts[0]).unwrap();
        let digest = extra["fixtures"][0]["claimDigest"].as_str().unwrap();
        let changed = format!("{}{}", if digest.starts_with('0') { "1" } else { "0" }, &digest[1..]);
        extra["fixtures"][0]["claimDigest"] = changed.into();
        let extra = canonical_json_bytes(&extra).unwrap();
        let noncanonical = serde_json::to_vec_pretty(
            &serde_json::from_slice::<serde_json::Value>(parts[0]).unwrap()).unwrap();
        for subject in [frame(&extra, parts[1], parts[2]),
            frame(&noncanonical, parts[1], parts[2])] {
            assert!(exact_private_failure(reject_terminal_fixture_catalog(&subject),
                B4ArtifactCatalogAdapterError::TerminalOracleReplay(
                    B4TerminalOracleReplayErrorKind::CandidateCatalogueInvalid)));
        }
        // Exercise the nested-map boundary directly: the swapped oracle map may
        // exceed the raw-map envelope bound before a framed subject can exist.
        let raw_maximum = terminal_byte_map_maximum_encoded_bytes(B4TerminalByteMapKind::RawSeal);
        let swapped_error = if parts[2].len() > raw_maximum {
            B4ByteMapError::EncodedTooLarge { actual: parts[2].len(), maximum: raw_maximum }
        } else {
            B4ByteMapError::ExpectedPathMismatch { index: 0 }
        };
        assert!(exact_private_failure(replay_and_bind_terminal_catalogue(parts[0], parts[2], parts[1]),
            B4ArtifactCatalogAdapterError::ByteMap(swapped_error)));
        // The wire codec itself rejects a changed order before any oracle replay.
        let raw = decode_terminal_byte_map(B4TerminalByteMapKind::RawSeal, parts[1]).unwrap();
        let mut reordered = raw.entries().iter().map(|entry|
            B4TerminalByteMapEntry::new(entry.path(), entry.payload())).collect::<Vec<_>>();
        reordered.swap(0, 1);
        assert!(encode_terminal_byte_map(B4TerminalByteMapKind::RawSeal, &reordered).is_err());
        let mut damaged_payload = raw.entries()[0].payload().to_vec();
        damaged_payload[0] ^= 1;
        let damaged_entries = raw.entries().iter().enumerate().map(|(index, entry)|
            B4TerminalByteMapEntry::new(entry.path(), if index == 0 {
                &damaged_payload
            } else { entry.payload() })).collect::<Vec<_>>();
        let damaged_map = encode_terminal_byte_map(B4TerminalByteMapKind::RawSeal, &damaged_entries).unwrap();
        assert!(exact_private_failure(reject_terminal_fixture_catalog(&frame(parts[0], &damaged_map, parts[2])),
            B4ArtifactCatalogAdapterError::TerminalOracleReplay(
                B4TerminalOracleReplayErrorKind::ReceiptProfileShape)));
        let mut corrupt = entries;
        let (_, bytes) = corrupt.iter_mut().find(|(path, _)| path.ends_with(".raw-seal.bin")).unwrap();
        bytes[0] ^= 1;
        assert!(join(corrupt).is_err()); // crypto/source integrity cannot become a catalogue mismatch
        let restored = reject_terminal_fixture_catalog(&joined.positive);
        assert!(!exact_matrix(restored.clone(), &[(11, restored),
            (12, Ok(B4ArtifactCatalogRejection::TerminalFixtureCatalogBinding)),
            (13, Ok(B4ArtifactCatalogRejection::TerminalFixtureCatalogBinding))]));
    }
}

use risc0_zkp::core::digest::Digest;

use crate::{
    b4::B4CandidateCorpus,
    b4_catalog::Eip0045B4SubjectCatalogV1,
    b4_plan::Eip0045B4NegativePlanV1,
    b4_registry_probe::Eip0045B4NegativeBindingIndexV1,
    b4_subject_envelope::{
        B4SubjectEnvelopeContract, B4SubjectEnvelopeError, B4SubjectEnvelopeKind,
        B4SubjectPartBounds, decode_subject_envelope, terminal_catalog_subject_envelope_contract,
        terminal_metadata_subject_envelope_contract,
    },
    b4_terminal_byte_map::{
        B4ByteMapError, B4DecodedTerminalByteMap, B4TerminalByteMapKind, decode_terminal_byte_map,
    },
    b4_terminal_oracle::{B4TerminalOracleReplayErrorKind, replay_fixed_terminal_oracles},
    b4_tree_probe::{
        B4AbstractCorpusRole, B4AbstractTreePolicyOutcome, Eip0045B4AbstractTreeV1,
        validate_abstract_tree_policy,
    },
    profile_manifest::{ProfileManifestError, StarkProfileManifestV1},
};

use super::{
    errors::B4StarkError,
    input::B4PositiveVerifierRootSources,
    terminal::TerminalCapture,
    terminal_metadata::{
        B4TerminalMetadataProducerErrorKind, TERMINAL_METADATA_RECORD_BYTES,
        reject_terminal_metadata_candidate_from_positive_sources,
    },
};

const SUBJECT_CATALOG_MAX_BYTES: usize = 128 * 1024;
const CANDIDATE_REGISTRY_MAX_BYTES: usize = 8 * 1024 * 1024;
const NEGATIVE_PLAN_MAX_BYTES: usize = 128 * 1024;
const NEGATIVE_BINDING_INDEX_MAX_BYTES: usize = 8 * 1024 * 1024;
const ABSTRACT_TREE_MAX_BYTES: usize = 16 * 1024;
const SEQUENCE_CATALOG_PARTS: [B4SubjectPartBounds; 1] =
    [B4SubjectPartBounds::new(1, SUBJECT_CATALOG_MAX_BYTES)];
const CANDIDATE_REGISTRY_PARTS: [B4SubjectPartBounds; 1] =
    [B4SubjectPartBounds::new(1, CANDIDATE_REGISTRY_MAX_BYTES)];
const NEGATIVE_BINDING_INDEX_PARTS: [B4SubjectPartBounds; 2] = [
    B4SubjectPartBounds::new(1, NEGATIVE_PLAN_MAX_BYTES),
    B4SubjectPartBounds::new(1, NEGATIVE_BINDING_INDEX_MAX_BYTES),
];

/// Missing immutable producer whose absence prevents one adapter from becoming
/// campaign authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum B4CatalogProducerContract {
    /// The exact 34-byte `(kind, parameter, controlId)` record derived from an
    /// authenticated positive terminal observation and its validated manifest.
    AuthenticatedPositiveTerminalRecord,
}

/// Closed rejections owned by catalog, registry, and corpus consumers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum B4ArtifactCatalogRejection {
    /// At the exact profile outer exponent, the terminal callback control ID is
    /// outside the authenticated allowlist. Outer-exponent failures stay private.
    TerminalPolicy,
    /// A derive-first terminal catalogue differs from the candidate catalogue.
    TerminalFixtureCatalogBinding,
    /// Candidate terminal metadata differs from the independently verified
    /// positive terminal.
    TerminalMetadataBinding,
    /// The candidate detached-subject catalogue violates its closed grammar.
    SequenceSubjectCatalog,
    /// The candidate registry violates its closed structural grammar.
    CandidateRegistry,
    /// The negative-binding index violates its strict structural codec.
    NegativeBindingIndexCodec,
    /// A structurally valid negative-binding index violates canonical-plan binding.
    NegativeBindingIndexPlanBinding,
    /// The abstract corpus omits a required role.
    CorpusRequiredRoleMissing,
    /// The abstract corpus contains a role outside the closed inventory.
    CorpusUnexpectedRole,
}

/// Private adapter failures.  These are harness/custody failures and can never
/// be projected into a campaign rejection observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum B4ArtifactCatalogAdapterError {
    SubjectEnvelope(B4SubjectEnvelopeError),
    ByteMap(B4ByteMapError),
    ProfileManifest(ProfileManifestError),
    CanonicalPlan,
    CatalogProducerUnavailable(B4CatalogProducerContract),
    TerminalOracleReplay(B4TerminalOracleReplayErrorKind),
    TerminalMetadataProducer(B4TerminalMetadataProducerErrorKind),
    MalformedConsumerEnvelope,
    UnexpectedAcceptance,
    UnexpectedConsumerRejection,
}

impl From<B4SubjectEnvelopeError> for B4ArtifactCatalogAdapterError {
    fn from(error: B4SubjectEnvelopeError) -> Self {
        Self::SubjectEnvelope(error)
    }
}

impl From<B4ByteMapError> for B4ArtifactCatalogAdapterError {
    fn from(error: B4ByteMapError) -> Self {
        Self::ByteMap(error)
    }
}

impl From<ProfileManifestError> for B4ArtifactCatalogAdapterError {
    fn from(error: ProfileManifestError) -> Self {
        Self::ProfileManifest(error)
    }
}

/// Validate one raw `outerPo2:u32le || codeRoot[32]` record through the same
/// exactly-once policy capture used by the production STARK verifier.
pub(super) fn reject_artifact_terminal_policy(
    terminal_record: &[u8],
    manifest_source: &[u8],
) -> Result<B4ArtifactCatalogRejection, B4ArtifactCatalogAdapterError> {
    let manifest = validated_initial_manifest(manifest_source)?;
    let record: &[u8; 36] = terminal_record
        .try_into()
        .map_err(|_| B4ArtifactCatalogAdapterError::MalformedConsumerEnvelope)?;
    let po2 = u32::from_le_bytes(
        record[..4]
            .try_into()
            .map_err(|_| B4ArtifactCatalogAdapterError::MalformedConsumerEnvelope)?,
    );
    let mut words = [0_u32; 8];
    for (index, chunk) in record[4..].chunks_exact(4).enumerate() {
        words[index] = u32::from_le_bytes(
            chunk
                .try_into()
                .map_err(|_| B4ArtifactCatalogAdapterError::MalformedConsumerEnvelope)?,
        );
    }
    let code_root = Digest::from(words);
    let capture = TerminalCapture::new(&manifest);
    let upstream = capture.check_code(po2, &code_root);
    match capture.finish(upstream) {
        Err(B4StarkError::TerminalControlIdNotAllowed { .. }) => {
            Ok(B4ArtifactCatalogRejection::TerminalPolicy)
        }
        Err(_) => Err(B4ArtifactCatalogAdapterError::UnexpectedConsumerRejection),
        Ok(_) => Err(B4ArtifactCatalogAdapterError::UnexpectedAcceptance),
    }
}

/// Validate the terminal-fixture bundle without consulting candidate fields
/// before all nine receipt oracles have been independently replayed.
///
/// Promotion of the handler-table row requires authenticated excluded-family
/// producer fixtures and physical dispatch closure for all three mutations.
/// A local dispatch observation does not itself grant campaign authority.
pub(super) fn reject_terminal_fixture_catalog(
    subject: &[u8],
) -> Result<B4ArtifactCatalogRejection, B4ArtifactCatalogAdapterError> {
    let parts = decode_subject_envelope(subject, terminal_catalog_subject_envelope_contract())?;
    let parts = parts.parts();
    replay_and_bind_terminal_catalogue(parts[0], parts[1], parts[2])
}

/// Derive the complete terminal catalogue from verified receipt oracles, then
/// compare the candidate bytes.  This function intentionally has no synthetic
/// success path.
fn replay_and_bind_terminal_catalogue(
    candidate_catalogue: &[u8],
    raw_map_source: &[u8],
    oracle_map_source: &[u8],
) -> Result<B4ArtifactCatalogRejection, B4ArtifactCatalogAdapterError> {
    let decoded_raw_map = decode_terminal_raw_map(raw_map_source)?;
    let decoded_oracle_map = decode_terminal_oracle_map(oracle_map_source)?;
    let raw_map = decoded_map_to_owned(&decoded_raw_map);
    let oracle_map = decoded_map_to_owned(&decoded_oracle_map);
    let replay = replay_fixed_terminal_oracles(&raw_map, &oracle_map)
        .map_err(|error| B4ArtifactCatalogAdapterError::TerminalOracleReplay(error.kind()))?;
    match replay.bind_candidate_catalogue_jcs(candidate_catalogue) {
        Err(error)
            if error.kind()
                == B4TerminalOracleReplayErrorKind::CandidateCatalogueBindingMismatch =>
        {
            Ok(B4ArtifactCatalogRejection::TerminalFixtureCatalogBinding)
        }
        Err(error) => Err(B4ArtifactCatalogAdapterError::TerminalOracleReplay(
            error.kind(),
        )),
        Ok(()) => Err(B4ArtifactCatalogAdapterError::UnexpectedAcceptance),
    }
}

/// Invoke the strict detached-subject catalogue parser exactly once.
pub(super) fn reject_sequence_subject_catalog(
    subject: &[u8],
) -> Result<B4ArtifactCatalogRejection, B4ArtifactCatalogAdapterError> {
    let parts = decode_subject_envelope(
        subject,
        B4SubjectEnvelopeContract::new(
            B4SubjectEnvelopeKind::SequenceCatalogBundle,
            &SEQUENCE_CATALOG_PARTS,
        ),
    )?;
    match Eip0045B4SubjectCatalogV1::from_canonical_jcs(parts.parts()[0]) {
        Err(_) => Ok(B4ArtifactCatalogRejection::SequenceSubjectCatalog),
        Ok(_) => Err(B4ArtifactCatalogAdapterError::UnexpectedAcceptance),
    }
}

/// Replay the terminal-join producer from seven positional byte contexts, then
/// compare the terminal-metadata candidate.
///
/// Context order is the closed positive-root order:
/// verifier input, manifest, B1, B2, guest ELF, statement, raw seal.
pub(super) fn reject_terminal_metadata(
    subject: &[u8],
    contexts: &[&[u8]],
) -> Result<B4ArtifactCatalogRejection, B4ArtifactCatalogAdapterError> {
    let (manifest_source, candidate_record) = decode_terminal_metadata_subject(subject)?;
    let sources = terminal_metadata_positive_sources(contexts)?;
    reject_terminal_metadata_candidate_from_positive_sources(
        sources,
        manifest_source,
        candidate_record,
    )
    .map_err(B4ArtifactCatalogAdapterError::TerminalMetadataProducer)?;
    Ok(B4ArtifactCatalogRejection::TerminalMetadataBinding)
}

fn decode_terminal_metadata_subject(
    subject: &[u8],
) -> Result<(&[u8], &[u8]), B4ArtifactCatalogAdapterError> {
    let parts = decode_subject_envelope(subject, terminal_metadata_subject_envelope_contract())?;
    let parts = parts.parts();
    let _manifest = validated_initial_manifest(parts[0])?;
    let _candidate_record: &[u8; TERMINAL_METADATA_RECORD_BYTES] = parts[1]
        .try_into()
        .map_err(|_| B4ArtifactCatalogAdapterError::MalformedConsumerEnvelope)?;
    Ok((parts[0], parts[1]))
}

fn terminal_metadata_positive_sources<'a>(
    contexts: &'a [&'a [u8]],
) -> Result<B4PositiveVerifierRootSources<'a>, B4ArtifactCatalogAdapterError> {
    let [
        verifier_input,
        manifest,
        algorithm,
        constants,
        guest_elf,
        statement,
        raw_seal,
    ] = contexts
    else {
        return Err(B4ArtifactCatalogAdapterError::CatalogProducerUnavailable(
            B4CatalogProducerContract::AuthenticatedPositiveTerminalRecord,
        ));
    };
    Ok(B4PositiveVerifierRootSources {
        verifier_input,
        profile_manifest: manifest,
        profile_algorithm: algorithm,
        profile_constants: constants,
        guest_elf,
        statement,
        raw_seal,
    })
}

/// Invoke the strict candidate-registry parser exactly once.
pub(super) fn reject_candidate_registry(
    subject: &[u8],
) -> Result<B4ArtifactCatalogRejection, B4ArtifactCatalogAdapterError> {
    let parts = decode_subject_envelope(
        subject,
        B4SubjectEnvelopeContract::new(
            B4SubjectEnvelopeKind::CandidateRegistryBundle,
            &CANDIDATE_REGISTRY_PARTS,
        ),
    )?;
    match B4CandidateCorpus::from_canonical_jcs(parts.parts()[0]) {
        Err(_) => Ok(B4ArtifactCatalogRejection::CandidateRegistry),
        Ok(_) => Err(B4ArtifactCatalogAdapterError::UnexpectedAcceptance),
    }
}

/// Validate the exact canonical plan base, invoke the negative-index codec once,
/// then invoke its plan-binding consumer only when structural decoding succeeds.
pub(super) fn reject_negative_binding_index(
    subject: &[u8],
) -> Result<B4ArtifactCatalogRejection, B4ArtifactCatalogAdapterError> {
    let parts = decode_subject_envelope(
        subject,
        B4SubjectEnvelopeContract::new(
            B4SubjectEnvelopeKind::NegativeBindingIndexBundle,
            &NEGATIVE_BINDING_INDEX_PARTS,
        ),
    )?;
    let parts = parts.parts();
    let plan = Eip0045B4NegativePlanV1::from_canonical_jcs(parts[0])
        .map_err(|_| B4ArtifactCatalogAdapterError::CanonicalPlan)?;
    if plan
        != Eip0045B4NegativePlanV1::canonical()
            .map_err(|_| B4ArtifactCatalogAdapterError::CanonicalPlan)?
    {
        return Err(B4ArtifactCatalogAdapterError::CanonicalPlan);
    }
    let Ok(index) = Eip0045B4NegativeBindingIndexV1::from_canonical_jcs(parts[1]) else {
        return Ok(B4ArtifactCatalogRejection::NegativeBindingIndexCodec);
    };
    match index.validate_against_plan(&plan) {
        Err(_) => Ok(B4ArtifactCatalogRejection::NegativeBindingIndexPlanBinding),
        Ok(()) => Err(B4ArtifactCatalogAdapterError::UnexpectedAcceptance),
    }
}

/// Parse the complete abstract tree, invoke the closed corpus policy once, and
/// project its typed role-set rejection without consulting QA metadata.
pub(super) fn reject_tree_corpus_closure(
    subject: &[u8],
) -> Result<B4ArtifactCatalogRejection, B4ArtifactCatalogAdapterError> {
    if subject.len() > ABSTRACT_TREE_MAX_BYTES {
        return Err(B4ArtifactCatalogAdapterError::MalformedConsumerEnvelope);
    }
    let model = Eip0045B4AbstractTreeV1::from_canonical_jcs(subject)
        .map_err(|_| B4ArtifactCatalogAdapterError::MalformedConsumerEnvelope)?;
    match validate_abstract_tree_policy(&model)
        .map_err(|_| B4ArtifactCatalogAdapterError::MalformedConsumerEnvelope)?
    {
        B4AbstractTreePolicyOutcome::Accepted => {
            Err(B4ArtifactCatalogAdapterError::UnexpectedAcceptance)
        }
        B4AbstractTreePolicyOutcome::Rejected(_) => {
            if model
                .roles
                .contains(&B4AbstractCorpusRole::UnregisteredExtra)
            {
                Ok(B4ArtifactCatalogRejection::CorpusUnexpectedRole)
            } else {
                Ok(B4ArtifactCatalogRejection::CorpusRequiredRoleMissing)
            }
        }
    }
}

fn validated_initial_manifest(
    source: &[u8],
) -> Result<StarkProfileManifestV1, B4ArtifactCatalogAdapterError> {
    let manifest = StarkProfileManifestV1::decode(source)?;
    manifest.validate_initial_profile_target()?;
    Ok(manifest)
}

fn decode_terminal_raw_map(source: &[u8]) -> Result<B4DecodedTerminalByteMap<'_>, B4ByteMapError> {
    decode_terminal_byte_map(B4TerminalByteMapKind::RawSeal, source)
}

fn decode_terminal_oracle_map(
    source: &[u8],
) -> Result<B4DecodedTerminalByteMap<'_>, B4ByteMapError> {
    decode_terminal_byte_map(B4TerminalByteMapKind::ReceiptOracle, source)
}

fn decoded_map_to_owned(decoded: &B4DecodedTerminalByteMap<'_>) -> BTreeMap<String, Vec<u8>> {
    let mut owned = BTreeMap::new();
    for entry in decoded.entries() {
        owned.insert(entry.path().to_owned(), entry.payload().to_vec());
    }
    owned
}

#[cfg(test)]
mod tests {
    use std::{env, fs, path::PathBuf};

    use super::super::input::{
        GUEST_ELF_FILE, POSITIVE_INPUT_FILE, PROFILE_ALGORITHM_FILE, PROFILE_CONSTANTS_FILE,
        PROFILE_MANIFEST_FILE, RAW_SEAL_FILE, STATEMENT_FILE,
    };
    use super::*;
    use crate::{
        b4::B4SequenceTarget,
        b4_catalog::{
            B4_SUBJECT_CATALOG_FORMAT, B4_SUBJECT_CATALOG_FORMAT_VERSION,
            B4SubjectArtifactIdentityV1, B4SubjectCatalogEntryV1, B4SubjectProvenanceV1,
        },
        b4_plan::{B4NegativeExecutionSurface, Eip0045B4NegativePlanV1},
        b4_registry_probe::{materialize_registry_probe, synthetic_registry_skeleton_source},
        b4_terminal::{B4_STOCK_CONTROL_LAYOUT, Eip0045B4TerminalFixtureCatalogV1},
        b4_tree_probe::{B4_TREE_PROBE_EXECUTION_IDS, materialize_tree_probe},
        canonical::canonical_json_bytes,
        constants::PROOF_BYTES,
        receipt_oracle_codec::RECEIPT_ORACLE_MAX_BYTES,
    };
    use sha2::{Digest as _, Sha256};

    const MANIFEST: &[u8] = include_bytes!("../../../profiles/risc0-v3-succinct/manifest.bin");
    const TERMINAL_RAW_PATHS: [&str; 9] =
        *crate::b4_terminal_byte_map::terminal_byte_map_paths(B4TerminalByteMapKind::RawSeal);
    const TERMINAL_ORACLE_PATHS: [&str; 9] =
        *crate::b4_terminal_byte_map::terminal_byte_map_paths(B4TerminalByteMapKind::ReceiptOracle);

    fn envelope(kind: B4SubjectEnvelopeKind, parts: &[&[u8]]) -> Vec<u8> {
        let mut source = b"EIP45B4S".to_vec();
        source.push(1);
        source.push(kind as u8);
        source.extend_from_slice(&u16::try_from(parts.len()).unwrap().to_le_bytes());
        for part in parts {
            source.extend_from_slice(&u32::try_from(part.len()).unwrap().to_le_bytes());
            source.extend_from_slice(part);
        }
        source
    }

    fn byte_map(paths: &[&str], payloads: &[Vec<u8>]) -> Vec<u8> {
        let mut source = Vec::new();
        source.extend_from_slice(&u16::try_from(paths.len()).unwrap().to_le_bytes());
        for (path, payload) in paths.iter().zip(payloads) {
            source.extend_from_slice(&u16::try_from(path.len()).unwrap().to_le_bytes());
            source.extend_from_slice(path.as_bytes());
            source.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_le_bytes());
            source.extend_from_slice(payload);
        }
        source
    }

    fn terminal_record(po2: u32, control_id_hex: &str) -> Vec<u8> {
        let mut record = po2.to_le_bytes().to_vec();
        record.extend_from_slice(&hex::decode(control_id_hex).unwrap());
        record
    }

    fn canonical_plan_source() -> Vec<u8> {
        Eip0045B4NegativePlanV1::canonical()
            .unwrap()
            .to_canonical_jcs()
            .unwrap()
    }

    #[test]
    fn every_artifact_terminal_policy_variant_reaches_the_same_typed_policy_boundary() {
        let manifest = StarkProfileManifestV1::decode(MANIFEST).unwrap();
        let po2 = u32::from(manifest.outer_po2());

        let unknown = terminal_record(po2, &"00".repeat(32));
        assert_eq!(
            reject_artifact_terminal_policy(&unknown, MANIFEST),
            Ok(B4ArtifactCatalogRejection::TerminalPolicy)
        );

        let excluded = B4_STOCK_CONTROL_LAYOUT
            .iter()
            .filter(|row| !row.eip_allowed)
            .collect::<Vec<_>>();
        assert_eq!(excluded.len(), 17);
        for row in &excluded {
            assert_eq!(
                reject_artifact_terminal_policy(&terminal_record(po2, row.control_id), MANIFEST,),
                Ok(B4ArtifactCatalogRejection::TerminalPolicy),
                "{}",
                row.family
            );
        }

        for family in [
            "lift-po2-14",
            "lift-povw-po2-18",
            "join-povw",
            "join-unwrap-povw",
            "resolve-povw",
            "resolve-unwrap-povw",
            "union",
            "unwrap-povw",
        ] {
            let row = excluded.iter().find(|row| row.family == family).unwrap();
            assert_eq!(
                reject_artifact_terminal_policy(&terminal_record(po2, row.control_id), MANIFEST,),
                Ok(B4ArtifactCatalogRejection::TerminalPolicy),
            );
        }
    }

    #[test]
    fn allowed_terminal_policy_record_is_not_a_negative_observation() {
        let manifest = StarkProfileManifestV1::decode(MANIFEST).unwrap();
        let control = manifest.terminal_controls()[0];
        assert_eq!(
            reject_artifact_terminal_policy(
                &terminal_record(
                    u32::from(manifest.outer_po2()),
                    &hex::encode(control.control_id())
                ),
                MANIFEST,
            ),
            Err(B4ArtifactCatalogAdapterError::UnexpectedAcceptance)
        );
    }

    #[test]
    fn artifact_terminal_outer_po2_mismatch_is_not_projected_as_control_id() {
        let manifest = StarkProfileManifestV1::decode(MANIFEST).unwrap();
        let control = manifest.terminal_controls()[0];
        let wrong_po2 = u32::from(manifest.outer_po2()) + 1;
        assert_eq!(
            reject_artifact_terminal_policy(
                &terminal_record(wrong_po2, &hex::encode(control.control_id())),
                MANIFEST,
            ),
            Err(B4ArtifactCatalogAdapterError::UnexpectedConsumerRejection)
        );
    }

    #[test]
    fn all_five_sequence_catalog_variants_reject_without_variant_dispatch() {
        let plan_source = canonical_plan_source();
        let baseline = subject_catalog(&plan_source);
        let mut variants = Vec::new();

        let mut positive = baseline.clone();
        positive.subjects[0].target = B4SequenceTarget::RegistryNegativeCases;
        variants.push(positive);

        let mut negative_cases = baseline.clone();
        let B4SubjectProvenanceV1::NegativePlan { plan_sha256 } =
            &mut negative_cases.subjects[1].provenance
        else {
            panic!("wrong baseline provenance")
        };
        *plan_sha256 = digest(999);
        variants.push(negative_cases);

        let mut negative_classes = baseline.clone();
        negative_classes.subjects[2].target = B4SequenceTarget::RegistryPositiveCases;
        variants.push(negative_classes);

        let mut profile = baseline.clone();
        profile.subjects[3].provenance = B4SubjectProvenanceV1::NegativePlan {
            plan_sha256: sha256_hex(&plan_source),
        };
        variants.push(profile);

        let mut proof = baseline;
        let B4SubjectProvenanceV1::ProofChunks { case_id, .. } = &mut proof.subjects[4].provenance
        else {
            panic!("wrong baseline provenance")
        };
        *case_id = "lift-po2-16".to_owned();
        variants.push(proof);

        for variant in variants {
            let source = canonical_json_bytes(&serde_json::to_value(variant).unwrap()).unwrap();
            let subject = envelope(B4SubjectEnvelopeKind::SequenceCatalogBundle, &[&source]);
            assert_eq!(
                reject_sequence_subject_catalog(&subject),
                Ok(B4ArtifactCatalogRejection::SequenceSubjectCatalog)
            );
        }
    }

    #[test]
    fn valid_catalog_registry_index_and_tree_bases_cannot_emit_rejections() {
        let plan_source = canonical_plan_source();
        let catalog_source = subject_catalog(&plan_source).to_canonical_jcs().unwrap();
        let catalog_subject = envelope(
            B4SubjectEnvelopeKind::SequenceCatalogBundle,
            &[&catalog_source],
        );
        assert_eq!(
            reject_sequence_subject_catalog(&catalog_subject),
            Err(B4ArtifactCatalogAdapterError::UnexpectedAcceptance)
        );

        let registry_subject = envelope(
            B4SubjectEnvelopeKind::CandidateRegistryBundle,
            &[synthetic_registry_skeleton_source().unwrap()],
        );
        assert_eq!(
            reject_candidate_registry(&registry_subject),
            Err(B4ArtifactCatalogAdapterError::UnexpectedAcceptance)
        );

        let plan = Eip0045B4NegativePlanV1::from_canonical_jcs(&plan_source).unwrap();
        let index_source = Eip0045B4NegativeBindingIndexV1::from_plan(&plan)
            .unwrap()
            .to_canonical_jcs()
            .unwrap();
        let index_subject = envelope(
            B4SubjectEnvelopeKind::NegativeBindingIndexBundle,
            &[&plan_source, &index_source],
        );
        assert_eq!(
            reject_negative_binding_index(&index_subject),
            Err(B4ArtifactCatalogAdapterError::UnexpectedAcceptance)
        );

        let tree_source = Eip0045B4AbstractTreeV1::canonical_baseline()
            .unwrap()
            .to_canonical_jcs()
            .unwrap();
        assert_eq!(
            reject_tree_corpus_closure(&tree_source),
            Err(B4ArtifactCatalogAdapterError::UnexpectedAcceptance)
        );
    }

    #[test]
    fn all_registry_and_binding_index_materializations_reach_only_their_typed_consumer() {
        let plan_source = canonical_plan_source();
        let plan = Eip0045B4NegativePlanV1::from_canonical_jcs(&plan_source).unwrap();
        let executions = plan
            .groups
            .iter()
            .flat_map(|group| &group.executions)
            .filter(|execution| {
                matches!(
                    execution.execution_surface,
                    B4NegativeExecutionSurface::CandidateRegistry
                        | B4NegativeExecutionSurface::NegativeBindingIndex
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(executions.len(), 23);

        for execution in executions {
            let materialized =
                materialize_registry_probe(&plan_source, &execution.execution_id).unwrap();
            let (kind, parts, expected) = match execution.execution_surface {
                B4NegativeExecutionSurface::CandidateRegistry => (
                    B4SubjectEnvelopeKind::CandidateRegistryBundle,
                    vec![materialized.output.as_slice()],
                    B4ArtifactCatalogRejection::CandidateRegistry,
                ),
                B4NegativeExecutionSurface::NegativeBindingIndex => (
                    B4SubjectEnvelopeKind::NegativeBindingIndexBundle,
                    vec![plan_source.as_slice(), materialized.output.as_slice()],
                    if execution.execution_id
                        == "registry-negative-case-id-duplicate--negative-case-id"
                    {
                        B4ArtifactCatalogRejection::NegativeBindingIndexCodec
                    } else {
                        B4ArtifactCatalogRejection::NegativeBindingIndexPlanBinding
                    },
                ),
                _ => unreachable!(),
            };
            let subject = envelope(kind, &parts);
            let observed = match execution.execution_surface {
                B4NegativeExecutionSurface::CandidateRegistry => {
                    reject_candidate_registry(&subject)
                }
                B4NegativeExecutionSurface::NegativeBindingIndex => {
                    reject_negative_binding_index(&subject)
                }
                _ => unreachable!(),
            };
            assert_eq!(observed, Ok(expected), "{}", execution.execution_id);
        }
    }

    #[test]
    fn all_twenty_one_tree_variants_reach_the_role_policy() {
        let plan_source = canonical_plan_source();
        for execution_id in B4_TREE_PROBE_EXECUTION_IDS {
            let materialized = materialize_tree_probe(&plan_source, execution_id).unwrap();
            let expected = if execution_id == "corpus-extra-file--unregistered-file" {
                B4ArtifactCatalogRejection::CorpusUnexpectedRole
            } else {
                B4ArtifactCatalogRejection::CorpusRequiredRoleMissing
            };
            assert_eq!(
                reject_tree_corpus_closure(&materialized.output_jcs),
                Ok(expected),
                "{execution_id}"
            );
        }
    }

    #[test]
    fn terminal_catalogue_replays_producer_before_consulting_candidate() {
        let raw_payloads = (0..9).map(|_| vec![0_u8; PROOF_BYTES]).collect::<Vec<_>>();
        let oracle_payloads = (0..9).map(|_| vec![0_u8]).collect::<Vec<_>>();
        let raw = byte_map(&TERMINAL_RAW_PATHS, &raw_payloads);
        let oracles = byte_map(&TERMINAL_ORACLE_PATHS, &oracle_payloads);

        for candidate in [b"{}".as_slice(), b"not-json", b"\xff"] {
            let subject = envelope(
                B4SubjectEnvelopeKind::TerminalCatalogBundle,
                &[candidate, &raw, &oracles],
            );
            assert_eq!(
                reject_terminal_fixture_catalog(&subject),
                Err(B4ArtifactCatalogAdapterError::TerminalOracleReplay(
                    B4TerminalOracleReplayErrorKind::ReceiptDecode
                ))
            );
        }
    }

    #[test]
    #[ignore = "requires EIP0045_B4_TERMINAL_FIXTURE_REPOSITORY_ROOT"]
    fn real_terminal_producer_replay_reaches_the_typed_catalogue_binding() {
        let root =
            PathBuf::from(env::var_os("EIP0045_B4_TERMINAL_FIXTURE_REPOSITORY_ROOT").unwrap());
        let raw_payloads = TERMINAL_RAW_PATHS
            .iter()
            .map(|path| fs::read(root.join(path)).unwrap())
            .collect::<Vec<_>>();
        let oracle_payloads = TERMINAL_ORACLE_PATHS
            .iter()
            .map(|path| fs::read(root.join(path)).unwrap())
            .collect::<Vec<_>>();
        let raw_map = TERMINAL_RAW_PATHS
            .iter()
            .zip(&raw_payloads)
            .map(|(path, payload)| ((*path).to_owned(), payload.clone()))
            .collect::<BTreeMap<_, _>>();
        let oracle_map = TERMINAL_ORACLE_PATHS
            .iter()
            .zip(&oracle_payloads)
            .map(|(path, payload)| ((*path).to_owned(), payload.clone()))
            .collect::<BTreeMap<_, _>>();
        let replay = replay_fixed_terminal_oracles(&raw_map, &oracle_map).unwrap();
        let derived = Eip0045B4TerminalFixtureCatalogV1::from_canonical_jcs(
            &replay.derived_catalogue_jcs().unwrap(),
        )
        .unwrap();
        let mut program_id = derived.clone();
        program_id.program_id = changed_digest(&program_id.program_id);
        let mut claim_digest = derived.clone();
        claim_digest.fixtures[0].claim_digest =
            changed_digest(&claim_digest.fixtures[0].claim_digest);
        let mut control_id = derived.clone();
        control_id.fixtures[0].terminal.control_id =
            changed_digest(&control_id.fixtures[0].terminal.control_id);
        let mut unplanned = derived.clone();
        let byte_length = &mut unplanned.fixtures[0].receipt_oracle.byte_length;
        *byte_length = if *byte_length < RECEIPT_ORACLE_MAX_BYTES as u64 {
            *byte_length + 1
        } else {
            *byte_length - 1
        };
        unplanned.validate().unwrap();
        let noncanonical =
            serde_json::to_vec_pretty(&serde_json::to_value(derived).unwrap()).unwrap();
        let raw_source = byte_map(&TERMINAL_RAW_PATHS, &raw_payloads);
        let oracle_source = byte_map(&TERMINAL_ORACLE_PATHS, &oracle_payloads);

        for candidate in [program_id, claim_digest, control_id] {
            let candidate =
                canonical_json_bytes(&serde_json::to_value(candidate).unwrap()).unwrap();
            let subject = envelope(
                B4SubjectEnvelopeKind::TerminalCatalogBundle,
                &[&candidate, &raw_source, &oracle_source],
            );
            assert_eq!(
                reject_terminal_fixture_catalog(&subject),
                Ok(B4ArtifactCatalogRejection::TerminalFixtureCatalogBinding)
            );
        }
        let unplanned = canonical_json_bytes(&serde_json::to_value(unplanned).unwrap()).unwrap();
        for candidate in [&unplanned, &noncanonical] {
            let subject = envelope(
                B4SubjectEnvelopeKind::TerminalCatalogBundle,
                &[candidate, &raw_source, &oracle_source],
            );
            assert_eq!(
                reject_terminal_fixture_catalog(&subject),
                Err(B4ArtifactCatalogAdapterError::TerminalOracleReplay(
                    B4TerminalOracleReplayErrorKind::CandidateCatalogueInvalid
                ))
            );
        }
    }

    #[test]
    fn terminal_metadata_requires_the_complete_positive_producer_context() {
        for offset in [0, 1, 2] {
            let mut record = [0_u8; TERMINAL_METADATA_RECORD_BYTES];
            record[offset] = 1;
            let subject = envelope(
                B4SubjectEnvelopeKind::TerminalMetadataBundle,
                &[MANIFEST, &record],
            );
            assert_eq!(
                reject_terminal_metadata(&subject, &[]),
                Err(B4ArtifactCatalogAdapterError::CatalogProducerUnavailable(
                    B4CatalogProducerContract::AuthenticatedPositiveTerminalRecord
                ))
            );

            let invalid_producer = [b"x".as_slice(); 7];
            assert_eq!(
                reject_terminal_metadata(&subject, &invalid_producer),
                Err(B4ArtifactCatalogAdapterError::TerminalMetadataProducer(
                    B4TerminalMetadataProducerErrorKind::PositiveRoot
                ))
            );
        }
    }

    #[test]
    #[ignore = "requires EIP0045_B4_TERMINAL_JOIN_POSITIVE_ROOT"]
    fn terminal_metadata_bundle_rejects_only_after_terminal_join_derivation() {
        let root = PathBuf::from(env::var_os("EIP0045_B4_TERMINAL_JOIN_POSITIVE_ROOT").unwrap());
        let owned_contexts = [
            POSITIVE_INPUT_FILE,
            PROFILE_MANIFEST_FILE,
            PROFILE_ALGORITHM_FILE,
            PROFILE_CONSTANTS_FILE,
            GUEST_ELF_FILE,
            STATEMENT_FILE,
            RAW_SEAL_FILE,
        ]
        .map(|path| fs::read(root.join(path)).unwrap());
        let contexts = owned_contexts.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let sources = terminal_metadata_positive_sources(&contexts).unwrap();
        let derived =
            super::super::terminal_metadata::derive_terminal_metadata_from_positive_sources(
                sources, MANIFEST,
            )
            .unwrap()
            .bytes();

        let accepted_subject = envelope(
            B4SubjectEnvelopeKind::TerminalMetadataBundle,
            &[MANIFEST, &derived],
        );
        assert_eq!(
            reject_terminal_metadata(&accepted_subject, &contexts),
            Err(B4ArtifactCatalogAdapterError::TerminalMetadataProducer(
                B4TerminalMetadataProducerErrorKind::UnexpectedAcceptance
            ))
        );

        for offset in [0, 1, 2] {
            let mut changed = derived;
            changed[offset] ^= 1;
            let subject = envelope(
                B4SubjectEnvelopeKind::TerminalMetadataBundle,
                &[MANIFEST, &changed],
            );
            assert_eq!(
                reject_terminal_metadata(&subject, &contexts),
                Ok(B4ArtifactCatalogRejection::TerminalMetadataBinding)
            );
        }
    }

    #[test]
    fn wrong_bundle_kind_and_noncanonical_plan_are_private_failures() {
        let candidate = envelope(B4SubjectEnvelopeKind::SequenceCatalogBundle, &[b"{}"]);
        assert!(matches!(
            reject_candidate_registry(&candidate),
            Err(B4ArtifactCatalogAdapterError::SubjectEnvelope(
                B4SubjectEnvelopeError::UnexpectedKind { .. }
            ))
        ));

        let plan_source = canonical_plan_source();
        let index = Eip0045B4NegativeBindingIndexV1::from_plan(
            &Eip0045B4NegativePlanV1::canonical().unwrap(),
        )
        .unwrap()
        .to_canonical_jcs()
        .unwrap();
        let mut noncanonical = plan_source;
        noncanonical.push(b'\n');
        let subject = envelope(
            B4SubjectEnvelopeKind::NegativeBindingIndexBundle,
            &[&noncanonical, &index],
        );
        assert_eq!(
            reject_negative_binding_index(&subject),
            Err(B4ArtifactCatalogAdapterError::CanonicalPlan)
        );
    }

    fn digest(value: usize) -> String {
        format!("{value:064x}")
    }

    fn changed_digest(source: &str) -> String {
        let mut changed = source.as_bytes().to_vec();
        changed[0] = if changed[0] == b'0' { b'1' } else { b'0' };
        String::from_utf8(changed).unwrap()
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    fn subject_entry(
        subject_id: &str,
        target: B4SequenceTarget,
        provenance: B4SubjectProvenanceV1,
        seed: usize,
    ) -> B4SubjectCatalogEntryV1 {
        B4SubjectCatalogEntryV1 {
            artifact: B4SubjectArtifactIdentityV1 {
                byte_length: 1,
                path: format!(
                    "reproduction/schema/b4-corpus-v1.candidate/subjects/{subject_id}.subject.json"
                ),
                sha256: digest(seed),
            },
            provenance,
            subject_id: subject_id.to_owned(),
            target,
        }
    }

    fn subject_catalog(plan_source: &[u8]) -> Eip0045B4SubjectCatalogV1 {
        let plan_sha256 = sha256_hex(plan_source);
        let profile_id = digest(77);
        let proof_cases = [
            ("proof-chunks-lift-po2-15", "lift-po2-15"),
            ("proof-chunks-lift-po2-16", "lift-po2-16"),
            ("proof-chunks-lift-po2-17", "lift-po2-17"),
            ("proof-chunks-lift-po2-18", "lift-po2-18"),
            ("proof-chunks-lift-po2-19", "lift-po2-19"),
            ("proof-chunks-lift-po2-20", "lift-po2-20"),
            ("proof-chunks-lift-po2-21", "lift-po2-21"),
            ("proof-chunks-lift-po2-22", "lift-po2-22"),
            ("proof-chunks-terminal-join", "terminal-join"),
            (
                "proof-chunks-terminal-resolve-explicit-root",
                "terminal-resolve-explicit-root",
            ),
            (
                "proof-chunks-resolve-zero-root-then-join",
                "resolve-zero-root-then-join",
            ),
        ];
        let mut subjects = vec![
            subject_entry(
                "registry-positive-cases",
                B4SequenceTarget::RegistryPositiveCases,
                B4SubjectProvenanceV1::PositiveProjection {
                    positive_case_count: 11,
                },
                1,
            ),
            subject_entry(
                "registry-negative-cases",
                B4SequenceTarget::RegistryNegativeCases,
                B4SubjectProvenanceV1::NegativePlan {
                    plan_sha256: plan_sha256.clone(),
                },
                2,
            ),
            subject_entry(
                "registry-negative-classes",
                B4SequenceTarget::RegistryNegativeClasses,
                B4SubjectProvenanceV1::NegativeClasses {
                    plan_sha256: plan_sha256.clone(),
                },
                3,
            ),
            subject_entry(
                "profile-package-files",
                B4SequenceTarget::ProfilePackageFiles,
                B4SubjectProvenanceV1::ProfilePackage { profile_id },
                4,
            ),
        ];
        subjects.extend(proof_cases.into_iter().enumerate().map(
            |(index, (subject_id, case_id))| {
                subject_entry(
                    subject_id,
                    B4SequenceTarget::ProofChunks,
                    B4SubjectProvenanceV1::ProofChunks {
                        case_id: case_id.to_owned(),
                        raw_seal_sha256: digest(20 + index),
                    },
                    40 + index,
                )
            },
        ));
        let catalog = Eip0045B4SubjectCatalogV1 {
            format: B4_SUBJECT_CATALOG_FORMAT.to_owned(),
            format_version: B4_SUBJECT_CATALOG_FORMAT_VERSION,
            subjects,
        };
        catalog.validate().unwrap();
        catalog
    }
}
