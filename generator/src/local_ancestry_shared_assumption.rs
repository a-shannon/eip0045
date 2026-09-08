//! Fixed local shared-assumption checkpoint. No campaign authority or branch proving.

use std::{
    collections::BTreeSet,
    fs::{self, File, Metadata},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};

use anyhow::{Context as _, Result, ensure};
use eip_0045_reproduction::{canonical::canonical_json_bytes, constants::{MAX_STATEMENT_BYTES, PROOF_BYTES}};
use risc0_zkvm::LocalProver;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    CANDIDATE_RECEIPT_ORACLE_MAX_BYTES,
    locked_negative_ancestry_guest::{LockedGuestPairV1, embedded_negative_ancestry_guest_pair},
    recursive::{LocalSharedAssumptionInput, RECURSIVE_ORACLE_MAX_BYTES, admit_local_shared_assumption},
};

const INPUT_ROLES: [&str; 4] = ["canonical-statement", "case9-recursive-oracle", "case9-assumption-raw-seal", "case9-final-raw-seal"];
const PAYLOAD_NAMES: [&str; 3] = ["shared-assumption.receipt-oracle.bincode", "shared-assumption.raw-seal.bin", "alternate-chain-domain-statement.bin"];
const MANIFEST: &str = "shared-assumption-checkpoint.json";
const MANIFEST_MAX_BYTES: usize = 16 * 1024;
const INPUT_LIMITS: [usize; 4] = [MAX_STATEMENT_BYTES, RECURSIVE_ORACLE_MAX_BYTES, PROOF_BYTES, PROOF_BYTES];
const OUTPUT_LIMITS: [usize; 3] = [CANDIDATE_RECEIPT_ORACLE_MAX_BYTES, PROOF_BYTES, MAX_STATEMENT_BYTES];
type Node = (u64, u64);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pin { bytes: u64, sha256: String }

impl Pin {
    fn of(bytes: &[u8]) -> Self {
        Self { bytes: bytes.len() as u64, sha256: hex::encode(Sha256::digest(bytes)) }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NamedPin { name: String, pin: Pin }

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GuestPin { elf: Pin, image_id: String }

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    schema: String,
    version: u32,
    role: String,
    terminal: String,
    inputs: [NamedPin; 4],
    consumer: GuestPin,
    alternate: GuestPin,
    payloads: [NamedPin; 3],
    outer_receipt_borsh: Pin,
}

impl Checkpoint {
    fn encode(&self) -> Result<Vec<u8>> {
        let bytes = canonical_json_bytes(&serde_json::to_value(self)?)?;
        ensure!(bytes.len() <= MANIFEST_MAX_BYTES, "local checkpoint manifest byte bound");
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(!bytes.is_empty() && bytes.len() <= MANIFEST_MAX_BYTES, "local checkpoint manifest byte bound");
        let value: Self = serde_json::from_slice(bytes).context("local checkpoint manifest typed JSON")?;
        ensure!(value.encode()? == bytes, "local checkpoint manifest is not canonical");
        Ok(value)
    }
}

struct Inputs { files: [Snapshot; 4] }

impl Inputs {
    fn read(paths: [&Path; 4]) -> Result<Self> {
        let files = paths.into_iter().zip(INPUT_LIMITS).map(|(path, limit)| Snapshot::read(path, limit))
            .collect::<Result<Vec<_>>>()?;
        let files: [Snapshot; 4] = files.try_into().map_err(|_| anyhow::anyhow!("local input cardinality"))?;
        ensure!(files.iter().map(|file| file.node).collect::<BTreeSet<_>>().len() == 4,
                "local input identities are duplicated");
        ensure!(files[2].bytes.len() == PROOF_BYTES && files[3].bytes.len() == PROOF_BYTES,
                "local Case9 raw seal byte length");
        Ok(Self { files })
    }

    fn admit(&self, locked: &LockedGuestPairV1) -> Result<LocalSharedAssumptionInput> {
        admit_local_shared_assumption(locked, &self.files[0].bytes, &self.files[1].bytes,
                                      &self.files[2].bytes, &self.files[3].bytes)
    }

    fn verify(&self) -> Result<()> {
        for file in &self.files { file.verify().context("local original input conservation")?; }
        Ok(())
    }
}

fn expected_checkpoint(inputs: &Inputs, locked: &LockedGuestPairV1, payloads: &[Vec<u8>; 3], outer: &[u8]) -> Checkpoint {
    let guest = |(elf, id): (&[u8], risc0_zkvm::Digest)| GuestPin { elf: Pin::of(elf), image_id: hex::encode(id.as_bytes()) };
    Checkpoint {
        schema: "eip0045.local-ancestry-shared-assumption.v1".to_owned(), version: 1,
        role: "alternate-chain-domain-shared-assumption".to_owned(), terminal: "stock-lift15".to_owned(),
        inputs: std::array::from_fn(|i| NamedPin { name: INPUT_ROLES[i].to_owned(), pin: Pin::of(&inputs.files[i].bytes) }),
        consumer: guest(locked.consumer()), alternate: guest(locked.alternate()),
        payloads: std::array::from_fn(|i| NamedPin { name: PAYLOAD_NAMES[i].to_owned(), pin: Pin::of(&payloads[i]) }),
        outer_receipt_borsh: Pin::of(outer),
    }
}

fn replay_checkpoint(inputs: &Inputs, locked: &LockedGuestPairV1, admitted: &LocalSharedAssumptionInput,
                     payloads: &[Vec<u8>; 3]) -> Result<Checkpoint> {
    ensure!(payloads[2] == admitted.statement(), "local derived statement mismatch");
    let receipt = admitted.replay(&payloads[0], &payloads[1])?;
    let outer = borsh::to_vec(&receipt)?;
    Ok(expected_checkpoint(inputs, locked, payloads, &outer))
}

/// Acquire one fixed Lift15 checkpoint from four retained canonical Case9 inputs.
///
/// # Errors
/// Rejects custody, Case9 replay, locked guest, proving, exact Receipt reconstruction,
/// publication or final conservation failure. A failed partial directory is retained.
pub fn generate(paths: [&Path; 4], output_root: &Path) -> Result<()> {
    let inputs = Inputs::read(paths)?;
    let locked = embedded_negative_ancestry_guest_pair()?;
    let admitted = inputs.admit(&locked)?;
    let root = create_fresh_directory(output_root)?;
    let result = (|| {
        let receipt = admitted.prove(&LocalProver::new("local-ancestry-shared-assumption"))?;
        let (oracle, raw, outer) = admitted.checkpoint_parts(&receipt)?;
        let payloads = [oracle, raw, admitted.statement().to_vec()];
        let expected = expected_checkpoint(&inputs, &locked, &payloads, &outer);
        root.verify()?;
        publish(&root, &payloads, &expected,
            |actual| replay_checkpoint(&inputs, &locked, &admitted, actual), || inputs.verify())
    })();
    // Failure does not bypass conservation; no failure path removes partial evidence.
    inputs.verify()?;
    result
}

/// Reopen all four checkpoint files and independently replay against retained inputs.
///
/// # Errors
/// Rejects missing/extra/aliased files, noncanonical metadata, any receipt or original
/// input drift. No proving or writing occurs on this route.
pub fn verify(paths: [&Path; 4], checkpoint_root: &Path) -> Result<()> {
    let inputs = Inputs::read(paths)?;
    let locked = embedded_negative_ancestry_guest_pair()?;
    let admitted = inputs.admit(&locked)?;
    let root = Directory::open(checkpoint_root)?;
    let result = verify_published(&root,
        |actual| replay_checkpoint(&inputs, &locked, &admitted, actual), || inputs.verify());
    inputs.verify()?;
    result
}

fn payload_snapshots(root: &Directory) -> Result<[Snapshot; 3]> {
    let files = PAYLOAD_NAMES.into_iter().zip(OUTPUT_LIMITS)
        .map(|(name, limit)| Snapshot::read_at(root, name, limit)).collect::<Result<Vec<_>>>()?;
    files.try_into().map_err(|_| anyhow::anyhow!("local payload cardinality"))
}

/// A replayed checkpoint and its first physical observations, not campaign or
/// historical selection authority. The local runner separately pins its origin.
pub(crate) struct AuthenticatedSharedCheckpoint {
    inputs: Inputs,
    locked: LockedGuestPairV1,
    admitted: LocalSharedAssumptionInput,
    root: Directory,
    manifest: Snapshot,
    payloads: [Snapshot; 3],
    receipt: risc0_zkvm::Receipt,
    outer: Vec<u8>,
}

impl AuthenticatedSharedCheckpoint {
    /// Authenticate and retain the SAME reads; never verify a path then reload
    /// its receipt as a new authority. Existing public verify/publish stay unchanged.
    pub(crate) fn open(paths: [&Path; 4], checkpoint_root: &Path) -> Result<Self> {
        let inputs = Inputs::read(paths)?;
        let result: Result<_> = (|| {
            let locked = embedded_negative_ancestry_guest_pair()?;
            let admitted = inputs.admit(&locked)?;
            let root = Directory::open(checkpoint_root)?;
            let names = [PAYLOAD_NAMES[0], PAYLOAD_NAMES[1], PAYLOAD_NAMES[2], MANIFEST];
            require_names(&root, &names)?;
            let manifest = Snapshot::read_at(&root, MANIFEST, MANIFEST_MAX_BYTES)?;
            let expected = Checkpoint::decode(manifest.bytes())?;
            let payloads = payload_snapshots(&root)?;
            let mut nodes = inputs.files.iter().map(Snapshot::node).collect::<BTreeSet<_>>();
            ensure!(nodes.insert(manifest.node()), "local reused checkpoint aliases an input");
            for file in &payloads {
                ensure!(nodes.insert(file.node()), "local reused checkpoint identities are duplicated");
            }
            let bytes = payload_bytes(&payloads);
            ensure!(bytes[2] == admitted.statement(), "local derived statement mismatch");
            let receipt = admitted.replay(&bytes[0], &bytes[1])?;
            let outer = borsh::to_vec(&receipt)?;
            ensure!(expected_checkpoint(&inputs, &locked, &bytes, &outer) == expected,
                "local reused checkpoint manifest identity mismatch");
            for file in &payloads { file.verify()?; }
            manifest.verify()?;
            require_names(&root, &names)?;
            root.verify()?;
            Ok((locked, admitted, root, manifest, payloads, receipt, outer))
        })();
        inputs.verify()?;
        let (locked, admitted, root, manifest, payloads, receipt, outer) = result?;
        let value = Self { inputs, locked, admitted, root, manifest, payloads, receipt, outer };
        value.verify()?;
        Ok(value)
    }

    pub(crate) fn statement(&self) -> &[u8] { self.admitted.statement() }
    pub(crate) fn consumer(&self) -> (&[u8], risc0_zkvm::Digest) { self.locked.consumer() }
    pub(crate) fn manifest_bytes(&self) -> &[u8] { self.manifest.bytes() }
    pub(crate) fn outer_bytes(&self) -> &[u8] { &self.outer }

    pub(crate) fn receipt_clone(&self) -> Result<risc0_zkvm::Receipt> {
        self.verify()?;
        let receipt = self.receipt.clone();
        ensure!(borsh::to_vec(&receipt)? == self.outer, "local reused Receipt outer bytes drift");
        Ok(receipt)
    }

    pub(crate) fn verify(&self) -> Result<()> {
        ensure!(borsh::to_vec(&self.receipt)? == self.outer, "local reused Receipt outer bytes drift");
        for file in &self.payloads { file.verify()?; }
        self.manifest.verify()?;
        require_names(&self.root, &[PAYLOAD_NAMES[0], PAYLOAD_NAMES[1], PAYLOAD_NAMES[2], MANIFEST])?;
        self.root.verify()?;
        self.inputs.verify()
    }
}

fn payload_bytes(files: &[Snapshot; 3]) -> [Vec<u8>; 3] {
    std::array::from_fn(|i| files[i].bytes.clone())
}

fn publish(root: &Directory, payloads: &[Vec<u8>; 3], expected: &Checkpoint,
           mut replay: impl FnMut(&[Vec<u8>; 3]) -> Result<Checkpoint>,
           mut conserve: impl FnMut() -> Result<()>) -> Result<()> {
    root.verify()?;
    require_names(root, &[])?;
    for (name, body) in PAYLOAD_NAMES.into_iter().zip(payloads) { root.write_new(name, body)?; }
    require_names(root, &PAYLOAD_NAMES)?;
    let files = payload_snapshots(root)?;
    ensure!(replay(&payload_bytes(&files))? == *expected, "local checkpoint rereplay identity mismatch");
    for file in &files { file.verify()?; }
    conserve()?;
    root.verify()?;
    root.write_new(MANIFEST, &expected.encode()?)?;
    root.file().sync_all()?;
    verify_published(root, &mut replay, || {
        for file in &files { file.verify()?; }
        root.verify()?;
        conserve()
    })
}

fn verify_published(root: &Directory, mut replay: impl FnMut(&[Vec<u8>; 3]) -> Result<Checkpoint>,
                    mut conserve: impl FnMut() -> Result<()>) -> Result<()> {
    let names = [PAYLOAD_NAMES[0], PAYLOAD_NAMES[1], PAYLOAD_NAMES[2], MANIFEST];
    root.verify()?;
    require_names(root, &names)?;
    let manifest = Snapshot::read_at(root, MANIFEST, MANIFEST_MAX_BYTES)?;
    let expected = Checkpoint::decode(&manifest.bytes)?;
    let files = payload_snapshots(root)?;
    let mut nodes: BTreeSet<Node> = files.iter().map(|file| file.node).collect();
    ensure!(nodes.insert(manifest.node) && nodes.len() == 4, "local checkpoint identities are duplicated");
    ensure!(replay(&payload_bytes(&files))? == expected, "local checkpoint manifest identity mismatch");
    for file in &files { file.verify()?; }
    manifest.verify()?;
    require_names(root, &names)?;
    root.verify()?;
    // This is the deciding last operation; no subsequent write or success artifact.
    conserve()
}

pub(crate) struct Snapshot {
    path: PathBuf,
    file: File,
    node: Node,
    signature: Vec<u64>,
    parents: Directory,
    bytes: Vec<u8>,
}

impl Snapshot {
    pub(crate) fn node(&self) -> (u64, u64) { self.node }

    pub(crate) fn bytes(&self) -> &[u8] { &self.bytes }

    pub(crate) fn read(path: &Path, maximum: usize) -> Result<Self> {
        let path = absolute(path)?;
        let parents = Directory::open(path.parent().context("local file has no parent")?)?;
        Self::read_at(&parents, path.file_name().context("local file has no name")?, maximum)
    }

    pub(crate) fn read_at(parent: &Directory, name: impl AsRef<std::ffi::OsStr>, maximum: usize) -> Result<Self> {
        let name = name.as_ref();
        parent.verify()?;
        let parents = parent.try_clone()?;
        let path = parent.join(name);
        let mut file = parents.open_read(name)?;
        let metadata = file.metadata()?;
        ensure!(metadata.len() > 0 && metadata.len() <= maximum as u64, "local file byte bound");
        let (node, links) = file_node(&file)?;
        ensure!(links == 1, "local file must have one link");
        let signature = metadata_signature(&metadata);
        let mut bytes = Vec::with_capacity(usize::try_from(metadata.len())?);
        (&mut file).take(maximum as u64 + 1).read_to_end(&mut bytes)?;
        ensure!(bytes.len() as u64 == metadata.len(), "local file changed length");
        ensure!(metadata_signature(&file.metadata()?) == signature, "local open file changed during read");
        let value = Self { path, file, node, signature, parents, bytes };
        value.verify_identity()?;
        Ok(value)
    }

    fn verify_identity(&self) -> Result<()> {
        self.parents.verify().context("local parent identity drift")?;
        let reopened = self.parents.open_read(self.path.file_name().context("local file has no name")?)?;
        ensure!(file_node(&self.file)? == (self.node, 1) && file_node(&reopened)? == (self.node, 1)
            && metadata_signature(&self.file.metadata()?) == self.signature
            && metadata_signature(&reopened.metadata()?) == self.signature, "local file identity drift");
        Ok(())
    }

    pub(crate) fn verify(&self) -> Result<()> {
        self.verify_identity()?;
        let current = Self::read_at(&self.parents, self.path.file_name().context("local file has no name")?, self.bytes.len())?;
        ensure!(current.node == self.node && current.bytes == self.bytes, "local original bytes drift");
        self.verify_identity()
    }
}

fn absolute(path: &Path) -> Result<PathBuf> {
    ensure!(!path.as_os_str().is_empty() && !path.components().any(|part| matches!(part, Component::ParentDir)),
            "local path is empty or parent traversing");
    std::path::absolute(path).context("cannot make local path absolute")
}

/// All namespace components remain open. Paths are used only for identity
/// revalidation; reads, writes, enumeration and synchronization use descriptors.
pub(crate) struct Directory { path: PathBuf, chain: Vec<(PathBuf, File, Node)> }

impl std::ops::Deref for Directory {
    type Target = Path;
    fn deref(&self) -> &Path { &self.path }
}

#[cfg(unix)]
fn directory_flags() -> rustix::fs::OFlags {
    use rustix::fs::OFlags;
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

fn single_name(name: &std::ffi::OsStr) -> Result<()> {
    let mut parts = Path::new(name).components();
    ensure!(matches!(parts.next(), Some(Component::Normal(_))) && parts.next().is_none(),
            "local descriptor-relative name is not one component");
    Ok(())
}

impl Directory {
    #[cfg(unix)]
    pub(crate) fn open(path: &Path) -> Result<Self> {
        let path = absolute(path)?;
        let first = File::from(rustix::fs::open("/", directory_flags(), rustix::fs::Mode::empty())?);
        let mut current = PathBuf::from("/");
        let mut chain = vec![(current.clone(), first.try_clone()?, file_node(&first)?.0)];
        for component in path.components() {
            match component {
                Component::RootDir => (),
                Component::Normal(name) => {
                    let file = File::from(rustix::fs::openat(&chain.last().expect("root anchor").1,
                        name, directory_flags(), rustix::fs::Mode::empty())?);
                    current.push(name);
                    let node = file_node(&file)?.0;
                    chain.push((current.clone(), file, node));
                }
                _ => anyhow::bail!("local directory component is not physical"),
            }
        }
        Ok(Self { path, chain })
    }

    #[cfg(not(unix))]
    pub(crate) fn open(_: &Path) -> Result<Self> {
        anyhow::bail!("local descriptor-relative custody requires Unix")
    }

    pub(crate) fn file(&self) -> &File { &self.chain.last().expect("retained root directory").1 }

    fn try_clone(&self) -> Result<Self> {
        let chain = self.chain.iter().map(|(path, file, node)| Ok((path.clone(), file.try_clone()?, *node)))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { path: self.path.clone(), chain })
    }

    pub(crate) fn verify(&self) -> Result<()> {
        let current = Self::open(&self.path).context("local directory identity drift")?;
        ensure!(current.chain.len() == self.chain.len(), "local directory identity drift");
        for ((path, retained, node), (other_path, reopened, other_node)) in self.chain.iter().zip(&current.chain) {
            ensure!(path == other_path && node == other_node && retained.metadata()?.is_dir()
                && reopened.metadata()?.is_dir() && file_node(retained)?.0 == *node
                && file_node(retained)?.1 > 0, "local directory identity drift");
        }
        Ok(())
    }

    #[cfg(unix)]
    fn open_read(&self, name: &std::ffi::OsStr) -> Result<File> {
        use rustix::fs::{Mode, OFlags};
        single_name(name)?;
        let file = File::from(rustix::fs::openat(self.file(), name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK, Mode::empty())?);
        ensure!(file.metadata()?.is_file(), "local opened path is not physical");
        Ok(file)
    }

    #[cfg(not(unix))]
    fn open_read(&self, _: &std::ffi::OsStr) -> Result<File> {
        anyhow::bail!("local descriptor-relative custody requires Unix")
    }

    pub(crate) fn write_new(&self, name: &str, bytes: &[u8]) -> Result<()> {
        self.write_new_with(name, bytes, || Ok(()))
    }

    fn write_new_with(&self, name: &str, bytes: &[u8], after_check: impl FnOnce() -> Result<()>) -> Result<()> {
        self.write_new_retained_with(name, bytes, after_check).map(|_| ())
    }

    /// Return the observation already checked against the creation descriptor.
    pub(crate) fn write_new_retained(&self, name: &str, bytes: &[u8]) -> Result<Snapshot> {
        self.write_new_retained_with(name, bytes, || Ok(()))
    }

    #[cfg(unix)]
    fn write_new_retained_with(&self, name: &str, bytes: &[u8], after_check: impl FnOnce() -> Result<()>) -> Result<Snapshot> {
        use rustix::fs::{Mode, OFlags};
        single_name(name.as_ref())?;
        self.verify()?;
        after_check()?; // Deterministic fault seam; production passes an inert closure.
        let mut file = File::from(rustix::fs::openat(self.file(), name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR)?);
        file.write_all(bytes)?; file.sync_all()?;
        self.verify()?;
        let reread = Snapshot::read_at(self, name, bytes.len())?;
        ensure!(file_node(&file)? == (reread.node, 1) && reread.bytes == bytes, "local output write identity drift");
        self.verify()?;
        Ok(reread)
    }

    #[cfg(not(unix))]
    fn write_new_retained_with(&self, _: &str, _: &[u8], _: impl FnOnce() -> Result<()>) -> Result<Snapshot> {
        anyhow::bail!("local descriptor-relative custody requires Unix")
    }
}

pub(crate) fn create_fresh_directory(path: &Path) -> Result<Directory> {
    create_fresh_directory_with(path, || Ok(()), || Ok(()))
}

#[cfg(unix)]
fn create_fresh_directory_with(path: &Path, after_parent: impl FnOnce() -> Result<()>,
                               after_acquire: impl FnOnce() -> Result<()>) -> Result<Directory> {
    let path = absolute(path)?;
    let mut root = Directory::open(path.parent().context("local destination has no parent")?)?;
    let name = path.file_name().context("local destination has no name")?;
    single_name(name)?;
    after_parent()?;
    root.verify()?;
    // Requires a single-writer parent namespace between mkdirat and the first
    // openat. These two syscalls cannot prove atomic same-UID/root isolation.
    rustix::fs::mkdirat(root.file(), name, rustix::fs::Mode::RWXU)
        .context("local destination must be fresh")?;
    let file = File::from(rustix::fs::openat(root.file(), name, directory_flags(), rustix::fs::Mode::empty())?);
    let node = file_node(&file)?.0;
    root.chain.push((path.clone(), file, node)); root.path = path;
    after_acquire()?;
    root.verify()?;
    require_names(&root, &[])?;
    Ok(root)
}

#[cfg(not(unix))]
fn create_fresh_directory_with(_: &Path, _: impl FnOnce() -> Result<()>,
                               _: impl FnOnce() -> Result<()>) -> Result<Directory> {
    anyhow::bail!("local descriptor-relative custody requires Unix")
}

#[cfg(unix)]
pub(crate) fn require_names(root: &Directory, expected: &[&str]) -> Result<()> {
    root.verify()?;
    let mut names = BTreeSet::new();
    let mut directory = rustix::fs::Dir::read_from(root.file())?;
    for entry in &mut directory {
        let entry = entry?;
        let name = entry.file_name().to_str().context("local checkpoint non-UTF8 entry")?;
        if matches!(name, "." | "..") { continue; }
        ensure!(names.len() < expected.len(), "extra local checkpoint entry");
        ensure!(names.insert(name.to_owned()), "duplicate local checkpoint entry");
    }
    ensure!(names == expected.iter().map(|name| (*name).to_owned()).collect(), "local checkpoint inventory mismatch");
    root.verify()
}

#[cfg(not(unix))]
pub(crate) fn require_names(_: &Directory, _: &[&str]) -> Result<()> {
    anyhow::bail!("local descriptor-relative custody requires Unix")
}

#[cfg(unix)]
fn file_node(file: &File) -> Result<(Node, u64)> {
    use std::os::unix::fs::MetadataExt as _;
    let meta = file.metadata()?; Ok(((meta.dev(), meta.ino()), meta.nlink()))
}

#[cfg(windows)]
fn file_node(file: &File) -> Result<(Node, u64)> {
    let info = winapi_util::file::information(file)?;
    Ok(((info.volume_serial_number(), info.file_index()), info.number_of_links()))
}

#[cfg(unix)]
fn metadata_signature(meta: &Metadata) -> Vec<u64> {
    use std::os::unix::fs::MetadataExt as _;
    vec![meta.len(), meta.mode() as u64, meta.mtime() as u64, meta.mtime_nsec() as u64,
         meta.ctime() as u64, meta.ctime_nsec() as u64]
}

#[cfg(windows)]
fn metadata_signature(meta: &Metadata) -> Vec<u64> {
    use std::os::windows::fs::MetadataExt as _;
    vec![meta.len(), meta.file_attributes() as u64, meta.creation_time(), meta.last_write_time()]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::atomic::{AtomicU64, Ordering}, time::{SystemTime, UNIX_EPOCH}};

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let root = std::env::temp_dir().join(format!("local-assumption-source-tests-{}-{}-{}",
                std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos(), NEXT.fetch_add(1, Ordering::Relaxed)));
            fs::create_dir(&root).unwrap(); Self(root)
        }
    }
    impl Drop for Fixture { fn drop(&mut self) { fs::remove_dir_all(&self.0).unwrap(); } }

    fn synthetic_manifest(payloads: &[Vec<u8>; 3]) -> Checkpoint {
        let named = |name: &str, body: &[u8]| NamedPin { name: name.to_owned(), pin: Pin::of(body) };
        Checkpoint { schema: "eip0045.local-ancestry-shared-assumption.v1".to_owned(), version: 1,
            role: "alternate-chain-domain-shared-assumption".to_owned(), terminal: "stock-lift15".to_owned(),
            inputs: std::array::from_fn(|i| named(INPUT_ROLES[i], b"synthetic input")),
            consumer: GuestPin { elf: Pin::of(b"consumer"), image_id: "00".repeat(32) },
            alternate: GuestPin { elf: Pin::of(b"alternate"), image_id: "11".repeat(32) },
            payloads: std::array::from_fn(|i| named(PAYLOAD_NAMES[i], &payloads[i])),
            outer_receipt_borsh: Pin::of(b"synthetic outer Receipt") }
    }

    #[test]
    fn manifest_is_exact_typed_canonical_and_rejects_each_field_drift() {
        let original = synthetic_manifest(&[vec![1], vec![2], vec![3]]);
        let bytes = original.encode().unwrap();
        assert_eq!(Checkpoint::decode(&bytes).unwrap(), original);
        for body in [b"".to_vec(), [bytes.clone(), b" ".to_vec()].concat(),
            vec![b' '; MANIFEST_MAX_BYTES + 1], b"{\"version\":1,\"version\":1}".to_vec()] {
            assert!(Checkpoint::decode(&body).is_err());
        }
        // JCS erases the lexical 1.0 fault by normalizing it to 1. Feed the
        // isolated floating token directly to the typed decoder instead.
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert_eq!(text.matches("\"version\":1").count(), 1, "version mutation anchor");
        let floating = text.replacen("\"version\":1", "\"version\":1.0", 1).into_bytes();
        assert_ne!(floating, bytes, "floating version mutation was erased");
        let generic: serde_json::Value = serde_json::from_slice(&floating).unwrap();
        assert_eq!(canonical_json_bytes(&generic).unwrap(), bytes, "JCS floating version normalization");
        assert_eq!(Checkpoint::decode(&floating).unwrap_err().to_string(),
            "local checkpoint manifest typed JSON", "floating version must fail typed decoding");
        for (field, replacement) in [("version", serde_json::json!(true)),
            ("unknown", serde_json::json!(1)), ("inputs", serde_json::json!([])), ("payloads", serde_json::json!([]))] {
            let mut value = serde_json::to_value(&original).unwrap(); value[field] = replacement;
            assert!(Checkpoint::decode(&canonical_json_bytes(&value).unwrap()).is_err(),
                "typed manifest field {field} mutation accepted");
        }
        // Shape-correct altered fields decode, but never equal independently derived expectations.
        for field in ["schema", "role", "terminal"] {
            let mut value = serde_json::to_value(&original).unwrap(); value[field] = serde_json::json!("wrong");
            assert_ne!(Checkpoint::decode(&canonical_json_bytes(&value).unwrap()).unwrap(), original,
                "manifest identity field {field} mutation accepted");
        }
        for field in ["consumer", "alternate", "outer_receipt_borsh"] {
            let mut value = serde_json::to_value(&original).unwrap();
            if field == "outer_receipt_borsh" { value[field]["sha256"] = serde_json::json!("00".repeat(32)); }
            else { value[field]["image_id"] = serde_json::json!("22".repeat(32)); }
            assert_ne!(Checkpoint::decode(&canonical_json_bytes(&value).unwrap()).unwrap(), original,
                "manifest binding field {field} mutation accepted");
        }
    }

    #[cfg(unix)]
    #[test]
    fn physical_reader_bounds_identity_links_and_late_bytes_are_closed() {
        let f = Fixture::new(); let path = f.0.join("input"); fs::write(&path, b"abc").unwrap();
        let original = Snapshot::read(&path, 3).unwrap(); original.verify().unwrap();
        assert!(Snapshot::read(&path, 2).is_err());
        let alias = f.0.join("outside-alias"); fs::hard_link(&path, &alias).unwrap();
        assert_eq!(Snapshot::read(&path, 3).err().unwrap().to_string(), "local file must have one link");
        fs::remove_file(&alias).unwrap();
        let original = Snapshot::read(&path, 3).unwrap();
        fs::write(&path, b"abd").unwrap(); assert!(original.verify().is_err());
        fs::write(&path, b"").unwrap(); assert!(Snapshot::read(&path, 3).is_err());
        fs::remove_file(&path).unwrap(); fs::create_dir(&path).unwrap(); assert!(Snapshot::read(&path, 3).is_err());
        assert!(absolute(&f.0.join("../escape")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn physical_reader_rejects_leaf_parent_symlinks_and_same_byte_replacement() {
        use std::os::unix::fs::symlink;
        let f = Fixture::new(); let dir = f.0.join("real"); fs::create_dir(&dir).unwrap();
        let path = dir.join("input"); fs::write(&path, b"abc").unwrap();
        let alias = f.0.join("alias"); symlink(&dir, &alias).unwrap();
        assert!(Snapshot::read(&alias.join("input"), 3).is_err());
        symlink(&path, f.0.join("leaf")).unwrap(); assert!(Snapshot::read(&f.0.join("leaf"), 3).is_err());
        let original = Snapshot::read(&path, 3).unwrap();
        fs::rename(&path, dir.join("old")).unwrap(); fs::write(&path, b"abc").unwrap();
        assert_eq!(original.verify().err().unwrap().to_string(), "local file identity drift");
    }

    #[cfg(unix)]
    #[test]
    fn physical_inputs_reject_duplicate_identity_and_exact_seal_length() {
        let f = Fixture::new();
        let paths: [PathBuf; 4] = std::array::from_fn(|i| f.0.join(i.to_string()));
        for (i, path) in paths.iter().enumerate() { fs::write(path, vec![1; if i >= 2 { PROOF_BYTES } else { 1 }]).unwrap(); }
        let refs = std::array::from_fn(|i| paths[i].as_path());
        Inputs::read(refs).unwrap().verify().unwrap();
        assert_eq!(Inputs::read([&paths[0], &paths[0], &paths[2], &paths[3]]).err().unwrap().to_string(), "local input identities are duplicated");
        fs::write(&paths[2], vec![1; PROOF_BYTES - 1]).unwrap();
        assert_eq!(Inputs::read(refs).err().unwrap().to_string(), "local Case9 raw seal byte length");
    }

    #[cfg(unix)]
    #[test]
    fn actual_publication_seam_reopens_before_and_after_manifest_and_conserves_last() {
        // Synthetic verifier seam only: this fixture does not assert cryptographic validity.
        let f = Fixture::new(); let root = create_fresh_directory(&f.0.join("checkpoint")).unwrap();
        let payloads = [vec![1], vec![2], vec![3]]; let expected = synthetic_manifest(&payloads);
        let calls = std::cell::RefCell::new(Vec::new());
        publish(&root, &payloads, &expected, |actual| {
            assert_eq!(actual, &payloads); calls.borrow_mut().push("replay"); Ok(expected.clone())
        }, || { calls.borrow_mut().push("conserve"); Ok(()) }).unwrap();
        assert_eq!(*calls.borrow(), ["replay", "conserve", "replay", "conserve"]);
        verify_published(&root, |_| Ok(expected.clone()), || Ok(())).unwrap();
        assert!(create_fresh_directory(&root).is_err());
        fs::write(root.join("extra"), b"x").unwrap();
        assert_eq!(verify_published(&root, |_| Ok(expected.clone()), || Ok(())).err().unwrap().to_string(), "extra local checkpoint entry");
    }

    #[cfg(unix)]
    #[test]
    fn publication_retains_first_payload_identity_across_conservation() {
        // Real publication and custody; only cryptographic replay is synthetic.
        for index in 0..PAYLOAD_NAMES.len() {
            for replace in [false, true, false] {
                let f = Fixture::new(); let root = create_fresh_directory(&f.0.join("checkpoint")).unwrap();
                let payloads = [vec![1], vec![2], vec![3]]; let expected = synthetic_manifest(&payloads);
                let held = f.0.join("outside-held");
                let mut first_node = None; let mut replays = 0; let mut conservations = 0;
                let result = publish(&root, &payloads, &expected, |actual| {
                    assert_eq!(actual, &payloads); replays += 1; Ok(expected.clone())
                }, || {
                    conservations += 1;
                    if replace && conservations == 1 {
                        first_node = Some(Snapshot::read_at(&root, PAYLOAD_NAMES[index], payloads[index].len())?.node());
                        fs::rename(root.join(PAYLOAD_NAMES[index]), &held)?;
                        fs::write(root.join(PAYLOAD_NAMES[index]), &payloads[index])?;
                    }
                    Ok(())
                });
                assert_eq!(replays, 2);
                require_names(&root, &[PAYLOAD_NAMES[0], PAYLOAD_NAMES[1], PAYLOAD_NAMES[2], MANIFEST]).unwrap();
                assert_eq!(fs::read(root.join(MANIFEST)).unwrap(), expected.encode().unwrap());
                if replace {
                    assert_eq!(result.unwrap_err().to_string(), "local file identity drift");
                    assert_eq!(conservations, 1);
                    let original = Snapshot::read(&held, payloads[index].len()).unwrap();
                    let replacement = Snapshot::read_at(&root, PAYLOAD_NAMES[index], payloads[index].len()).unwrap();
                    assert_eq!(Some(original.node()), first_node);
                    assert_ne!(original.node(), replacement.node());
                    assert_eq!(original.bytes(), payloads[index].as_slice());
                    assert_eq!(replacement.bytes(), original.bytes());
                } else {
                    result.unwrap(); assert_eq!(conservations, 2); assert!(!held.exists());
                    verify_published(&root, |_| Ok(expected.clone()), || Ok(())).unwrap();
                }
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn omitted_replay_or_final_conservation_cannot_pass_the_failure_seams() {
        for fault in ["replay", "late-replay", "conservation"] {
            let f = Fixture::new(); let root = create_fresh_directory(&f.0.join("checkpoint")).unwrap();
            let payloads = [vec![1], vec![2], vec![3]]; let expected = synthetic_manifest(&payloads);
            let mut replay_count = 0; let mut conservation_count = 0;
            let error = publish(&root, &payloads, &expected, |_| {
                replay_count += 1;
                ensure!(fault != "replay" && !(fault == "late-replay" && replay_count == 2), "synthetic replay rejected");
                Ok(expected.clone())
            }, || {
                conservation_count += 1;
                ensure!(fault != "conservation" || conservation_count != 2, "synthetic original drift"); Ok(())
            }).unwrap_err();
            assert_eq!(error.to_string(), if fault == "conservation" { "synthetic original drift" } else { "synthetic replay rejected" });
            assert!(root.exists());
            assert_eq!(root.join(MANIFEST).exists(), fault != "replay");
        }
    }

    #[cfg(unix)]
    #[test]
    fn actual_reread_rejects_payload_manifest_and_late_original_drift() {
        let f = Fixture::new(); let root = create_fresh_directory(&f.0.join("checkpoint")).unwrap();
        let payloads = [vec![1], vec![2], vec![3]]; let expected = synthetic_manifest(&payloads);
        let origin = f.0.join("origin"); fs::write(&origin, b"abc").unwrap(); let snapshot = Snapshot::read(&origin, 3).unwrap();
        let mut count = 0;
        let error = publish(&root, &payloads, &expected, |_| {
            count += 1; if count == 2 { fs::write(&origin, b"abd")?; } Ok(expected.clone())
        }, || snapshot.verify()).unwrap_err();
        assert_eq!(error.to_string(), "local file identity drift");
        assert!(root.join(MANIFEST).exists());
        let check = |actual: &[Vec<u8>; 3]| -> Result<Checkpoint> {
            ensure!(actual == &payloads, "synthetic payload drift"); Ok(expected.clone())
        };
        fs::write(root.join(PAYLOAD_NAMES[0]), [9]).unwrap();
        assert_eq!(verify_published(&root, check, || Ok(())).err().unwrap().to_string(), "synthetic payload drift");
        fs::write(root.join(PAYLOAD_NAMES[0]), &payloads[0]).unwrap();
        let mut changed = expected.clone(); changed.outer_receipt_borsh.bytes += 1;
        fs::write(root.join(MANIFEST), changed.encode().unwrap()).unwrap();
        assert_eq!(verify_published(&root, check, || Ok(())).err().unwrap().to_string(), "local checkpoint manifest identity mismatch");
    }

    #[cfg(unix)]
    #[test]
    fn publication_rejects_raced_manifest_missing_payload_and_alias_without_cleanup() {
        for fault in ["occupied-manifest", "missing", "hardlink", "empty-directory"] {
            let f = Fixture::new(); let root = create_fresh_directory(&f.0.join("checkpoint")).unwrap();
            let payloads = [vec![1], vec![2], vec![3]]; let expected = synthetic_manifest(&payloads);
            if fault == "occupied-manifest" {
                let mut calls = 0;
                let result = publish(&root, &payloads, &expected, |_| Ok(expected.clone()), || {
                    calls += 1;
                    if calls == 1 { fs::write(root.join(MANIFEST), b"raced original")?; }
                    Ok(())
                });
                assert!(result.is_err()); assert_eq!(fs::read(root.join(MANIFEST)).unwrap(), b"raced original");
            } else {
                publish(&root, &payloads, &expected, |_| Ok(expected.clone()), || Ok(())).unwrap();
                if fault == "missing" { fs::remove_file(root.join(PAYLOAD_NAMES[0])).unwrap(); }
                if fault == "hardlink" { fs::hard_link(root.join(PAYLOAD_NAMES[0]), f.0.join("outside-alias")).unwrap(); }
                if fault == "empty-directory" { fs::create_dir(root.join("extra-dir")).unwrap(); }
                let error = verify_published(&root, |_| Ok(expected.clone()), || Ok(())).unwrap_err();
                assert_eq!(error.to_string(), match fault {
                    "missing" => "local checkpoint inventory mismatch",
                    "hardlink" => "local file must have one link",
                    "empty-directory" => "extra local checkpoint entry", _ => unreachable!(),
                });
                assert!(root.join(MANIFEST).exists());
            }
            assert!(root.exists());
        }
    }

    #[cfg(unix)]
    #[test]
    fn retained_parent_and_root_replacement_deny_without_outside_writes() {
        use std::os::unix::fs::symlink;
        for stage in ["parent", "root"] {
          for replacement in ["symlink", "directory"] {
            let f = Fixture::new();
            let parent = f.0.join("parent"); let outside = f.0.join("outside");
            fs::create_dir(&parent).unwrap(); fs::create_dir(&outside).unwrap();
            let target = parent.join("checkpoint"); let retired = f.0.join("retired");
            let replace = |path: &Path| -> Result<()> {
                fs::rename(path, &retired)?;
                if replacement == "symlink" { symlink(&outside, path)?; }
                else { fs::create_dir(path)?; }
                Ok(())
            };
            let error = create_fresh_directory_with(&target, || {
                if stage == "parent" { replace(&parent)?; }
                Ok(())
            }, || {
                if stage == "root" { replace(&target)?; }
                Ok(())
            }).err().unwrap();
            assert_eq!(error.to_string(), "local directory identity drift");
            assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
            assert_eq!(fs::read_dir(&retired).unwrap().count(), 0);
            let replaced = if stage == "parent" { &parent } else { &target };
            assert_eq!(fs::read_dir(replaced).unwrap().count(), 0);
          }
        }
        let f = Fixture::new(); let target = f.0.join("occupied");
        fs::create_dir(&target).unwrap(); fs::write(target.join("original"), b"retained").unwrap();
        assert_eq!(create_fresh_directory(&target).err().unwrap().to_string(), "local destination must be fresh");
        assert_eq!(fs::read(target.join("original")).unwrap(), b"retained");
    }

    #[cfg(unix)]
    #[test]
    fn descriptor_relative_write_cannot_follow_late_parent_or_root_redirection() {
        use std::os::unix::fs::symlink;
        for stage in ["parent", "root"] {
          for replacement in ["symlink", "directory"] {
            let f = Fixture::new(); let parent = f.0.join("parent");
            let outside = f.0.join("outside"); let retired = f.0.join("retired");
            fs::create_dir(&parent).unwrap(); fs::create_dir(&outside).unwrap();
            // A path-based mutant would find a writable matching outside subtree.
            fs::create_dir(outside.join("checkpoint")).unwrap();
            let root = create_fresh_directory(&parent.join("checkpoint")).unwrap();
            let error = root.write_new_with("payload", b"retained partial", || {
                let path = if stage == "parent" { parent.as_path() } else { &*root };
                fs::rename(path, &retired)?;
                if replacement == "symlink" { symlink(&outside, path)?; }
                else {
                    fs::create_dir(path)?;
                    if stage == "parent" { fs::create_dir(parent.join("checkpoint"))?; }
                }
                Ok(())
            }).unwrap_err();
            assert_eq!(error.to_string(), "local directory identity drift");
            assert!(!outside.join("payload").exists());
            assert!(!outside.join("checkpoint/payload").exists());
            assert!(!root.join("payload").exists());
            let partial = if stage == "parent" { retired.join("checkpoint/payload") } else { retired.join("payload") };
            assert_eq!(fs::read(partial).unwrap(), b"retained partial");
          }
        }
    }

    #[cfg(not(unix))]
    #[test]
    fn unsupported_host_custody_denies_before_creation() {
        let f = Fixture::new(); let target = f.0.join("checkpoint");
        assert_eq!(create_fresh_directory(&target).err().unwrap().to_string(), "local descriptor-relative custody requires Unix");
        assert!(!target.exists());
        assert_eq!(Directory::open(&f.0).err().unwrap().to_string(), "local descriptor-relative custody requires Unix");
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "requires only retained authentic Case9 inputs; no shared checkpoint or proving"]
    fn genuine_case9_admission_rejects_interior_proof_corruption() -> Result<()> {
        use crate::recursive::{decode_recursive_oracle, encode_recursive_oracle};
        let paths = ["EIP0045_SHARED_CANONICAL_STATEMENT", "EIP0045_SHARED_CASE9_ORACLE",
                     "EIP0045_SHARED_CASE9_ASSUMPTION_RAW", "EIP0045_SHARED_CASE9_FINAL_RAW"]
            .map(|name| std::env::var_os(name).map(PathBuf::from).with_context(|| format!("missing {name}")))
            .into_iter().collect::<Result<Vec<_>>>()?;
        let inputs = Inputs::read([&paths[0], &paths[1], &paths[2], &paths[3]])?;
        let locked = embedded_negative_ancestry_guest_pair()?;
        inputs.admit(&locked)?;
        let original = decode_recursive_oracle(&inputs.files[1].bytes)?;
        assert_eq!(encode_recursive_oracle(&original)?, inputs.files[1].bytes);
        assert_eq!(original.steps.len(), 2); assert_eq!(original.final_step, 1);
        // Only the interior Lift proof words change. All graph selectors, claims,
        // source, independent assumption, final Resolve and supplied raw seals stay exact.
        let mut corrupt = original.clone();
        assert!(!corrupt.steps[0].receipt.seal.is_empty());
        corrupt.steps[0].receipt.seal[0] ^= 1;
        let changed = encode_recursive_oracle(&corrupt)?;
        assert_eq!(changed.len(), inputs.files[1].bytes.len());
        assert_ne!(changed, inputs.files[1].bytes);
        assert_eq!(encode_recursive_oracle(&decode_recursive_oracle(&changed)?)?, changed);
        assert_eq!(borsh::to_vec(&corrupt.source_receipt)?, borsh::to_vec(&original.source_receipt)?);
        assert_eq!(borsh::to_vec(&corrupt.assumption_receipt)?, borsh::to_vec(&original.assumption_receipt)?);
        assert_eq!(borsh::to_vec(&corrupt.steps[1])?, borsh::to_vec(&original.steps[1])?);
        let error = admit_local_shared_assumption(&locked, &inputs.files[0].bytes, &changed,
            &inputs.files[2].bytes, &inputs.files[3].bytes).err().context("corrupt interior proof was accepted")?;
        assert!(error.chain().any(|cause| cause.to_string() == "recursive oracle failed complete replay"), "{error:#}");
        // With only validate_recursive_oracle omitted in authenticate_recursive_oracle_bytes,
        // admission succeeds and the assertion above fails: parsing/graph/seal guards alone
        // cannot reject this exact-typed single fault.
        inputs.admit(&locked)?;
        inputs.verify()
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "requires retained authentic Case9 inputs and a separately proved local checkpoint; never generates proofs"]
    fn genuine_reused_checkpoint_retains_receipt_and_first_physical_custody() -> Result<()> {
        let paths = ["EIP0045_SHARED_CANONICAL_STATEMENT", "EIP0045_SHARED_CASE9_ORACLE",
            "EIP0045_SHARED_CASE9_ASSUMPTION_RAW", "EIP0045_SHARED_CASE9_FINAL_RAW"]
            .map(|name| std::env::var_os(name).map(PathBuf::from).with_context(|| format!("missing {name}")))
            .into_iter().collect::<Result<Vec<_>>>()?;
        let original_root = PathBuf::from(std::env::var_os("EIP0045_SHARED_CHECKPOINT").context("missing local checkpoint")?);
        let originals = Inputs::read([&paths[0], &paths[1], &paths[2], &paths[3]])?;
        let original_dir = Directory::open(&original_root)?;
        let original_payloads = payload_snapshots(&original_dir)?;
        let original_manifest = Snapshot::read_at(&original_dir, MANIFEST, MANIFEST_MAX_BYTES)?;
        let names = [PAYLOAD_NAMES[0], PAYLOAD_NAMES[1], PAYLOAD_NAMES[2], MANIFEST];
        let bodies = [original_payloads[0].bytes(), original_payloads[1].bytes(), original_payloads[2].bytes(), original_manifest.bytes()];
        let f = Fixture::new();
        let copies: [PathBuf; 4] = std::array::from_fn(|i| f.0.join(format!("input-{i}")));
        for i in 0..4 { fs::write(&copies[i], originals.files[i].bytes())?; }
        let refs = std::array::from_fn(|i| copies[i].as_path());
        for fault in ["outer", "payload", "manifest", "root", "parent", "input", "extra"] {
            let parent = f.0.join(fault); fs::create_dir(&parent)?;
            let root = parent.join("checkpoint"); fs::create_dir(&root)?;
            for i in 0..4 { fs::write(root.join(names[i]), bodies[i])?; }
            let mut retained = AuthenticatedSharedCheckpoint::open(refs, &root)?;
            let bytes = retained.outer_bytes().to_vec();
            assert_eq!(borsh::to_vec(&retained.receipt_clone()?)?, bytes);
            match fault {
                "outer" => retained.receipt.metadata.verifier_parameters =
                    if retained.receipt.metadata.verifier_parameters == risc0_zkvm::Digest::ZERO {
                        risc0_zkvm::Digest::from([1_u32; 8])
                    } else { risc0_zkvm::Digest::ZERO },
                "payload" | "manifest" => {
                    let i = if fault == "payload" { 0 } else { 3 };
                    fs::rename(root.join(names[i]), parent.join("old-file"))?;
                    fs::write(root.join(names[i]), bodies[i])?;
                }
                "root" => {
                    fs::rename(&root, parent.join("old-root"))?; fs::create_dir(&root)?;
                    for i in 0..4 { fs::write(root.join(names[i]), bodies[i])?; }
                }
                "parent" => {
                    fs::rename(&parent, f.0.join("old-parent"))?;
                    fs::create_dir(&parent)?; fs::create_dir(&root)?;
                    for i in 0..4 { fs::write(root.join(names[i]), bodies[i])?; }
                }
                "input" => {
                    fs::rename(&copies[0], f.0.join("old-input"))?;
                    fs::write(&copies[0], originals.files[0].bytes())?;
                }
                "extra" => { fs::write(root.join("extra"), b"x")?; }
                _ => unreachable!(),
            }
            let error = retained.verify().unwrap_err();
            let expected = match fault {
                "outer" => "local reused Receipt outer bytes drift", "input" => "local original input conservation",
                "root" | "parent" => "local parent identity drift", "extra" => "extra local checkpoint entry",
                _ => "local file identity drift",
            };
            assert_eq!(error.to_string(), expected, "{fault}: {error:#}");
            assert!(retained.receipt_clone().is_err(), "{fault}: cloning bypassed custody");
            if fault == "extra" { fs::remove_file(root.join("extra"))?; }
            // A fresh explicit admission is the positive control, not a replacement
            // of the failed handle's first identity. Real retained inputs never change.
            AuthenticatedSharedCheckpoint::open(refs, &root)?.verify()?;
        }
        originals.verify()?;
        for file in &original_payloads { file.verify()?; }
        original_manifest.verify()?;
        original_dir.verify()
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "requires retained authentic Case9 inputs and a separately proved local checkpoint; never generates proofs"]
    fn genuine_checkpoint_replay_and_single_faults() -> Result<()> {
        let paths = ["EIP0045_SHARED_CANONICAL_STATEMENT", "EIP0045_SHARED_CASE9_ORACLE",
                     "EIP0045_SHARED_CASE9_ASSUMPTION_RAW", "EIP0045_SHARED_CASE9_FINAL_RAW"]
            .map(|name| std::env::var_os(name).map(PathBuf::from).with_context(|| format!("missing {name}")))
            .into_iter().collect::<Result<Vec<_>>>()?;
        let refs = [&*paths[0], &*paths[1], &*paths[2], &*paths[3]];
        let root = PathBuf::from(std::env::var_os("EIP0045_SHARED_CHECKPOINT").context("missing local checkpoint")?);
        verify(refs, &root)?;
        let inputs = Inputs::read(refs)?;
        let locked = embedded_negative_ancestry_guest_pair()?;
        let admitted = inputs.admit(&locked)?;
        let checkpoint = Directory::open(&root)?;
        let files = payload_snapshots(&checkpoint)?;
        let payloads = payload_bytes(&files);
        let original = admitted.replay(&payloads[0], &payloads[1])?;
        let mut metadata = original.clone();
        metadata.metadata.verifier_parameters = risc0_zkvm::Digest::ZERO;
        if metadata.metadata.verifier_parameters == original.metadata.verifier_parameters {
            metadata.metadata.verifier_parameters = risc0_zkvm::Digest::from([1_u32; 8]);
        }
        assert!(admitted.checkpoint_parts(&metadata).is_err());
        for fault in ["control", "parameters", "hashfn", "claim", "raw", "trailing"] {
            let mut inner = crate::receipt_oracle_wire::decode_succinct_receipt_oracle::<risc0_zkvm::ReceiptClaim>(&payloads[0])?;
            let mut raw = payloads[1].clone();
            match fault {
                "control" => inner.control_id = crate::expected_normal_lift_control_id(16)?,
                "parameters" => inner.verifier_parameters = risc0_zkvm::Digest::ZERO,
                "hashfn" => inner.hashfn = "sha-256".to_owned(),
                "claim" => inner.claim = risc0_zkvm::MaybePruned::Pruned(risc0_zkvm::Digest::ZERO),
                "raw" => raw[0] ^= 1,
                "trailing" => (),
                _ => unreachable!(),
            }
            let mut oracle = crate::receipt_oracle_wire::encode_succinct_receipt_oracle(&inner)?;
            if fault == "trailing" { oracle.push(0); }
            assert!(admitted.replay(&oracle, &raw).is_err(), "isolated {fault} mutation accepted");
        }
        for fault in ["statement", "assumption", "final", "oracle"] {
            let mut bytes: [Vec<u8>; 4] = std::array::from_fn(|i| inputs.files[i].bytes.clone());
            let index = match fault { "statement" => 0, "oracle" => 1, "assumption" => 2, "final" => 3, _ => unreachable!() };
            if fault == "oracle" { bytes[index].push(0); } else { bytes[index][0] ^= 1; }
            assert!(admit_local_shared_assumption(&locked, &bytes[0], &bytes[1], &bytes[2], &bytes[3]).is_err(),
                    "isolated Case9 {fault} mutation accepted");
        }
        inputs.verify()?;
        for file in &files { file.verify()?; }
        verify(refs, &root)
    }
}
