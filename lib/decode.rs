//! This module handles decoding and de-globbing of rules
use std::borrow::{Borrow, Cow};
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::fmt::Formatter;
use std::hash::Hash;
use std::ops::Deref;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use bimap::hash::RightValues;
use bimap::BiMap;
use bstr::ByteSlice;
use daggy::Dag;
use log::{debug, log_enabled};
use parking_lot::{MappedRwLockReadGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};
use path_dedot::ParseDot;
use pathdiff::diff_paths;
use petgraph::graph::NodeIndex;
use regex::{Captures, Regex};
use walkdir::WalkDir;

use errors::{Error as Err, Error};
use glob;
use glob::{Candidate, GlobBuilder, GlobMatcher};
use statements::*;
use transform::{get_parent, Artifacts, TupParser};

pub(crate) fn without_curdir_prefix(p: &Path) -> Cow<'_, Path> {
    let p = if p
        .components()
        .take_while(|x| Component::CurDir.eq(x))
        .count()
        > 0
    {
        let p: PathBuf = p
            .components()
            .skip_while(|x| Component::CurDir.eq(x))
            .collect();
        debug_assert!(!p
            .components()
            .any(|ref c| Component::ParentDir.eq(c) || Component::CurDir.eq(c)));
        Cow::Owned(p)
    } else {
        Cow::Borrowed(p)
    };
    p
}

/// Trait to discover paths from an external source (such as a database)
pub trait PathSearcher {
    /// Discover paths from glob string
    fn discover_paths(
        &self,
        path_buffers: &mut impl PathBuffers,
        glob_path: &GlobPath,
    ) -> Result<Vec<MatchingPath>, Error>;

    /// Find Outputs
    fn get_outs(&self) -> &OutputHolder;

    /// Merge outputs from previous outputs
    fn merge(&mut self, p: &impl PathBuffers, o: &impl OutputHandler) -> Result<(), Error>;
}

/// Methods to store and retrieve paths, groups, bins, rules from in-memory buffers
/// This way we can identify paths /groups/bins and environment by their unique descriptors (ids)
pub trait PathBuffers {
    /// Add path of bin. Folder is the one where  Tupfile declaring the bin. name is bin name
    fn add_bin_path_expr(&mut self, tup_cwd: &Path, pe: &str) -> (BinDescriptor, bool);

    /// add env var and fetch its descriptor
    fn add_env(&mut self, e: Cow<Env>) -> (EnvDescriptor, bool);

    /// Add a path to a group in this buffer
    fn add_group_pathexpr(&mut self, tup_cwd: &Path, pe: &str) -> (GroupPathDescriptor, bool);

    /// add a path from root and fetch its unique id
    fn add_abs(&mut self, path: &Path) -> (PathDescriptor, bool);
    /// add a path relative to tup_cwd and fetch its unique id
    fn add_path_from<P: AsRef<Path>>(&mut self, tup_cwd: &Path, path: P) -> (PathDescriptor, bool);

    /// add a rule and fetch a unique id
    fn add_rule(&mut self, rule: RuleFormulaUsage) -> (RuleDescriptor, bool);

    /// add tup file and fetch its unique id
    fn add_tup(&mut self, p: &Path) -> (TupPathDescriptor, bool);

    /// add env vars and fetch an id for them
    fn add_env_var(&mut self, var: String, cur_env_desc: &EnvDescriptor) -> EnvDescriptor;

    /// Return input path from resolved input
    fn get_input_path_name(&self, i: &InputResolvedType) -> String;
    /// Return parent folder id from input path descriptor
    fn get_parent_id(&self, pd: &PathDescriptor) -> Option<PathDescriptor>;
    /// get id stored against input path
    fn get_id(&self, np: &NormalPath) -> Option<&PathDescriptor>;

    /// return path from its descriptor
    fn get_path(&self, pd: &PathDescriptor) -> &NormalPath;
    /// return path from its descriptor
    fn get_rel_path(&self, pd: &PathDescriptor, vd: &PathDescriptor) -> NormalPath;
    /// Return Rule from its descriptor
    fn get_rule(&self, rd: &RuleDescriptor) -> &RuleFormulaUsage;
    /// return Env from its descriptor
    fn try_get_env(&self, ed: &EnvDescriptor) -> Option<&Env>;
    /// Return tup file path
    fn get_tup_path(&self, p: &TupPathDescriptor) -> &Path;
    /// Return path from its descriptor
    fn try_get_path(&self, id: &PathDescriptor) -> Option<&NormalPath>;

    /// Try get a bin path entry by its descriptor.
    fn try_get_group_path(&self, gd: &GroupPathDescriptor) -> Option<&NormalPath>;

    /// Get group ids as an iter
    fn get_group_descs(&self) -> RightValues<'_, NormalPath, GroupPathDescriptor>;
    /// Get tup id corresponding to its path
    fn get_tup_id(&self, p: &Path) -> &TupPathDescriptor;

    /// Return root folder where tup was initialized
    fn get_root_dir(&self) -> &Path;

    /// Name of the group its  group descriptor
    fn get_group_name(&self, gd: &GroupPathDescriptor) -> String;

    /// Extract path from input
    fn get_path_from(&self, input_glob: &InputResolvedType) -> &Path;

    /// Get Path as string
    fn get_path_str(&self, p: &PathDescriptor) -> String;

    /// Finds if env var is present
    fn has_env(&self, id: &str, cur_env_desc: &EnvDescriptor) -> bool;

    /// Return an iterator over all the id-group path pairs.
    /// Group path is of the form folder/\<group\>, Where folder is the file system path relative to root
    fn group_iter(&self) -> bimap::hash::Iter<'_, NormalPath, GroupPathDescriptor>;
}

/// Normal Path packages a PathBuf, giving relative paths wrt current tup directory
#[derive(Debug, Default, Eq, PartialEq, Clone, Hash)]
pub struct NormalPath {
    inner: PathBuf,
}
/// Constructor and accessor for a NormalPath
impl NormalPath {
    /// Construct consuming the given pathbuf
    pub fn new(p: PathBuf) -> NormalPath {
        if p.as_os_str().is_empty() || p.as_os_str() == "/" || p.as_os_str() == "\\" {
            NormalPath {
                inner: PathBuf::from("."),
            }
        } else {
            NormalPath { inner: p }
        }
    }
    /// Construct a `NormalPath' by joining tup_cwd with path
    pub fn absolute_from(path: &Path, tup_cwd: &Path) -> Self {
        let p1 = Self::cleanup(path, tup_cwd);
        debug!("abs:{:?}", p1);
        NormalPath::new(p1)
    }

    fn cleanup<P: AsRef<Path>>(path: &Path, tup_cwd: P) -> PathBuf {
        let p1 = without_curdir_prefix(path);
        let p2: PathBuf = if tup_cwd
            .as_ref()
            .components()
            .all(|ref x| Component::CurDir.eq(x))
        {
            p1.parse_dot_from(".").unwrap_or_default().into()
        } else {
            tup_cwd
                .as_ref()
                .join(p1.as_ref())
                .parse_dot_from(".")
                .unwrap_or_else(|_| {
                    panic!(
                        "could not join paths: {:?} with {:?}",
                        tup_cwd.as_ref(),
                        path
                    )
                })
                .into()
        };
        p2
    }

    /// Inner path reference
    pub fn as_path(&self) -> &Path {
        self.inner.as_path()
    }

    /// Inner path buffer
    pub fn to_path_buf(self) -> PathBuf {
        self.inner
    }

    /// File name
    pub fn file_name(&self) -> String {
        self.inner
            .as_path()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string()
    }
}

/// Get a string version of path that normalizes using `/` as path separator and replaces empty paths with cur dir '.'
pub(crate) fn normalize_path(p: &Path) -> Candidate {
    if p.as_os_str().is_empty() {
        Candidate::new(".")
    } else {
        Candidate::new(p)
    }
}
impl ToString for NormalPath {
    /// Inner path in form that can be compared or stored as a bytes
    fn to_string(&self) -> String {
        // following converts backslashes to forward slashes
        normalize_path(self.as_path()).to_string()
    }
}

/// Expose the inner path of NormalPath via the `into' call or Path::from
impl<'a> From<&'a NormalPath> for &'a Path {
    fn from(np: &'a NormalPath) -> Self {
        np.as_path()
    }
}

/// `RuleRef` keeps track of the current file being processed and rule location.
/// This is mostly useful for error handling to let the user know we ran into problem with a rule at
/// a particular line
#[derive(Debug, Default, PartialEq, Eq, Clone, Hash)]
pub struct RuleRef {
    tup_path_desc: TupPathDescriptor,
    loc: Loc,
}

/// `RuleFormulaUsage` keep both rule formula and its whereabouts(`RuleRef`) in a Tupfile
#[derive(Debug, Default, PartialEq, Eq, Clone, Hash)]
pub struct RuleFormulaUsage {
    rule_formula: RuleFormula,
    rule_ref: RuleRef,
}

impl RuleFormulaUsage {
    /// Command string to execute in a rule
    pub fn get_rule_str(&self) -> String {
        self.rule_formula.formula.cat()
    }
    /// Display string that appears in the console as the rule is run
    pub fn get_display_str(&self) -> String {
        let description = self.rule_formula.description.cat();
        let r = Regex::new("^\\^([bcjot]+)").unwrap();
        let display_str = if let Some(s) = r.captures(description.as_str()) {
            //formula.strip_prefix("^o ").unwrap()
            description
                .strip_prefix(s.get(0).unwrap().as_str())
                .unwrap()
        } else {
            description.as_str()
        };
        display_str.trim_start().to_string()
    }
    /// additional flags "bcjot" that alter the way rule is run
    pub fn get_flags(&self) -> String {
        let description = self.rule_formula.description.cat();
        let r = Regex::new("^\\^([bcjot]+)").unwrap();
        if r.is_match(description.as_str()) {
            let s = r.captures(description.as_str()).unwrap();
            s.get(0).unwrap().as_str().to_string()
        } else {
            "".to_string()
        }
    }
}

impl std::fmt::Display for RuleRef {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:?}: {:?}, {:?}",
            self.tup_path_desc, self.loc.line, self.loc.offset
        )
    }
}

///`Ruleref` constructor and accessors
impl RuleRef {
    /// Construct a RuleRef
    pub fn new(tup_desc: &TupPathDescriptor, loc: &Loc) -> RuleRef {
        RuleRef {
            tup_path_desc: *tup_desc,
            loc: *loc,
        }
    }
    /// Line of Tupfile where portion of rule is found
    pub fn get_line(&self) -> u32 {
        self.loc.line
    }
    /// Directory
    pub fn get_tupfile_desc(&self) -> &TupPathDescriptor {
        &self.tup_path_desc
    }
}

impl RuleFormulaUsage {
    pub(crate) fn new(rule_formula: RuleFormula, rule_ref: RuleRef) -> RuleFormulaUsage {
        RuleFormulaUsage {
            rule_formula,
            rule_ref,
        }
    }
    /// `RuleFormula` that this object refers to
    pub(crate) fn get_formula(&self) -> &RuleFormula {
        &self.rule_formula
    }
    /// returns `RuleRef' which is the location of the referred rule in a Tupfile
    pub fn get_rule_ref(&self) -> &RuleRef {
        &self.rule_ref
    }
}

impl std::fmt::Display for RuleFormulaUsage {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "?{:?}? {:?}", self.rule_ref, self.rule_formula)
    }
}

/// ```PathDescriptor``` is an id given to a  folder where tupfile was found
#[derive(Debug, PartialEq, Eq, Clone, Hash, Copy, PartialOrd, Ord)]
pub struct PathDescriptor(usize);

/// ```GroupPathDescriptor``` is an id given to a group that appears in a tupfile.
#[derive(Debug, PartialEq, Eq, Clone, Hash, Copy, PartialOrd, Ord)]
pub struct GroupPathDescriptor(usize);

/// ```GlobalPathDescriptor``` is an id given to a glob that appears as an input to a rule in a tupfile.
#[derive(Debug, PartialEq, Eq, Clone, Hash, Copy, PartialOrd, Ord)]
pub struct GlobPathDescriptor(usize);

/// ```BinDescriptor``` is an id given to a  folder where tupfile was found
#[derive(Debug, PartialEq, Eq, Clone, Hash, Copy, PartialOrd, Ord)]
pub struct BinDescriptor(usize);

/// ```TupPathDescriptor``` is an unique id given to a tupfile
#[derive(Debug, PartialEq, Eq, Clone, Hash, Copy, PartialOrd, Ord)]
pub struct TupPathDescriptor(usize);

/// ```RuleDescriptor``` maintains the id of rule based on rules tracked for far in BufferObjects
#[derive(Debug, PartialEq, Eq, Clone, Hash, Copy, PartialOrd, Ord)]
pub struct RuleDescriptor(usize);

// macros implementing default rust traits for *descriptors
macro_rules! impl_from_usize {
    ($t:ty) => {
        impl From<usize> for $t {
            fn from(i: usize) -> Self {
                Self(i)
            }
        }
        impl From<$t> for usize {
            fn from(t: $t) -> usize {
                t.0
            }
        }
        impl Default for $t {
            fn default() -> Self {
                Self(usize::MAX)
            }
        }

        impl $t {
            /// Construct a descriptor using a usize id
            pub fn new(i: usize) -> Self {
                Self(i)
            }
        }
        impl std::fmt::Display for $t {
            fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                write!(f, "{0}({1})", stringify!($t), self.0)
            }
        }
    };
}

impl_from_usize!(PathDescriptor);
impl_from_usize!(GroupPathDescriptor);
impl_from_usize!(BinDescriptor);
impl_from_usize!(TupPathDescriptor);
impl_from_usize!(RuleDescriptor);
impl_from_usize!(GlobPathDescriptor);

/// path to descriptor(T) `BiMap', path stored is relative to rootdir (.1 in this struct)
#[derive(Debug, Default, Clone)]
pub(crate) struct GenPathBufferObject<T: PartialEq + Eq + Hash + Clone> {
    descriptor: BiMap<NormalPath, T>,
    root: PathBuf,
}

/// Env to descriptor bimap
#[derive(Debug, Default, Clone)]
pub(crate) struct GenEnvBufferObject(BiMap<Env, EnvDescriptor>);

/// Rule to its descriptor bimap
#[derive(Debug, Default, Clone)]
pub(crate) struct GenRuleBufferObject(BiMap<RuleFormulaUsage, RuleDescriptor>);

impl<T> GenPathBufferObject<T>
where
    T: Eq + Clone + Hash + From<usize> + std::fmt::Display,
{
    /// Construct  that stores paths and its descriptors as a `BiMap' relative to root_dir
    pub fn new(root_dir: &Path) -> Self {
        GenPathBufferObject {
            descriptor: BiMap::new(),
            root: root_dir.to_path_buf(),
        }
    }

    /// add a path to buffer that is absolutized by removing dots as many as we can when joining @tup_cwd with @path
    pub fn add_relative(&mut self, tup_cwd: &Path, path: &Path) -> (T, bool) {
        let np = NormalPath::absolute_from(path, tup_cwd);
        debug!("adding np:{:?}", np);
        self.add_normal_path(np)
    }

    /// root director of the paths stored in this buffer
    fn get_root_dir(&self) -> &Path {
        self.root.as_path()
    }

    /// Store a path relative to rootdir. path is expected not to have dots
    /// descriptor is assigned by finding using size of buffer
    pub fn add<P: AsRef<Path>>(&mut self, path: P) -> (T, bool) {
        //debug_assert!(path.as_ref().is_absolute(), "expected a absolute path as input but found:{:?}", path.as_ref());
        let pbuf: PathBuf = if path.as_ref().is_relative() && self.get_root_dir().is_absolute() {
            path.as_ref()
                .components()
                .skip_while(|x| Component::CurDir.eq(x))
                .collect()
        } else {
            diff_paths(path.as_ref(), self.get_root_dir()).unwrap_or_else(|| {
                panic!(
                    "could not diff paths \n: {:?} - {:?}",
                    path.as_ref(),
                    self.get_root_dir()
                )
            })
        };
        let np = NormalPath::new(pbuf);
        self.add_normal_path(np)
    }

    /// Return ids of all paths in this buffer
    pub fn get_ids(&self) -> RightValues<'_, NormalPath, T> {
        self.descriptor.right_values()
    }

    /// Find id
    fn get_id(&self, np: &NormalPath) -> Option<&T> {
        self.descriptor.get_by_left(np)
    }

    /// add a path with a automatically assigned id
    fn add_normal_path(&mut self, np: NormalPath) -> (T, bool) {
        let l = self.descriptor.len();
        if let Some(prev_index) = self.descriptor.get_by_left(&np) {
            (prev_index.clone(), false)
        } else {
            debug!("inserted np:{:?}", np);
            let _ = self.descriptor.insert(np, l.into());
            (l.into(), true)
        }
    }
    /// get Path with the given id in this buffer
    pub fn get(&self, pd: &T) -> &NormalPath {
        self.try_get(pd)
            .unwrap_or_else(|| panic!("path for id:{} not in buffer", pd))
    }
    /// `try_get' is a fallible method to fetch Path with given id in this buffer
    pub fn try_get(&self, pd: &T) -> Option<&NormalPath> {
        self.descriptor.get_by_right(pd)
    }
}
/// Friendly name for BiMap<TupPathDescriptor, NormalPath>
pub(crate) type TupPathBufferObject = GenPathBufferObject<TupPathDescriptor>;
/// Friendly name for BiMap<PathDescriptor, NormalPath>
pub(crate) type PathBufferObject = GenPathBufferObject<PathDescriptor>;
/// Friendly name for BiMap<EnvDescriptor, Env>
pub(crate) type EnvBufferObject = GenEnvBufferObject;
/// Friendly name for BiMap<GroupPathDescriptor, NormalPath>
pub(crate) type GroupBufferObject = GenPathBufferObject<GroupPathDescriptor>;
/// Friendly name for BiMap<BinDescriptor, NormalPath>
pub(crate) type BinBufferObject = GenPathBufferObject<BinDescriptor>;

/// Friendly name for BiMap<RuleDescriptor, RuleFormulaUsage>
pub(crate) type RuleBufferObject = GenRuleBufferObject;

/// methods to add or get group entries from a buffer
impl GroupBufferObject {
    // Returns name of group (wrapped with angle-brackets)
    fn get_group_name(&self, group_desc: &GroupPathDescriptor) -> String {
        self.get(group_desc)
            .as_path()
            .file_stem()
            .unwrap()
            .to_string_lossy()
            .to_string()
    }

    /// iterator over all the (groupid, grouppath) pairs stored in this buffer
    pub(crate) fn group_iter(&self) -> bimap::hash::Iter<'_, NormalPath, GroupPathDescriptor> {
        self.descriptor.iter()
    }
}

/// methods to modify get Rules of `RuleBufferObject'
impl RuleBufferObject {
    /// Add a ```RuleFormulaUsage''' object to this buffer returning a unique id
    pub(crate) fn add_rule(&mut self, r: RuleFormulaUsage) -> (RuleDescriptor, bool) {
        let l = self.0.len();
        let rulestr = r.get_formula().cat();
        debug!("adding rule {} to buffer", rulestr);
        if let Some(prev_index) = self.0.get_by_left(&r) {
            (*prev_index, false)
        } else {
            let _ = self.0.insert(r, l.into());
            (l.into(), true)
        }
    }

    /// return rule corresponding to its id
    pub(crate) fn get_rule(&self, id: &RuleDescriptor) -> Option<&RuleFormulaUsage> {
        self.0.get_by_right(id)
    }
}

/// Methods to add/modify `BinObjectObject'
impl BinBufferObject {
    /// add /insert an binId-path pair in bin buffer
    pub(crate) fn add_relative_bin(
        &mut self,
        bin_as_path: &Path,
        tup_cwd: &Path,
    ) -> (BinDescriptor, bool) {
        self.add_relative(tup_cwd, bin_as_path)
    }
}

impl GenEnvBufferObject {
    /// Add an Env to the buffer and return a unique id.
    pub(crate) fn add_env(&mut self, env: Cow<Env>) -> (EnvDescriptor, bool) {
        let l = 0;
        if let Some(prev_index) = self.0.get_by_left(env.borrow()) {
            (prev_index.clone(), false)
        } else {
            let _ = self.0.insert(env.into_owned(), l.into());
            (l.into(), true)
        }
    }
    /// Check if var is present in the buffer
    pub(crate) fn has_env(&self, var: &str, cur_env_desc: &EnvDescriptor) -> bool {
        // check the env corresponding to the last added env for the presence of var
        if let Some(rvalue) = self.0.get_by_right(cur_env_desc) {
            rvalue.contains(var)
        } else {
            false
        }
    }

    /// Fallible version of the above
    pub(crate) fn try_get(&self, pd: &EnvDescriptor) -> Option<&Env> {
        self.0.get_by_right(pd)
    }
}

/// Wrapper over outputs
#[derive(Default, Debug, Clone)]
pub struct OutputHolder(Arc<RwLock<GeneratedFiles>>);

impl OutputHolder {
    /// construct from
    pub fn from(outs: GeneratedFiles) -> OutputHolder {
        OutputHolder(Arc::new(RwLock::new(outs)))
    }
    /// Create an empty output holder
    pub fn new() -> OutputHolder {
        OutputHolder(Arc::new(RwLock::new(GeneratedFiles::new())))
    }

    /// Fetch generated files for read
    pub(crate) fn get(&self) -> RwLockReadGuard<'_, GeneratedFiles> {
        self.0.deref().read()
    }
    /// Fetch generated files for write
    pub(crate) fn get_mut(&self) -> RwLockWriteGuard<'_, GeneratedFiles> {
        self.0.deref().write()
    }
}

/// Dump yard for outputs from rules, containing output_files, maps to paths corresponding to bin names, or group names
/// Also keeps track of parent rules that generated them.
/// Currently resolution of rule inputs formula and outputs happens in two stages.
/// In the first stage we gather inputs and perform variable substitution but skip resolving inputs and rules that have group references. But we still collect all
/// the group provider outputs from different tupfiles
/// We then re-resolve  after ordering the dag formed by rules with connections from  rules providing groups
/// and rules that take groups as input. Dag is built to check for cyclic dependencies.
#[derive(Debug, Default, Clone)]
pub struct GeneratedFiles {
    /// rule output files accumulated thus far
    output_files: HashSet<PathDescriptor>,
    /// output files under a directory.
    children: HashMap<PathDescriptor, Vec<PathDescriptor>>,
    /// paths accumulated in a bin
    bins: HashMap<BinDescriptor, HashSet<PathDescriptor>>,
    /// paths accumulated in groups
    groups: HashMap<GroupPathDescriptor, HashSet<PathDescriptor>>,
    /// track the parent rule that generates a output file
    parent_rule: HashMap<PathDescriptor, RuleRef>,
}

impl GeneratedFiles {
    /// Construct [GeneratedFiles] with resolve_groups set to false
    pub fn new() -> GeneratedFiles {
        GeneratedFiles::default()
    }

    /// Discover outputs by their path descriptors
    pub(crate) fn outputs_with_desc(
        &self,
        path_desc: &PathDescriptor,
        base_path_desc: &PathDescriptor,
        vs: &mut Vec<MatchingPath>,
    ) {
        let mut hs = HashSet::new();
        hs.extend(vs.iter().map(MatchingPath::path_descriptor));
        let mut found = false;
        if let Some(children) = self.children.get(base_path_desc) {
            if children.contains(path_desc) {
                vs.push(MatchingPath::new(*path_desc));
                found = true;
            }
        }
        if !found {
            let bins_groups = self
                .bins
                .iter()
                .map(|x| x.1)
                .chain(self.groups.iter().map(|x| x.1))
                .filter(|v| v.contains(path_desc));
            for _ in bins_groups {
                if hs.insert(*path_desc) {
                    vs.push(MatchingPath::new(*path_desc));
                    found = true;
                    break;
                }
            }
        }
        if !found && log_enabled!(log::Level::Debug) {
            debug!("missed finding !:{:?} in any of the outputs", path_desc);
            for o in &self.output_files {
                debug!("{:?}", o);
            }
        }
    }

    /// discover outputs matching glob in the same tupfile
    pub(crate) fn outputs_matching_glob(
        &self,
        path_buffers: &mut impl PathBuffers,
        glob_path: &GlobPath,
        vs: &mut Vec<MatchingPath>,
    ) {
        let mut hs = HashSet::new();
        let base_path_desc = glob_path.get_base_desc();
        hs.extend(vs.iter().map(MatchingPath::path_descriptor));
        debug!("looking for globmatches:{:?}", glob_path.get_abs_path());
        debug!(
            "in dir id {:?}, {:?}",
            base_path_desc,
            path_buffers.get_path(&base_path_desc)
        );
        if let Some(children) = self.children.get(&base_path_desc) {
            for pd in children.iter() {
                path_buffers.try_get_path(pd).map(|np| {
                    let p: &Path = np.into();
                    if glob_path.is_match(p) && hs.insert(*pd) {
                        vs.push(MatchingPath::with_captures(
                            *pd,
                            glob_path.get_glob_desc(),
                            glob_path.group(p),
                        ))
                    }
                });
            }
        }

        self.bins
            .iter()
            .map(|x| x.1)
            .chain(self.groups.iter().map(|x| x.1))
            //   .chain(std::iter::once(&self.output_files))
            .for_each(|v| {
                for pd in v.iter() {
                    if let Some(np) = path_buffers.try_get_path(pd) {
                        let p: &Path = np.into();
                        if glob_path.is_match(p) && hs.insert(*pd) {
                            vs.push(MatchingPath::with_captures(
                                *pd,
                                glob_path.get_glob_desc(),
                                glob_path.group(p),
                            ))
                        }
                    }
                }
            });
    }
}

impl GeneratedFiles {
    /// Get all the output files from rules accumulated so far
    fn get_output_files(&self) -> &HashSet<PathDescriptor> {
        &self.output_files
    }
    /// Get all the groups with collected rule outputs
    fn get_groups(&self) -> &HashMap<GroupPathDescriptor, HashSet<PathDescriptor>> {
        &self.groups
    }
    /// Get paths stored against a bin
    fn get_bins(&self) -> &HashMap<BinDescriptor, HashSet<PathDescriptor>> {
        &self.bins
    }
    /// Get paths stored against a group
    fn get_group(&self, group_desc: &GroupPathDescriptor) -> Option<&HashSet<PathDescriptor>> {
        self.groups.get(group_desc)
    }
    /// Get paths stored against each bin
    fn get_bin(&self, bin_desc: &BinDescriptor) -> Option<&HashSet<PathDescriptor>> {
        self.bins.get(bin_desc)
    }
    /// Get parent dir -> children map
    fn get_children(&self) -> &HashMap<PathDescriptor, Vec<PathDescriptor>> {
        &self.children
    }
    /// Get a mutable references all the groups with collected rule outputs.
    /// This can be used to to fill path references from a database.
    fn get_mut_groups(&mut self) -> &mut HashMap<GroupPathDescriptor, HashSet<PathDescriptor>> {
        &mut self.groups
    }
    /// Get a mutable references all the bins with collected rule outputs.
    fn get_mut_bins(&mut self) -> &mut HashMap<BinDescriptor, HashSet<PathDescriptor>> {
        &mut self.bins
    }

    /// Add an entry to the set that holds paths
    fn add_output(&mut self, pd: PathDescriptor) -> bool {
        self.output_files.insert(pd)
    }

    /// Add an entry to the collector that holds paths of a group
    fn add_group_entry(&mut self, group_desc: &GroupPathDescriptor, pd: PathDescriptor) {
        self.get_mut_groups()
            .entry(*group_desc)
            .or_default()
            .insert(pd);
    }
    /// Add an entry to the collector that holds paths of a bin
    fn add_bin_entry(&mut self, bin_desc: &BinDescriptor, pd: PathDescriptor) {
        self.get_mut_bins().entry(*bin_desc).or_default().insert(pd);
    }

    /// the parent rule that generates a output file
    pub(crate) fn get_parent_rule(&self, o: &PathDescriptor) -> Option<&RuleRef> {
        self.parent_rule.get(o)
    }

    /// Add an entry to the set that holds paths
    fn add_parent_rule(&mut self, pd: PathDescriptor, rule_ref: RuleRef) -> RuleRef {
        match self.parent_rule.entry(pd) {
            Entry::Occupied(e) => e.get().clone(),
            Entry::Vacant(e) => e.insert(rule_ref).clone(),
        }
    }

    /// Merge paths of different groups from new_outputs into current group path container
    fn merge_group_tags(
        &mut self,
        path_buffers: &impl PathBuffers,
        new_outputs: &impl OutputHandler,
    ) -> Result<(), Err> {
        for (k, new_paths) in new_outputs.get_groups().iter() {
            self.groups
                .entry(*k)
                .or_insert_with(HashSet::new)
                .extend(new_paths.iter().cloned());
            self.merge_parent_rules(path_buffers, &new_outputs.get_parent_rules(), new_paths)?;
        }
        Ok(())
    }
    /// Merge bins from its new outputs
    fn merge_bin_tags(
        &mut self,
        path_buffers: &impl PathBuffers,
        other: &impl OutputHandler,
    ) -> Result<(), Err> {
        for (k, new_paths) in other.get_bins().iter() {
            self.bins
                .entry(*k)
                .or_insert_with(HashSet::new)
                .extend(new_paths.iter().cloned());
            self.merge_parent_rules(path_buffers, &other.get_parent_rules(), new_paths)?;
        }
        Ok(())
    }
    /// merge groups , outputs and bins from other `OutputHandler`
    ///  erorr-ing out if unique parent rule
    /// of an output is not found
    fn merge(
        &mut self,
        path_buffers: &impl PathBuffers,
        out: &impl OutputHandler,
    ) -> Result<(), Err> {
        self.merge_group_tags(path_buffers, out)?;
        self.merge_output_files(path_buffers, out)?;
        self.merge_bin_tags(path_buffers, out)
    }

    /// extend the list of outputs. Update children of directories with new outputs. Update also the parent rules of each of the output files.
    /// The last step can error out if the same output is found to have different parent rules.
    fn merge_output_files(
        &mut self,
        path_buffers: &impl PathBuffers,
        new_outputs: &impl OutputHandler,
    ) -> Result<(), Err> {
        self.output_files
            .extend(new_outputs.get_output_files().iter().cloned());
        for (dir, ch) in new_outputs.get_children().iter() {
            self.children
                .entry(*dir)
                .or_insert_with(Vec::new)
                .extend(ch.iter());
        }
        self.merge_parent_rules(
            path_buffers,
            &new_outputs.get_parent_rules(),
            &new_outputs.get_output_files(),
        )
    }
    /// Track parent rules of outputs, error-ing out if unique parent rule
    /// of an output is not found
    fn merge_parent_rules(
        &mut self,
        path_buffers: &impl PathBuffers,
        new_parent_rule: &HashMap<PathDescriptor, RuleRef>,
        new_path_descs: &HashSet<PathDescriptor>,
    ) -> Result<(), Err> {
        for new_path_desc in new_path_descs.iter() {
            let new_parent = new_parent_rule
                .get(new_path_desc)
                .expect("parent rule not found");
            log::debug!(
                "Setting parent for  path: {:?} to rule:{:?}:{:?}",
                path_buffers.get_path(new_path_desc),
                path_buffers.get_tup_path(new_parent.get_tupfile_desc()),
                new_parent.get_line()
            );
            match self.parent_rule.entry(*new_path_desc) {
                Entry::Occupied(pe) => {
                    if pe.get() != new_parent {
                        let old_parent = pe.get();
                        let old_rule_path =
                            path_buffers.get_tup_path(old_parent.get_tupfile_desc());
                        let old_rule_line = old_parent.get_line();
                        log::warn!(
                            "path {:?} is an output of a previous rule at:{:?}:{:?}",
                            path_buffers.get_path(new_path_desc),
                            old_rule_path,
                            old_rule_line
                        );
                        return Err(Err::MultipleRulesToSameOutput(
                            *new_path_desc,
                            new_parent.clone(),
                            pe.get().clone(),
                        ));
                    }
                }
                Entry::Vacant(pe) => {
                    pe.insert(new_parent.clone());
                }
            }
        }
        Ok(())
    }
    /// return the map from output file descriptor to the parent rule that generates it.
    fn get_parent_rules(&self) -> &HashMap<PathDescriptor, RuleRef> {
        &self.parent_rule
    }
}

/// Interface to add and read outputs of rules parsed in tupfiles.
pub trait OutputHandler {
    /// Get all the output files from rules accumulated so far
    fn get_output_files(&self) -> MappedRwLockReadGuard<'_, HashSet<PathDescriptor>>;
    /// Get all the groups with collected rule outputs
    fn get_groups(
        &self,
    ) -> MappedRwLockReadGuard<'_, HashMap<GroupPathDescriptor, HashSet<PathDescriptor>>>;
    /// Get paths stored against a bin
    fn get_bins(
        &self,
    ) -> MappedRwLockReadGuard<'_, HashMap<BinDescriptor, HashSet<PathDescriptor>>>;
    /// Get parent dir -> children map
    fn get_children(
        &self,
    ) -> MappedRwLockReadGuard<'_, HashMap<PathDescriptor, Vec<PathDescriptor>>>;
    /// the parent rule that generates a output file
    fn get_parent_rule(&self, o: &PathDescriptor) -> Option<MappedRwLockReadGuard<'_, RuleRef>>;
    /// parent rule of each output path
    fn get_parent_rules(&self) -> MappedRwLockReadGuard<'_, HashMap<PathDescriptor, RuleRef>>;
    /// Add an entry to the set that holds output paths
    fn add_output(&mut self, pd: PathDescriptor) -> bool;

    /// Add parent rule to a give output path id. Returns false if unsuccessful
    fn add_parent_rule(&mut self, pd: PathDescriptor, rule_ref: RuleRef) -> RuleRef;

    /// Add children
    fn add_children(&mut self, path_desc: &PathDescriptor, ch: Vec<PathDescriptor>);

    /// Add an entry to the collector that holds paths of a group
    fn add_group_entry(&mut self, group_desc: &GroupPathDescriptor, pd: PathDescriptor);

    /// Add an entry to the collector that holds paths of a group
    fn add_bin_entry(&mut self, bin_desc: &BinDescriptor, pd: PathDescriptor);

    /// merge groups, outputs and bins from other `OutputHandler`
    ///  erorr-ing out if unique parent rule
    /// of an output is not found
    fn merge(&mut self, p: &impl PathBuffers, out: &impl OutputHandler) -> Result<(), Err>;
}

impl PathSearcher for OutputHolder {
    fn discover_paths(
        &self,
        path_buffers: &mut impl PathBuffers,
        glob_path: &GlobPath,
    ) -> Result<Vec<MatchingPath>, Error> {
        let mut vs = Vec::new();
        if !glob_path.has_glob_pattern() {
            let path_desc: PathDescriptor = glob_path.get_path_desc().0.into();
            self.get()
                .outputs_with_desc(&path_desc, glob_path.get_base_desc(), &mut vs);
        } else {
            self.get()
                .outputs_matching_glob(path_buffers, &glob_path, &mut vs);
        }
        Ok(vs)
    }

    fn get_outs(&self) -> &OutputHolder {
        &self
    }

    fn merge(&mut self, p: &impl PathBuffers, o: &impl OutputHandler) -> Result<(), Error> {
        self.get_mut().merge(p, o)
    }
}
impl OutputHandler for OutputHolder {
    fn get_output_files(&self) -> MappedRwLockReadGuard<'_, HashSet<PathDescriptor>> {
        RwLockReadGuard::map(self.get(), |x| x.get_output_files())
    }

    fn get_groups(
        &self,
    ) -> MappedRwLockReadGuard<'_, HashMap<GroupPathDescriptor, HashSet<PathDescriptor>>> {
        RwLockReadGuard::map(self.get(), |x| x.get_groups())
    }

    fn get_bins(
        &self,
    ) -> MappedRwLockReadGuard<'_, HashMap<BinDescriptor, HashSet<PathDescriptor>>> {
        RwLockReadGuard::map(self.get(), |x| x.get_bins())
    }

    fn get_children(
        &self,
    ) -> MappedRwLockReadGuard<'_, HashMap<PathDescriptor, Vec<PathDescriptor>>> {
        RwLockReadGuard::map(self.get(), |x| x.get_children())
    }

    fn get_parent_rule(&self, o: &PathDescriptor) -> Option<MappedRwLockReadGuard<'_, RuleRef>> {
        let r = self.get();
        if r.get_parent_rule(o).is_some() {
            Some(RwLockReadGuard::map(self.get(), |x| {
                x.get_parent_rule(o).unwrap()
            }))
        } else {
            None
        }
    }

    fn get_parent_rules(&self) -> MappedRwLockReadGuard<'_, HashMap<PathDescriptor, RuleRef>> {
        RwLockReadGuard::map(self.get(), |x| x.get_parent_rules())
    }

    fn add_output(&mut self, pd: PathDescriptor) -> bool {
        self.get_mut().add_output(pd)
    }
    fn add_parent_rule(&mut self, pd: PathDescriptor, rule_ref: RuleRef) -> RuleRef {
        self.get_mut().add_parent_rule(pd, rule_ref)
    }

    // add output files under a directory
    fn add_children(&mut self, dir: &PathDescriptor, ch: Vec<PathDescriptor>) {
        self.get_mut()
            .children
            .entry(*dir)
            .or_insert_with(Vec::new)
            .extend(ch)
    }

    fn add_group_entry(&mut self, group_desc: &GroupPathDescriptor, pd: PathDescriptor) {
        self.get_mut().add_group_entry(group_desc, pd)
    }
    fn add_bin_entry(&mut self, bin_desc: &BinDescriptor, pd: PathDescriptor) {
        self.get_mut().add_bin_entry(bin_desc, pd)
    }

    fn merge(&mut self, p: &impl PathBuffers, out: &impl OutputHandler) -> Result<(), Err> {
        self.get_mut().merge(p, out)
    }
}

/// A Matching path id discovered using glob matcher along with captured groups
#[derive(Debug, Default, Eq, PartialEq, Clone)]
pub struct MatchingPath {
    /// path that matched a glob
    path_descriptor: PathDescriptor,
    /// id of the glob pattern that matched this path
    glob_descriptor: Option<GlobPathDescriptor>,
    /// first glob match in the above path
    captured_globs: Vec<String>,
}

const GLOB_PATTERN_CHARACTERS: &str = "*?[";

/// return the parent directory
fn get_non_pattern_prefix(glob_path: &Path) -> (PathBuf, bool) {
    let mut prefix = PathBuf::new();
    let mut num_comps = 0;
    for component in glob_path.iter() {
        let component_str = component.to_str().unwrap();

        if GLOB_PATTERN_CHARACTERS
            .chars()
            .any(|special_char| component_str.contains(special_char))
        {
            break;
        }
        prefix.push(component);
        num_comps += 1;
    }
    if prefix.is_dir() {
        (prefix, num_comps + 1 < glob_path.components().count())
    } else {
        (
            prefix.parent().unwrap().to_path_buf(),
            num_comps + 1 < glob_path.components().count(),
        )
    }
}

///  check if any of the components of the input path has glob pattern
fn has_glob_pattern(glob_path: &Path) -> bool {
    for component in glob_path.iter() {
        let component_str = component.to_str().unwrap();

        if GLOB_PATTERN_CHARACTERS
            .chars()
            .any(|special_char| component_str.contains(special_char))
        {
            return true;
        }
    }
    false
}

/// Wrapper over Burnt sushi's GlobMatcher
#[derive(Debug, Clone)]
pub(crate) struct MyGlob {
    matcher: GlobMatcher,
}

impl MyGlob {
    pub(crate) fn new(path_pattern: Candidate) -> Result<Self, Error> {
        let to_glob_error = |e: &glob::Error| {
            Error::GlobError(path_pattern.to_string() + ":" + e.kind().to_string().as_str())
        };
        let glob_pattern = GlobBuilder::new(path_pattern.path().to_str_lossy().as_ref())
            .literal_separator(true)
            .capture_globs(true)
            .build()
            .map_err(|e| to_glob_error(&e))?;
        let matcher = glob_pattern.compile_matcher();
        Ok(MyGlob { matcher })
    }

    /// Check whether the path is a match for this glob
    pub(crate) fn is_match<P: AsRef<Path>>(&self, path: P) -> bool {
        self.matcher.is_match(path)
    }

    /// get ith capturing group from matched path
    pub(crate) fn group<P: AsRef<Path>>(&self, path: P) -> Vec<String> {
        self.matcher.group(path)
    }

    /// Get regex
    pub(crate) fn re(&self) -> &regex::bytes::Regex {
        self.matcher.re()
    }
}
impl MatchingPath {
    ///Create a bare matching path with no captured groups
    pub fn new(path: PathDescriptor) -> MatchingPath {
        MatchingPath {
            path_descriptor: path,
            glob_descriptor: None,
            captured_globs: vec![],
        }
    }

    /// Create a `MatchingPath` with captured glob strings.
    pub fn with_captures(
        path: PathDescriptor,
        glob: &GlobPathDescriptor,
        captured_globs: Vec<String>,
    ) -> MatchingPath {
        MatchingPath {
            path_descriptor: path,
            glob_descriptor: Some(*glob),
            captured_globs,
        }
    }
    /// Get path represented by this entry
    pub fn path_descriptor(&self) -> &PathDescriptor {
        &self.path_descriptor
    }

    /// Get id of the glob pattern that matched this path
    pub fn glob_descriptor(&self) -> Option<GlobPathDescriptor> {
        self.glob_descriptor
    }

    /// Captured globs
    fn get_captured_globs(&self) -> &Vec<String> {
        &self.captured_globs
    }
}

/// Types of decoded input to rules which includes
/// files in glob, group paths, bin entries
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum InputResolvedType {
    /// DeGlob contains a path that matched glob strings or plain inputs passed to rule
    Deglob(MatchingPath),
    /// GroupEntry contains a group id and a path that was collected in this group as an output to some rule
    GroupEntry(GroupPathDescriptor, PathDescriptor),
    /// UnResolvedGroupEntry contains descriptor of group. Actual path (or descriptors) of files that is group collects isnt available yet.
    UnResolvedGroupEntry(GroupPathDescriptor),
    /// BinEntry contains a bin id and a path (descriptor) that was collected in this bin as  output to some rule
    BinEntry(BinDescriptor, PathDescriptor),
    /// Unresolved file that failed glob match
    UnResolvedFile(PathDescriptor),
}

impl InputResolvedType {
    /// Checks if this input is a glob match or plain input
    pub fn is_glob_match(&self) -> bool {
        if let Some(x) = self.as_glob_match() {
            return !x.is_empty();
        }
        return false;
    }
    /// Get matched glob in the input to a rule
    fn as_glob_match(&self) -> Option<&Vec<String>> {
        match self {
            InputResolvedType::Deglob(e) => Some(e.get_captured_globs()),
            _ => None,
        }
    }

    /// Checks if this input is still unresolved. Unresolved inputs are those that are not yet available in the filesystem and is expected to be generated by some rule
    pub fn is_unresolved(&self) -> bool {
        match self {
            InputResolvedType::UnResolvedFile(_) => true,
            InputResolvedType::UnResolvedGroupEntry(_) => true,
            _ => false,
        }
    }

    /// Extracts the actual file system path corresponding to a de-globbed input or bin or group entry
    fn get_resolved_path<'a, 'b>(&'a self, pbo: &'b PathBufferObject) -> &'b Path {
        match self {
            InputResolvedType::Deglob(e) => pbo.get(e.path_descriptor()).as_path(),
            InputResolvedType::GroupEntry(_, p) => pbo.get(p).as_path(),
            InputResolvedType::BinEntry(_, p) => pbo.get(p).as_path(),
            InputResolvedType::UnResolvedGroupEntry(_) => Path::new(""),
            //InputResolvedType::RawUnchecked(p) => pbo.get(p).as_path()
            InputResolvedType::UnResolvedFile(p) => pbo.get(p).as_path(),
        }
    }

    /// Fetch path descriptor of path stored in the Input path
    pub fn get_resolved_path_desc(&self) -> Option<&PathDescriptor> {
        match self {
            InputResolvedType::Deglob(e) => Some(e.path_descriptor()),
            InputResolvedType::GroupEntry(_, p) => Some(p),
            InputResolvedType::BinEntry(_, p) => Some(p),
            InputResolvedType::UnResolvedGroupEntry(_) => None,
            InputResolvedType::UnResolvedFile(_) => None,
        }
    }

    /// path descriptor of the glob pattern that matched this input
    pub fn get_glob_path_desc(&self) -> Option<GlobPathDescriptor> {
        match self {
            InputResolvedType::Deglob(e) => e.glob_descriptor(),
            _ => None,
        }
    }

    /// Resolved name of the given Input,
    /// For Group(or UnResolvedGroup) entries, group name is returned
    /// For Bin entries, bin name is returned
    /// For others the file name is returned
    fn get_resolved_name<'a, 'b>(
        &'a self,
        pbo: &PathBufferObject,
        gbo: &'b GroupBufferObject,
        bbo: &'b BinBufferObject,
    ) -> String {
        match self {
            InputResolvedType::Deglob(e) => pbo.get(e.path_descriptor()).to_string(),
            InputResolvedType::GroupEntry(g, _) => gbo.get(g).to_string(),
            InputResolvedType::BinEntry(b, _) => bbo.get(b).to_string(),
            InputResolvedType::UnResolvedGroupEntry(g) => gbo.get(g).to_string(),
            InputResolvedType::UnResolvedFile(p) => pbo.get(p).to_string(),
        }
    }
}

/// Output path and its id.
struct OutputType {
    pub path: NormalPath,
    pub pid: PathDescriptor,
}
impl OutputType {
    fn new(path: NormalPath, pid: PathDescriptor) -> Self {
        Self { path, pid }
    }
    fn as_path(&self) -> &Path {
        self.path.as_path()
    }
    fn get_id(&self) -> PathDescriptor {
        self.pid
    }
}

pub(crate) trait ExcludeInputPaths {
    fn exclude(
        &self,
        deglobbed: Vec<InputResolvedType>,
        path_buffers: &impl PathBuffers,
    ) -> Vec<InputResolvedType>;
}
impl ExcludeInputPaths for PathExpr {
    fn exclude(
        &self,
        deglobbed: Vec<InputResolvedType>,
        path_buffers: &impl PathBuffers,
    ) -> Vec<InputResolvedType> {
        match self {
            PathExpr::ExcludePattern(patt) => {
                let re = Regex::new(patt).ok();
                if let Some(ref re) = re {
                    let matches = |i: &InputResolvedType| {
                        let s = path_buffers.get_input_path_name(i);
                        re.captures(s.as_str()).is_some()
                    };
                    deglobbed.into_iter().filter(|x| !matches(x)).collect()
                } else {
                    deglobbed
                }
            }
            _ => deglobbed,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct IdedPath<T>
where
    T: From<usize>,
{
    p: NormalPath,
    id: T,
}

impl<T> IdedPath<T>
where
    T: From<usize>,
{
    pub fn new(p: NormalPath, id: PathDescriptor) -> Self {
        IdedPath::<T> {
            p,
            id: (id.0.into()),
        }
    }
    pub fn as_path(&self) -> &Path {
        self.p.as_path()
    }
    pub fn as_desc(&self) -> &T {
        &self.id
    }
    pub fn from_rel_path(tup_cwd: &Path, p: &Path, path_buffers: &mut impl PathBuffers) -> Self {
        let tup_cwd = path_buffers.get_root_dir().join(tup_cwd);
        let np = NormalPath::absolute_from(p, tup_cwd.as_path());
        let id = path_buffers.add_abs(np.as_path()).0;
        Self::new(np, id)
    }
}

/// Buffers to store files, groups, bins, env with its id.
/// Each sub-buffer is a bimap from names to a unique id which simplifies storing references.
#[derive(Debug, Clone, Default)]
pub struct BufferObjects {
    pbo: PathBufferObject,    //< paths by id
    gbo: GroupBufferObject,   //< groups by id
    bbo: BinBufferObject,     //< bins by id
    tbo: TupPathBufferObject, //< tup paths by id
    ebo: EnvBufferObject,     //< environment variables by id
    rbo: RuleBufferObject,    //< Rules by id
}
/// Accessors and modifiers for BufferObjects
impl BufferObjects {
    /// Construct Buffer object using tup (most) root directory where Tupfile.ini is found
    pub fn new<P: AsRef<Path>>(root: P) -> BufferObjects {
        BufferObjects {
            pbo: PathBufferObject::new(root.as_ref()),
            bbo: BinBufferObject::new(root.as_ref()),
            gbo: GroupBufferObject::new(root.as_ref()),
            tbo: TupPathBufferObject::new(root.as_ref()),
            ..Default::default()
        }
    }
}

/// Id, Path pairs corresponding to glob path and its parent folder. Also stores a glob pattern regexp for matching.
#[derive(Debug, Clone)]
pub struct GlobPath {
    glob_path: IdedPath<GlobPathDescriptor>,
    base_path: IdedPath<PathDescriptor>,
    glob: MyGlob,
}

impl GlobPath {
    /// tup_cwd should include root (it is not relative to root but includes root)
    pub fn new(
        tup_cwd: &Path,
        glob_path: &Path,
        path_buffers: &mut impl PathBuffers,
    ) -> Result<Self, Error> {
        let ided_path = IdedPath::from_rel_path(tup_cwd, glob_path, path_buffers);
        Self::build_from(path_buffers, ided_path)
    }

    fn build_from(
        path_buffers: &mut impl PathBuffers,
        ided_path: IdedPath<GlobPathDescriptor>,
    ) -> Result<GlobPath, Error> {
        let (mut base_path, _) = get_non_pattern_prefix(ided_path.as_path());
        if base_path.eq(&PathBuf::new()) {
            base_path = base_path.join(".");
        }
        let (base_desc, _) = path_buffers.add_abs(base_path.as_path());
        let glob = MyGlob::new(normalize_path(ided_path.as_path()))?;
        Ok(GlobPath {
            base_path: IdedPath::new(NormalPath::new(base_path), base_desc),
            glob_path: ided_path,
            glob,
        })
    }

    /// Construct from id to path
    pub fn from_path_desc(
        path_buffers: &mut impl PathBuffers,
        p: PathDescriptor,
    ) -> Result<Self, Error> {
        let np = path_buffers.get_path(&p).clone();
        let ided_path = IdedPath::new(np, p);
        Self::build_from(path_buffers, ided_path)
    }

    /// Id to Glob path
    pub fn get_path_desc(&self) -> PathDescriptor {
        PathDescriptor::from(self.glob_path.as_desc().0)
    }
    /// Id to the glob path from root
    pub fn get_glob_desc(&self) -> &GlobPathDescriptor {
        self.glob_path.as_desc()
    }
    /// Glob path as [Path]
    pub fn get_abs_path(&self) -> &Path {
        self.glob_path.as_path()
    }
    /// Get path relative to root
    pub fn get_rel_path(&self, path_buffers: &impl PathBuffers) -> NormalPath {
        path_buffers
            .get_path(&PathDescriptor::from(self.glob_path.as_desc().0))
            .clone()
    }
    /// Glob path as a string
    pub fn get_path_str(&self) -> &OsStr {
        self.glob_path.as_path().as_os_str()
    }

    /// Id of the parent folder corresponding to glob path
    pub fn get_base_desc(&self) -> &PathDescriptor {
        self.base_path.as_desc()
    }

    /// parent folder corresponding to glob path
    pub fn get_base_abs_path(&self) -> &Path {
        self.base_path.as_path()
    }

    /// fix path string to regularize the path with forward slashes
    pub fn get_slash_corrected(&self) -> Candidate {
        let slash_corrected_glob = normalize_path(self.get_abs_path());
        slash_corrected_glob
    }
    /// Check if the pattern for matching has glob pattern chars such as "*[]"
    pub fn has_glob_pattern(&self) -> bool {
        has_glob_pattern(self.get_abs_path())
    }

    /// Regexp string corresponding to glob
    pub fn re(&self) -> String {
        self.glob.re().to_string()
    }

    /// Checks if the path is a match with the glob we have
    pub fn is_match<P: AsRef<Path>>(&self, p: P) -> bool {
        self.glob.is_match(p.as_ref())
    }

    /// List of all glob captures in a path
    pub fn group<P: AsRef<Path>>(&self, p: P) -> Vec<String> {
        self.glob.group(p)
    }
}

/// Searcher of paths in directory tree and those stored in [OutputHolder]
#[derive(Debug, Default, Clone)]
pub struct DirSearcher {
    output_holder: OutputHolder,
}

impl DirSearcher {
    ///  Constructs a blank `DirSearcher`
    pub fn new() -> DirSearcher {
        DirSearcher {
            output_holder: OutputHolder::new(),
        }
    }
}
impl PathSearcher for DirSearcher {
    /// scan folder tree for paths
    /// This function runs the glob matcher to discover rule inputs by walking from given directory. The paths are returned as descriptors stored in [MatchingPatch]
    /// @tup_cwd is expected to be current tupfile directory under which a rule is found. @glob_path
    /// Also calls the next in chain of searchers
    fn discover_paths(
        &self,
        path_buffers: &mut impl PathBuffers,
        glob_path: &GlobPath,
    ) -> Result<Vec<MatchingPath>, Error> {
        let to_match = glob_path.get_abs_path();
        debug!(
            "bp:{:?}, to_match:{:?}",
            glob_path.get_base_abs_path(),
            to_match
        );
        if !glob_path.has_glob_pattern() {
            let mut pes = Vec::new();
            let path_desc = glob_path.get_path_desc().0;
            debug!("looking for child {:?}", to_match);
            if to_match.is_file() {
                pes.push(MatchingPath::new(path_desc.into()));
            } else {
                // discover inputs from previous outputs
                pes.extend(self.output_holder.discover_paths(path_buffers, glob_path)?);
            }

            if log_enabled!(log::Level::Debug) {
                for pe in pes.iter() {
                    debug!("mp:{:?}", pe);
                }
            }
            return Ok(pes);
        }

        let globs = MyGlob::new(glob_path.get_slash_corrected())?;
        let base_path = glob_path.get_base_abs_path();
        debug!("glob regex used for finding matches {}", globs.re());
        debug!("base path for files matching glob: {:?}", base_path);
        let mut walkdir = WalkDir::new(base_path);
        walkdir = walkdir.max_depth(1);
        let filtered_paths = walkdir
            .min_depth(1)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|entry| {
                let match_path = normalize_path(entry.path());
                entry.path().is_file() && globs.is_match(match_path.path().to_str_lossy().as_ref())
            });
        let mut pes = Vec::new();
        for matching in filtered_paths {
            let path = matching.path();
            let (path_desc, _) = path_buffers.add_abs(path);
            pes.push(MatchingPath::with_captures(
                path_desc,
                glob_path.get_glob_desc(),
                globs.group(path),
            ));
        }
        if log_enabled!(log::Level::Debug) {
            for pe in pes.iter() {
                debug!("mp_glob:{:?}", pe);
            }
        }
        pes.extend(self.output_holder.discover_paths(path_buffers, glob_path)?);
        Ok(pes)
    }

    fn get_outs(&self) -> &OutputHolder {
        &self.output_holder
    }

    fn merge(&mut self, p: &impl PathBuffers, o: &impl OutputHandler) -> Result<(), Error> {
        OutputHandler::merge(&mut self.output_holder, p, o)
    }
}

impl PathBuffers for BufferObjects {
    /// Add path of bin. Folder is the one where  Tupfile declaring the bin. name is bin name
    fn add_bin_path_expr(&mut self, tup_cwd: &Path, pe: &str) -> (BinDescriptor, bool) {
        self.bbo.add_relative_bin(pe.as_ref(), tup_cwd)
    }

    fn add_env(&mut self, e: Cow<Env>) -> (EnvDescriptor, bool) {
        self.ebo.add_env(e)
    }

    /// Add a path to a group in this buffer
    fn add_group_pathexpr(
        &mut self,
        tup_cwd: &Path,
        group_str: &str,
    ) -> (GroupPathDescriptor, bool) {
        self.gbo.add_relative(tup_cwd, Path::new(group_str))
    }

    /// Add a path to buffer and return its unique id in the buffer
    /// It is assumed that no de-dotting is necessary for the input path and path is already from the root
    fn add_abs(&mut self, p: &Path) -> (PathDescriptor, bool) {
        let p = without_curdir_prefix(p);
        self.pbo.add(p)
    }

    /// Add a path to buffer and return its unique id in the buffer
    fn add_path_from<P: AsRef<Path>>(&mut self, tup_cwd: &Path, p: P) -> (PathDescriptor, bool) {
        self.pbo.add_relative(tup_cwd, p.as_ref())
    }

    fn add_rule(&mut self, r: RuleFormulaUsage) -> (RuleDescriptor, bool) {
        self.rbo.add_rule(r)
    }
    fn add_tup(&mut self, p: &Path) -> (TupPathDescriptor, bool) {
        let p1 = NormalPath::cleanup(p, Path::new("."));
        self.tbo.add(p1.as_path())
    }

    /// add environment variable to the list of variables active in current tupfile until now
    /// This appends a new env var current list of env vars.
    fn add_env_var(&mut self, var: String, cur_env_desc: &EnvDescriptor) -> EnvDescriptor {
        if let Some(env) = self.try_get_env(cur_env_desc) {
            if env.contains(&var) {
                cur_env_desc.clone()
            } else {
                let mut env = env.clone();
                env.add(var);
                let (id, _) = self.ebo.add_env(Cow::Owned(env));
                id
            }
        } else {
            panic!("Unknown environment descriptor:{}", cur_env_desc)
        }
    }

    /// Get file name or bin name or group name of the input path
    /// use `get_resolve_path` to get resolved path
    fn get_input_path_name(&self, i: &InputResolvedType) -> String {
        i.get_resolved_name(&self.pbo, &self.gbo, &self.bbo)
    }

    /// Returns parent id for the path
    fn get_parent_id(&self, pd: &PathDescriptor) -> Option<PathDescriptor> {
        let p = self.pbo.try_get(pd)?;
        let np = NormalPath::new(get_parent(p.as_path()));
        self.get_id(&np).copied()
    }

    /// Returns id for the path
    fn get_id(&self, np: &NormalPath) -> Option<&PathDescriptor> {
        self.pbo.get_id(np)
    }

    /// Returns path corresponding to an path descriptor. This panics if there is no match
    fn get_path(&self, id: &PathDescriptor) -> &NormalPath {
        self.pbo.get(id)
    }

    fn get_rel_path(&self, pd: &PathDescriptor, vd: &PathDescriptor) -> NormalPath {
        let np1 = self.get_path(pd);
        let np2 = self.get_path(vd);
        NormalPath::new(diff_paths(np1.as_path(), np2.as_path()).unwrap())
    }

    /// Returns rule corresponding to a rule descriptor. Panics if none is found
    fn get_rule(&self, id: &RuleDescriptor) -> &RuleFormulaUsage {
        self.rbo
            .get_rule(id)
            .unwrap_or_else(|| panic!("unable to fetch rule formula for id:{}", id))
    }
    /// Returns env corresponding to a env descriptor. Panics if none is found
    fn try_get_env(&self, id: &EnvDescriptor) -> Option<&Env> {
        self.ebo.try_get(id)
    }

    /// Returns path corresponding to the given tupfile descriptor
    fn get_tup_path(&self, t: &TupPathDescriptor) -> &Path {
        self.tbo.get(t).as_path()
    }
    // Attempts to get path corresponding to an path descriptor. None if no match is found
    fn try_get_path(&self, id: &PathDescriptor) -> Option<&NormalPath> {
        self.pbo.try_get(id)
    }

    /// Try get a bin path entry by its descriptor.
    fn try_get_group_path(&self, gd: &GroupPathDescriptor) -> Option<&NormalPath> {
        self.gbo.try_get(gd)
    }
    /// Get group ids as an iter
    fn get_group_descs(&self) -> RightValues<'_, NormalPath, GroupPathDescriptor> {
        self.gbo.get_ids()
    }

    /// Get tup id corresponding to its path
    fn get_tup_id(&self, p: &Path) -> &TupPathDescriptor {
        let p = without_curdir_prefix(p);
        let p: &Path = p.as_ref();
        self.tbo.get_id(&NormalPath::new(p.to_path_buf())).unwrap()
    }

    /// Return root folder where tup was initialized
    fn get_root_dir(&self) -> &Path {
        self.pbo.get_root_dir()
    }

    /// Get group name stored against its id
    fn get_group_name(&self, gd: &GroupPathDescriptor) -> String {
        self.gbo.get_group_name(gd)
    }

    /// Get path of a maybe resolved input
    fn get_path_from(&self, input_glob: &InputResolvedType) -> &Path {
        input_glob.get_resolved_path(&self.pbo)
    }

    /// Get Path stored against its id
    fn get_path_str(&self, p: &PathDescriptor) -> String {
        let p = self.pbo.get(p).as_path();
        p.to_string_lossy().to_string()
    }

    /// check if env var exists in our stored buffers
    fn has_env(&self, id: &str, cur_env_desc: &EnvDescriptor) -> bool {
        self.ebo.has_env(id, cur_env_desc)
    }

    /// Return an iterator over all the id-group path pairs.
    /// Group path is of the form folder/\<group\>, Where folder is the file system path relative to root
    fn group_iter(&self) -> bimap::hash::Iter<'_, NormalPath, GroupPathDescriptor> {
        self.gbo.group_iter()
    }
}

/// Decode input paths from file globs, bins(buckets), and groups
pub(crate) trait DecodeInputPaths {
    fn decode(
        &self,
        tup_cwd: &Path,
        path_searcher: &impl PathSearcher,
        path_buffers: &mut impl PathBuffers,
        rule_ref: &RuleRef,
    ) -> Result<Vec<InputResolvedType>, Err>;
}

// Decode input paths in RvalGeneral
impl DecodeInputPaths for PathExpr {
    // convert globs into regular paths, remember that matched groups
    fn decode(
        &self,
        tup_cwd: &Path,
        path_searcher: &impl PathSearcher,
        path_buffers: &mut impl PathBuffers,
        rule_ref: &RuleRef,
    ) -> Result<Vec<InputResolvedType>, Err> {
        let mut vs = Vec::new();
        debug!("Decoding input paths of {:?}", &self);

        match self {
            PathExpr::Literal(_) => {
                let pbuf = normalized_path(self);
                let glob_path = GlobPath::new(tup_cwd, pbuf.as_path(), path_buffers)?;

                debug!("glob str: {:?}", glob_path.get_abs_path());
                let pes = path_searcher.discover_paths(path_buffers, &glob_path)?;
                if pes.is_empty() {
                    let (pd, _) = path_buffers.add_abs(glob_path.get_abs_path());
                    vs.push(InputResolvedType::UnResolvedFile(pd));
                } else {
                    vs.extend(pes.into_iter().map(InputResolvedType::Deglob));
                }
            }
            PathExpr::Group(_, _) => {
                let (ref grp_desc, _) =
                    path_buffers.add_group_pathexpr(tup_cwd, self.cat().as_str());
                {
                    debug!(
                        "resolving grp: {:?} with desc:{:?}",
                        path_buffers.try_get_group_path(grp_desc).unwrap(),
                        grp_desc
                    );
                    if let Some(paths) = path_searcher.get_outs().get().get_group(grp_desc) {
                        vs.extend(
                            paths
                                .deref()
                                .iter()
                                .map(|x| InputResolvedType::GroupEntry(*grp_desc, *x)),
                        )
                    } else {
                        //let (, _) = bo.add_path(Path::new(&*p.cat()), tup_cwd);
                        vs.push(InputResolvedType::UnResolvedGroupEntry(*grp_desc));
                    }
                }
            }
            PathExpr::Bin(b) => {
                let (ref bin_desc, _) = path_buffers.add_bin_path_expr(tup_cwd, b.as_ref());
                debug!("resolving bin: {:?}/{:?}", tup_cwd, b.as_str());
                if let Some(paths) = path_searcher.get_outs().get().get_bin(bin_desc) {
                    for p in paths.deref() {
                        vs.push(InputResolvedType::BinEntry(*bin_desc, *p))
                    }
                } else {
                    return Err(Error::StaleBinRef(b.clone(), rule_ref.clone()));
                }
            }
            _ => {}
        }
        Ok(vs)
    }
}
// decode input paths
impl DecodeInputPaths for Vec<PathExpr> {
    fn decode(
        &self,
        tup_cwd: &Path,
        path_searcher: &impl PathSearcher,
        path_buffers: &mut impl PathBuffers,
        rule_ref: &RuleRef,
    ) -> Result<Vec<InputResolvedType>, Err> {
        // gather locations where exclude patterns show up
        debug!("decoding inputs");
        let excludeindices: Vec<_> = self
            .iter()
            .enumerate()
            .filter(|pi| matches!(&pi.1, &PathExpr::ExcludePattern(_)))
            .map(|ref pi| pi.0)
            .collect();

        // now collect decoded pathexpressions that form inputs
        let decoded: Result<Vec<_>, _> = self
            .iter()
            .inspect(|x| debug!("before decode {:?}", x))
            .map(|x| x.decode(tup_cwd, path_searcher, path_buffers, rule_ref))
            .inspect(|x| debug!("after {:?}", x))
            .collect();
        let filter_out_excludes =
            |(i, ips): (usize, Vec<InputResolvedType>)| -> Vec<InputResolvedType> {
                // find the immediately following exclude pattern
                let pp = excludeindices.partition_point(|&j| j <= i);
                if pp < excludeindices.len() {
                    // remove paths that match exclude pattern
                    let v = self.as_slice();
                    let exclude_regex = &v[excludeindices[pp]];
                    exclude_regex.exclude(ips, path_buffers)
                } else {
                    ips
                }
            };
        let decoded = decoded?;
        debug!("done processing inputs");
        Ok(decoded
            .into_iter()
            .enumerate()
            .flat_map(filter_out_excludes)
            .collect())
    }
}

trait GatherOutputs {
    fn gather_outputs(
        &self,
        output_handler: &mut impl OutputHandler,
        path_buffers: &mut impl PathBuffers,
    ) -> Result<(), Err>;
}

trait DecodeInputPlaceHolders {
    fn decode_input_place_holders(
        &self,
        inputs: &InputsAsPaths,
        secondary_inputs: &InputsAsPaths,
    ) -> Result<Self, Err>
    where
        Self: Sized;
}

struct OutputsAsPaths {
    outputs: Vec<PathBuf>,
    rule_ref: RuleRef,
}

impl OutputsAsPaths {
    pub fn get_paths(&self) -> Vec<String> {
        self.outputs
            .iter()
            .map(|x| x.as_path().to_string_lossy().to_string())
            .collect()
    }
    pub fn get_file_stem(&self) -> Option<String> {
        self.outputs
            .first()
            .and_then(|x| x.as_path().file_stem())
            .map(|x| x.to_string_lossy().to_string())
    }
    pub fn is_empty(&self) -> bool {
        self.outputs.is_empty()
    }
}

trait DecodeOutputPlaceHolders {
    fn decode_output_place_holders(&self, outputs: &OutputsAsPaths) -> Result<Self, Err>
    where
        Self: Sized;
}

/// 'GroupInputs' represents a collection of paths associated with a group name
pub trait GroupInputs {
    /// Returns all paths  (space separated) associated with a given group name for a given rule
    /// Full path of the group is infered from the rule inputs that of the form path/<group_name>
    fn get_group_paths(&self, group_name: &str, rule_id: i64, rule_dir: i64) -> Option<String>
    where
        Self: Sized;
}

/// `InputsAsPaths' represents resolved inputs to pass to a rule.
/// Bins are converted to raw paths, groups paths are expanded into a space separated path list
pub struct InputsAsPaths {
    raw_inputs: Vec<PathBuf>,
    groups_by_name: HashMap<String, String>,
    raw_inputs_glob_match: Option<InputResolvedType>,
    rule_ref: RuleRef,
    tup_dir: PathBuf,
}

impl GroupInputs for InputsAsPaths {
    /// Returns all paths  (space separated) associated with a given group name
    /// This is used for group name substitutions in rule formulas that appear as %<group_name>
    fn get_group_paths(&self, group_name: &str, _rule_id: i64, _rule_dir: i64) -> Option<String> {
        if group_name.starts_with('<') {
            self.groups_by_name.get(group_name).cloned()
        } else {
            self.groups_by_name
                .get(&*format!("<{}>", group_name))
                .cloned()
        }
    }
}

impl InputsAsPaths {
    /// Returns all paths as strings in a vector
    pub(crate) fn get_file_names(&self) -> Vec<String> {
        self.raw_inputs
            .iter()
            .map(|x| x.as_path())
            .filter_map(|f| f.file_name())
            .map(|x| x.to_string_lossy().to_string())
            .collect()
    }

    /// Returns the first parent folder name
    pub(crate) fn parent_folder_name(&self) -> &Path {
        self.tup_dir.as_path()
    }

    /// returns all the inputs
    pub(crate) fn get_paths(&self) -> Vec<String> {
        self.raw_inputs
            .iter()
            .map(|x| x.as_path())
            .chain(self.groups_by_name.values().map(Path::new))
            .map(|x| x.to_string_lossy().to_string())
            .collect()
    }

    pub(crate) fn get_extension(&self) -> Option<String> {
        self.raw_inputs
            .iter()
            .map(|x| x.as_path())
            .chain(self.groups_by_name.values().map(Path::new))
            .filter_map(|x| x.extension())
            .map(|x| x.to_string_lossy().to_string())
            .next()
    }
    pub(crate) fn get_file_stem(&self) -> Vec<String> {
        self.raw_inputs
            .iter()
            .map(|x| x.as_path())
            .chain(self.groups_by_name.values().map(Path::new))
            .filter_map(|x| x.file_stem())
            .map(|x| x.to_string_lossy().to_string())
            .collect()
    }

    pub(crate) fn get_glob(&self) -> Option<&Vec<String>> {
        self.raw_inputs_glob_match
            .as_ref()
            .and_then(InputResolvedType::as_glob_match)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.raw_inputs.is_empty()
    }
}
impl InputsAsPaths {
    pub(crate) fn new(
        tup_cwd: &Path,
        inp: &[InputResolvedType],
        path_buffers: &mut impl PathBuffers,
        rule_ref: RuleRef,
    ) -> InputsAsPaths {
        let isnotgrp = |x: &InputResolvedType| {
            !matches!(x, &InputResolvedType::GroupEntry(_, _))
                && !matches!(x, &InputResolvedType::UnResolvedGroupEntry(_))
        };
        if !inp.is_empty() {
            debug!(
                "processing inputs at {:?} first of which is {:?}",
                tup_cwd, inp[0]
            );
        }
        let relpath = |x: &Path| {
            diff_paths(x, tup_cwd)
                .unwrap_or_else(|| panic!("path diff failure {:?} with base:{:?}", x, tup_cwd))
        };
        let try_grp = |x: &InputResolvedType| {
            if let &InputResolvedType::GroupEntry(ref grp_desc, _) = x {
                Some((
                    path_buffers.get_group_name(grp_desc),
                    relpath(path_buffers.get_path_from(x)),
                ))
            } else if let &InputResolvedType::UnResolvedGroupEntry(ref grp_desc) = x {
                let grp_name = path_buffers.get_group_name(grp_desc);
                Some((grp_name.clone(), Path::new(&*grp_name).to_path_buf()))
            } else {
                None
            }
        };
        let allnongroups: Vec<_> = inp
            .iter()
            .filter(|&x| isnotgrp(x))
            .map(|x| relpath(path_buffers.get_path_from(x)))
            .collect();
        let mut namedgroupitems: HashMap<_, Vec<String>> = HashMap::new();
        for x in inp.iter().filter_map(|x| try_grp(x)) {
            namedgroupitems
                .entry(x.0)
                .or_insert_with(Default::default)
                .push(x.1.to_string_lossy().to_string())
        }
        let namedgroupitems = namedgroupitems
            .drain()
            .map(|(s, v)| (s, v.join(" ")))
            .collect();
        let raw_inputs_glob_match = inp.first().cloned();
        debug!("input glob match :{:?}", raw_inputs_glob_match);
        InputsAsPaths {
            raw_inputs: allnongroups,
            groups_by_name: namedgroupitems,
            raw_inputs_glob_match,
            rule_ref,
            tup_dir: tup_cwd.to_path_buf(),
        }
    }
}

lazy_static! {
    static ref PERC_NUM_F_RE: Regex =
        Regex::new(r"%([1-9][0-9]*)f").expect("regex compilation error"); // pattern for matching  numberedinputs that appear in command line
    static ref PERC_NUM_B_RE: Regex =
        Regex::new(r"%([1-9][0-9]*)b").expect("regex compilation error"); //< pattern for matching a numbered basename with extension of a input to a rule
    static ref GRPRE: Regex = Regex::new(r"%<([^>]+)>").expect("regex compilation error"); //< pattern for matching a group
    static ref PER_CAP_B_RE: Regex =
        Regex::new(r"%([1-9][0-9]*)B").expect("regex compilation failure"); //< pattern for matching basename of input to a rule
    static ref PERC_NUM_G_RE: Regex =
        Regex::new(r"%([1-9][0-9]*)g").expect("regex compilation error"); //< pattern for matching outputs that appear on command line
    static ref PERC_NUM_O_RE: Regex =
        Regex::new(r"%([1-9][0-9]*)o").expect("regex compilation error"); //< pattern for matching outputs that appear on command line
    static ref PERC_NUM_CAP_O_RE: Regex =
        Regex::new(r"%([1-9][0-9]*)O").expect("regex compilation error");
    static ref PERC_NUM_I : Regex = Regex::new(r"%([1-9][0-9]*)i").expect("regex compilation error"); //< pattern for matching numbered order only inputs (that dont appear in command line)
}

/// replace all occurrences of <{}> in rule strings with the paths that are associated with corresponding group input for that that rule.
pub fn decode_group_captures(
    inputs: &impl GroupInputs,
    rule_ref: &RuleRef,
    rule_id: i64,
    dirid: i64,
    rule_str: &str,
) -> Result<String, Error> {
    let replacer = |caps: &Captures| {
        let c = caps
            .get(1)
            .ok_or_else(|| Err::StaleGroupRef("unknown".to_string(), rule_ref.clone()))?;
        inputs
            .get_group_paths(c.as_str(), rule_id, dirid)
            .ok_or_else(|| Err::StaleGroupRef(c.as_str().to_string(), rule_ref.clone()))
    };
    let reps: Result<Vec<_>, _> = GRPRE
        .captures(rule_str)
        .iter()
        .inspect(|x| {
            debug!(
                "group capture before replace :{}",
                x.get(0).unwrap().as_str()
            )
        })
        .map(|x| replacer(x))
        .inspect(|x| {
            if let Ok(ref x) = x {
                debug!("group capture after replace :{}", x.as_str());
            }
        })
        .collect();
    let reps = reps?;
    let mut i = 0;

    let d = GRPRE
        .replace(rule_str, |_: &Captures| {
            let r = &reps[i];
            i += 1;
            r.as_str()
        })
        .to_string();
    Ok(d)
}

impl DecodeInputPlaceHolders for PathExpr {
    fn decode_input_place_holders(
        &self,
        inputs: &InputsAsPaths,
        secondary_inputs: &InputsAsPaths,
    ) -> Result<Self, Err> {
        let frep = |inp: &InputsAsPaths, sinp: &InputsAsPaths, d: &str| -> Result<String, Err> {
            let rule_ref = &inp.rule_ref;
            let d = if d.contains("%f") {
                let inputs = inp.get_paths();
                if inputs.is_empty() {
                    return Err(Err::StalePerc('f', rule_ref.clone(), d.to_string()));
                }
                d.replace("%f", inputs.join(" ").as_str())
            } else {
                d.to_string()
            };

            let d = if PERC_NUM_F_RE.captures(d.as_str()).is_some() {
                // numbered inputs will be replaced here
                let inputs = inp.get_paths();
                if inputs.is_empty() {
                    return Err(Err::StalePerc('f', rule_ref.clone(), d.clone()));
                }
                replace_decoded_str(d.as_str(), &inputs, &PERC_NUM_F_RE, rule_ref, 'f')?
            } else {
                d
            };

            let d = if d.contains("%b") {
                let fnames = inputs.get_file_names();
                if fnames.is_empty() {
                    return Err(Err::StalePerc('b', rule_ref.clone(), d.clone()));
                }
                d.replace("%b", fnames.join(" ").as_str())
            } else {
                d
            };

            let d = if PERC_NUM_B_RE.captures(d.as_str()).is_some() {
                let fnames = inputs.get_file_names();
                if fnames.is_empty() {
                    return Err(Err::StalePercNumberedRef('b', rule_ref.clone(), d.clone()));
                }
                replace_decoded_str(d.as_str(), &fnames, &PERC_NUM_B_RE, rule_ref, 'b')?
            } else {
                d
            };

            let d = if d.contains("%B") {
                let stems = inp.get_file_stem();
                if stems.is_empty() {
                    return Err(Err::StalePerc('B', rule_ref.clone(), d.clone()));
                }
                d.replace("%B", stems.join(" ").as_str())
            } else {
                d
            };

            let d = if PER_CAP_B_RE.captures(d.as_str()).is_some() {
                let stems = inp.get_file_stem();
                if stems.is_empty() {
                    return Err(Err::StalePercNumberedRef('B', rule_ref.clone(), d.clone()));
                }
                replace_decoded_str(d.as_ref(), &stems, &PER_CAP_B_RE, rule_ref, 'B')?
            } else {
                d
            };

            let d = if d.contains("%e") {
                let ext = inp
                    .get_extension()
                    .ok_or_else(|| Err::StalePerc('e', rule_ref.clone(), d.clone()))?;
                d.replace("%e", ext.as_str())
            } else {
                d
            };
            let d = if d.contains("%d") {
                let parent_name = inp.parent_folder_name().to_string_lossy().to_string();
                d.replace("%d", parent_name.as_str())
            } else {
                d
            };
            let d = if d.contains("%g") {
                let g = inp.get_glob().and_then(|x| x.first());
                let g = g.ok_or_else(|| Err::StalePerc('g', rule_ref.clone(), d.clone()))?;
                d.replace("%g", g.as_str())
            } else {
                d
            };

            let d = if d.contains("%i") {
                // replace with secondary inputs (order only inputs)
                let sinputsflat = sinp.get_paths();
                if sinp.is_empty() {
                    return Err(Err::StalePerc('i', sinp.rule_ref.clone(), d));
                }
                d.replace("%i", sinputsflat.join(" ").as_str())
            } else {
                d
            };
            let d = if PERC_NUM_I.captures(d.as_str()).is_some() {
                // replaced with numbered captures of order only inputs
                if sinp.is_empty() {
                    return Err(Err::StalePercNumberedRef('i', sinp.rule_ref.clone(), d));
                }
                let sinputsflat = sinp.get_paths();
                replace_decoded_str(d.as_str(), &sinputsflat, &PERC_NUM_I, &sinp.rule_ref, 'i')?
            } else {
                d
            };

            let d = if PERC_NUM_G_RE.captures(d.as_str()).is_some() {
                let captures = inp.get_glob().ok_or(Err::StalePercNumberedRef(
                    'g',
                    inp.rule_ref.clone(),
                    d.clone(),
                ))?;
                replace_decoded_str(d.as_str(), captures, &PERC_NUM_G_RE, &inp.rule_ref, 'g')?
            } else {
                d
            };
            Ok(d)
        };
        let pe = if let PathExpr::Literal(s) = self {
            PathExpr::from(frep(inputs, secondary_inputs, s)?)
        } else {
            self.clone()
        };
        Ok(pe)
    }
}

fn replace_decoded_str(
    decoded_str: &str,
    file_names: &[String],
    perc_b_re: &'static Regex,
    rule_ref: &RuleRef,
    c: char,
) -> Result<String, Err> {
    let reps: Result<Vec<&String>, Err> = perc_b_re
        .captures(decoded_str)
        .iter()
        .map(|caps: &Captures| {
            let i = caps[1].parse::<usize>().unwrap();
            file_names.get(i - 1).ok_or_else(|| {
                Err::StalePercNumberedRef(c, rule_ref.clone(), decoded_str.to_string())
            })
        })
        .collect();
    let reps = reps?;
    let mut i: usize = 0;
    let s = perc_b_re.replace(decoded_str, |_: &Captures| {
        let r = reps[i];
        i += 1;
        r
    });
    Ok(s.to_string())
}

impl DecodeInputPlaceHolders for Vec<PathExpr> {
    fn decode_input_place_holders(
        &self,
        inputs: &InputsAsPaths,
        secondary_inputs: &InputsAsPaths,
    ) -> Result<Self, Err> {
        self.iter()
            .map(|x| x.decode_input_place_holders(inputs, secondary_inputs))
            .collect()
    }
}

impl DecodeOutputPlaceHolders for Vec<PathExpr> {
    fn decode_output_place_holders(&self, outputs: &OutputsAsPaths) -> Result<Self, Err> {
        self.iter()
            .map(|x| x.decode_output_place_holders(outputs))
            .collect()
    }
}

impl DecodeOutputPlaceHolders for PathExpr {
    fn decode_output_place_holders(&self, outputs: &OutputsAsPaths) -> Result<Self, Err> {
        let frep = |d: &str| -> Result<String, Err> {
            debug!("replacing %o's from rule string :{}", d);
            let d = if d.contains("%o") {
                let space_separated_outputs = outputs.get_paths().join(" ");
                if outputs.is_empty() {
                    debug!("no output found for %o replacement");
                    return Err(Err::StalePerc('o', outputs.rule_ref.clone(), d.to_string()));
                }
                d.replace("%o", space_separated_outputs.as_str())
            } else {
                d.to_string()
            };
            let d = if d.contains("%O") {
                if outputs.is_empty() {
                    return Err(Err::StalePerc('O', outputs.rule_ref.clone(), d));
                }
                let stem = outputs
                    .get_file_stem()
                    .ok_or_else(|| Err::StalePerc('O', outputs.rule_ref.clone(), d.clone()))?;
                d.replace("%O", stem.as_str())
            } else {
                d
            };

            let d = if PERC_NUM_O_RE.captures(d.as_str()).is_some() {
                replace_decoded_str(
                    d.as_str(),
                    &outputs.get_paths(),
                    &PERC_NUM_O_RE,
                    &outputs.rule_ref,
                    'o',
                )?
            } else {
                d
            };
            let d = if PERC_NUM_CAP_O_RE.captures(d.as_str()).is_some() {
                replace_decoded_str(
                    d.as_str(),
                    &outputs.get_paths(),
                    &PERC_NUM_CAP_O_RE,
                    &outputs.rule_ref,
                    'O',
                )?
            } else {
                d
            };
            Ok(d)
        };
        Ok(if let PathExpr::Literal(s) = self {
            PathExpr::from(frep(s)?)
        } else {
            self.clone()
        })
    }
}

fn normalized_path(x: &PathExpr) -> PathBuf {
    //  backslashes with forward slashes
    let pbuf = PathBuf::new().join(x.cat_ref().replace('\\', "/").as_str());
    pbuf
    //NormalPath::absolute_from(pbuf.as_path(), tup_cwd).to_path_buf()
}
fn excluded_patterns(
    tup_cwd: &Path,
    p: &[PathExpr],
    path_buffers: &mut impl PathBuffers,
) -> Vec<PathDescriptor> {
    p.iter()
        .filter_map(|x| {
            if let PathExpr::ExcludePattern(pattern) = x {
                let s = "^".to_string() + pattern.as_str();
                let path = Path::new(s.as_str());
                let (pid, _) = path_buffers.add_path_from(tup_cwd, path);
                Some(pid)
            } else {
                None
            }
        })
        .collect()
}

fn paths_from_exprs(
    tup_cwd: &Path,
    p: &[PathExpr],
    path_buffers: &mut impl PathBuffers,
) -> Vec<OutputType> {
    p.split(|x| matches!(x, &PathExpr::Sp1) || matches!(x, &PathExpr::ExcludePattern(_)))
        .filter(|x| !x.is_empty())
        .map(|x| {
            let path = PathBuf::new().join(x.to_vec().cat());
            let (pid, _) = path_buffers.add_path_from(tup_cwd, path.as_path());
            let _ = path_buffers.add_path_from(tup_cwd, &*get_parent(path.as_path()));
            let pathbuf = path_buffers.get_path(&pid);
            OutputType::new(pathbuf.clone(), pid)
        })
        .collect()
}

// replace % specifiers in a target of rule statement which has already been
// deglobbed
impl DecodeInputPlaceHolders for Target {
    fn decode_input_place_holders(
        &self,
        inputs: &InputsAsPaths,
        secondary_inputs: &InputsAsPaths,
    ) -> Result<Self, Err> {
        let newprimary = self
            .primary
            .decode_input_place_holders(inputs, secondary_inputs)?;
        let newsecondary = self
            .secondary
            .decode_input_place_holders(inputs, secondary_inputs)?;
        Ok(Target {
            primary: newprimary,
            secondary: newsecondary,
            bin: self.bin.clone(),
            group: self.group.clone(),
        })
    }
}

impl DecodeInputPlaceHolders for RuleFormula {
    /// rebuild a rule formula with input placeholders filled up
    fn decode_input_place_holders(
        &self,
        inputs: &InputsAsPaths,
        secondary_inputs: &InputsAsPaths,
    ) -> Result<Self, Err> {
        Ok(RuleFormula::new_from_parts(
            self.description
                .decode_input_place_holders(inputs, secondary_inputs)?,
            self.formula
                .decode_input_place_holders(inputs, secondary_inputs)?,
        ))
    }
}

impl DecodeOutputPlaceHolders for RuleFormula {
    /// rebuild rule by replacing output placeholders such as %o
    fn decode_output_place_holders(&self, outputs: &OutputsAsPaths) -> Result<Self, Err> {
        Ok(RuleFormula {
            description: self.description.decode_output_place_holders(outputs)?,
            formula: self.formula.decode_output_place_holders(outputs)?,
        })
    }
}

/// decode input and output placeholders to rebuild a rule
fn get_deglobbed_rule(
    rule_ctx: &RuleContext,
    primary_deglobbed_inps: &[InputResolvedType],
    path_buffers: &mut impl PathBuffers,
    env: &EnvDescriptor,
) -> Result<ResolvedLink, Err> {
    let r = rule_ctx.get_rule_formula();
    let rule_ref = rule_ctx.get_rule_ref();
    let t = rule_ctx.get_target();
    let tup_cwd = rule_ctx.get_tup_cwd();
    let secondary_deglobbed_inps = rule_ctx.get_secondary_inp();
    debug!("deglobbing tup at dir:{:?}, rule:{:?}", tup_cwd, r.cat());

    let input_as_paths = InputsAsPaths::new(
        tup_cwd,
        primary_deglobbed_inps,
        path_buffers,
        rule_ref.clone(),
    );
    let secondary_inputs_as_paths = InputsAsPaths::new(
        tup_cwd,
        secondary_deglobbed_inps,
        path_buffers,
        rule_ref.clone(),
    );
    let decoded_target = t.decode_input_place_holders(&input_as_paths, &secondary_inputs_as_paths);
    if decoded_target.is_err() {
        debug!("Failed to decode {:?}", t);
    }
    let mut decoded_target = decoded_target?;
    let excluded_targets = excluded_patterns(tup_cwd, &decoded_target.primary, path_buffers);
    let pp = paths_from_exprs(tup_cwd, &decoded_target.primary, path_buffers);

    let df = |x: &OutputType| diff_paths(x.as_path(), tup_cwd).unwrap();
    let output_as_paths = OutputsAsPaths {
        outputs: pp.iter().map(df).collect(),
        rule_ref: rule_ref.clone(),
    };
    decoded_target.secondary = decoded_target
        .secondary
        .decode_output_place_holders(&output_as_paths)?;
    let sec_pp = paths_from_exprs(tup_cwd, &decoded_target.secondary, path_buffers);
    let resolved_rule: RuleFormula = r
        .decode_input_place_holders(&input_as_paths, &secondary_inputs_as_paths)?
        .decode_output_place_holders(&output_as_paths)?;

    let bin_desc = t.bin.as_ref().map(|x| {
        if let PathExpr::Bin(x) = x {
            path_buffers.add_bin_path_expr(tup_cwd, x).0
        } else {
            Default::default()
        }
    });
    let group_desc = t
        .group
        .as_ref()
        .map(|x| path_buffers.add_group_pathexpr(tup_cwd, x.cat().as_str()).0);

    let rule_formula_desc = path_buffers
        .add_rule(RuleFormulaUsage::new(resolved_rule, rule_ref.clone()))
        .0;
    Ok(ResolvedLink {
        primary_sources: primary_deglobbed_inps.to_vec(),
        secondary_sources: secondary_deglobbed_inps.to_vec(),
        rule_formula_desc,
        primary_targets: pp.into_iter().map(|x| x.get_id()).collect(),
        secondary_targets: sec_pp.into_iter().map(|x| x.get_id()).collect(),
        excluded_targets,
        bin: bin_desc,
        group: group_desc,
        rule_ref: rule_ref.clone(),
        env: env.clone(),
    })
}
/// ResolvedLink represents a rule with its inputs, outputs and command string fully or partially resolved.
/// This means that paths stored here are file paths that are or expected to be in file system.
/// Rule string is also expect to be executable or ready for persistence with all  symbols and variable references resolved
/// Group references are an exception and may not be resolved until all the tupfiles are read.
#[derive(Clone, Debug, Default)]
pub struct ResolvedLink {
    /// Inputs that are read by a rule that can be used for %f substitution
    primary_sources: Vec<InputResolvedType>,
    /// Other inputs read by a rule not available for %f substitution
    secondary_sources: Vec<InputResolvedType>,
    /// Rule formula refered to by its descriptor
    rule_formula_desc: RuleDescriptor,
    /// Outputs that are written to by a rule that can be used for %o substitution
    primary_targets: Vec<PathDescriptor>,
    /// Other outputs written to by a rule
    secondary_targets: Vec<PathDescriptor>,
    /// Exclusion patterns on targets
    excluded_targets: Vec<PathDescriptor>,
    /// Optional Group that outputs go into.
    /// Groups are collectors of ouptuts that are accessible as inputs to other rules which may not be from
    /// the same tupfile as the rule that provides this group
    group: Option<GroupPathDescriptor>,
    /// Optional bin that outputs go into. Bins are available as inputs to other rules in the
    /// same Tupfile that produced them
    bin: Option<BinDescriptor>,
    /// Tupfile and location where the rule was found
    rule_ref: RuleRef,
    /// Env(environment) needed by this rule
    env: EnvDescriptor,
}

impl ResolvedLink {
    /// Plain no-arg constructor for a ResolvedLink, that sets default values to most entries
    pub fn new() -> Self {
        ResolvedLink {
            primary_sources: vec![],
            secondary_sources: vec![],
            rule_formula_desc: Default::default(),
            primary_targets: vec![],
            secondary_targets: vec![],
            excluded_targets: vec![],
            group: None,
            bin: None,
            rule_ref: Default::default(),
            env: Default::default(),
        }
    }

    /// iterator over all the sources (primary and secondary) in this link
    pub fn get_sources(
        &self,
    ) -> std::iter::Chain<
        std::slice::Iter<'_, InputResolvedType>,
        std::slice::Iter<'_, InputResolvedType>,
    > {
        self.primary_sources
            .iter()
            .chain(self.secondary_sources.iter())
    }
    ///  iterator over all the targets  (primary and secondary) in this link
    pub fn get_targets(
        &self,
    ) -> std::iter::Chain<std::slice::Iter<'_, PathDescriptor>, std::slice::Iter<'_, PathDescriptor>>
    {
        self.primary_targets
            .iter()
            .chain(self.secondary_targets.iter())
    }
    /// Returns descriptor for the Env vars to be assigned before execution of this rule
    pub fn get_env_desc(&self) -> &EnvDescriptor {
        &self.env
    }
    /// Unique descriptor for rule formula
    pub fn get_rule_desc(&self) -> &RuleDescriptor {
        &self.rule_formula_desc
    }
    /// Group path descriptor that collects outputs of this rule
    pub fn get_group_desc(&self) -> Option<&GroupPathDescriptor> {
        self.group.as_ref()
    }
    /// {bin} object descriptor that collects outputs of this rule
    pub fn get_bin_desc(&self) -> Option<&BinDescriptor> {
        self.bin.as_ref()
    }

    /// returns `RuleRef' of this link that referes to the the  tupfile and the location of the rule
    pub fn get_rule_ref(&self) -> &RuleRef {
        &self.rule_ref
    }

    /// returns ids of excluded patterns
    pub fn get_excluded_targets(&self) -> &Vec<PathDescriptor> {
        &self.excluded_targets
    }

    /// Check if there are any sources which are still unresolved
    pub fn has_unresolved_inputs(&self) -> bool {
        self.get_sources().any(InputResolvedType::is_unresolved)
    }

    /// Get parent directory ids of glob inputs
    pub fn for_each_glob_path_desc<F>(&self, f: F) -> Result<(), Error>
    where
        F: FnMut(GlobPathDescriptor) -> Result<(), Error>,
    {
        self.get_sources()
            .filter_map(|x| x.get_glob_path_desc())
            .try_for_each(f)
    }

    fn reresolve(
        path_searcher: &impl PathSearcher,
        path_buffers: &mut impl PathBuffers,
        p: &PathDescriptor,
        rule_ref: &RuleRef,
    ) -> Result<Vec<MatchingPath>, Error> {
        let glob_path = GlobPath::from_path_desc(path_buffers, *p)?;
        debug!("need to resolve file:{:?}", glob_path.get_abs_path());
        let pes: Vec<MatchingPath> = path_searcher.discover_paths(path_buffers, &glob_path)?;
        if pes.is_empty() {
            debug!("Could not resolve :{:?}", path_buffers.get_path(p));
            return Err(Error::UnResolvedFile(
                glob_path.get_abs_path().to_string_lossy().to_string(),
                rule_ref.clone(),
            ));
        }
        Ok(pes)
    }
}

// update the groups/bins with the path to primary target and also add secondary targets
impl GatherOutputs for ResolvedLink {
    fn gather_outputs(
        &self,
        output_handler: &mut impl OutputHandler,
        path_buffers: &mut impl PathBuffers,
    ) -> Result<(), Err> {
        let rule_ref = &self.rule_ref;
        struct PathsWithParent {
            pd: PathDescriptor,
            parent_pd: PathDescriptor,
        }
        let mut children = Vec::new();
        for path_desc in self.get_targets() {
            let path = path_buffers.get_path(path_desc);
            log::debug!(
                "adding parent for: {:?} to {:?}:{}",
                path,
                path_buffers.get_tup_path(rule_ref.get_tupfile_desc()),
                rule_ref.get_line()
            );
            if path.as_path().is_dir() {
                return Err(Err::OutputIsDir(
                    path_buffers.get_path(path_desc).to_string(),
                    rule_ref.clone(),
                ));
            }
            let rule_ref_inserted = output_handler.add_parent_rule(*path_desc, rule_ref.clone());
            if &rule_ref_inserted != rule_ref {
                return Err(Err::MultipleRulesToSameOutput(
                    *path_desc,
                    rule_ref.clone(),
                    rule_ref_inserted.clone(),
                ));
            }
            output_handler.add_output(*path_desc);
            children.push(PathsWithParent {
                pd: *path_desc,
                parent_pd: path_buffers.get_parent_id(path_desc).unwrap(),
            });
        }

        children
            .as_mut_slice()
            .sort_by(|x, y| x.parent_pd.cmp(&y.parent_pd));
        let mut slice = children.as_slice();
        while !slice.is_empty() {
            let pp = slice.first().unwrap();
            let mut prev = slice;
            if let Some(r) = slice[1..]
                .iter()
                .enumerate()
                .find(|x| !x.1.parent_pd.eq(&pp.parent_pd))
            {
                (prev, slice) = slice.split_at(r.0 + 1);
            } else {
                slice = &slice[1..]
            }
            output_handler.add_children(&pp.parent_pd, prev.iter().map(|x| x.pd.clone()).collect());
        }
        for path_desc in self.primary_targets.iter() {
            if let Some(ref group_desc) = self.group {
                output_handler.add_group_entry(group_desc, *path_desc)
            };
            if let Some(ref bin_desc) = self.bin {
                output_handler.add_bin_entry(bin_desc, *path_desc);
            };
            debug!(
                "fetching parent of path_desc:{:?}, {:?}",
                path_desc,
                path_buffers.get_path(path_desc)
            );
        }
        Ok(())
    }
}

/// Method to return resolved paths statements in Tupfile
/// This is called after initial variable substution to
pub(crate) trait ResolvePaths {
    fn resolve_paths(
        &self,
        tupfile: &Path,
        path_searcher: &mut impl PathSearcher,
        path_buffers: &mut impl PathBuffers,
        tup_desc: &TupPathDescriptor,
    ) -> Result<Artifacts, Err>;
}

impl ResolvePaths for Vec<ResolvedLink> {
    fn resolve_paths(
        &self,
        _tupfile: &Path,
        path_searcher: &mut impl PathSearcher,
        path_buffers: &mut impl PathBuffers,
        _tup_desc: &TupPathDescriptor,
    ) -> Result<Artifacts, Err> {
        let mut resolved_artifacts = Artifacts::new();
        for resolved_link in self.iter() {
            if resolved_link.has_unresolved_inputs() {
                let cur_tup_desc = resolved_link.get_rule_ref().get_tupfile_desc();
                let tup_cwd = path_buffers.get_tup_path(cur_tup_desc).to_path_buf();

                let art = resolved_link.resolve_paths(
                    tup_cwd.as_path(),
                    path_searcher,
                    path_buffers,
                    resolved_link.get_rule_ref().get_tupfile_desc(),
                )?;
                resolved_artifacts.extend(art);
            } else {
                resolved_artifacts.add_link(resolved_link.clone())
            }
        }
        Ok(resolved_artifacts)
    }
}

/// implementation for ResolvedLink performs unresolved paths in Group inputs using data in taginfo
impl ResolvePaths for ResolvedLink {
    /// the method below replaces
    fn resolve_paths(
        &self,
        _tupfile: &Path,
        path_searcher: &mut impl PathSearcher,
        path_buffers: &mut impl PathBuffers,
        _tup_desc: &TupPathDescriptor,
    ) -> Result<Artifacts, Err> {
        let mut rlink: ResolvedLink = self.clone();
        rlink.primary_sources.clear();
        rlink.secondary_sources.clear();
        for i in self.primary_sources.iter() {
            match i {
                InputResolvedType::UnResolvedFile(p) => {
                    let pes =
                        Self::reresolve(path_searcher, path_buffers, &p, rlink.get_rule_ref())?;
                    rlink
                        .primary_sources
                        .extend(pes.into_iter().map(InputResolvedType::Deglob));
                }
                InputResolvedType::UnResolvedGroupEntry(g) => {
                    if let Some(hs) = path_searcher.get_outs().get().get_group(&g) {
                        for pd in hs.deref() {
                            rlink
                                .primary_sources
                                .push(InputResolvedType::GroupEntry(*g, *pd));
                        }
                    } else {
                        return Err(Error::StaleGroupRef(
                            path_buffers.get_input_path_name(i),
                            rlink.get_rule_ref().clone(),
                        ));
                    }
                }
                _ => rlink.primary_sources.push(i.clone()),
            }
        }

        for i in self.secondary_sources.iter() {
            match i {
                InputResolvedType::UnResolvedFile(p) => {
                    let pes =
                        Self::reresolve(path_searcher, path_buffers, &p, rlink.get_rule_ref())?;
                    rlink
                        .secondary_sources
                        .extend(pes.into_iter().map(InputResolvedType::Deglob));
                }
                InputResolvedType::UnResolvedGroupEntry(ref g) => {
                    if let Some(hs) = path_searcher.get_outs().get().get_group(g) {
                        for pd in hs.deref() {
                            rlink
                                .secondary_sources
                                .push(InputResolvedType::GroupEntry(*g, *pd))
                        }
                    } else {
                        return Err(Error::StaleGroupRef(
                            path_buffers.get_input_path_name(i),
                            rlink.get_rule_ref().clone(),
                        ));
                    }
                }
                _ => rlink.secondary_sources.push(i.clone()),
            }
        }
        /* group placeholders cannot be resolved right away.. Delay until rule execution
        let rule_ref = self.get_rule_ref();
        let rule_str = path_buffers.get_rule(self.get_rule_desc()).get_formula().cat();
        if GRPRE.is_match(rule_str.as_str()) {
            let mut primary_inps =
                InputsAsPaths::new(tupfile, &rlink.primary_sources[..], path_buffers, rule_ref.clone());
            let secondary_inps =
                InputsAsPaths::new(tupfile, &rlink.secondary_sources[..], path_buffers, rule_ref.clone());
            primary_inps
                .groups_by_name
                .extend(secondary_inps.groups_by_name);
            let rs = decode_group_captures(&primary_inps, rule_ref, rule_str)?;
            let r = RuleFormula::new_from_raw(rs.as_str());
            let (rule_desc, _) = path_buffers.add_rule(RuleFormulaUsage::new(r, rule_ref.clone()));
            rlink.rule_formula_desc = rule_desc;
        } */
        let mut out = OutputHolder::new();
        self.gather_outputs(&mut out, path_buffers)?;
        path_searcher.merge(path_buffers, &mut out)?;
        Ok(Artifacts::from(vec![rlink]))
    }
}

struct RuleContext<'a, 'b, 'c, 'd> {
    tup_cwd: &'d Path,
    rule_formula: &'a RuleFormula,
    rule_ref: &'b RuleRef,
    target: &'a Target,
    secondary_inp: &'c [InputResolvedType],
}

impl<'a, 'b, 'c, 'd> RuleContext<'a, 'b, 'c, 'd> {
    fn get_rule_formula(&self) -> &RuleFormula {
        self.rule_formula
    }
    fn get_rule_ref(&self) -> &RuleRef {
        self.rule_ref
    }
    fn get_target(&self) -> &Target {
        self.target
    }
    fn get_secondary_inp(&self) -> &[InputResolvedType] {
        self.secondary_inp
    }
    fn get_tup_cwd(&self) -> &Path {
        self.tup_cwd
    }
}

/// deglob rule statement into multiple deglobbed rules, gather deglobbed targets to put in bins/groups
impl LocatedStatement {
    pub(crate) fn resolve_paths(
        &self,
        tupfile: &Path,
        path_searcher: &mut impl PathSearcher,
        path_buffers: &mut impl PathBuffers,
        tup_desc: &TupPathDescriptor,
    ) -> Result<(Artifacts, OutputHolder), Err> {
        let mut deglobbed = Vec::new();
        // use same resolve_groups as input
        let mut output = OutputHolder::new();
        let tup_cwd = if tupfile.is_dir() {
            tupfile
        } else {
            tupfile.parent().unwrap()
        };
        debug!("resolving  rule at dir:{:?} rule: {:?}", tup_cwd, &self);
        if let LocatedStatement {
            statement:
                Statement::Rule(
                    Link {
                        source: s,
                        target: t,
                        rule_formula,
                        pos: _pos,
                    },
                    env,
                ),
            loc,
        } = self
        {
            let rule_ref = &RuleRef::new(tup_desc, loc);
            let inpdec = s
                .primary
                .decode(tup_cwd, path_searcher, path_buffers, rule_ref)?;
            let secondinpdec =
                s.secondary
                    .decode(tup_cwd, path_searcher, path_buffers, rule_ref)?;
            let resolver = RuleContext {
                tup_cwd,
                rule_formula,
                rule_ref,
                target: t,
                secondary_inp: secondinpdec.as_slice(),
            };
            let for_each = s.for_each;
            if for_each {
                for input in inpdec {
                    if input.is_unresolved() {
                        log::warn!("Unresolved input files found : {:?} for rule:{:?} at  {:?}/Tupfile:{:?}", input, resolver.get_rule_formula(), resolver.get_tup_cwd(), rule_ref);
                        continue;
                    }
                    let delink = get_deglobbed_rule(
                        &resolver,
                        core::slice::from_ref(&input),
                        path_buffers,
                        env,
                    )?;
                    delink.gather_outputs(&mut output, path_buffers)?;
                    deglobbed.push(delink);
                }
            } else if !inpdec.is_empty() || !secondinpdec.is_empty() {
                debug!("Resolving rule {:?} at {:?}", rule_ref, tup_cwd);
                let delink = get_deglobbed_rule(&resolver, inpdec.as_slice(), path_buffers, env)?;
                delink.gather_outputs(&mut output, path_buffers)?;
                deglobbed.push(delink);
            }
            path_searcher.merge(path_buffers, &mut output)?;
        }
        Ok((Artifacts::from(deglobbed), output))
    }
}

impl ResolvePaths for Vec<LocatedStatement> {
    fn resolve_paths(
        &self,
        tupfile: &Path,
        path_searcher: &mut impl PathSearcher,
        path_buffers: &mut impl PathBuffers,
        tup_desc: &TupPathDescriptor,
    ) -> Result<Artifacts, Err> {
        let mut merged_arts = Artifacts::new();
        debug!("Resolving paths for rules in {:?}", tupfile);
        for stmt in self.iter() {
            let (art, _) = stmt.resolve_paths(tupfile, path_searcher, path_buffers, tup_desc)?;
            debug!("{:?}", art);
            merged_arts.extend(art);
        }
        Ok(merged_arts)
    }
}

/// `parse_dir' scans and parses all Tupfiles from a directory root, When sucessful it returns de-globbed, decoded links(rules)
pub fn parse_dir(root: &Path) -> Result<Artifacts, Error> {
    let mut tupfiles = Vec::new();
    let tf = OsString::from("Tupfile");
    let tflua = OsString::from("Tupfile.lua");
    for entry in WalkDir::new(root)
        .follow_links(true)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let f_name = entry.file_name();
        if f_name.eq(tf.as_os_str()) || f_name.eq(tflua.as_os_str()) {
            tupfiles.push(entry.path().to_path_buf());
        }
    }
    let mut artifacts_all = Artifacts::new();
    let mut parser = TupParser::<DirSearcher>::try_new_from(root, DirSearcher::new())?;
    for tup_file_path in tupfiles.iter() {
        let artifacts = parser.parse(tup_file_path)?;
        artifacts_all.extend(artifacts);
    }

    {
        let path_buffers = parser.borrow_ref();
        let _ = dag_check_artifacts(path_buffers.deref(), &mut artifacts_all)?;
    }
    parser.reresolve(artifacts_all)
}

/// checks for cycles in dependency graph between inputs and outputs
pub fn dag_check_artifacts(
    bo: &impl PathBuffers,
    artifacts_all: &mut Artifacts,
) -> Result<Vec<NodeIndex>, Error> {
    let statement_from_id = |i: NodeIndex| artifacts_all.get_resolved_link(i.index());
    let mut dag: Dag<u32, u32> = Dag::new();
    let mut provided_by: HashMap<_, Vec<_>> = HashMap::new();
    let mut required_by: HashMap<_, Vec<_>> = HashMap::new();
    for s in artifacts_all.get_resolved_links().iter() {
        let n = dag.add_node(1);
        if let Some(grp_id) = s.group.as_ref() {
            provided_by.entry(*grp_id).or_default().push(n);
        }
        for i in s.primary_sources.iter().chain(s.secondary_sources.iter()) {
            if let InputResolvedType::UnResolvedGroupEntry(g) = i {
                required_by.entry(*g).or_default().push(n);
            }
        }
    }
    for (group, nodeids) in required_by.iter() {
        if let Some(pnodeids) = provided_by.get(group) {
            for pnodeid in pnodeids {
                for nodeid in nodeids {
                    dag.update_edge(*pnodeid, *nodeid, 1).map_err(|_| {
                        Error::DependencyCycle(
                            {
                                let stmt = statement_from_id(*pnodeid);
                                let tup_desc = stmt.get_rule_ref().get_tupfile_desc();
                                let tupfile = bo.get_tup_path(tup_desc);
                                format!(
                                    "tupfile at {:?}, and rule at line:{}",
                                    tupfile,
                                    stmt.get_rule_ref().get_line(),
                                )
                            },
                            {
                                let stmt = statement_from_id(*nodeid);
                                let tup_desc = stmt.get_rule_ref().get_tupfile_desc();
                                let tupfile = bo.get_tup_path(tup_desc);
                                format!(
                                    "tupfile at {:?}, and rule at line:{}",
                                    tupfile,
                                    stmt.get_rule_ref().get_line()
                                )
                            },
                        )
                    })?;
                }
            }
        } else if !nodeids.is_empty() {
            let stmt = statement_from_id(*nodeids.first().unwrap());
            let p = bo.try_get_group_path(group).unwrap();
            return Err(Error::StaleGroupRef(
                p.as_path().to_string_lossy().to_string(),
                stmt.get_rule_ref().clone(),
            ));
        }
    }

    for i in 0..dag.node_count() {
        let j = i + 1;
        if j < dag.node_count() {
            let r = statement_from_id(NodeIndex::new(i));
            let s = statement_from_id(NodeIndex::new(j));
            if r.rule_ref.get_tupfile_desc() == s.rule_ref.get_tupfile_desc() {
                let _ = dag.add_edge(NodeIndex::new(i), NodeIndex::new(j), 1);
            }
        }
    }
    // Run toposort to check for cycles in dependency
    let nodes: Vec<_> = petgraph::algo::toposort(&dag, None).map_err(|e| {
        Error::DependencyCycle("".to_string(), {
            let stmt = statement_from_id(e.node_id());
            let tup_file_desc = stmt.get_rule_ref().get_tupfile_desc();
            let tupfile = bo.get_tup_path(tup_file_desc);
            format!(
                "tupfile:{}, and rule at line:{}",
                tupfile.to_string_lossy(),
                stmt.rule_ref.get_line()
            )
        })
    })?;
    Ok(nodes)
}
