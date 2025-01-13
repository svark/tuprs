//! Module to hold buffers of tupfile paths, bins, groups which can be referenced by their descriptors
use log::{debug, log_enabled};
use parking_lot::{MappedRwLockReadGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::{hash_map::Entry, BTreeSet, HashMap, HashSet, VecDeque};
use std::ffi::{OsStr, OsString};
use std::fmt::{Display, Formatter};
use std::hash::Hash;
use std::marker::PhantomData;
use std::ops::{AddAssign, Deref};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use tinyset::Fits64;

use crate::intern::Intern;
use crate::paths::get_non_pattern_prefix;
use crate::{
    decode::{OutputHandler, RuleFormulaInstance, TaskInstance, TupLoc},
    errors::Error,
    glob,
    glob::{GlobBuilder, GlobMatcher},
    paths::{GlobPath, InputResolvedType, MatchingPath, NormalPath},
    statements::Env,
};

/// Methods to store and retrieve paths, groups, bins, rules from in-memory buffers
/// This way we can identify paths /groups/bins and environment by their unique descriptors (ids)
pub trait PathBuffers {
    /// Add path of bin. Folder is the one where  Tupfile declaring the bin. name is bin name
    fn add_bin_path_expr(&self, tup_cwd: &PathDescriptor, pe: &str) -> BinDescriptor;

    /// add env var and fetch its descriptor
    fn add_env(&self, e: Cow<Env>) -> EnvDescriptor;

    /// Add a path to a group in this buffer
    fn add_group_pathexpr(&self, tup_cwd: &PathDescriptor, pe: &str) -> GroupPathDescriptor;
    /// return non pattern prefix in the glob path
    fn get_glob_prefix(&self, glob_desc: &GlobPathDescriptor) -> PathDescriptor;
    /// return the portion of path from non pattern prefix to the parent of the glob
    fn get_recursive_glob_str(&self, p0: &GlobPathDescriptor) -> String;
    /// return if the glob is recursive
    fn is_recursive_glob(&self, p0: &GlobPathDescriptor) -> bool;
    /// return the name of the group from its descriptor removing the non pattern prefix from the path
    fn get_glob_name(&self, glob_desc: &GlobPathDescriptor) -> String;

    /// add a path from root and fetch its unique id
    fn add_abs<P: AsRef<Path>>(&self, path: P) -> Result<PathDescriptor, Error>;
    /// add a path relative to tup_cwd and fetch its unique id. It can fail if path is not relative to tup_cwd
    fn add_path_from<P: AsRef<Path>>(
        &self,
        tup_cwd: &PathDescriptor,
        path: P,
    ) -> Result<PathDescriptor, Error>;

    /// add a path (with single component) relative to tup_cwd and fetch its unique id
    fn add_leaf(&self, tup_cwd: &PathDescriptor, path: &str) -> PathDescriptor;

    /// add a rule and fetch a unique id
    fn add_rule(&self, rule: RuleFormulaInstance) -> RuleDescriptor;

    /// add tup file and fetch its unique id
    fn add_tup(&self, p: &Path) -> TupPathDescriptor;

    /// add env vars and fetch an id for them
    fn add_env_var(&self, var: Env) -> EnvDescriptor;

    /// add a task instance to buffer and return a unique id
    fn add_task_path(&self, task: TaskInstance) -> TaskDescriptor;

    /// Return input path from resolved input
    fn get_input_path_name(&self, i: &InputResolvedType) -> String;
    /// Return parent folder id from input path descriptor
    fn get_parent_id(&self, pd: &PathDescriptor) -> PathDescriptor;
    /// get id stored against input path
    fn get_id(&self, np: &NormalPath) -> Option<PathDescriptor>;

    /// return path from its descriptor.
    fn get_path<'a, 'b>(&'a self, pd: &'b PathDescriptor) -> &'b NormalPath;
    /// return path (raw std::path) from its descriptor
    fn get_path_ref<'a, 'b>(&'a self, pd: &'b PathDescriptor) -> &'b Path;

    /// return full path from root from its descriptor.
    fn get_abs_path(&self, pd: &PathDescriptor) -> PathBuf;

    /// return relative path from current and base.
    fn get_rel_path(&self, pd: &PathDescriptor, base: &PathDescriptor) -> NormalPath;
    /// Return Rule from its descriptor
    fn get_rule<'a>(&'a self, rd: &'a RuleDescriptor) -> &'a RuleFormulaInstance;
    /// return Env from its descriptor
    fn get_env<'a>(&'a self, ed: &'a EnvDescriptor) -> &'a Env;

    /// Return tup file path from its descriptor

    /// Return task reference name from its descriptor
    fn get_task<'a>(&'a self, id: &'a TaskDescriptor) -> &'a TaskInstance;

    /// fetch the descriptor for a task using its name and directory
    fn try_get_task_desc(&self, tup_cwd: &PathDescriptor, name: &str) -> Option<TaskDescriptor>;

    /// Try get a bin path entry by its descriptor.
    fn get_group_path<'a>(&'a self, gd: &'a GroupPathDescriptor) -> &'a GroupPathEntry;

    /// Directory descriptor from a group descriptor
    fn get_group_dir(&self, gd: &GroupPathDescriptor) -> PathDescriptor;

    /// Return root folder where tup was initialized
    fn get_root_dir(&self) -> &Path;

    /// Name of the group from its descriptor
    fn get_group_name(&self, gd: &GroupPathDescriptor) -> String;

    /// Extract path from input
    fn get_path_from(&self, input_glob: &InputResolvedType) -> PathDescriptor;

    /// Get Path as string
    fn get_path_str(&self, p: &PathDescriptor) -> String;

    /// Bin Name
    fn get_bin_name<'a>(&'a self, b: &'a BinDescriptor) -> Cow<'a, str>;
}

/// ```PathDescriptor``` is an id given to a  folder where tupfile was found
pub type PathSym = u64;

/// return dir entry from its PathSym (id)
pub fn fetch_dir_entry(path_sym: &PathSym) -> Intern<DirEntry> {
    if *path_sym == 0 {
        return Intern::from(DirEntry::default());
    }
    unsafe { Intern::from_u64(*path_sym) }
}

/// Directory entry (file or folder) in tup heirarchy. Stores an id of parent folder and name of the file or folder
#[derive(Clone)]
pub struct DirEntry {
    path_sym: PathSym,
    name: Arc<OsStr>,
    cached_path: std::sync::OnceLock<NormalPath>,
}

/// PathStep represents a step to reach a target directory from source directory
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum PathStep {
    /// Backward corresponds to a step backward to the parent directory
    #[default]
    Backward,
    /// Step forward to directory under current
    Forward(PathDescriptor),
}
/// Chain of env descriptors accumulated by the parser until a rule.
#[derive(Debug, Clone, Default)]
pub struct EnvList {
    env: EnvDescriptor,
    prevs: Option<Box<EnvList>>,
}
/// Iterator for EnvList
pub struct EnvListIter {
    current: Option<Box<EnvList>>,
}
impl Iterator for EnvListIter {
    type Item = EnvDescriptor;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(node) = self.current.take() {
            self.current = node.prevs;
            Some(node.env.clone())
        } else {
            None
        }
    }
}
impl Eq for EnvList {}

impl Hash for EnvList {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.env.hash(state);
        self.prevs.hash(state);
    }
}

impl PartialEq<Self> for EnvList {
    fn eq(&self, other: &Self) -> bool {
        self.env.eq(&other.env) && self.prevs.eq(&other.prevs)
    }
}

impl PartialOrd<Self> for EnvList {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for EnvList {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.env == other.env {
            self.prevs.cmp(&other.prevs)
        } else {
            self.env.cmp(&other.env)
        }
    }
}
impl EnvList {
    /// Construct a new env list
    pub fn new(env: EnvDescriptor) -> Self {
        EnvList { env, prevs: None }
    }
    /// Clone the chain of env descriptors
    pub fn clone_(&mut self) -> EnvList {
        EnvList {
            env: self.env.clone(),
            prevs: self.prevs.take(),
        }
    }

    /// descriptor of the current env
    pub fn get_desc(&self) -> EnvDescriptor {
        self.env.clone()
    }
    /// previously defined env descriptors
    pub fn get_prev(&self) -> Option<&EnvList> {
        self.prevs.as_ref().map(|x| x.as_ref())
    }
    /// get the str rep of the current env descriptor
    pub fn get_key_str(&self) -> &str {
        self.env.get().get_key_str()
    }
    /// add a new env descriptor to the chain
    pub fn add(&mut self, env: EnvDescriptor) {
        if self.prevs.is_none() && self.env.eq(&EnvDescriptor::default()) {
            self.env = env;
        } else {
            let boxed_self = Box::new(self.clone_());
            self.env = env;
            self.prevs = Some(boxed_self);
        }
    }

    /// assign initial values for each tup files
    pub fn from(vec: Vec<EnvDescriptor>) -> Self {
        let mut env_list = EnvList::new(EnvDescriptor::default());
        for e in vec {
            env_list.add(e);
        }
        env_list
    }
    /// iterator over the env descriptors
    pub fn iter(&self) -> EnvListIter {
        EnvListIter {
            current: Some(Box::new(self.clone())),
        }
    }

    /// string representation of the env descriptors
    pub fn get_var_keys(&self) -> impl Iterator<Item = String> {
        self.iter().map(|x| x.get().get_key_str().to_string())
    }

    /// get key value pairs of the env descriptors
    pub fn get_key_value_pairs(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        for env in self.iter() {
            let e = env.get();
            map.insert(e.get_key_str().to_string(), e.get_val_str().to_string());
        }
        map
    }
    /// find a key in the env descriptors
    pub fn find_key(&self, key: &str) -> Option<EnvDescriptor> {
        self.iter().find(|x| x.get().get_key_str().eq(key))
    }
}

impl PathStep {
    fn as_os_str(&self) -> &OsStr {
        match self {
            PathStep::Backward => OsStr::new(".."),
            PathStep::Forward(pd) => pd.get().get_os_str(),
        }
    }
}
/// ```RelativeDirEntry``` contains a path relative to a base directory
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct RelativeDirEntry {
    basedir: PathDescriptor,
    target: PathDescriptor,
    steps: Vec<PathStep>,
}
fn first_common_ancestor(base: PathDescriptor, target: PathDescriptor) -> PathDescriptor {
    let is_ancestor = |base: &PathDescriptor, target: &PathDescriptor| {
        target.ancestors().find(|x| x.eq(base)).is_some()
    };
    if base == target {
        return base;
    } else if base.is_root() {
        return base;
    } else if target.is_root() {
        return target;
    } else if is_ancestor(&base, &target) {
        return base;
    } else if is_ancestor(&target, &base) {
        return target;
    }
    let set: HashSet<_> = base.ancestors().collect();
    target
        .ancestors()
        .find(|item| set.contains(&item))
        .unwrap_or_default()
}

impl RelativeDirEntry {
    /// Construct a new relative dir entry
    pub fn new(basedir: PathDescriptor, target: PathDescriptor) -> Self {
        // find the first common ancestor and then find the steps to reach the target from the common ancestor
        let mut basedir = basedir.clone();
        let mut target = target.clone();
        /*debug!(
            "basedir:{:?} target:{:?}",
            basedir.get_path_ref(),
            target.get_path_ref()
        );*/
        let common_root = first_common_ancestor(basedir.clone(), target.clone());
        let mut steps = Vec::new();
        while basedir != common_root {
            let parent = basedir.get_parent_descriptor();
            //debug!("parent:{:?} ", parent.get().get_name());
            steps.push(PathStep::Backward);
            basedir = parent;
        }
        let mut fwd_steps = VecDeque::new();
        while target != common_root {
            let parent = target.get_parent_descriptor();
            //debug!("parent:{:?} ", parent.get().get_name());
            fwd_steps.push_front(PathStep::Forward(target.clone()));
            target = parent;
        }
        steps.extend(fwd_steps);
        Self {
            basedir,
            target,
            steps,
        }
    }
    /// Normalized path relative to basedir
    pub fn get_path(&self) -> NormalPath {
        let mut first = true;
        let mut path_os_string = OsString::new();
        for step in self.components() {
            if first {
                first = false;
            } else {
                path_os_string.push("/");
            }
            path_os_string.push(match step {
                PathStep::Backward => OsStr::new(".."),
                PathStep::Forward(pd) => pd.get().get_os_str(),
            });
        }
        let path = NormalPath::new_from_raw(path_os_string);
        path
    }

    /// directory components of this path including self
    pub fn components(&self) -> impl Iterator<Item = &PathStep> {
        self.steps.iter()
    }

    /// count the number of components in this path
    pub fn count(&self) -> usize {
        self.steps.iter().count()
    }

    /// check if this path is root
    pub fn is_empty(&self) -> bool {
        self.basedir == self.target
    }
}

impl AddAssign<&RelativeDirEntry> for PathDescriptor {
    fn add_assign(&mut self, rhs: &RelativeDirEntry) {
        let mut pathsym = self.to_u64();
        for components in rhs.components() {
            let nxt = Intern::new(DirEntry::new(pathsym, components.as_os_str()));
            pathsym = nxt.to_u64();
        }
        *self = PathDescriptor::from_interned(fetch_dir_entry(&pathsym));
    }
}

impl Hash for DirEntry {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.path_sym.hash(state);
        self.name.as_ref().hash(state);
    }
}

impl PartialOrd for DirEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        (self.path_sym, self.name.as_ref()).partial_cmp(&(other.path_sym, other.name.as_ref()))
    }
}

impl PartialEq for DirEntry {
    fn eq(&self, other: &Self) -> bool {
        (self.path_sym, self.name.as_ref()).eq(&(other.path_sym, other.name.as_ref()))
    }
}

impl Eq for DirEntry {}

impl Ord for DirEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.path_sym == other.path_sym {
            self.name.as_ref().cmp(other.name.as_ref())
        } else if self.path_sym == 0 {
            Ordering::Less
        } else if other.path_sym == 0 {
            Ordering::Greater
        } else {
            self.get_parent_descriptor()
                .cmp(&other.get_parent_descriptor())
        }
    }
}

impl std::fmt::Debug for DirEntry {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.path_sym == 0 {
            write!(f, "{:?}", self.name)
        } else {
            write!(f, "{:?}/{:?}", fetch_dir_entry(&self.path_sym), self.name)
        }
    }
}

unsafe impl Sync for DirEntry {}

unsafe impl Send for DirEntry {}

impl Default for DirEntry {
    fn default() -> Self {
        Self {
            path_sym: 0,
            name: Arc::from(OsStr::new(".")),
            cached_path: std::sync::OnceLock::from(NormalPath::new_from_raw(".".into())),
        }
    }
}

impl RuleDescriptor {
    pub(crate) fn get_name(&self) -> String {
        self.get().get_rule_str()
    }
}
impl TaskDescriptor {
    pub(crate) fn get_name(&self) -> &str {
        self.get().get_target()
    }
}

impl PathDescriptor {
    /// build a new path descriptor by adding path components to the current path
    pub fn join<P: AsRef<Path>>(&self, name: P) -> Result<Self, Error> {
        debug!("join:{:?} to {:?}", name.as_ref(), self);
        name.as_ref().components().try_fold(self.clone(), |acc, x| {
            match x {
                Component::Normal(name) => {
                    let dir_entry = DirEntry::new(acc.to_u64(), name);
                    Ok(Self::from_interned(Intern::from(dir_entry)))
                }
                Component::ParentDir => Ok(acc.as_ref().get_parent_descriptor()),
                Component::CurDir => Ok(acc),
                Component::RootDir => {
                    debug!("switching to root dir from {:?}", acc.as_ref());
                    Ok(PathDescriptor::default())
                },
                Component::Prefix(_) =>
                    Err(Error::new_path_search_error(format!("attempting to join unexpected path component:{:?}\n Consider only relative paths or paths from tup root for rule building", x)))
            }
        })
    }
    /// build a new path descriptor by adding single path component to the current path
    pub fn join_leaf(&self, name: &str) -> PathDescriptor {
        let dir_entry = DirEntry::new(self.to_u64(), OsStr::new(name));
        Self::from_interned(Intern::from(dir_entry))
    }

    /// get name of the file or folder
    pub fn get_file_name(&self) -> Cow<'_, str> {
        (*self).get().get_name()
    }
    /// get os string reference of the name of directory entry
    pub fn get_file_name_os_str(&self) -> &OsStr {
        (*self).get().get_os_str()
    }
    /// get parent path descriptor
    pub fn get_parent_descriptor(&self) -> Self {
        if self.to_u64() == 0 {
            return self.clone();
        }
        let dir_entry = fetch_dir_entry(&self.to_u64());
        dir_entry.get_parent_descriptor()
    }

    /// get reference to path stored in this descriptor
    pub fn get_path_ref(&self) -> &NormalPath {
        self.as_ref()
            .cached_path
            .get_or_init(|| self.prepare_stored_path())
    }

    /// relative path to root from current path
    pub fn get_path_to_root(&self) -> PathBuf {
        let mut path = PathBuf::new();
        const PARENT_WITH_SLASH: &str = "../";
        for _ in self.ancestors() {
            path.push(PARENT_WITH_SLASH);
        }
        path.pop();
        path
    }

    fn prepare_stored_path(&self) -> NormalPath {
        let cap: usize = self.ancestors().count();
        log::debug!("caching:{:?}", self);
        let mut parts = Vec::with_capacity(cap);
        for ancestor in self.components() {
            parts.push(ancestor.as_ref().get_rc_name());
        }
        parts.pop(); // last component (self) is removed and added later
        let parent_path =
            OsString::with_capacity(parts.iter().fold(cap, |acc, x| acc + x.len() + 1));
        let mut parent_path = parts
            .iter()
            .skip(1) // skip the "./" component
            .fold(parent_path, |mut acc, x| {
                acc.push(x.as_ref());
                acc.push("/");
                acc
            });
        parent_path.push(self.as_ref().get_rc_name().as_ref());
        let path = NormalPath::new_from_raw(parent_path);
        path
    }

    /// get parent directory path
    pub fn get_parent_path(&self) -> NormalPath {
        self.get_parent_descriptor().get_path_ref().clone()
    }
    /// ancestors  including self
    pub fn ancestors(&self) -> impl Iterator<Item = PathDescriptor> {
        let mut cur_path = self.clone();
        std::iter::from_fn(move || {
            if cur_path.is_root() {
                None
            } else {
                let last_cur_path = cur_path.clone();
                cur_path = cur_path.get_parent_descriptor();
                Some(last_cur_path)
            }
        })
    }
    /// check if this path is root
    pub fn is_root(&self) -> bool {
        self.as_ref().path_sym == 0
    }
    /// components of this path including self
    pub fn components(&self) -> impl Iterator<Item = PathDescriptor> {
        let mut all_components = Vec::new();
        for ancestor in self.ancestors() {
            all_components.push(ancestor);
        }
        all_components.push(PathDescriptor::default()); // add root
        std::iter::from_fn(move || all_components.pop())
    }
}

impl DirEntry {
    /// construct a new dir entry from its parent descriptor and name
    pub fn new(path_sym: PathSym, name: &OsStr) -> Self {
        Self {
            path_sym,
            name: Arc::from(name),
            cached_path: std::sync::OnceLock::new(),
        }
    }

    /// get parent directory descriptor
    pub fn get_parent_descriptor(&self) -> PathDescriptor {
        PathDescriptor::from_interned(fetch_dir_entry(&self.path_sym))
    }
    /// get name of the file or folder
    pub fn get_name(&self) -> Cow<'_, str> {
        self.name.to_string_lossy()
    }

    /// internal string representation of the name of directory entry
    pub fn get_rc_name(&self) -> Arc<OsStr> {
        self.name.clone()
    }
    /// get os string reference of the name of directory entry
    pub fn get_os_str(&self) -> &OsStr {
        self.name.as_ref()
    }
}

impl Display for DirEntry {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.path_sym == 0 {
            self.get_name().as_ref().fmt(f)
        } else {
            write!(
                f,
                "{}/{}",
                fetch_dir_entry(&self.path_sym).as_ref(),
                self.get_name().as_ref()
            )
        }
    }
}

/// ```NamedPathEntry``` is a (folder,name) pair to be interned for a group or bin
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct NamedPathEntry<T>(PathDescriptor, Arc<str>, PhantomData<T>);

impl<T> Default for NamedPathEntry<T> {
    fn default() -> Self {
        Self(PathDescriptor::default(), Arc::from(""), PhantomData)
    }
}

impl<T> NamedPathEntry<T> {
    /// construct a new named path entry from its parent descriptor and name
    pub fn new(dir_entry: PathDescriptor, name: &str) -> Self {
        Self(dir_entry, Arc::from(name), PhantomData)
    }
    /// get name of the group or bin
    pub fn get_name(&self) -> &str {
        self.1.as_ref()
    }
    /// get path descriptor of the group or bin
    pub fn get_dir_descriptor(&self) -> &PathDescriptor {
        &self.0
    }
    /// get path of the group or bin
    pub fn get_path(&self) -> NormalPath {
        self.0.get_path_ref().join(self.get_name()).into()
    }
}

/// ```GroupTag``` is a tag to be used for interning groups
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct GroupTag;

/// ```BinTag``` is a tag to be used for interning bins
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct BinTag;

/// ```GroupPathEntry``` is the (folder,group) pair to be interned for a group
pub type GroupPathEntry = NamedPathEntry<GroupTag>;
/// ```BinPathEntry``` is the (folder,bin) pair to be interned for a bin
pub type BinPathEntry = NamedPathEntry<BinTag>;

impl Display for GroupPathEntry {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/<{}>", self.0, self.1)
    }
}

impl Display for BinPathEntry {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{{{}}} ", self.0, self.1)
    }
}

/// Descriptor for interned objects
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Descriptor<T: 'static + Eq + Send + Sync + Hash + Display>(Intern<T>);

impl<T: Eq + Hash + Send + Sync + 'static + Display> Descriptor<T> {
    /// get the object corresponding to the input,
    pub fn get(&self) -> &T {
        self.0.deref()
    }

    /// Construct a descriptor interned object
    pub fn from_interned(i: Intern<T>) -> Self {
        Self(i)
    }

    /// integer representation of the descriptor
    pub fn to_u64(&self) -> u64 {
        self.0.to_u64()
    }

    /// from integer representation of the descriptor
    pub fn from_u64(u: u64) -> Self {
        unsafe { Self::from_interned(Intern::from_u64(u)) }
    }
}

impl<T: Display + Eq + Send + Sync + Hash> Display for Descriptor<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.get())
    }
}

impl<T: 'static + Eq + Send + Sync + Hash + Display> From<Intern<T>> for Descriptor<T> {
    fn from(i: Intern<T>) -> Self {
        Self(i)
    }
}

impl<T: 'static + Eq + Hash + Send + Sync + Display> From<T> for Descriptor<T> {
    fn from(t: T) -> Self {
        Self(Intern::from(t))
    }
}

impl<T: Eq + Hash + Send + Sync + Display> AsRef<T> for Descriptor<T> {
    fn as_ref(&self) -> &T {
        self.0.as_ref()
    }
}

/// ```PathDescriptor``` is an id given to a  file or folder in tup heirarchy
pub type PathDescriptor = Descriptor<DirEntry>;
/// ```GroupPathDescriptor``` is an id given to a group that appears in a tupfile.

pub type GroupPathDescriptor = Descriptor<GroupPathEntry>;

/// ```GlobPathDescriptor``` is an id given to a glob that appears as an input to a rule in a tupfile.
pub type GlobPathDescriptor = PathDescriptor;

/// ```BinDescriptor``` is an id given to a  folder where tupfile was found
pub type BinDescriptor = Descriptor<BinPathEntry>;

/// ```TupPathDescriptor``` is an unique id given to a tupfile
pub type TupPathDescriptor = PathDescriptor;

/// ```RuleDescriptor``` maintains the id of rule based on rules tracked so far in BufferObjects
pub type RuleDescriptor = Descriptor<RuleFormulaInstance>;

/// ```TaskDescriptor``` maintains the id of task based on tasks tracked so far in BufferObjects
pub type TaskDescriptor = Descriptor<TaskInstance>;

/// ```EnvDescriptor``` maintains the id of an env variable and its value based on envs tracked so far in ParseState
pub type EnvDescriptor = Descriptor<Env>;

/// path to descriptor(T) `BiMap', path stored is relative to rootdir (.1 in this struct)
#[derive(Debug, Default, Clone)]
pub(crate) struct PathBufferObject {
    root: PathBuf,
}

/// `GenBufferObject` is a trait that  has methods to add or get objects from a buffer
pub trait GenBufferObject {
    /// type of the Data to be interned
    type T: Eq + Hash + Send + Sync + 'static + Display;
    /// intern given input and return its descriptor
    fn add_ref(t: Self::T) -> Descriptor<Self::T> {
        Descriptor::from(t)
    }
    /// get the object corresponding to the input,
    fn get(id: &Descriptor<Self::T>) -> &Self::T {
        id.get()
    }
    /// get the internered object corresponding to the input, if it exists
    fn fetch_interned(t: &Self::T) -> Option<Descriptor<Self::T>> {
        Intern::fetch_interned(t).map(Descriptor::from_interned)
    }
    /// apply a function  over all the (group_desciptors)  stored in this buffer
    fn for_each<F>(mut f: F) -> Result<(), Error>
    where
        F: FnMut(&Descriptor<Self::T>) -> Result<(), Error>,
    {
        Intern::iter_interned(move |x| f(&Descriptor::from_interned(x)))
    }
}

impl GenBufferObject for PathBufferObject {
    type T = DirEntry;
}

impl GenBufferObject for EnvBufferObject {
    type T = Env;
}

impl GenBufferObject for GroupBufferObject {
    type T = GroupPathEntry;
}

impl GenBufferObject for BinBufferObject {
    type T = BinPathEntry;
}

impl GenBufferObject for RuleBufferObject {
    type T = RuleFormulaInstance;
}

impl GenBufferObject for TaskBufferObject {
    type T = TaskInstance;
}

impl PathBufferObject {
    /// Construct  that stores paths and its descriptors as a `BiMap' relative to root_dir
    pub fn new<P: AsRef<Path>>(root_dir: P) -> Self {
        PathBufferObject {
            root: root_dir.as_ref().to_path_buf(),
        }
    }

    /// root director of the paths stored in this buffer
    fn get_root_dir(&self) -> &Path {
        self.root.as_path()
    }

    /// Store a path relative to rootdir. path is expected not to have dots
    /// descriptor is assigned by finding using size of buffer
    pub fn add<P: AsRef<Path>>(&self, path: P) -> Result<PathDescriptor, Error> {
        let tup_cwd = PathDescriptor::default();
        tup_cwd.join(path)
    }

    fn fetch_interned_from(&self, np: &NormalPath) -> Option<PathDescriptor> {
        //self.descriptor_arena.intern(np)
        let dir_entry0 = Intern::from(DirEntry::default());
        let dir_entry = np.as_path().components().try_fold(dir_entry0, |acc, x| {
            let dir_entry = DirEntry::new(acc.to_u64(), x.as_os_str());
            Intern::fetch_interned(&dir_entry)
        });
        dir_entry.map(PathDescriptor::from_interned)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct EnvBufferObject;

#[derive(Debug, Clone)]
pub(crate) struct GroupBufferObject;

#[derive(Debug, Clone)]
pub(crate) struct BinBufferObject;

#[derive(Debug, Clone)]
pub(crate) struct RuleBufferObject;

#[derive(Debug, Clone)]
pub(crate) struct TaskBufferObject;

/// methods to add or get group entries from a buffer
///
impl GroupBufferObject {
    // Returns name of group (wrapped with angle-brackets)
    fn get_group_name(group_desc: &GroupPathDescriptor) -> String {
        group_desc.get().get_name().to_string()
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
    output_files: BTreeSet<PathDescriptor>,
    /// output files under a directory.
    children: HashMap<PathDescriptor, Vec<PathDescriptor>>,
    /// paths accumulated in a bin
    bins: HashMap<BinDescriptor, BTreeSet<PathDescriptor>>,
    /// paths accumulated in groups
    groups: HashMap<GroupPathDescriptor, BTreeSet<PathDescriptor>>,
    /// track the parent rule that generates an output file
    parent_rule: HashMap<PathDescriptor, TupLoc>,
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
        tup_cwd: &PathDescriptor,
        vs: &mut Vec<MatchingPath>,
    ) {
        let mut hs = HashSet::new();
        hs.extend(vs.iter().map(MatchingPath::path_descriptor));
        let mut found = false;
        if let Some(children) = self.children.get(base_path_desc) {
            if children.contains(path_desc) {
                vs.push(MatchingPath::new(path_desc.clone(), tup_cwd.clone()));
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
                if hs.insert(path_desc.clone()) {
                    vs.push(MatchingPath::new(path_desc.clone(), tup_cwd.clone()));
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
        path_buffers: &impl PathBuffers,
        glob_path: &GlobPath,
        vs: &mut Vec<MatchingPath>,
    ) {
        let mut hs = HashSet::new();
        let base_path_desc = glob_path.get_non_pattern_prefix_desc();
        hs.extend(vs.iter().map(MatchingPath::path_descriptor));
        debug!("looking for globmatches:{:?}", glob_path.get_abs_path());
        let tup_cwd = glob_path.get_tup_dir_desc();
        debug!(
            "in dir {:?} with tup base:{:?}",
            base_path_desc.get_path_ref(),
            tup_cwd.get_path_ref()
        );
        if let Some(children) = self.children.get(base_path_desc) {
            for pd in children.iter() {
                let np = path_buffers.get_path(pd);
                let p: &Path = np.as_path();
                if glob_path.is_match(p) && hs.insert(pd.clone()) {
                    let capture_grps = glob_path.group(p);
                    debug!("found match:{:?} with groups:{:?}", p, capture_grps);
                    vs.push(MatchingPath::with_captures(
                        pd.clone(),
                        glob_path.get_glob_desc(),
                        capture_grps,
                        tup_cwd.clone(),
                    ))
                }
            }
        }

        self.bins
            .iter()
            .map(|x| x.1)
            .chain(self.groups.iter().map(|x| x.1))
            //   .chain(std::iter::once(&self.output_files))
            .for_each(|v| {
                for pd in v.iter() {
                    let np = path_buffers.get_path(pd);
                    {
                        let p: &Path = np.as_path();
                        if glob_path.is_match(p) && hs.insert(pd.clone()) {
                            let capture_grps = glob_path.group(p);
                            debug!("found match:{:?} with groups:{:?}", p, capture_grps);
                            vs.push(MatchingPath::with_captures(
                                pd.clone(),
                                glob_path.get_glob_desc(),
                                capture_grps,
                                tup_cwd.clone(),
                            ))
                        }
                    }
                }
            });
    }
}

impl GeneratedFiles {
    /// Get all the output files from rules accumulated so far
    fn get_output_files(&self) -> &BTreeSet<PathDescriptor> {
        &self.output_files
    }
    /// Get all the groups with collected rule outputs
    fn get_groups(&self) -> &HashMap<GroupPathDescriptor, BTreeSet<PathDescriptor>> {
        &self.groups
    }
    /// Get paths stored against a bin
    fn get_bins(&self) -> &HashMap<BinDescriptor, BTreeSet<PathDescriptor>> {
        &self.bins
    }
    /// Get paths stored against a group
    pub(crate) fn get_group(
        &self,
        group_desc: &GroupPathDescriptor,
    ) -> Option<&BTreeSet<PathDescriptor>> {
        self.groups.get(group_desc)
    }
    /// Get paths stored against each bin
    pub(crate) fn get_bin(&self, bin_desc: &BinDescriptor) -> Option<&BTreeSet<PathDescriptor>> {
        self.bins.get(bin_desc)
    }
    /// Get parent dir -> children map
    fn get_children(&self) -> &HashMap<PathDescriptor, Vec<PathDescriptor>> {
        &self.children
    }
    /// Get a mutable references all the groups with collected rule outputs.
    /// This can be used to fill path references from a database.
    fn get_mut_groups(&mut self) -> &mut HashMap<GroupPathDescriptor, BTreeSet<PathDescriptor>> {
        &mut self.groups
    }
    /// Get a mutable references all the bins with collected rule outputs.
    fn get_mut_bins(&mut self) -> &mut HashMap<BinDescriptor, BTreeSet<PathDescriptor>> {
        &mut self.bins
    }

    /// Add an entry to the set that holds paths
    fn add_output(&mut self, pd: &PathDescriptor) -> bool {
        self.output_files.insert(pd.clone())
    }

    /// Add an entry to the collector that holds paths of a group
    fn add_group_entry(&mut self, group_desc: &GroupPathDescriptor, pd: PathDescriptor) {
        self.get_mut_groups()
            .entry(group_desc.clone())
            .or_default()
            .insert(pd);
    }
    /// Add an entry to the collector that holds paths of a bin
    fn add_bin_entry(&mut self, bin_desc: &BinDescriptor, pd: PathDescriptor) {
        self.get_mut_bins()
            .entry(bin_desc.clone())
            .or_default()
            .insert(pd);
    }

    /// the parent rule that generates a output file
    pub(crate) fn get_parent_rule(&self, o: &PathDescriptor) -> Option<&TupLoc> {
        self.parent_rule.get(o)
    }

    /// Add an entry to the set that holds paths
    fn add_parent_rule(&mut self, pd: PathDescriptor, rule_ref: TupLoc) -> TupLoc {
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
    ) -> Result<(), Error> {
        for (k, new_paths) in new_outputs.get_groups().iter() {
            self.groups
                .entry(k.clone())
                .or_insert_with(BTreeSet::new)
                .extend(new_paths.iter().cloned());
            new_outputs
                .with_parent_rules(|m| self.merge_parent_rules(path_buffers, &m, new_paths))?
        }
        Ok(())
    }
    /// Merge bins from its new outputs
    fn merge_bin_tags(
        &mut self,
        path_buffers: &impl PathBuffers,
        other: &impl OutputHandler,
    ) -> Result<(), Error> {
        for (k, new_paths) in other.get_bins().iter() {
            self.bins
                .entry(k.clone())
                .or_insert_with(BTreeSet::new)
                .extend(new_paths.iter().cloned());
            other.with_parent_rules(|rules| {
                self.merge_parent_rules(path_buffers, rules, new_paths)
            })?
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
    ) -> Result<(), Error> {
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
    ) -> Result<(), Error> {
        self.output_files
            .extend(new_outputs.get_output_files().iter().cloned());
        for (dir, ch) in new_outputs.get_children().iter() {
            self.children
                .entry(dir.clone())
                .or_insert_with(Vec::new)
                .extend(ch.iter().cloned());
        }

        new_outputs.with_parent_rules(|rules| {
            self.merge_parent_rules(path_buffers, rules, &new_outputs.get_output_files())
        })
    }
    /// Track parent rules of outputs, error-ing out if unique parent rule
    /// of an output is not found
    fn merge_parent_rules(
        &mut self,
        path_buffers: &impl PathBuffers,
        new_parent_rule: &HashMap<PathDescriptor, TupLoc>,
        new_path_descs: &BTreeSet<PathDescriptor>,
    ) -> Result<(), Error> {
        for new_path_desc in new_path_descs.iter() {
            let new_parent = new_parent_rule
                .get(new_path_desc)
                .expect("parent rule not found");
            debug!(
                "Setting parent for  path: {:?} to rule:{:?}:{:?}",
                path_buffers.get_path(new_path_desc),
                new_parent.get_tupfile_desc().get_path_ref(),
                new_parent.get_line()
            );
            match self.parent_rule.entry(new_path_desc.clone()) {
                Entry::Occupied(pe) => {
                    if pe.get() != new_parent {
                        let old_parent = pe.get();
                        let old_rule_path = old_parent.get_tupfile_desc().get_path_ref();
                        let old_rule_line = old_parent.get_line();
                        log::warn!(
                            "path {:?} is an output of a previous rule at:{:?}:{:?}",
                            path_buffers.get_path(new_path_desc),
                            old_rule_path,
                            old_rule_line
                        );
                        return Err(Error::MultipleRulesToSameOutput(
                            new_path_desc.clone(),
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
    fn get_parent_rules(&self) -> &HashMap<PathDescriptor, TupLoc> {
        &self.parent_rule
    }
}

impl OutputHolder {
    /// Discover paths matching glob pattern from outputs accumulated so far
    pub fn discover_paths(
        &self,
        path_buffers: &impl PathBuffers,
        glob_paths: &[GlobPath],
    ) -> Result<Vec<MatchingPath>, Error> {
        let mut vs = Vec::new();
        for glob_path in glob_paths {
            if !glob_path.has_glob_pattern() {
                let path_desc: PathDescriptor = glob_path.get_glob_path_desc();
                self.get().outputs_with_desc(
                    &path_desc,
                    glob_path.get_non_pattern_prefix_desc(),
                    glob_path.get_tup_dir_desc(),
                    &mut vs,
                );
            } else {
                self.get()
                    .outputs_matching_glob(path_buffers, &glob_path, &mut vs);
            }
            if !vs.is_empty() {
                break;
            }
        }
        Ok(vs)
    }

    fn _get_outs(&self) -> &OutputHolder {
        &self
    }

    fn _merge(&mut self, p: &impl PathBuffers, o: &impl OutputHandler) -> Result<(), Error> {
        self.get_mut().merge(p, o)
    }
}

impl OutputHandler for OutputHolder {
    fn get_output_files(&self) -> MappedRwLockReadGuard<'_, BTreeSet<PathDescriptor>> {
        RwLockReadGuard::map(self.get(), |x| x.get_output_files())
    }

    fn get_groups(
        &self,
    ) -> MappedRwLockReadGuard<'_, HashMap<GroupPathDescriptor, BTreeSet<PathDescriptor>>> {
        RwLockReadGuard::map(self.get(), |x| x.get_groups())
    }

    fn get_bins(
        &self,
    ) -> MappedRwLockReadGuard<'_, HashMap<BinDescriptor, BTreeSet<PathDescriptor>>> {
        RwLockReadGuard::map(self.get(), |x| x.get_bins())
    }

    fn get_children(
        &self,
    ) -> MappedRwLockReadGuard<'_, HashMap<PathDescriptor, Vec<PathDescriptor>>> {
        RwLockReadGuard::map(self.get(), |x| x.get_children())
    }

    fn get_parent_rule(&self, o: &PathDescriptor) -> Option<TupLoc> {
        let r = self.get();
        r.get_parent_rule(o).map(|x| x.clone())
    }
    fn with_parent_rules<R, F>(&self, mut f: F) -> R
    where
        F: FnMut(&HashMap<PathDescriptor, TupLoc>) -> R,
    {
        let rules = RwLockReadGuard::map(self.get(), |x| x.get_parent_rules());
        f(rules.deref())
    }

    fn add_output(&mut self, pd: &PathDescriptor) -> bool {
        self.get_mut().add_output(pd)
    }
    fn add_parent_rule(&mut self, pd: &PathDescriptor, rule_ref: TupLoc) -> TupLoc {
        self.get_mut().add_parent_rule(pd.clone(), rule_ref)
    }

    // add output files under a directory
    fn add_children(&mut self, dir: &PathDescriptor, ch: Vec<PathDescriptor>) {
        self.get_mut()
            .children
            .entry(dir.clone())
            .or_insert_with(Vec::new)
            .extend(ch)
    }

    fn add_group_entry(&mut self, group_desc: &GroupPathDescriptor, pd: PathDescriptor) {
        self.get_mut().add_group_entry(group_desc, pd)
    }
    fn add_bin_entry(&mut self, bin_desc: &BinDescriptor, pd: PathDescriptor) {
        self.get_mut().add_bin_entry(bin_desc, pd)
    }

    fn merge(&mut self, p: &impl PathBuffers, out: &impl OutputHandler) -> Result<(), Error> {
        self.get_mut().merge(p, out)
    }
}

/// Wrapper over Burnt sushi's GlobMatcher
#[derive(Debug, Clone)]
pub(crate) struct MyGlob {
    matcher: GlobMatcher,
}

impl Hash for MyGlob {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        //self.matcher.hash(state)
        self.matcher.re().as_str().hash(state);
    }
}

impl MyGlob {
    /// Create a new glob from a path pattern
    /// It is assumed that path_pattern is relative to root directory
    pub(crate) fn new_raw(path_pattern: &Path) -> Result<Self, Error> {
        let to_glob_error = |e: &glob::Error| {
            Error::GlobError(
                path_pattern.to_string_lossy().to_string() + ":" + e.kind().to_string().as_str(),
            )
        };
        let glob_pattern = GlobBuilder::new(path_pattern.to_string_lossy().as_ref())
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
/// Output path and its id.
pub struct OutputType {
    pub(crate) pid: PathDescriptor,
}

impl Display for OutputType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("OutputType({:?})", self.get_id()))
    }
}

impl OutputType {
    pub(crate) fn new(pid: PathDescriptor) -> Self {
        Self { pid }
    }
    pub(crate) fn get_id(&self) -> PathDescriptor {
        self.pid.clone()
    }
}

/// Buffers to store files, groups, bins, env with its id.
/// Each sub-buffer is a bimap from names to a unique id which simplifies storing references.
#[derive(Debug, Clone)]
pub struct BufferObjects {
    path_bo: PathBufferObject,
    //< paths by id
}

impl Default for BufferObjects {
    fn default() -> Self {
        let root = Path::new(".");
        BufferObjects {
            path_bo: PathBufferObject::new(root),
        }
    }
}

/// Accessors and modifiers for BufferObjects
impl BufferObjects {
    /// Construct Buffer object using tup (most) root directory where Tupfile.ini is found
    pub fn new<P: AsRef<Path>>(root: P) -> BufferObjects {
        BufferObjects {
            path_bo: PathBufferObject::new(root.as_ref()),
            ..Default::default()
        }
    }
}

/// Methods to add or get objects from a buffer
impl PathBuffers for BufferObjects {
    /// Add path of bin. Folder is the one where  Tupfile declaring the bin. name is bin name
    fn add_bin_path_expr(&self, tup_cwd: &PathDescriptor, pe: &str) -> BinDescriptor {
        let bin_entry = BinPathEntry::new(tup_cwd.clone(), pe);
        BinBufferObject::add_ref(bin_entry)
    }

    fn add_env(&self, e: Cow<Env>) -> EnvDescriptor {
        let e = e.into_owned();
        debug!("adding env {:?}", e);
        EnvBufferObject::add_ref(e)
    }

    /// Add a path to a group in this buffer
    fn add_group_pathexpr(&self, tup_cwd: &PathDescriptor, pe: &str) -> GroupPathDescriptor {
        let mut pd = tup_cwd.clone();
        if pe.contains("/") || pe.contains("\\") {
            let res = tup_cwd.join(pe).unwrap_or_else(|e| {
                panic!(
                    "unable to join {} with {} due to {}",
                    tup_cwd.get_path_ref(),
                    pe,
                    e
                )
            });
            pd = res.get_parent_descriptor();
        }
        GroupBufferObject::add_ref(GroupPathEntry::new(pd, pe))
    }

    /// return the non pattern prefix of the glob
    fn get_glob_prefix(&self, glob_desc: &GlobPathDescriptor) -> PathDescriptor {
        get_non_pattern_prefix(glob_desc).0
    }

    // return the portion of path from non pattern prefix to the parent of the glob
    fn get_recursive_glob_str(&self, p0: &GlobPathDescriptor) -> String {
        let (par, hasglob) = get_non_pattern_prefix(p0);
        if !hasglob {
            return "".to_string();
        }
        RelativeDirEntry::new(par, p0.get_parent_descriptor())
            .get_path()
            .to_string()
            .replace("**", "*")
    }
    fn is_recursive_glob(&self, p0: &GlobPathDescriptor) -> bool {
        let p = p0.get_path_ref();
        let mut has_rglob = false;
        for c in p.as_path().components() {
            if let Component::Normal(c) = c {
                if c == "**" {
                    has_rglob = true;
                    break;
                }
            }
        }
        has_rglob
    }

    /// return the name of the group from its descriptor removing the non pattern prefix from the path
    fn get_glob_name(&self, glob_desc: &GlobPathDescriptor) -> String {
        let (par, hasglob) = get_non_pattern_prefix(glob_desc);
        if hasglob {
            RelativeDirEntry::new(par, glob_desc.clone())
                .get_path()
                .to_string()
        } else {
            glob_desc.get_file_name().to_string()
        }
    }

    /// Add a path to buffer and return its unique id in the buffer
    /// It is assumed that no de-dotting is necessary for the input path and path is already from the root
    fn add_abs<P: AsRef<Path>>(&self, p: P) -> Result<PathDescriptor, Error> {
        self.path_bo.add(p)
    }

    /// Add a path to buffer and return its unique id in the buffer
    fn add_path_from<P: AsRef<Path>>(
        &self,
        tup_cwd: &PathDescriptor,
        path: P,
    ) -> Result<PathDescriptor, Error> {
        //self.path_bo.add_relative(tup_cwd, path.as_ref())
        let joined_path = tup_cwd.join(path.as_ref());
        joined_path
    }

    fn add_leaf(&self, tup_cwd: &PathDescriptor, path: &str) -> PathDescriptor {
        tup_cwd.join_leaf(path)
    }

    /// Add a rule formula to the buffer and return its descriptor
    fn add_rule(&self, r: RuleFormulaInstance) -> RuleDescriptor {
        RuleBufferObject::add_ref(r)
    }

    ///  add a tup file path to the buffer and return its descriptor
    fn add_tup(&self, p: &Path) -> TupPathDescriptor {
        if p.is_absolute() {
            let num_base_comps = self.path_bo.get_root_dir().components().count();
            let p: PathBuf = p.components().skip(num_base_comps).collect();
            self.path_bo.add(p.as_path())
        } else {
            self.path_bo.add(p)
        }
        .expect(
            format!(
                "unable to add tup path {}. Root and Prefix components are not supported",
                p.display()
            )
            .as_str(),
        )
    }

    /// add environment variable to the list of variables active in current tupfile until now
    /// This appends a new env var current list of env vars.
    fn add_env_var(&self, var: Env) -> EnvDescriptor {
        debug!("add env var {} in ebo ", var);
        if var.get_val_str().is_empty() {
            log::warn!("empty env var {:?}", var);
        }
        EnvBufferObject::add_ref(var)
    }

    /// add a task to the buffer and return its descriptor
    fn add_task_path(&self, task: TaskInstance) -> TaskDescriptor {
        TaskBufferObject::add_ref(task)
    }

    /// Get file name or bin name or group name of the input path
    /// use `get_resolve_path` to get resolved path
    fn get_input_path_name(&self, i: &InputResolvedType) -> String {
        i.get_resolved_name(&self)
    }

    /// Returns parent id for the path
    fn get_parent_id(&self, pd: &PathDescriptor) -> PathDescriptor {
        pd.get_parent_descriptor()
    }

    /// Returns id for the path
    fn get_id(&self, np: &NormalPath) -> Option<PathDescriptor> {
        self.path_bo.fetch_interned_from(np)
    }

    /// Returns path corresponding to an path descriptor. This panics if there is no match
    fn get_path<'a, 'b>(&'a self, pd: &'b PathDescriptor) -> &'b NormalPath {
        pd.get_path_ref()
    }

    fn get_path_ref<'a, 'b>(&'a self, pd: &'b PathDescriptor) -> &'b Path {
        pd.get_path_ref().as_path()
    }
    fn get_abs_path(&self, pd: &PathDescriptor) -> PathBuf {
        self.get_root_dir().join(pd.get_path_ref())
    }
    fn get_rel_path(&self, pd: &PathDescriptor, base: &PathDescriptor) -> NormalPath {
        let rel = RelativeDirEntry::new(base.clone(), pd.clone());
        rel.get_path()
    }

    /// Returns rule corresponding to a rule descriptor. Panics if none is found
    fn get_rule<'a>(&'a self, id: &'a RuleDescriptor) -> &'a RuleFormulaInstance {
        RuleBufferObject::get(id)
    }
    /// Returns env corresponding to a env descriptor. Panics if none is found
    fn get_env<'a>(&'a self, id: &'a EnvDescriptor) -> &'a Env {
        EnvBufferObject::get(id)
    }

    /// Returns path corresponding to the given tupfile descriptor
    fn get_task<'a>(&'a self, id: &'a TaskDescriptor) -> &'a TaskInstance {
        TaskBufferObject::get(id)
    }

    /// query for task at specified path by its name
    fn try_get_task_desc(&self, tup_cwd: &PathDescriptor, name: &str) -> Option<TaskDescriptor> {
        let task = TaskInstance::new(
            tup_cwd,
            name,
            vec![],
            vec![],
            TupLoc::default(),
            vec![],
            EnvList::default(),
        );
        TaskBufferObject::fetch_interned(&task)
    }
    /// Try get a bin path entry by its descriptor.
    fn get_group_path<'a>(&'a self, gd: &'a GroupPathDescriptor) -> &'a GroupPathEntry {
        GroupBufferObject::get(gd)
    }

    fn get_group_dir(&self, gd: &GroupPathDescriptor) -> PathDescriptor {
        gd.get().get_dir_descriptor().clone()
    }

    /// Return root folder where tup was initialized
    fn get_root_dir(&self) -> &Path {
        self.path_bo.get_root_dir()
    }

    /// Get group name stored against its id
    fn get_group_name(&self, gd: &GroupPathDescriptor) -> String {
        GroupBufferObject::get_group_name(gd)
    }

    /// Get path of a maybe resolved input
    fn get_path_from(&self, input_glob: &InputResolvedType) -> PathDescriptor {
        input_glob
            .get_resolved_path_desc()
            .cloned()
            .unwrap_or_default()
    }

    /// Get Path stored against its id
    fn get_path_str(&self, p: &PathDescriptor) -> String {
        let p = p.get_path_ref();
        p.as_path().to_string_lossy().to_string()
    }

    /// return name of bin stored against its id
    fn get_bin_name<'a>(&'a self, b: &'a BinDescriptor) -> Cow<'a, str> {
        b.get().get_name().into()
    }
}
