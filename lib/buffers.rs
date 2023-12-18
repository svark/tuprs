//! Module to hold buffers of tupfile paths, bins, groups which can be referenced by their descriptors
use std::borrow::{Borrow, Cow};
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::fmt::{Display, Formatter};
use std::hash::Hash;
use std::ops::Deref;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use bimap::hash::RightValues;
use bimap::{BiBTreeMap, BiMap};
use bstr::ByteSlice;
use log::{debug, log_enabled};
use parking_lot::{MappedRwLockReadGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};
use pathdiff::diff_paths;

use crate::decode::{OutputHandler, RuleFormulaInstance, TaskInstance, TupLoc};
use crate::errors::Error;
use crate::glob::{Candidate, GlobBuilder, GlobMatcher};
use crate::paths::{GlobPath, InputResolvedType, MatchingPath, NormalPath};
use crate::statements::{Cat, Env, EnvDescriptor};
use crate::transform::get_parent;
use crate::{glob, paths};

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
    fn add_rule(&mut self, rule: RuleFormulaInstance) -> (RuleDescriptor, bool);

    /// add tup file and fetch its unique id
    fn add_tup(&mut self, p: &Path) -> (TupPathDescriptor, bool);

    /// add env vars and fetch an id for them
    fn add_env_var(&mut self, var: String, cur_env_desc: &EnvDescriptor) -> EnvDescriptor;

    /// add a task instance to buffer and return a unique id
    fn add_task_path(&mut self, task: TaskInstance) -> (TaskDescriptor, bool);

    /// Return input path from resolved input
    fn get_input_path_name(&self, i: &InputResolvedType) -> String;
    /// Return parent folder id from input path descriptor
    fn get_parent_id(&self, pd: &PathDescriptor) -> Option<PathDescriptor>;
    /// get id stored against input path
    fn get_id(&self, np: &NormalPath) -> Option<&PathDescriptor>;

    /// return path from its descriptor. Panics when the path is not found
    fn get_path(&self, pd: &PathDescriptor) -> &NormalPath;

    /// return path from its descriptor
    fn get_rel_path<P: AsRef<Path>>(&self, pd: &PathDescriptor, vd: P) -> NormalPath;
    /// Return Rule from its descriptor
    fn get_rule(&self, rd: &RuleDescriptor) -> &RuleFormulaInstance;
    /// return Env from its descriptor
    fn try_get_env(&self, ed: &EnvDescriptor) -> Option<&Env>;
    /// Return tup file path
    fn get_tup_path(&self, p: &TupPathDescriptor) -> &Path;
    /// Return path from its descriptor
    fn try_get_path(&self, id: &PathDescriptor) -> Option<&NormalPath>;

    /// Return task reference name from its descriptor
    fn try_get_task(&self, id: &TaskDescriptor) -> Option<&TaskInstance>;

    /// fetch the descriptor for a task using its name and directory
    fn try_get_task_desc(&self, tup_cwd: &Path, name: &str) -> Option<&TaskDescriptor>;

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

    /// Bin Name
    fn get_bin_name(&self, b: &BinDescriptor) -> Cow<'_, str>;
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

/// ```TaskDescriptor``` maintains the id of task based on tasks tracked for far in BufferObjects
#[derive(Debug, PartialEq, Eq, Clone, Hash, Copy, PartialOrd, Ord)]
pub struct TaskDescriptor(usize);

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
pub(crate) struct GenRuleBufferObject(BiMap<RuleFormulaInstance, RuleDescriptor>);

#[derive(Debug, Default, Clone)]
pub(crate) struct GenTaskBufferObject(BiBTreeMap<TaskInstance, TaskDescriptor>);

impl<T> GenPathBufferObject<T>
where
    T: Eq + Clone + Hash + From<usize> + Display,
{
    /// Construct  that stores paths and its descriptors as a `BiMap' relative to root_dir
    pub fn new<P: AsRef<Path>>(root_dir: P) -> Self {
        GenPathBufferObject {
            descriptor: BiMap::new(),
            root: root_dir.as_ref().to_path_buf(),
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
            diff_paths(path.as_ref(), self.get_root_dir())
                .unwrap_or_else(|| {
                    panic!(
                        "could not diff paths \n: {:?} - {:?}",
                        path.as_ref(),
                        self.get_root_dir()
                    )
                })
                .into()
        };
        let np = NormalPath::new_from_cow_path(Cow::from(pbuf));
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

pub(crate) type TaskBufferObject = GenTaskBufferObject;
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
impl_from_usize!(TaskDescriptor);

/// methods to modify get Rules of `RuleBufferObject'
impl RuleBufferObject {
    /// Add a ```RuleFormulaUsage''' object to this buffer returning a unique id
    pub(crate) fn add_rule(&mut self, r: RuleFormulaInstance) -> (RuleDescriptor, bool) {
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
    pub(crate) fn get_rule(&self, id: &RuleDescriptor) -> Option<&RuleFormulaInstance> {
        self.0.get_by_right(id)
    }
}

impl TaskBufferObject {
    pub(crate) fn add_task(&mut self, r: TaskInstance) -> (TaskDescriptor, bool) {
        let l = self.0.len();
        debug!("adding task {} to buffer", r.get_target());
        if let Some(prev_index) = self.0.get_by_left(&r) {
            (*prev_index, false)
        } else {
            let _ = self.0.insert(r, l.into());
            (l.into(), true)
        }
    }

    pub(crate) fn try_get_task(&self, id: &TaskDescriptor) -> Option<&TaskInstance> {
        self.0.get_by_right(id)
    }
    pub(crate) fn try_get_task_desc(&self, task: &TaskInstance) -> Option<&TaskDescriptor> {
        self.0.get_by_left(task)
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
        vs: &mut Vec<MatchingPath>,
        path_buffers: &impl PathBuffers,
    ) {
        let mut hs = HashSet::new();
        hs.extend(vs.iter().map(MatchingPath::path_descriptor));
        let mut found = false;
        if let Some(children) = self.children.get(base_path_desc) {
            if children.contains(path_desc) {
                vs.push(MatchingPath::new(
                    *path_desc,
                    path_buffers.get_path(path_desc).clone(),
                ));
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
                    vs.push(MatchingPath::new(
                        *path_desc,
                        path_buffers.get_path(path_desc).clone(),
                    ));
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
                        let capture_grps = glob_path.group(p);
                        debug!("found match:{:?} with groups:{:?}", p, capture_grps);
                        vs.push(MatchingPath::with_captures(
                            *pd,
                            np.clone(),
                            glob_path.get_glob_desc(),
                            capture_grps,
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
                            let capture_grps = glob_path.group(p);
                            debug!("found match:{:?} with groups:{:?}", p, capture_grps);
                            vs.push(MatchingPath::with_captures(
                                *pd,
                                np.clone(),
                                glob_path.get_glob_desc(),
                                capture_grps,
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
    pub(crate) fn get_group(
        &self,
        group_desc: &GroupPathDescriptor,
    ) -> Option<&HashSet<PathDescriptor>> {
        self.groups.get(group_desc)
    }
    /// Get paths stored against each bin
    pub(crate) fn get_bin(&self, bin_desc: &BinDescriptor) -> Option<&HashSet<PathDescriptor>> {
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
    ) -> Result<(), Error> {
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
        new_parent_rule: &HashMap<PathDescriptor, TupLoc>,
        new_path_descs: &HashSet<PathDescriptor>,
    ) -> Result<(), Error> {
        for new_path_desc in new_path_descs.iter() {
            let new_parent = new_parent_rule
                .get(new_path_desc)
                .expect("parent rule not found");
            debug!(
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
                        return Err(Error::MultipleRulesToSameOutput(
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
                let path_desc: PathDescriptor = glob_path.get_glob_path_desc().0.into();
                self.get().outputs_with_desc(
                    &path_desc,
                    glob_path.get_base_desc(),
                    &mut vs,
                    path_buffers,
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

    fn get_parent_rule(&self, o: &PathDescriptor) -> Option<MappedRwLockReadGuard<'_, TupLoc>> {
        let r = self.get();
        if r.get_parent_rule(o).is_some() {
            Some(RwLockReadGuard::map(self.get(), |x| {
                x.get_parent_rule(o).unwrap()
            }))
        } else {
            None
        }
    }

    fn get_parent_rules(&self) -> MappedRwLockReadGuard<'_, HashMap<PathDescriptor, TupLoc>> {
        RwLockReadGuard::map(self.get(), |x| x.get_parent_rules())
    }

    fn add_output(&mut self, pd: PathDescriptor) -> bool {
        self.get_mut().add_output(pd)
    }
    fn add_parent_rule(&mut self, pd: PathDescriptor, rule_ref: TupLoc) -> TupLoc {
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

    fn merge(&mut self, p: &impl PathBuffers, out: &impl OutputHandler) -> Result<(), Error> {
        self.get_mut().merge(p, out)
    }
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

    pub(crate) fn is_recursive_prefix(&self) -> bool {
        self.matcher.is_recursive_prefix()
    }
}

/// Output path and its id.
pub struct OutputType {
    pub(crate) path: NormalPath,
    pub(crate) pid: PathDescriptor,
}

impl Display for OutputType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("OutputType({:?})", self.path.as_path()))
    }
}

impl OutputType {
    pub(crate) fn new(path: NormalPath, pid: PathDescriptor) -> Self {
        Self { path, pid }
    }
    pub(crate) fn as_path(&self) -> &Path {
        self.path.as_path()
    }
    pub(crate) fn get_id(&self) -> PathDescriptor {
        self.pid
    }
}

/// Buffers to store files, groups, bins, env with its id.
/// Each sub-buffer is a bimap from names to a unique id which simplifies storing references.
#[derive(Debug, Clone)]
pub struct BufferObjects {
    path_bo: PathBufferObject,
    //< paths by id
    group_bo: GroupBufferObject,
    //< groups by id
    bin_bo: BinBufferObject,
    //< bins by id
    tup_bo: TupPathBufferObject,
    //< tup paths by id
    ebo: EnvBufferObject,
    //< environment variables by id
    rule_bo: RuleBufferObject,
    //< Rules by id
    // < task paths by id
    task_bo: TaskBufferObject,
}

impl Default for BufferObjects {
    fn default() -> Self {
        let root = Path::new(".");
        BufferObjects {
            path_bo: PathBufferObject::new(root),
            bin_bo: BinBufferObject::new(root),
            group_bo: GroupBufferObject::new(root),
            tup_bo: TupPathBufferObject::new(root),
            ebo: EnvBufferObject::default(),
            rule_bo: RuleBufferObject::default(),
            task_bo: TaskBufferObject::default(),
        }
    }
}

/// Accessors and modifiers for BufferObjects
impl BufferObjects {
    /// Construct Buffer object using tup (most) root directory where Tupfile.ini is found
    pub fn new<P: AsRef<Path>>(root: P) -> BufferObjects {
        BufferObjects {
            path_bo: PathBufferObject::new(root.as_ref()),
            bin_bo: BinBufferObject::new(root.as_ref()),
            group_bo: GroupBufferObject::new(root.as_ref()),
            tup_bo: TupPathBufferObject::new(root.as_ref()),
            ..Default::default()
        }
    }
}

impl PathBuffers for BufferObjects {
    /// Add path of bin. Folder is the one where  Tupfile declaring the bin. name is bin name
    fn add_bin_path_expr(&mut self, tup_cwd: &Path, pe: &str) -> (BinDescriptor, bool) {
        self.bin_bo.add_relative_bin(pe.as_ref(), tup_cwd)
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
        self.group_bo.add_relative(tup_cwd, Path::new(group_str))
    }

    /// Add a path to buffer and return its unique id in the buffer
    /// It is assumed that no de-dotting is necessary for the input path and path is already from the root
    fn add_abs(&mut self, p: &Path) -> (PathDescriptor, bool) {
        let p = paths::without_curdir_prefix(p);
        self.path_bo.add(p)
    }

    /// Add a path to buffer and return its unique id in the buffer
    fn add_path_from<P: AsRef<Path>>(&mut self, tup_cwd: &Path, p: P) -> (PathDescriptor, bool) {
        self.path_bo.add_relative(tup_cwd, p.as_ref())
    }

    fn add_rule(&mut self, r: RuleFormulaInstance) -> (RuleDescriptor, bool) {
        self.rule_bo.add_rule(r)
    }
    fn add_tup(&mut self, p: &Path) -> (TupPathDescriptor, bool) {
        let p1 = NormalPath::cleanup(p, Path::new("."));
        self.tup_bo.add(p1.as_path())
    }

    /// add environment variable to the list of variables active in current tupfile until now
    /// This appends a new env var current list of env vars.
    fn add_env_var(&mut self, var: String, cur_env_desc: &EnvDescriptor) -> EnvDescriptor {
        debug!(
            "add env var {} to cur env :{} in ebo with size:{}",
            var.as_str(),
            cur_env_desc,
            self.ebo.0.len()
        );
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

    fn add_task_path(&mut self, task: TaskInstance) -> (TaskDescriptor, bool) {
        self.task_bo.add_task(task)
    }

    /// Get file name or bin name or group name of the input path
    /// use `get_resolve_path` to get resolved path
    fn get_input_path_name(&self, i: &InputResolvedType) -> String {
        i.get_resolved_name(&self)
    }

    /// Returns parent id for the path
    fn get_parent_id(&self, pd: &PathDescriptor) -> Option<PathDescriptor> {
        let p = self.path_bo.try_get(pd)?;
        let np = NormalPath::new_from_cow_path(get_parent(p.as_path()));
        self.get_id(&np).copied()
    }

    /// Returns id for the path
    fn get_id(&self, np: &NormalPath) -> Option<&PathDescriptor> {
        self.path_bo.get_id(np)
    }

    /// Returns path corresponding to an path descriptor. This panics if there is no match
    fn get_path(&self, id: &PathDescriptor) -> &NormalPath {
        self.path_bo.get(id)
    }
    fn get_rel_path<P: AsRef<Path>>(&self, pd: &PathDescriptor, np2: P) -> NormalPath {
        let np1 = self.get_path(pd);
        NormalPath::new_from_cow_path(diff_paths(np1.as_path(), np2.as_ref()).unwrap().into())
    }

    /// Returns rule corresponding to a rule descriptor. Panics if none is found
    fn get_rule(&self, id: &RuleDescriptor) -> &RuleFormulaInstance {
        self.rule_bo
            .get_rule(id)
            .unwrap_or_else(|| panic!("unable to fetch rule formula for id:{}", id))
    }
    /// Returns env corresponding to a env descriptor. Panics if none is found
    fn try_get_env(&self, id: &EnvDescriptor) -> Option<&Env> {
        self.ebo.try_get(id)
    }

    /// Returns path corresponding to the given tupfile descriptor
    fn get_tup_path(&self, t: &TupPathDescriptor) -> &Path {
        self.tup_bo.get(t).as_path()
    }
    // Attempts to get path corresponding to an path descriptor. None if no match is found
    fn try_get_path(&self, id: &PathDescriptor) -> Option<&NormalPath> {
        self.path_bo.try_get(id)
    }

    fn try_get_task(&self, id: &TaskDescriptor) -> Option<&TaskInstance> {
        self.task_bo.try_get_task(id)
    }

    fn try_get_task_desc(&self, tup_cwd: &Path, name: &str) -> Option<&TaskDescriptor> {
        let task = TaskInstance::new(
            tup_cwd,
            name,
            vec![],
            vec![],
            TupLoc::default(),
            vec![],
            EnvDescriptor::default(),
        );
        self.task_bo.try_get_task_desc(&task)
    }
    /// Try get a bin path entry by its descriptor.
    fn try_get_group_path(&self, gd: &GroupPathDescriptor) -> Option<&NormalPath> {
        self.group_bo.try_get(gd)
    }
    /// Get group ids as an iter
    fn get_group_descs(&self) -> RightValues<'_, NormalPath, GroupPathDescriptor> {
        self.group_bo.get_ids()
    }

    /// Get tup id corresponding to its path
    fn get_tup_id(&self, p: &Path) -> &TupPathDescriptor {
        let p = paths::without_curdir_prefix(p);
        self.tup_bo
            .get_id(&NormalPath::new_from_cow_path(p))
            .unwrap()
    }

    /// Return root folder where tup was initialized
    fn get_root_dir(&self) -> &Path {
        self.path_bo.get_root_dir()
    }

    /// Get group name stored against its id
    fn get_group_name(&self, gd: &GroupPathDescriptor) -> String {
        self.group_bo.get_group_name(gd)
    }

    /// Get path of a maybe resolved input
    fn get_path_from(&self, input_glob: &InputResolvedType) -> &Path {
        input_glob.get_resolved_path(&self.path_bo)
    }

    /// Get Path stored against its id
    fn get_path_str(&self, p: &PathDescriptor) -> String {
        let p = self.path_bo.get(p).as_path();
        p.to_string_lossy().to_string()
    }

    /// check if env var exists in our stored buffers
    fn has_env(&self, id: &str, cur_env_desc: &EnvDescriptor) -> bool {
        self.ebo.has_env(id, cur_env_desc)
    }

    /// Return an iterator over all the id-group path pairs.
    /// Group path is of the form folder/\<group\>, Where folder is the file system path relative to root
    fn group_iter(&self) -> bimap::hash::Iter<'_, NormalPath, GroupPathDescriptor> {
        self.group_bo.group_iter()
    }

    fn get_bin_name(&self, b: &BinDescriptor) -> Cow<'_, str> {
        self.bin_bo.get(b).as_path().to_string_lossy()
    }
}
