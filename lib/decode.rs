//! This module handles decoding and de-globbing of rules
use std::borrow::{Borrow, Cow};
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::fmt::Formatter;
use std::hash::Hash;
use std::iter::Chain;
use std::ops::Deref;
use std::path::{Component, Path, PathBuf};
use std::slice::Iter;

use glob::{Candidate, GlobBuilder, GlobMatcher};
use walkdir::WalkDir;
use path_dedot::ParseDot;
use regex::{Captures, Regex};

use crate::transform::locate_file;
use bimap::hash::RightValues;
use bimap::BiMap;
use bstr::ByteSlice;
use daggy::Dag;
use errors::{Error as Err, Error};
use log::{debug, log_enabled};
use pathdiff::diff_paths;
use petgraph::graph::NodeIndex;
use statements::*;
use transform::{load_conf_vars, Artifacts, SubstState, TupParser};
use {glob, transform};

/// Normal Path packages a PathBuf, giving relative paths wrt current tup directory
#[derive(Debug, Default, Eq, PartialEq, Clone, Hash)]
pub struct NormalPath {
    inner: PathBuf,
}
/// Constructor and accessor for a NormalPath
impl NormalPath {
    /// Construct consuming the given pathbuf
    pub fn new(p: PathBuf) -> NormalPath {
        NormalPath { inner: p }
    }
    /// Construct a `NormalPath' from joining tup_cwd with path
    pub fn absolute_from(path: &Path, tup_cwd: &Path) -> Self {
        let p1 = Self::cleanup(path, tup_cwd);
        NormalPath::new(p1)
    }

    fn cleanup(path: &Path, tup_cwd: &Path) -> PathBuf {
        let p1: PathBuf = path
            .components()
            .skip_while(|x| Component::CurDir.eq(x))
            .collect();
        let p2: PathBuf = if tup_cwd.components().all(|ref x| Component::CurDir.eq(x)) {
            p1
        } else {
            tup_cwd
                .join(p1.as_path())
                .parse_dot()
                .unwrap_or_else(|_| panic!("could not join paths: {:?} with {:?}", tup_cwd, path))
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
}

pub(crate) fn normalize_path(p: &Path) -> String {
    Candidate::new(p).path().to_str_lossy().to_string()
}
impl ToString for NormalPath {
    /// Inner path in form that can be compared or stored as a bytes
    fn to_string(&self) -> String {
        // following converts backslashes to forward slashes
        normalize_path(self.as_path())
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

/// `RuleFormula' usage new and accessors
impl RuleFormulaUsage {
    pub(crate) fn new(rule_formula: RuleFormula, rule_ref: RuleRef) -> RuleFormulaUsage {
        RuleFormulaUsage {
            rule_formula,
            rule_ref,
        }
    }
    pub(crate) fn get_formula(&self) -> &RuleFormula {
        &self.rule_formula
    }
    /// `RuleRef' that this usage refers to
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
#[derive(Debug, PartialEq, Eq, Clone, Hash, Copy)]
pub struct PathDescriptor(usize);
/// ```GroupPathDescriptor``` is an id given to a group that appears in a tupfile.
#[derive(Debug, PartialEq, Eq, Clone, Hash, Copy)]
pub struct GroupPathDescriptor(usize);
/// ```BinDescriptor``` is an id given to a  folder where tupfile was found
#[derive(Debug, PartialEq, Eq, Clone, Hash, Copy)]
pub struct BinDescriptor(usize);
/// ```TupPathDescriptor``` is an unique id given to a tupfile
#[derive(Debug, PartialEq, Eq, Clone, Hash, Copy)]
pub struct TupPathDescriptor(usize);
/// ```RuleDescriptor``` maintains the id of rule based on rules tracked for far in BufferObjects
#[derive(Debug, PartialEq, Eq, Clone, Hash, Copy)]
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

/// path to descriptor(T) `BiMap', path stored is relative to rootdir (.1 in this struct)
#[derive(Debug, Default, Clone)]
pub(crate) struct GenPathBufferObject<T: PartialEq + Eq + Hash + Clone>(
    BiMap<NormalPath, T>,
    PathBuf,
);

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
        GenPathBufferObject(BiMap::new(), root_dir.to_path_buf())
    }

    /// add a path to buffer that is absolutized by removing dots as many as we can when joining @tup_cwd with @path
    pub fn add_relative(&mut self, path: &Path, tup_cwd: &Path) -> (T, bool) {
        let np = NormalPath::absolute_from(path, tup_cwd);
        self.add_normal_path(np)
    }

    /// root director of the paths stored in this buffer
    fn get_root_dir(&self) -> &Path {
        self.1.as_path()
    }

    /// Store a path relative to rootdir. path is expected not to have dots
    /// descriptor is assigned by finding using size of buffer
    pub fn add<P: AsRef<Path>>(&mut self, path: P) -> (T, bool) {
        //debug_assert!(path.as_ref().is_absolute(), "expected a absolute path as input but found:{:?}", path.as_ref());
        let pbuf = if path.as_ref().is_relative() && self.get_root_dir().is_absolute() {
            path.as_ref().to_path_buf() //assume that the relative-path is relative to the root
        }
        else {
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
        self.0.right_values()
    }

    /// add a path with a automatically assigned id
    fn add_normal_path(&mut self, np: NormalPath) -> (T, bool) {
        let l = self.0.len();
        if let Some(prev_index) = self.0.get_by_left(&np) {
            (prev_index.clone(), false)
        } else {
            let _ = self.0.insert(np, l.into());
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
        self.0.get_by_right(pd)
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
    /// add  path of group path expr joining from base directory where Tupfile exists
    /// Final path added would be relative to root tup folder
    pub(crate) fn add_relative_group(
        &mut self,
        pathexpr: &PathExpr,
        tup_cwd: &Path,
    ) -> (GroupPathDescriptor, bool) {
        if let PathExpr::Group(_, _) = pathexpr {
            self.add_relative(Path::new(pathexpr.cat().as_str()), tup_cwd)
        } else {
            (Default::default(), false)
        }
    }

    /// iterator over all the (groupid, grouppath) pairs stored in this buffer
    pub(crate) fn group_iter(&self) -> bimap::hash::Iter<'_, NormalPath, GroupPathDescriptor> {
        self.0.iter()
    }
}

/// methods to modify get Rules of `RuleBufferObject'
impl RuleBufferObject {
    /// Add a ```RuleFormulaUsage''' object to this buffer returning a unique id
    pub(crate) fn add_rule(&mut self, r: RuleFormulaUsage) -> (RuleDescriptor, bool) {
        let l = self.0.len();
        let rulestr = r.rule_formula.cat();
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
        pathexpr: &PathExpr,
        tup_cwd: &Path,
    ) -> (BinDescriptor, bool) {
        if let PathExpr::Bin(bin) = pathexpr {
            let bin_as_path = Path::new(bin);
            self.add_relative(bin_as_path, tup_cwd)
        } else {
            (Default::default(), false)
        }
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
    pub(crate) fn has_env(&self, var: &str) -> bool {
        let start = 1;
        // check the env corresponding to the last added env for the presence of var
        if let Some(rvalue) = self.0.get_by_right(&(start - 1).into()) {
            rvalue.contains(var)
        } else {
            false
        }
    }

    /// returns a Env in the buffer corresponding to the given EnvDescriptor
    /// This panics if not found
    pub(crate) fn get(&self, pd: &EnvDescriptor) -> &Env {
        self.try_get(pd)
            .unwrap_or_else(|| panic!("Env for id:{} not in buffer", pd))
    }

    /// Fallible version of the above
    pub(crate) fn try_get(&self, pd: &EnvDescriptor) -> Option<&Env> {
        self.0.get_by_right(pd)
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
pub struct OutputAssocs {
    /// rule output files accumulated thus far
    output_files: HashSet<PathDescriptor>,
    /// paths accumulated in a bin
    bins: HashMap<BinDescriptor, HashSet<PathDescriptor>>,
    /// paths accumulated in groups
    groups: HashMap<GroupPathDescriptor, HashSet<PathDescriptor>>,
    /// track the parent rule that generates a output file
    parent_rule: HashMap<PathDescriptor, RuleRef>,
    ///  Should group references be resolved in inputs and rules?
    resolve_groups: bool,
}

impl OutputAssocs {
    pub(crate) fn acquire_groups(
        &mut self,
        grps: HashMap<GroupPathDescriptor, HashSet<PathDescriptor>>,
    ) {
        self.groups = grps
    }
}

impl OutputAssocs {
    /// Get all the output files from rules accumulated so far
    pub fn get_output_files(&self) -> &HashSet<PathDescriptor> {
        &self.output_files
    }

    /// Get all the groups with collected rule outputs
    pub fn get_groups(&self) -> &HashMap<GroupPathDescriptor, HashSet<PathDescriptor>> {
        &self.groups
    }
    /// Get a mutable references all the groups with collected rule outputs.
    /// This can be used to to fill path references from a database.
    pub fn get_mut_groups(&mut self) -> &mut HashMap<GroupPathDescriptor, HashSet<PathDescriptor>> {
        &mut self.groups
    }

    /// Add an entry to the collector that holds paths of a group
    pub fn add_group_entry(&mut self, group_desc: &GroupPathDescriptor, pd: PathDescriptor) {
        self.get_mut_groups()
            .entry(*group_desc)
            .or_default()
            .extend(std::iter::once(pd));
    }
    /// the parent rule that generates a output file
    pub fn get_parent_rule(&self, o: &PathDescriptor) -> Option<&RuleRef> {
        self.parent_rule.get(o)
    }

    /// Merge paths of different groups from new_outputs into current group path container
    fn merge_group_tags(&mut self, new_outputs: &OutputAssocs) -> Result<(), Err> {
        for (k, new_paths) in new_outputs.groups.iter() {
            self.groups
                .entry(*k)
                .or_insert_with(HashSet::new)
                .extend(new_paths.iter().cloned());
            self.merge_parent_rules(&new_outputs.parent_rule, new_paths)?;
        }
        Ok(())
    }

    /// Merge bins from its new outputs
    fn merge_bin_tags(&mut self, other: &OutputAssocs) -> Result<(), Err> {
        for (k, new_paths) in other.bins.iter() {
            self.bins
                .entry(*k)
                .or_insert_with(HashSet::new)
                .extend(new_paths.iter().cloned());
            self.merge_parent_rules(&other.parent_rule, new_paths)?;
        }
        Ok(())
    }

    /// merge groups , outputs and bins from other OutputAssocs
    ///  erorr-ing out if unique parent rule
    /// of an output is not found
    pub fn merge(&mut self, out: &OutputAssocs) -> Result<(), Err> {
        self.merge_group_tags(out)?;
        self.merge_output_files(out)?;
        self.merge_bin_tags(out)
    }

    fn merge_output_files(&mut self, new_outputs: &OutputAssocs) -> Result<(), Err> {
        self.output_files
            .extend(new_outputs.output_files.iter().cloned());
        self.merge_parent_rules(&new_outputs.parent_rule, &new_outputs.output_files)
    }

    /// Track parent rules of outputs, error-ing out if unique parent rule
    /// of an output is not found
    fn merge_parent_rules(
        &mut self,
        new_parent_rule: &HashMap<PathDescriptor, RuleRef>,
        new_path_descs: &HashSet<PathDescriptor>,
    ) -> Result<(), Err> {
        for new_path_desc in new_path_descs.iter() {
            let newparent = new_parent_rule
                .get(new_path_desc)
                .expect("parent rule not found");
            match self.parent_rule.entry(*new_path_desc) {
                Entry::Occupied(pe) => {
                    if pe.get() != newparent {
                        return Err(Err::MultipleRulesToSameOutput(
                            *new_path_desc,
                            pe.get().clone(),
                            newparent.clone(),
                        ));
                    }
                }
                Entry::Vacant(pe) => {
                    pe.insert(newparent.clone());
                }
            }
        }
        Ok(())
    }

    /// Construct [OutputAssocs] with resolve_groups set to false
    pub fn new() -> OutputAssocs {
        OutputAssocs {
            resolve_groups: true,
            ..Default::default()
        }
    }

    /// Construct [OutputAssocs] default values
    pub fn new_no_resolve_groups() -> OutputAssocs {
        Default::default()
    }

    /// discover outputs matching glob in the same tupfile
    pub(crate) fn outputs_matching_glob(
        &self,
        bo: &BufferObjects,
        glob: &MyGlob,
        vs: &mut Vec<MatchingPath>,
    ) {
        let mut hs = HashSet::new();
        hs.extend(vs.iter().map(|mp| mp.path_descriptor));

        self.bins
            .iter()
            .map(|x| x.1)
            .chain(self.groups.iter().map(|x| x.1))
            .chain(std::iter::once(&self.output_files))
            .for_each(|v| {
                for pd in v.iter() {
                    if let Some(np) = bo.try_get_path(pd) {
                        let p: &Path = np.into();
                        if glob.is_match(p) && hs.insert(*pd) {
                            vs.push(MatchingPath::with_captures(*pd, glob.group(p, "GM")))
                        }
                    }
                }
            });
    }
}
/// A Matching Path discovered using glob matcher.
#[derive(Debug, Default, Eq, PartialEq, Clone)]
pub struct MatchingPath {
    path_descriptor: PathDescriptor, // path that matched a glob
    first_group: Option<String>,     // first glob match in the above path
}
const GLOB_PATTERN_CHARACTERS: &str = "*?[";
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

#[derive(Debug, Clone)]
pub(crate) struct MyGlob {
    matcher: GlobMatcher,
}

impl MyGlob {
    pub(crate) fn new(path_pattern: &str) -> Result<Self, crate::errors::Error> {
        let to_glob_error = |e: &glob::Error| {
            crate::errors::Error::GlobError(
                path_pattern.to_string() + ":" + e.kind().to_string().as_str(),
            )
        };
        let glob_pattern = GlobBuilder::new(path_pattern)
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
    pub(crate) fn group<P: AsRef<Path>>(&self, path: P, name: &str) -> Option<String> {
        self.matcher.group(path, name)
    }

    /// Get regex
    pub(crate) fn re(&self) -> &regex::bytes::Regex {
        self.matcher.re()
    }
}
// matching path with first group
impl MatchingPath {
    pub(crate) fn with_captures(path: PathDescriptor, first_group: Option<String>) -> MatchingPath {
        MatchingPath {
            path_descriptor: path,
            first_group,
        }
    }
    /// Get path represented by this entry
    pub fn path_descriptor(&self) -> &PathDescriptor {
        &self.path_descriptor
    }
    pub(crate) fn as_path<'a>(&self, bo: &'a BufferObjects) -> &'a Path {
        bo.get_path(&self.path_descriptor).into()
    }
}
/// This function runs the glob matcher to discover rule inputs by walking from given directory. The paths are returned as descriptors stored in [MatchingPatch]
/// @tup_cwd is expected to be current tupfile directory under which a rule is found. @glob_path
pub(crate) fn discover_inputs_from_glob(
    tup_cwd: &Path,
    glob_path: &Path,
    outputs: &OutputAssocs,
    bo: &mut BufferObjects,
) -> Result<Vec<MatchingPath>, crate::errors::Error> {
    let np = NormalPath::absolute_from(glob_path, tup_cwd);
    let (mut base_path, recurse) = get_non_pattern_prefix(np.as_path());
    let mut to_match = np.as_path();
    if base_path.eq(np.as_path())
    {
        let mut pes = Vec::new();
        {
            let path = base_path.as_path();
            let (path_desc, _) = bo.add_path_from(path, tup_cwd);
            pes.push(MatchingPath::with_captures(path_desc, None));
        }
         if log_enabled!(log::Level::Debug) {
             //    debug!("{:?}", pes);
             for pe in pes.iter() {
                 debug!("mp:{:?}", pe);
             }
         }
        // discover inputs from previous outputs
        //outputs.outputs_matching_glob(bo, &globs, &mut pes);
        return Ok(pes)
    }
    let pbuf: PathBuf;
    if base_path.eq(&PathBuf::new()) {
        base_path = base_path.join(".");
        pbuf = Path::new(".").join(glob_path);
        to_match = &pbuf;
    }
    let slash_corrected_glob = to_match.to_string_lossy().replace('\\', "/");
    let globs = MyGlob::new(slash_corrected_glob.as_str())?;
    debug!("glob regex used for finding matches {}", globs.re());
    debug!("base path for files matching glob: {:?}", base_path.as_path());
    let mut walkdir = WalkDir::new(base_path.as_path());
    if !recurse {
        walkdir = walkdir.max_depth(1);
    }
    let filtered_paths = walkdir
        .min_depth(1)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|entry| {
            let match_path = entry
                .path()
                .to_string_lossy()
                .to_string()
                .replace('\\', "/"); //.strip_prefix(tup_cwd).unwrap();
            globs.is_match(match_path)
        });
    let mut pes = Vec::new();
    for matching in filtered_paths {
        let path = matching.path();
        let (path_desc, _) = bo.add_path_from_root(path);
        pes.push(MatchingPath::with_captures(path_desc,
                                             globs.group(path, "GM")));
    }
    if log_enabled!(log::Level::Debug) {
        for pe in pes.iter() {
            debug!("mp_glob:{:?}", pe);
        }
    }

    // discover inputs from previous outputs
    outputs.outputs_matching_glob(bo, &globs, &mut pes);
    Ok(pes)
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
}

/// Extracts the actual file system path corresponding to a de-globbed input or bin or group entry
fn get_resolved_path<'a, 'b>(
    input_glob: &'a InputResolvedType,
    pbo: &'b PathBufferObject,
) -> &'b Path {
    match input_glob {
        InputResolvedType::Deglob(e) => pbo.get(e.path_descriptor()).as_path(),
        InputResolvedType::GroupEntry(_, p) => pbo.get(p).as_path(),
        InputResolvedType::BinEntry(_, p) => pbo.get(p).as_path(),
        InputResolvedType::UnResolvedGroupEntry(_) => Path::new(""),
        //InputResolvedType::RawUnchecked(p) => pbo.get(p).as_path()
    }
}

/// Resolved name of the given Input,
/// For Group(or UnResolvedGroup) entries, group name is returned
/// For Bin entries, bin name is returned
/// For others the file name is returned
fn get_resolved_name<'a, 'b>(
    input_glob: &'a InputResolvedType,
    pbo: &PathBufferObject,
    gbo: &'b GroupBufferObject,
    bbo: &'b BinBufferObject,
) -> String {
    match input_glob {
        InputResolvedType::Deglob(e) => pbo.get(e.path_descriptor()).to_string(),
        InputResolvedType::GroupEntry(g, _) => gbo.get(g).to_string(),
        InputResolvedType::BinEntry(b, _) => bbo.get(b).to_string(),
        InputResolvedType::UnResolvedGroupEntry(g) => gbo.get(g).to_string(),
        //InputResolvedType::RawUnchecked(p) => pbo.get(p).to_string()
    }
}

struct OutputType {
    pub path: PathBuf,
}

impl OutputType {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }
    fn as_path(&self) -> &Path {
        self.path.as_path()
    }
}

/// Get matched glob in the input to a rule
fn as_glob_match(inpg: &InputResolvedType) -> Option<String> {
    match inpg {
        InputResolvedType::Deglob(e) => (e).first_group.as_ref().cloned(),
        _ => None,
    }
}

pub(crate) trait ExcludeInputPaths {
    fn exclude(
        &self,
        deglobbed: Vec<InputResolvedType>,
        bo: &BufferObjects,
    ) -> Vec<InputResolvedType>;
}
impl ExcludeInputPaths for PathExpr {
    fn exclude(
        &self,
        deglobbed: Vec<InputResolvedType>,
        bo: &BufferObjects,
    ) -> Vec<InputResolvedType> {
        match self {
            PathExpr::ExcludePattern(patt) => {
                let re = Regex::new(patt).ok();
                if let Some(ref re) = re {
                    let matches = |i: &InputResolvedType| {
                        let s = bo.get_input_path_str(i);
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
/// Buffers to store files, groups, bins, env with its id.
/// Each sub-buffer is a bimap from names to a unique id which simplifies storing references.
#[derive(Debug, Clone, Default)]
pub(crate) struct BufferObjects {
    pbo: PathBufferObject,
    gbo: GroupBufferObject,
    bbo: BinBufferObject,
    tbo: TupPathBufferObject,
    ebo: EnvBufferObject,
    rbo: RuleBufferObject,
}
// Accessors for BufferObjects
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
    pub(crate) fn add_tup(&mut self, p: &Path) -> (TupPathDescriptor, bool) {
        self.tbo.add(p)
    }

    pub(crate) fn add_env(&mut self, e: Cow<Env>) -> (EnvDescriptor, bool) {
        self.ebo.add_env(e)
    }

    /// Add a path to buffer and return its unique id in the buffer
    pub fn add_path_from(&mut self, p: &Path, tup_cwd: &Path) -> (PathDescriptor, bool) {
        self.pbo.add_relative(p, tup_cwd)
    }

    /// Add a path to buffer and return its unique id in the buffer
    /// It is assumed that no de-dotting is necessary for the input path
    pub fn add_path_from_root(&mut self, p: &Path) -> (PathDescriptor, bool) {
        let p: PathBuf = p
            .components()
            .skip_while(|x| Component::CurDir.eq(x))
            .collect();
        debug_assert!(!p
            .components()
            .any(|ref c| Component::ParentDir.eq(c) || Component::CurDir.eq(c)));
        self.pbo.add(p)
    }

    /// Add a path to a group in this buffer
    fn add_group_pathexpr(&mut self, p: &PathExpr, tup_cwd: &Path) -> (GroupPathDescriptor, bool) {
        self.gbo.add_relative_group(p, tup_cwd)
    }

    /// Add path of bin. Folder is the one where  Tupfile declaring the bin. name is bin name
    pub(crate) fn add_bin_pathexpr(
        &mut self,
        p: &PathExpr,
        tup_cwd: &Path,
    ) -> (BinDescriptor, bool) {
        self.bbo.add_relative_bin(p, tup_cwd)
    }

    pub(crate) fn add_rule(&mut self, r: RuleFormulaUsage) -> (RuleDescriptor, bool) {
        self.rbo.add_rule(r)
    }

    /// Get file name of the input path
    pub fn get_input_path_str(&self, i: &InputResolvedType) -> String {
        get_resolved_name(i, &self.pbo, &self.gbo, &self.bbo)
    }

    /// Returns path corresponding to the given tupfile descriptor
    pub fn get_tup_path(&self, t: &TupPathDescriptor) -> &Path {
        self.tbo.get(t).as_path()
    }

    /// Returns env correponding to a envdescriptor. Panics if none is found
    pub fn get_env(&self, id: &EnvDescriptor) -> &Env {
        self.ebo.get(id)
    }

    pub(crate) fn add_env_var(
        &mut self,
        var: String,
        cur_env_desc: &EnvDescriptor,
    ) -> Option<EnvDescriptor> {
        if !self.has_env(&var) {
            let mut env = self.get_env(cur_env_desc).clone();
            env.add(var);
            let (id, _) = self.add_env(Cow::Owned(env));
            Some(id)
        } else {
            None
        }
    }

    pub(crate) fn has_env(&self, id: &str) -> bool {
        self.ebo.has_env(id)
    }
    /// Returns rule correponding to a rule descrtor. Panics if none is found
    pub fn get_rule(&self, id: &RuleDescriptor) -> &RuleFormulaUsage {
        self.rbo
            .get_rule(id)
            .unwrap_or_else(|| panic!("unable to fetch rule formula for id:{}", id))
    }

    /// Returns path corresponding to an path descriptor. This panics if there is no match
    pub fn get_path(&self, id: &PathDescriptor) -> &NormalPath {
        self.pbo.get(id)
    }
    // Attempts to get path corresponding to an path descriptor. None if no match is found
    pub(crate) fn try_get_path(&self, id: &PathDescriptor) -> Option<&NormalPath> {
        self.pbo.try_get(id)
    }

    /// Try get  a bin path entry by its descriptor.
    pub fn try_get_group_path(&self, gd: &GroupPathDescriptor) -> Option<&NormalPath> {
        self.gbo.try_get(gd)
    }
    /// Get group ids as an iter
    pub fn get_group_descs(&self) -> RightValues<'_, NormalPath, GroupPathDescriptor> {
        self.gbo.get_ids()
    }

    /// Return root folder where tup was initialized
    pub fn get_root_dir(&self) -> &Path {
        self.pbo.get_root_dir()
    }

    pub(crate) fn get_group_name(&self, gd: &GroupPathDescriptor) -> String {
        self.gbo.get_group_name(gd)
    }

    pub(crate) fn get_path_from(&self, input_glob: &InputResolvedType) -> &Path {
        get_resolved_path(input_glob, &self.pbo)
    }
    pub(crate) fn get_path_str(&self, p: &PathDescriptor) -> String {
        let p = self.pbo.get(p).as_path();
        p.to_string_lossy().to_string()
    }

    /// Return an iterator over all the id-group path pairs.
    /// Group path is of the form folder/\<group\>, Where folder is the file system path relative to root
    pub fn group_iter(&self) -> bimap::hash::Iter<'_, NormalPath, GroupPathDescriptor> {
        self.gbo.group_iter()
    }
}

/// Decode input paths from file globs, bins(buckets), and groups
pub(crate) trait DecodeInputPaths {
    fn decode(
        &self,
        tup_cwd: &Path,
        tag_info: &OutputAssocs,
        bo: &mut BufferObjects,
        rule_ref: &RuleRef,
    ) -> Result<Vec<InputResolvedType>, Err>;
}

// Decode input paths in RvalGeneral
impl DecodeInputPaths for PathExpr {
    // convert globs into regular paths, remember that matched groups
    fn decode(
        &self,
        tup_cwd: &Path,
        tag_info: &OutputAssocs,
        bo: &mut BufferObjects,
        rule_ref: &RuleRef,
    ) -> Result<Vec<InputResolvedType>, Err> {
        let mut vs = Vec::new();
        debug!("Decoding input paths of {:?}", &self);
        match self {
            PathExpr::Literal(_) => {
                let np = normalized_path(tup_cwd, self);
                let path_buf = diff_paths(np.as_path(), tup_cwd).unwrap_or_else(|| {
                    panic!("unable to diff with {:?} from {:?}", tup_cwd, np.as_path())
                });
                let root = bo.get_root_dir();
                let pes = discover_inputs_from_glob(
                    root.join(tup_cwd).as_path(),
                    path_buf.as_path(),
                    tag_info,
                    bo,
                )?;
                vs.extend(pes.into_iter().map(InputResolvedType::Deglob));
            }
            PathExpr::Group(_, _) => {
                let (ref grp_desc, _) = bo.add_group_pathexpr(self, tup_cwd);
                if tag_info.resolve_groups {
                    if let Some(paths) = tag_info.groups.get(grp_desc) {
                        vs.extend( paths.iter().map( |x| InputResolvedType::GroupEntry(*grp_desc,*x)))
                    } else {
                        //let (, _) = bo.add_path(Path::new(&*p.cat()), tup_cwd);
                        vs.push(InputResolvedType::UnResolvedGroupEntry(*grp_desc));
                    }
                } else {
                    vs.push(InputResolvedType::UnResolvedGroupEntry(*grp_desc));
                }
            }
            PathExpr::Bin(b) => {
                let (ref bin_desc, _) = bo.add_bin_pathexpr(self, tup_cwd);
                if let Some(paths) = tag_info.bins.get(bin_desc) {
                    for p in paths {
                        vs.push(InputResolvedType::BinEntry(*bin_desc, *p))
                    }
                } else {
                    return Err(Error::StaleBinRef(
                        b.clone(),
                        rule_ref.clone(),
                    ));
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
        tag_info: &OutputAssocs,
        bo: &mut BufferObjects,
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
            .map(|x| x.decode(tup_cwd, tag_info, bo, rule_ref))
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
                    exclude_regex.exclude(ips, bo)
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

// decode input paths

trait GatherOutputs {
    fn gather_outputs(&self, oti: &mut OutputAssocs) -> Result<(), Err>;
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

/// `InputsAsPaths' represents resolved inputs to pass to a rule
/// Bins are converted to raw paths, groups paths are expanded into a space separated path list
pub struct InputsAsPaths {
    raw_inputs: Vec<PathBuf>,
    groups_by_name: HashMap<String, String>,
    raw_inputs_glob_match: Option<InputResolvedType>,
    rule_ref: RuleRef,
}
impl InputsAsPaths {
    /// return all paths  (space separated) stored in given group name
    /// This is used for group name substitions in rule formulas that appear as %<group_name>
    pub(crate) fn get_group_paths(&self, grp_name: &str) -> Option<&String> {
        if grp_name.starts_with('<') {
            self.groups_by_name.get(grp_name)
        } else {
            self.groups_by_name.get(&*format!("<{}>", grp_name))
        }
    }

    /// returns all paths as strings in a vector
    pub(crate) fn get_file_names(&self) -> Vec<String> {
        self.raw_inputs
            .iter()
            .filter_map(|f| f.file_name())
            .map(|x| x.to_string_lossy().to_string())
            .collect()
    }

    /// Returns the first parent folder name
    pub(crate) fn parent_folder_name(&self) -> Option<String> {
        self.raw_inputs
            .iter()
            .filter_map(|f| f.parent())
            .filter_map(|f| f.file_name())
            .map(|x| x.to_string_lossy().to_string())
            .next()
    }

    /// returns all the inputs
    pub(crate) fn get_paths(&self) -> Vec<String> {
        self.raw_inputs
            .iter()
            .map(|x| x.to_string_lossy().to_string())
            .collect()
    }

    pub(crate) fn get_extension(&self) -> Option<String> {
        self.raw_inputs
            .first()
            .and_then(|x| x.extension())
            .map(|x| x.to_string_lossy().to_string())
    }
    pub(crate) fn get_file_stem(&self) -> Vec<String> {
        self.raw_inputs
            .iter()
            .filter_map(|x| x.file_stem())
            .map(|x| x.to_string_lossy().to_string())
            .collect()
    }

    pub(crate) fn get_glob(&self) -> Option<String> {
        self.raw_inputs_glob_match.as_ref().and_then(as_glob_match)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.raw_inputs.is_empty()
    }
}
impl InputsAsPaths {
    pub(crate) fn new(
        tup_cwd: &Path,
        inp: &[InputResolvedType],
        bo: &BufferObjects,
        rule_ref: RuleRef,
    ) -> InputsAsPaths {
        let isnotgrp = |x: &InputResolvedType| {
            !matches!(x, &InputResolvedType::GroupEntry(_, _))
                && !matches!(x, &InputResolvedType::UnResolvedGroupEntry(_))
        };
        let relpath = |x| diff_paths(x, tup_cwd)
            .unwrap_or_else(|| panic!("path diff failure {:?} with base:{:?}", x, tup_cwd));
        let try_grp = |x: &InputResolvedType| {
            if let &InputResolvedType::GroupEntry(ref grp_desc, _) = x {
                Some((bo.get_group_name(grp_desc), relpath(bo.get_path_from(x))))
            } else if let &InputResolvedType::UnResolvedGroupEntry(ref grp_desc) = x {
                let grp_name = bo.get_group_name(grp_desc);
                Some((grp_name.clone(), Path::new(&*grp_name).to_path_buf()))
            } else {
                None
            }
        };
        let allnongroups: Vec<_> = inp
            .iter()
            .filter(|&x| isnotgrp(x))
            .map(|x| relpath(bo.get_path_from(x)))
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
        InputsAsPaths {
            raw_inputs: allnongroups,
            groups_by_name: namedgroupitems,
            raw_inputs_glob_match: inp.first().cloned(),
            rule_ref,
        }
    }
}
lazy_static! {
    static ref PERC_NUM_F_RE: Regex =
        Regex::new(r"%([1-9]+[0-9]*)f").expect("regex compilation error");
    static ref PERC_NUM_B_RE: Regex =
        Regex::new(r"%([1-9]+[0-9]*)b").expect("regex compilation error");
    static ref GRPRE: Regex = Regex::new(r"%<([^>]+)>").expect("regex compilation error");
    static ref PER_CAP_B_RE: Regex =
        Regex::new(r"%([1-9]+[0-9]*)B").expect("regex compilation failure");
    static ref PERC_NUM_O_RE: Regex =
        Regex::new(r"%([1-9]+[0-9]*)o").expect("regex compilation error");
    static ref PERC_NUM_CAP_O_RE: Regex =
        Regex::new(r"%([1-9]+[0-9]*)O").expect("regex compilation error");
    static ref PERC_I : Regex = Regex::new(r"%([1-9][0-9]*)i").expect("regex compilation error"); // pattern for matching numbered inputs
}

pub(crate) fn decode_group_captures(
    inputs: &InputsAsPaths,
    rule_ref: &RuleRef,
    d: String,
) -> Result<String, Err> {
    let replacer = |caps: &Captures| {
        let c = caps
            .get(1)
            .ok_or_else(|| Err::StaleGroupRef("unknown".to_string(), rule_ref.clone()))?;
        inputs
            .get_group_paths(c.as_str())
            .cloned()
            .ok_or_else(|| Err::StaleGroupRef(c.as_str().to_string(), rule_ref.clone()))
    };
    let reps: Result<Vec<_>, _> = GRPRE
        .captures(d.as_str())
        .iter()
        .map(|x| replacer(x))
        .collect();
    let reps = reps?;
    let mut i = 0;

    let d = GRPRE
        .replace(d.as_str(), |_: &Captures| {
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
        // at this stage all placeholders are pleaced except %<group>s
        let frep = |inp: &InputsAsPaths, sinp: &InputsAsPaths, d: &str| -> Result<String, Err> {
            let rule_ref = &inp.rule_ref;
            let d = if d.contains("%f") {
                let inputs = inp.get_paths();
                if inputs.is_empty() {
                    return Err(Err::StalePerc('f', rule_ref.clone()));
                }
                d.replace("%f", inputs.join(" ").as_str())
            } else {
                d.to_string()
            };

            let d = if PERC_NUM_F_RE.captures(d.as_str()).is_some() {
                let inputs = inp.get_paths();
                if inputs.is_empty() {
                    return Err(Err::StalePerc('f', rule_ref.clone()));
                }
                replace_decoded_str(d.as_str(), inputs, &PERC_NUM_F_RE, rule_ref, 'f')?
            } else {
                d
            };

            let d = if d.contains("%b") {
                let fnames = inputs.get_file_names();
                if fnames.is_empty() {
                    return Err(Err::StalePerc('b', rule_ref.clone()));
                }
                d.replace("%b", fnames.join(" ").as_str())
            } else {
                d
            };

            let d = if PERC_NUM_B_RE.captures(d.as_str()).is_some() {
                let fnames = inputs.get_file_names();
                if fnames.is_empty() {
                    return Err(Err::StalePercNumberedRef('b', rule_ref.clone()));
                }
                replace_decoded_str(d.as_str(), fnames, &PERC_NUM_B_RE, rule_ref, 'b')?
            } else {
                d
            };

            let d = if d.contains("%B") {
                let stems = inp.get_file_stem();
                if stems.is_empty() {
                    return Err(Err::StalePerc('B', rule_ref.clone()));
                }
                d.replace("%B", inp.get_file_stem().join(" ").as_str())
            } else {
                d
            };

            let d = if PER_CAP_B_RE.captures(d.as_str()).is_some() {
                let stems = inp.get_file_stem();
                if stems.is_empty() {
                    return Err(Err::StalePercNumberedRef('B', rule_ref.clone()));
                }
                replace_decoded_str(d.as_str(), stems, &PER_CAP_B_RE, rule_ref, 'B')?
            } else {
                d
            };

            let d = if d.contains("%e") {
                let ext = inp
                    .get_extension()
                    .ok_or_else(|| Err::StalePerc('e', rule_ref.clone()))?;
                d.replace("%e", ext.as_str())
            } else {
                d
            };
            let d = if d.contains("%d") {
                let parent_name = inp
                    .parent_folder_name()
                    .ok_or_else(|| Err::StalePerc('d', rule_ref.clone()))?;
                d.replace("%d", parent_name.as_str())
            } else {
                d
            };
            let d = if d.contains("%g") {
                let glb = inp
                    .get_glob()
                    .ok_or_else(|| Err::StalePerc('g', rule_ref.clone()))?;
                d.replace("%g", glb.as_str())
            } else {
                d
            };

            let d = if d.contains("%i") {
                let sinputsflat = sinp.get_paths();
                if sinp.is_empty() {
                    return Err(Err::StalePerc('i', sinp.rule_ref.clone()));
                }
                d.replace("%i", sinputsflat.join(" ").as_str())
            } else {
                d
            };
            let d = if PERC_I.captures(d.as_str()).is_some() {
                if sinp.is_empty() {
                    return Err(Err::StalePercNumberedRef('i', sinp.rule_ref.clone()));
                }
                let sinputsflat = sinp.get_paths();
                replace_decoded_str(d.as_str(), sinputsflat, &PERC_I, &sinp.rule_ref, 'i')?
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
    file_names: Vec<String>,
    perc_b_re: &'static Regex,
    rule_ref: &RuleRef,
    c: char,
) -> Result<String, Err> {
    let reps: Result<Vec<&String>, Err> = perc_b_re
        .captures(decoded_str)
        .iter()
        .map(|caps: &Captures| {
            let i = caps[1].parse::<usize>().unwrap();
            file_names
                .get(i)
                .ok_or_else(|| Err::StalePercNumberedRef(c, rule_ref.clone()))
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
            debug!("replacing %o's from rule :{}", d);
            let d = if d.contains("%o") {
                let space_separated_outputs = outputs.get_paths().join(" ");
                if outputs.is_empty() {
                    return Err(Err::StalePerc('o', outputs.rule_ref.clone()));
                }
                d.replace("%o", space_separated_outputs.as_str())
            } else {
                d.to_string()
            };
            let d = if d.contains("%O") {
                if outputs.is_empty() {
                    return Err(Err::StalePerc('O', outputs.rule_ref.clone()));
                }
                let stem = outputs
                    .get_file_stem()
                    .ok_or_else(|| Err::StalePerc('O', outputs.rule_ref.clone()))?;
                d.replace("%O", stem.as_str())
            } else {
                d
            };

            let d = if PERC_NUM_O_RE.captures(d.as_str()).is_some() {
                replace_decoded_str(
                    d.as_str(),
                    outputs.get_paths(),
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
                    outputs.get_paths(),
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

fn normalized_path(tup_cwd: &Path, x: &PathExpr) -> PathBuf {
    let pbuf = PathBuf::new().join(x.cat_ref().replace('\\', "/").as_str());
    NormalPath::absolute_from(pbuf.as_path(), tup_cwd).to_path_buf()
}

fn paths_from_exprs(tup_cwd: &Path, p: &[PathExpr], bo: &mut BufferObjects) -> Vec<OutputType> {
    p.split(|x| matches!(x, &PathExpr::Sp1))
        .filter(|x| !x.is_empty())
        .map(|x| {
            let path = PathBuf::new().join(x.to_vec().cat());
            let (pid, _) = bo.add_path_from(path.as_path(), tup_cwd);
            let pathbuf = bo.get_path(&pid);
            OutputType::new(pathbuf.as_path().into())
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
            exclude_pattern: self.exclude_pattern.clone(),
            bin: self.bin.clone(),
            group: self.group.clone(),
        })
    }
}
impl DecodeOutputPlaceHolders for Target {
    fn decode_output_place_holders(&self, outputs: &OutputsAsPaths) -> Result<Self, Err> {
        let newprimary = self.primary.clone();
        let newsecondary = self.secondary.decode_output_place_holders(outputs)?;
        Ok(Target {
            primary: newprimary,
            secondary: newsecondary,
            exclude_pattern: self.exclude_pattern.clone(),
            bin: self.bin.clone(),
            group: self.group.clone(),
        })
    }
}

// reconstruct a rule formula that has placeholders filled up
impl DecodeInputPlaceHolders for RuleFormula {
    fn decode_input_place_holders(
        &self,
        inputs: &InputsAsPaths,
        secondary_inputs: &InputsAsPaths,
    ) -> Result<Self, Err> {
        Ok(RuleFormula {
            description: self
                .description
                .decode_input_place_holders(inputs, secondary_inputs)?,
            formula: self
                .formula
                .decode_input_place_holders(inputs, secondary_inputs)?,
        })
    }
}

trait DecodeGroups {}

// reconstruct rule by replacing output placeholders such as %o
impl DecodeOutputPlaceHolders for RuleFormula {
    fn decode_output_place_holders(&self, outputs: &OutputsAsPaths) -> Result<Self, Err> {
        Ok(RuleFormula {
            description: self.description.decode_output_place_holders(outputs)?,
            formula: self.formula.decode_output_place_holders(outputs)?,
        })
    }
}

fn get_deglobbed_rule(
    resolver: &RuleInterimDat,
    primary_deglobbed_inps: &[InputResolvedType],
    bo: &mut BufferObjects,
    env: &EnvDescriptor,
) -> Result<ResolvedLink, Err> {
    let r = resolver.rule_formula;
    let rule_ref = resolver.rule_ref;
    let t = resolver.target;
    let tup_cwd = resolver.tup_cwd;
    let secondary_deglobbed_inps = resolver.secondary_inp;
    debug!(
        "deglobbing tup at dir:{:?}, rule:{:?}",
        tup_cwd,
        r.cat()
    );

    let input_as_paths = InputsAsPaths::new(tup_cwd, primary_deglobbed_inps, bo, rule_ref.clone());
    let secondary_inputs_as_paths =
        InputsAsPaths::new(tup_cwd, secondary_deglobbed_inps, bo, rule_ref.clone());
    let mut decoded_target =
        t.decode_input_place_holders(&input_as_paths, &secondary_inputs_as_paths)?;
    let pp = paths_from_exprs(tup_cwd, &decoded_target.primary, bo);
    let output_as_paths = OutputsAsPaths {
        outputs: pp
            .iter()
            .map(|x| diff_paths(x.as_path(), tup_cwd).expect("path diff failure"))
            .collect(),
        rule_ref: rule_ref.clone(),
    };
    decoded_target.secondary = decoded_target
        .secondary
        .decode_output_place_holders(&output_as_paths)?;
    let sec_pp = paths_from_exprs(tup_cwd, &decoded_target.secondary, bo);
    let resolved_rule: RuleFormula = r
        .decode_input_place_holders(&input_as_paths, &secondary_inputs_as_paths)?
        .decode_output_place_holders(&output_as_paths)?;

    let bin_desc = t.bin.as_ref().map(|x| bo.add_bin_pathexpr(x, tup_cwd).0);
    let group_desc = t
        .group
        .as_ref()
        .map(|x| bo.add_group_pathexpr(x, tup_cwd).0);

    let rule_formula_desc = bo
        .add_rule(RuleFormulaUsage::new(resolved_rule, rule_ref.clone()))
        .0;
    let l = ResolvedLink {
        primary_sources: primary_deglobbed_inps.to_vec(),
        secondary_sources: secondary_deglobbed_inps.to_vec(),
        rule_formula_desc,
        primary_targets: pp
            .into_iter()
            .map(|x| bo.add_path_from(x.as_path(), tup_cwd).0)
            .collect(),
        secondary_targets: sec_pp
            .into_iter()
            .map(|x| bo.add_path_from(x.as_path(), tup_cwd).0)
            .collect(),
        bin: bin_desc,
        group: group_desc,
        rule_ref: rule_ref.clone(),
        env: env.clone(),
    };
    Ok(l)
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
            group: None,
            bin: None,
            rule_ref: Default::default(),
            env: Default::default(),
        }
    }

    /// iterator over all the sources (primary and secondary) in this link
    pub fn get_sources(&self) -> Chain<Iter<'_, InputResolvedType>, Iter<'_, InputResolvedType>> {
        self.primary_sources
            .iter()
            .chain(self.secondary_sources.iter())
    }
    ///  iterator over all the targets  (primary and secondary) in this link
    pub fn get_targets(&self) -> Chain<Iter<'_, PathDescriptor>, Iter<'_, PathDescriptor>> {
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
}

// update the groups/bins with the path to primary target and also add secondary targets
impl GatherOutputs for ResolvedLink {
    fn gather_outputs(&self, oti: &mut OutputAssocs) -> Result<(), Err> {
        let rule_ref = &self.rule_ref;
        for path_desc in self
            .primary_targets
            .iter()
            .chain(self.secondary_targets.iter())
        {
            let e = oti.parent_rule.entry(*path_desc);
            match e {
                Entry::Occupied(p) => {
                    return Err(Err::MultipleRulesToSameOutput(
                        *path_desc,
                        rule_ref.clone(),
                        p.get().clone(),
                    ));
                }
                Entry::Vacant(p) => p.insert(rule_ref.clone()),
            };
            oti.output_files.insert(*path_desc);
        }
        for path_desc in self.primary_targets.iter() {
            if let Some(ref group_desc) = self.group {
                oti.groups
                    .entry(*group_desc)
                    .or_insert_with(HashSet::new)
                    .insert(*path_desc);
            };
            if let Some(ref bin_desc) = self.bin {
                oti.bins
                    .entry(*bin_desc)
                    .or_insert_with(HashSet::new)
                    .insert(*path_desc);
            };
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
        taginfo: &OutputAssocs,
        bo: &mut BufferObjects,
        tup_desc: &TupPathDescriptor,
    ) -> Result<Artifacts, Err>;
}

pub(crate) trait ExpandRun {
    fn expand_run(&self, m: &mut SubstState, bo: &mut BufferObjects) -> Vec<Self>
    where
        Self: Sized;
}
impl ResolvePaths for Vec<ResolvedLink> {
    fn resolve_paths(
        &self,
        _tupfile: &Path,
        taginfo: &OutputAssocs,
        bo: &mut BufferObjects,
        _tup_desc: &TupPathDescriptor,
    ) -> Result<Artifacts, Err> {
        let mut resolved_artifacts = Artifacts::new();
        resolved_artifacts.acquire_groups(taginfo);
        let mut last_tup_desc = TupPathDescriptor(usize::MAX);
        let last_pbuf = PathBuf::new();
        for statement in self.iter() {

            let cur_tup_desc = statement.get_rule_ref().get_tupfile_desc();
            let tup_cwd = if last_tup_desc.eq(cur_tup_desc) {
                last_pbuf.clone()
            }else {
                bo.get_tup_path(cur_tup_desc).to_path_buf()
            };

            let art = statement.resolve_paths(
                tup_cwd.as_path(),
                resolved_artifacts.get_outs(),
                bo,
                statement.get_rule_ref().get_tupfile_desc(),
            )?;
            /*for f in art.output_files.iter() {
                out.parent_rule.remove(f); // to avoid conflicts with the same undecoded rule as we  merge
            }*/
            resolved_artifacts.merge(art)?;
            last_tup_desc = *cur_tup_desc;
        }
        Ok(resolved_artifacts)
    }
}

/// implementation for ResolvedLink performs unresolved paths in Group inputs using data in taginfo
impl ResolvePaths for ResolvedLink {
    /// the method below replaces
    fn resolve_paths(
        &self,
        tup_cwd: &Path,
        taginfo: &OutputAssocs,
        bo: &mut BufferObjects,
        _tup_desc: &TupPathDescriptor,
    ) -> Result<Artifacts, Err> {
        let mut rlink: ResolvedLink = self.clone();
        rlink.primary_sources.clear();
        rlink.secondary_sources.clear();
        for i in self.primary_sources.iter() {
            match i {
                InputResolvedType::UnResolvedGroupEntry(g) => {
                    if let Some(hs) = taginfo.groups.get(g) {
                        for pd in hs {
                            rlink
                                .primary_sources
                                .push(InputResolvedType::GroupEntry(*g, *pd));
                        }
                    } else {
                        return Err(Error::StaleGroupRef(
                            bo.get_input_path_str(i),
                            rlink.get_rule_ref().clone(),
                        ));
                    }
                }
                _ => rlink.primary_sources.push(i.clone()),
            }
        }

        for i in self.secondary_sources.iter() {
            match i {
                InputResolvedType::UnResolvedGroupEntry(ref g) => {
                    if let Some(hs) = taginfo.groups.get(g) {
                        for pd in hs {
                            rlink
                                .secondary_sources
                                .push(InputResolvedType::GroupEntry(*g, *pd))
                        }
                    } else {
                        return Err(crate::errors::Error::StaleGroupRef(
                            bo.get_input_path_str(i),
                            rlink.get_rule_ref().clone(),
                        ));
                    }
                }
                _ => rlink.secondary_sources.push(i.clone()),
            }
        }
        let rule_ref = self.get_rule_ref();
        let rule_str = (bo.get_rule(self.get_rule_desc())).get_formula().cat();
        if GRPRE.is_match(rule_str.as_str()) {
            let mut primary_inps = InputsAsPaths::new(
                tup_cwd,
                &rlink.primary_sources[..],
                bo.deref(),
                rule_ref.clone(),
            );
            let secondary_inps = InputsAsPaths::new(
                tup_cwd,
                &rlink.secondary_sources[..],
                bo.deref(),
                rule_ref.clone(),
            );
            primary_inps
                .groups_by_name
                .extend(secondary_inps.groups_by_name);
            let rs = decode_group_captures(&primary_inps, rule_ref, rule_str)?;
            let r = RuleFormula::new_from_raw(rs.as_str());
            let (rule_desc, _) = bo.add_rule(RuleFormulaUsage::new(r, rule_ref.clone()));
            rlink.rule_formula_desc = rule_desc;
        }
        let mut out = OutputAssocs::new();
        self.gather_outputs(&mut out)?;
        Ok(Artifacts::from(vec![rlink], out))
    }
}

struct RuleInterimDat<'a, 'b, 'c, 'd> {
    tup_cwd: &'d Path,
    rule_formula: &'a RuleFormula,
    rule_ref: &'b RuleRef,
    target: &'a Target,
    secondary_inp: &'c [InputResolvedType],
}
/// deglob rule statement into multiple deglobbed rules, gather deglobbed targets to put in bins/groups
impl ResolvePaths for LocatedStatement {
    fn resolve_paths(
        &self,
        tupfile: &Path,
        taginfo: &OutputAssocs,
        bo: &mut BufferObjects,
        tup_desc: &TupPathDescriptor,
    ) -> Result<Artifacts, Err> {
        let mut deglobbed = Vec::new();
        // use same resolve_groups as input
        let mut output: OutputAssocs = OutputAssocs {
            resolve_groups: taginfo.resolve_groups,
            ..Default::default()
        };
        let tup_cwd = if tupfile.is_dir() {
            tupfile
        } else {
            tupfile.parent().unwrap()
        };
        let tup_cwd = &*tup_cwd;
        debug!("resolving rule:{:?} at dir:{:?}", self, tup_cwd);
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
            let inpdec = s.primary.decode(tup_cwd, taginfo, bo, rule_ref)?;
            let secondinpdec = s.secondary.decode(tup_cwd, taginfo, bo, rule_ref)?;
            let resolver = RuleInterimDat {
                tup_cwd,
                rule_formula,
                rule_ref,
                target: t,
                secondary_inp: secondinpdec.as_slice(),
            };
            let for_each = s.for_each;
            if for_each {
                for input in inpdec {
                    let delink =
                        get_deglobbed_rule(&resolver, core::slice::from_ref(&input), bo, env)?;
                    delink.gather_outputs(&mut output)?;
                    deglobbed.push(delink);
                }
            } else if !inpdec.is_empty() || !secondinpdec.is_empty() {
                let delink = get_deglobbed_rule(&resolver, inpdec.as_slice(), bo, env)?;
                delink.gather_outputs(&mut output)?;
                deglobbed.push(delink);
            }
        }
        Ok(Artifacts::from(deglobbed, output))
    }
}

impl ResolvePaths for Vec<LocatedStatement> {
    fn resolve_paths(
        &self,
        tupfile: &Path,
        taginfo: &OutputAssocs,
        bo: &mut BufferObjects,
        tup_desc: &TupPathDescriptor,
    ) -> Result<Artifacts, Err> {
        let mut alltaginfos = taginfo.clone();
        alltaginfos.resolve_groups = taginfo.resolve_groups;
        let mut merged_arts = Artifacts::from(Vec::new(), alltaginfos);
        for stmt in self.iter() {
            let art = stmt.resolve_paths(tupfile, merged_arts.get_outs(), bo, tup_desc)?;
            merged_arts.merge(art)?;
        }
        Ok(merged_arts)
    }
}

/// `parse_dir' scans and parses all Tupfiles from a directory root, When sucessful it returns de-globbed, decoded links(rules)
pub fn parse_dir(root: &Path) -> Result<Artifacts, crate::errors::Error> {
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
    let root_tupfile_ini =
        locate_file(root, "Tupfile.ini", "").ok_or(crate::errors::Error::RootNotFound)?;
    let conf_vars = load_conf_vars(root_tupfile_ini.as_path())?;
    let mut artifacts_all = Artifacts::new();
    let mut parser = transform::TupParser::new_from(root, conf_vars);
    for tup_file_path in tupfiles.iter() {
        let artifacts = parser.parse(tup_file_path)?;
        artifacts_all.merge(artifacts)?;
    }

    let _ = dag_check_artifacts(&mut parser, &mut artifacts_all)?;
    parser.reresolve(artifacts_all)
}

fn dag_check_artifacts(
    parser: &mut TupParser,
    artifacts_all: &mut Artifacts,
) -> Result<Vec<NodeIndex>, crate::errors::Error> {
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
                        crate::errors::Error::DependencyCycle(
                            {
                                let stmt = statement_from_id(*pnodeid);
                                let tup_desc = stmt.get_rule_ref().get_tupfile_desc();
                                let bo = parser.borrow_ref();
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
                                let bo = parser.borrow_ref();
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
            let boref = parser.borrow_ref();
            let p = boref.try_get_group_path(group).unwrap();
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
        crate::errors::Error::DependencyCycle("".to_string(), {
            let stmt = statement_from_id(e.node_id());
            let tup_file_desc = stmt.get_rule_ref().get_tupfile_desc();
            let bo_ref = parser.borrow_ref();
            let tupfile = bo_ref.get_tup_path(tup_file_desc);
            format!(
                "tupfile:{}, and rule at line:{}",
                tupfile.to_string_lossy(),
                stmt.rule_ref.get_line()
            )
        })
    })?;
    Ok(nodes)
}
