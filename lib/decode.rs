//! This module handles decoding and de-globbing of rules

use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::{BTreeSet, LinkedList};
use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::fmt::{Display, Formatter};
use std::format;
use std::fs::File;
use std::hash::Hash;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use log::debug;
use parking_lot::MappedRwLockReadGuard;
use regex::{Captures, Regex};
use walkdir::{DirEntry, WalkDir};

use crate::buffers::{
    BinDescriptor, EnvList, GlobPathDescriptor, GroupPathDescriptor, MyGlob, OutputHolder,
    OutputType, PathBuffers, PathDescriptor, RelativeDirEntry, RuleDescriptor, TaskDescriptor,
    TupPathDescriptor,
};
use crate::decode::Index::All;
use crate::errors::Error::PathSearchError;
use crate::errors::{Error as Err, Error};
use crate::parser::reparse_literal_as_input;
use crate::paths::SelOptions::Either;
use crate::paths::{
    ExcludeInputPaths, FormatReplacements, GlobPath, InputResolvedType, InputsAsPaths,
    MatchingPath, NormalPath, OutputsAsPaths, SelOptions,
};
use crate::statements::*;
use crate::transform::{to_regex, ResolvedRules, TupParser};
use crate::ReadWriteBufferObjects;
use std::sync::OnceLock;

static PERC_INP_REGEX: OnceLock<Regex> = OnceLock::new();
static PERC_BIN_REGEX: OnceLock<Regex> = OnceLock::new();
static PERC_GRP_REGEX: OnceLock<Regex> = OnceLock::new();

fn perc_io_regex() -> &'static Regex {
    PERC_INP_REGEX
        .get_or_init(|| Regex::new(r"%(\d+)?[fbBoOgieh%]").expect("Failed to create regex"))
}
fn perc_bin_regex() -> &'static Regex {
    PERC_BIN_REGEX.get_or_init(|| Regex::new(r"%\{([^}]+)\}").expect("Failed to create regex"))
}

fn perc_group_regex() -> &'static Regex {
    PERC_GRP_REGEX.get_or_init(|| Regex::new(r"%<([^>]+)>").expect("Failed to create regex"))
}

/// Lite version of PathSearcher that specifies method to discover paths from glob strings
pub trait PathDiscovery {
    /// Discover paths from glob string with a callback to process outputs
    fn discover_paths_with_cb(
        &self,
        path_buffers: &impl PathBuffers,
        glob_path: &[GlobPath],
        cb: impl FnMut(MatchingPath),
        sel: SelOptions,
    ) -> Result<usize, Error>;
    /// Discover paths from glob string and return them as a vector
    fn discover_paths(
        &self,
        path_buffers: &impl PathBuffers,
        glob_path: &[GlobPath],
        sel: SelOptions,
    ) -> Result<Vec<MatchingPath>, Error> {
        let mut pes = Vec::new();
        self.discover_paths_with_cb(path_buffers, glob_path, |mp| pes.push(mp), sel)?;
        Ok(pes)
    }
}
/// Trait to discover paths from a source (such as a database or directory tree)
/// Outputs from rules can be added to list of paths searched using `merge` method
pub trait PathSearcher: PathDiscovery {
    /// Discover Tuprules.lua or Tuprules.tup in all parent directories of tup_cwd
    fn locate_tuprules(
        &self,
        tup_cwd: &PathDescriptor,
        path_buffers: &impl PathBuffers,
    ) -> Vec<PathDescriptor>;

    /// Find Outputs
    fn get_outs(&self) -> &OutputHolder;

    /// Root of the tup hierarchy, where tupfiles are found
    fn get_root(&self) -> &Path;

    /// Merge outputs from previous outputs
    fn merge(&mut self, p: &impl PathBuffers, o: &impl OutputHandler) -> Result<(), Error>;
}

/// `TupLoc` keeps track of the current file being processed and rule location.
/// This is mostly useful for error handling to let the user know we ran into problem with a rule at
/// a particular line
#[derive(Debug, Default, PartialEq, Eq, Clone, Hash, PartialOrd, Ord)]
pub struct TupLoc {
    tup_path_desc: TupPathDescriptor,
    loc: Loc,
}

/// `RuleFormulaInstance` stores both rule formula and its whereabouts(`TupLoc`) in a Tupfile
/// Caller locations are stored in the linked list
#[derive(Debug, Default, PartialEq, Eq, Clone, Hash, Ord, PartialOrd)]
pub struct RuleFormulaInstance {
    rule_formula: RuleFormula,
    rule_ref: LinkedList<TupLoc>,
}

/// `TaskUsage` stores task name, its dependents, recipe  and its location in Tupfile
#[derive(Debug, Default, Clone)]
pub struct TaskInstance {
    name: String,
    deps: Vec<PathExpr>,
    recipe: Vec<Vec<PathExpr>>,
    tup_loc: TupLoc,
    #[allow(dead_code)]
    search_dirs: Vec<PathDescriptor>,
    env: EnvList,
}

impl Hash for TaskInstance {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.name.hash(state);
    }
}

impl Display for TaskInstance {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}
impl PartialOrd for TaskInstance {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.name.partial_cmp(&other.name)
    }
}

impl Ord for TaskInstance {
    fn cmp(&self, other: &Self) -> Ordering {
        self.name.cmp(&other.name)
    }
}

impl PartialEq for TaskInstance {
    fn eq(&self, other: &Self) -> bool {
        self.name.eq(&other.name)
    }
}

impl Eq for TaskInstance {}

impl RuleFormulaInstance {
    /// Command string to execute in a rule
    pub fn get_rule_str(&self) -> String {
        self.rule_formula.formula.cat()
    }
    /// Get parent path descriptor
    pub fn get_parent_id(&self) -> PathDescriptor {
        self.get_rule_ref()
            .get_tupfile_desc()
            .get_parent_descriptor()
    }

    /// Display string that appears in the console as the rule is run
    pub fn get_display_str(&self) -> String {
        let description = self.rule_formula.get_description_str();
        description.trim_start().to_string()
    }
    #[allow(dead_code)]
    pub(crate) fn get_rule_description(&self) -> Option<&Vec<PathExpr>> {
        self.rule_formula
            .get_description()
            .map(|x| x.get_display_str())
    }
    /// additional flags "bcjot" that alter the way rule is run
    pub fn get_flags(&self) -> &str {
        self.get_formula().get_flags()
    }

    /// Path for a rule constructed by prefixing parent path to the rule name
    pub fn get_path(&self) -> NormalPath {
        self.get_rule_ref()
            .get_tupfile_desc()
            .get_path_ref()
            .join(self.get_rule_str().as_str())
    }
}

impl TaskInstance {
    ///Create a new TaskInstance
    pub(crate) fn new(
        tup_cwd: &PathDescriptor,
        name: &str,
        deps: Vec<PathExpr>,
        recipe: Vec<Vec<PathExpr>>,
        tup_loc: TupLoc,
        search_dirs: Vec<PathDescriptor>,
        env: EnvList,
    ) -> TaskInstance {
        let name = format!("{}/{}", tup_cwd.to_string(), name);
        TaskInstance {
            name,
            deps,
            recipe,
            tup_loc,
            search_dirs,
            env,
        }
    }
    /// Returns the name of the task in the format dir/&task:name
    pub fn get_target(&self) -> &str {
        self.name.as_str()
    }

    /// dependents of the task
    #[allow(dead_code)]
    pub(crate) fn get_deps(&self) -> &Vec<PathExpr> {
        &self.deps
    }

    /// Returns the recipe of the task
    pub fn get_recipe(&self) -> Vec<String> {
        self.recipe.iter().map(|x| x.cat()).collect()
    }

    /// Returns the location of the task in the Tupfile
    pub fn get_tup_loc(&self) -> &TupLoc {
        &self.tup_loc
    }
    /// env required for the task
    pub(crate) fn get_env_list(&self) -> &EnvList {
        &self.env
    }
    /// full path to task at the parent directory in which the task defined.
    pub fn get_path(&self) -> NormalPath {
        self.get_parent().join(self.get_target())
    }

    /// id of the parent directory
    pub fn get_parent_id(&self) -> PathDescriptor {
        self.tup_loc.get_tupfile_desc().get_parent_descriptor()
    }

    /// folder containing the task
    pub fn get_parent(&self) -> &NormalPath {
        self.get_tup_loc().get_tupfile_desc().get_path_ref()
    }
}

impl Display for TupLoc {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.tup_path_desc, self.loc)
    }
}

///`Ruleref` constructor and accessors
impl TupLoc {
    /// Construct a RuleRef
    pub fn new(tup_desc: &TupPathDescriptor, loc: &Loc) -> TupLoc {
        TupLoc {
            tup_path_desc: tup_desc.clone(),
            loc: *loc,
        }
    }

    /// Line of Tupfile where portion of rule is found
    pub fn get_line(&self) -> u32 {
        self.loc.get_line()
    }
    /// Get the column of Tupfile where portion of rule is found
    pub fn get_col(&self) -> u32 {
        self.loc.get_col()
    }
    /// Get the span of the region in Tupfile where rule is found
    pub fn get_span(&self) -> u32 {
        self.loc.get_span()
    }

    pub(crate) fn set_loc(&mut self, loc: Loc) {
        self.loc = loc;
    }

    pub(crate) fn get_loc(&self) -> &Loc {
        &self.loc
    }

    /// Directory
    pub fn get_tupfile_desc(&self) -> &TupPathDescriptor {
        &self.tup_path_desc
    }
}

impl RuleFormulaInstance {
    pub(crate) fn new(rule_formula: RuleFormula, rule_ref: TupLoc) -> RuleFormulaInstance {
        RuleFormulaInstance {
            rule_formula,
            rule_ref: std::collections::LinkedList::from([rule_ref]),
        }
    }
    #[allow(dead_code)]
    pub(crate) fn chain(&mut self, caller_loc: TupLoc) {
        self.rule_ref.push_back(caller_loc);
    }
    #[allow(dead_code)]
    /// `RuleFormula` that this object refers to
    pub(crate) fn get_formula(&self) -> &RuleFormula {
        &self.rule_formula
    }
    /// returns `RuleRef' which is the location of the referred rule in a Tupfile
    pub fn get_rule_ref(&self) -> &TupLoc {
        &self.rule_ref.front().unwrap()
    }
}

impl Display for RuleFormulaInstance {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "?{:?}? {:?}", self.rule_ref, self.rule_formula)
    }
}

/// Interface to add and read outputs of rules parsed in tupfiles.
pub trait OutputHandler {
    /// Get all the output files from rules accumulated so far
    fn get_output_files(&self) -> MappedRwLockReadGuard<'_, BTreeSet<PathDescriptor>>;
    /// Get all the groups with collected rule outputs
    fn get_groups(
        &self,
    ) -> MappedRwLockReadGuard<'_, HashMap<GroupPathDescriptor, BTreeSet<PathDescriptor>>>;
    /// Get paths stored against a bin
    fn get_bins(
        &self,
    ) -> MappedRwLockReadGuard<'_, HashMap<BinDescriptor, BTreeSet<PathDescriptor>>>;
    /// Get parent dir -> children map
    fn get_children(
        &self,
    ) -> MappedRwLockReadGuard<'_, HashMap<PathDescriptor, Vec<PathDescriptor>>>;
    /// the parent rule that generates an output file
    fn get_parent_rule(&self, o: &PathDescriptor) -> Option<TupLoc>;
    /// parent rule of each output path
    fn with_parent_rules<R, F>(&self, f: F) -> R
    where
        F: FnMut(&HashMap<PathDescriptor, TupLoc>) -> R;
    /// Add an entry to the set that holds output paths
    fn add_output(&mut self, pd: &PathDescriptor) -> bool;

    /// Add parent rule to a give output path id. Returns false if unsuccessful
    fn add_parent_rule(&mut self, pd: &PathDescriptor, rule_ref: TupLoc) -> TupLoc;

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

/// Searcher of paths in directory tree and those stored in [OutputHolder]
#[derive(Debug, Default, Clone)]
pub struct DirSearcher {
    root: PathBuf,
    output_holder: OutputHolder,
}

impl DirSearcher {
    ///  Constructs a blank `DirSearcher`
    pub fn new() -> DirSearcher {
        DirSearcher {
            root: PathBuf::from("."),
            output_holder: OutputHolder::new(),
        }
    }
    /// Constructs a `DirSearcher` with a given root
    pub fn new_at<P: AsRef<Path>>(p: P) -> Self {
        DirSearcher {
            root: p.as_ref().to_path_buf(),
            output_holder: OutputHolder::new(),
        }
    }

    /// Walk directory tree from the non pattern prefix to capture all
    /// file paths that match the first glob pattern in the input array
    pub(crate) fn discover_input_files(
        path_buffers: &impl PathBuffers,
        glob_path: &[GlobPath],
        options: SelOptions,
        mut handle_match: impl FnMut(MatchingPath) -> (),
    ) -> Result<usize, Error> {
        let mut count = 0;
        for glob_path in glob_path {
            let to_match = glob_path.get_abs_path();
            debug!(
                "looking at non pattern base path:{:?} for pattern:{:?}",
                glob_path.get_non_pattern_abs_path(),
                to_match
            );

            let root = path_buffers.get_root_dir();
            if !glob_path.has_glob_pattern() {
                if let Ok(1) = Self::discover_non_glob_match(&mut handle_match, glob_path, to_match, root) {
                    return Ok(1);
                }
            } else {
                count = Self::discover_glob_match(path_buffers, &options, &mut handle_match, glob_path, to_match)?;
                if count > 0 {
                    break;
                }
            }
        }
        Ok(count)
    }

    fn discover_glob_match(path_buffers: &impl PathBuffers, options: &SelOptions,
                           handle_match: &mut impl FnMut(MatchingPath), glob_path: &GlobPath, to_match: &NormalPath)
                           -> Result<usize, Error>{
        let mut unique_path_descs = HashSet::new();
        let mut count = 0;
        let root = path_buffers.get_root_dir();
        let non_pattern_prefixh = glob_path.get_non_pattern_abs_path();
        let prefix_path_from_root = path_buffers
            .get_root_dir()
            .join(non_pattern_prefixh.as_path());
        if !prefix_path_from_root.is_dir() {
            debug!("base path {:?} is not a directory", non_pattern_prefixh);
        }
        let globs = MyGlob::new_raw(to_match.as_path())?;
        debug!("glob regex used for finding matches {}", globs.re());
        debug!(
                    "non pattern prefix path for files matching glob: {:?}",
                    non_pattern_prefixh
                );
        let mut walkdir = WalkDir::new(prefix_path_from_root);
        if glob_path.is_recursive_prefix() {
            walkdir = walkdir.max_depth(usize::MAX);
        } else {
            walkdir = walkdir.max_depth(1);
        }
        let len = root.components().count();
        let relative_path_on_matching_file_type = |e: DirEntry| {
            options
                .allows(e.file_type())
                .then(|| e.path().components().skip(len).collect::<PathBuf>())
        };
        let filtered_paths = walkdir
            .min_depth(1)
            .into_iter()
            .filter_map(move |e| e.ok().and_then(relative_path_on_matching_file_type))
            .filter(|entry| globs.is_match(entry.as_path()));
        for path in filtered_paths {
            let path_desc = path_buffers.add_abs(path.as_path())?;
            let captured_globs = globs.group(path.as_path());
            debug!("found path {:?} with captures {:?}", path, captured_globs);
            if unique_path_descs.insert(path_desc.clone()) {
                let matching_path = MatchingPath::with_captures(
                    path_desc,
                    glob_path.get_glob_desc(),
                    captured_globs,
                    glob_path.get_non_pattern_prefix_desc().clone(),
                );
                debug!("matching path {:?}", matching_path);
                handle_match(matching_path);
                count += 1;
            }
        }
        Ok(count)
    }

    fn discover_non_glob_match(handle_match: &mut impl FnMut(MatchingPath), glob_path: &GlobPath, to_match: &NormalPath, root: &Path) ->Result<usize, Error> {
        let path_desc = glob_path.get_glob_path_desc();
        let mp_from_root = root.join(to_match.as_path());
        debug!(
                    "looking for fixed pattern path {:?} at {:?}",
                    to_match, mp_from_root
                );
        if mp_from_root.is_file() || mp_from_root.is_dir() {
            let matching_path = MatchingPath::new(
                path_desc,
                glob_path.get_non_pattern_prefix_desc().clone(),
            );
            debug!("mp:{:?}", matching_path);
            handle_match(matching_path);
            Ok(1)
        } else {
            log::warn!("Could not find path {:?}", mp_from_root);
            Ok(0)
        }
    }
}

impl PathDiscovery for DirSearcher {
    /// scan folder tree for paths
    /// This function runs the glob matcher to discover rule inputs by walking from given directory. The paths are returned as descriptors stored in [MatchingPatch]
    /// @tup_cwd is expected to be current tupfile directory under which a rule is found. @glob_path
    /// Also calls the next in chain of searchers
    fn discover_paths_with_cb(
        &self,
        path_buffers: &impl PathBuffers,
        glob_path: &[GlobPath],
        mut cb: impl FnMut(MatchingPath),
        sel: SelOptions,
    ) -> Result<usize, Error>
    {
        let mut matching_outs = self.output_holder.discover_paths(path_buffers, glob_path)?;
        let mut count = 0;
        if !matching_outs.is_empty() {
            for o in matching_outs.drain(..)  { cb(o); count += 1; }
             Ok(count)
        } else {
            Self::discover_input_files(path_buffers, glob_path, sel, cb)
        }
    }
}
impl PathSearcher for DirSearcher {
    fn locate_tuprules(
        &self,
        tup_cwd: &PathDescriptor,
        _path_buffers: &impl PathBuffers,
    ) -> Vec<PathDescriptor> {
        crate::parser::locate_tuprules_from(tup_cwd.clone())
    }

    fn get_outs(&self) -> &OutputHolder {
        &self.output_holder
    }

    fn get_root(&self) -> &Path {
        self.root.as_path()
    }

    fn merge(&mut self, p: &impl PathBuffers, o: &impl OutputHandler) -> Result<(), Error> {
        OutputHandler::merge(&mut self.output_holder, p, o)
    }
}

/// Decode input paths from file globs, bins(buckets), and groups
pub(crate) trait DecodeInputPaths {
    fn decode(
        &self,
        tup_cwd: &PathDescriptor,
        path_searcher: &impl PathSearcher,
        path_buffers: &impl PathBuffers,
        rule_ref: &TupLoc,
        search_dirs: &Vec<PathDescriptor>,
    ) -> Result<Vec<InputResolvedType>, Err>;
}

// Decode input paths in RvalGeneral
impl DecodeInputPaths for PathExpr {
    // convert globs into regular paths, remember that matched groups
    fn decode(
        &self,
        tup_cwd: &PathDescriptor,
        path_searcher: &impl PathSearcher,
        path_buffers: &impl PathBuffers,
        rule_ref: &TupLoc,
        search_dirs: &Vec<PathDescriptor>,
    ) -> Result<Vec<InputResolvedType>, Err> {
        let mut vs = Vec::new();
        debug!("Decoding input paths of {:?}", &self);

        match self {
            PathExpr::Literal(_) => {
                let s = self.cat_ref();
                debug!("resolving literal: {:?}", s);
                let p = path_buffers.add_path_from(tup_cwd, s.as_ref())?;
                let glob_path = GlobPath::build_from(tup_cwd, &p)?;
                let glob_path_desc = glob_path.get_glob_path_desc();
                let mut glob_paths = vec![glob_path];
                let rel_path_desc = RelativeDirEntry::new(tup_cwd.clone(), glob_path_desc.clone());
                for search_dir in search_dirs {
                    let mut glob_desc = search_dir.clone();
                    glob_desc += &rel_path_desc;
                    let glob_path = GlobPath::build_from(tup_cwd, &glob_desc)?;
                    //debug!("glob str: {:?}", glob_path.get_abs_path());
                    glob_paths.push(glob_path);
                }

                let pes =
                    path_searcher.discover_paths(path_buffers, glob_paths.as_slice(), Either)?;
                if pes.is_empty() {
                    log::warn!("Could not find any paths matching {:?}", glob_path_desc);
                    vs.push(InputResolvedType::UnResolvedFile(glob_path_desc));
                } else {
                    vs.extend(pes.into_iter().map(InputResolvedType::Deglob));
                }
            }
            PathExpr::Group(dir, name) => {
                let to_join = dir.cat();
                let group_dir = path_buffers.add_path_from(tup_cwd, to_join.as_str())?;
                let ref grp_desc = path_buffers.add_group_pathexpr(&group_dir, name.cat().as_str());
                {
                    debug!(
                        "resolving grp: {:?} with desc:{:?}",
                        path_buffers.get_group_path(grp_desc),
                        grp_desc
                    );
                    if let Some(paths) = path_searcher.get_outs().get().get_group(grp_desc) {
                        vs.extend(
                            paths.iter().map(|x| {
                                InputResolvedType::GroupEntry(grp_desc.clone(), x.clone())
                            }),
                        )
                    } else {
                        //let (, _) = bo.add_path(Path::new(&*p.cat()), tup_cwd);
                        vs.push(InputResolvedType::UnResolvedGroupEntry(grp_desc.clone()));
                    }
                }
            }
            PathExpr::Bin(b) => {
                let ref bin_desc = path_buffers.add_bin_path_expr(tup_cwd, b.as_ref());
                debug!("resolving bin: {:?}/{:?}", tup_cwd, b.as_str());
                if let Some(paths) = path_searcher.get_outs().get().get_bin(bin_desc) {
                    for p in paths {
                        vs.push(InputResolvedType::BinEntry(bin_desc.clone(), p.clone()))
                    }
                } else {
                    return Err(Error::StaleBinRef(b.clone(), rule_ref.clone()));
                }
            }
            PathExpr::DeGlob(mp) => {
                vs.push(InputResolvedType::Deglob(mp.clone()));
            }
            PathExpr::TaskRef(name) => {
                if let Some(task_desc) = path_buffers.try_get_task_desc(tup_cwd, name.as_str()) {
                    vs.push(InputResolvedType::TaskRef(task_desc));
                } else {
                    return Err(Error::TaskNotFound(
                        name.as_str().to_string(),
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
        tup_cwd: &PathDescriptor,
        path_searcher: &impl PathSearcher,
        path_buffers: &impl PathBuffers,
        rule_ref: &TupLoc,
        search_dirs: &Vec<PathDescriptor>,
    ) -> Result<Vec<InputResolvedType>, Err> {
        // gather locations where exclude patterns show up
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
            .map(|x| x.decode(tup_cwd, path_searcher, path_buffers, rule_ref, &search_dirs))
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
        path_buffers: &impl PathBuffers,
    ) -> Result<(), Err>;
}

/// Decode input placeholders in a command string or in the output string
pub trait DecodeInputPlaceHolders {
    /// Ouput of decoding input placeholders
    type Output;
    /// Decode input placeholders in a command string or in the output string
    fn decode_input_place_holders(
        &self,
        inputs: &InputsAsPaths,
        secondary_inputs: &InputsAsPaths,
    ) -> Self::Output
    where
        Self: Sized;
}

trait DecodeOutputPlaceHolders {
    type Output;
    fn decode_output_place_holders(&self, outputs: &OutputsAsPaths) -> Self::Output
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

/// replace all occurrences of <{}> in rule strings with the paths that are associated with corresponding group input for that that rule.
pub fn decode_group_captures(
    inputs: &impl GroupInputs,
    _rule_ref: &TupLoc,
    rule_id: i64,
    dirid: i64,
    rule_str: &str,
) -> String {
    let replacer = |caps: &Captures| {
        let c = caps
            .get(1)
            .and_then(|c| inputs.get_group_paths(c.as_str(), rule_id, dirid));
        c
    };
    let reps: Vec<_> = perc_group_regex()
        .captures(rule_str)
        .iter()
        .inspect(|x| {
            debug!(
                "group capture before replace :{}",
                x.get(0).unwrap().as_str()
            )
        })
        .filter_map(replacer)
        .inspect(|x| {
            debug!("group capture after replace :{}", x.as_str());
        })
        .collect();
    let mut i = 0;
    let d = perc_group_regex()
        .replace(rule_str, |_: &Captures| {
            let r = &reps[i];
            i += 1;
            r.as_str()
        })
        .to_string();
    d
}
fn replace_io_patterns<'a, F>(input: &str, replacer: F) -> String
where
    F: Fn(&char, &str) -> String,
{
    // Define the regex pattern to match the required patterns
    let re = perc_io_regex();
    let binre = perc_bin_regex();
    let res = binre.replace_all(input, |caps: &Captures| {
        let tok = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
        replacer(&'}', tok)
    });

    // Replace all matches with the output of the replacer function
    let res = re.replace_all(res.as_ref(), |caps: &Captures| {
        // Extract the matched pattern
        let matched_pattern = caps.get(0).unwrap().as_str();
        let ref end_char = matched_pattern
            .chars()
            .last()
            .expect("Unexpected missing last char in pattern");
        let num: &str = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
        // Call the replacer function with the matched pattern
        replacer(end_char, num)
    });
    if matches!(res, Cow::Owned(_)) {
        debug!("replaced io patterns in {} to {}", input, res);
    }
    res.into_owned()
}

fn to_index(capture: &str, def: Index) -> Index {
    let c: Option<usize> = capture.parse().ok();
    if c.is_none() {
        def
    } else {
        Index::Ith(c.unwrap() - 1)
    }
}
fn replacer_outputs(pattern: &char, outputs: &impl FormatReplacements, capture: &str) -> String {
    let output_raw_paths = outputs.get_paths_str_from_tok(pattern);
    let idx = to_index(capture, All);
    replace_fmt_char(&output_raw_paths, pattern, idx)
}
fn replacer_inputs(
    pattern: &char,
    inputs: &impl FormatReplacements,
    order_only_inputs: &impl FormatReplacements,
    capture: &str,
) -> String {
    match pattern {
        'f' | 'b' | 'B' | 'e' => {
            let input_raw_paths = inputs.get_paths_str_from_tok(pattern);
            let idx = to_index(capture, All);
            replace_fmt_char(&input_raw_paths, pattern, idx)
        }
        'g' => {
            log::debug!("replacing %g");
            let input_raw_paths = inputs.get_paths_str_from_tok(pattern);
            let idx = to_index(capture, Index::Ith(0));
            replace_fmt_char(&input_raw_paths, pattern, idx)
        }
        'h' => {
            log::debug!("replacing %h");
            let input_raw_paths = inputs.get_paths_str_from_tok(pattern);
            let idx = to_index(capture, Index::Last);
            replace_fmt_char(&input_raw_paths, pattern, idx)
        }
        'i' => {
            let input_raw_paths = order_only_inputs.get_paths_str_from_tok(pattern);
            let idx = to_index(capture, Index::All);
            replace_fmt_char(&input_raw_paths, pattern, idx)
        }
        '%' => {
            if capture.is_empty() {
                "%".to_string()
            } else {
                format!("%{}%", capture.to_string())
            }
        }
        '}' => {
            let input_raw_paths = inputs.get_bin_paths(capture);
            replace_fmt_char(&input_raw_paths, pattern, Index::All)
        }
        _ => {
            format!("%{}{}", capture.to_string(), pattern)
        }
    }
}

fn formatted_pe<F: Fn(&str) -> String>(replacer: F, pe: &PathExpr) -> Vec<PathExpr> {
    let pe = if let PathExpr::Literal(s) = pe {
        let mut result = Vec::new();
        for s in replacer(s).split(" \t") {
            result.push(PathExpr::from(s.to_string()));
            result.push(PathExpr::Sp1);
        }
        result.pop();
        result
    } else if let PathExpr::Quoted(s) = pe {
        let mut result: Vec<PathExpr> = Vec::new();
        if s.is_empty() {
            result
        } else {
            let s = s.as_slice();
            for s in replacer(&*s.cat_ref()).split(" \t") {
                result.push(PathExpr::from(s.to_string()));
                result.push(PathExpr::Sp1);
            }
            result.pop();
            result
        }
    } else {
        vec![pe.clone()]
    };
    pe
}

impl DecodeInputPlaceHolders for PathExpr {
    type Output = Vec<PathExpr>;
    fn decode_input_place_holders(
        &self,
        inputs: &InputsAsPaths,
        secondary_inputs: &InputsAsPaths,
    ) -> Self::Output {
        let frep = move |d: &str| -> String {
            replace_io_patterns(d, |pattern, capture| {
                replacer_inputs(pattern, inputs, secondary_inputs, capture)
            })
        };
        formatted_pe(frep, self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
enum Index {
    #[default]
    All,
    Last,
    Ith(usize),
}
/// replace %[i]c specifiers
fn replace_fmt_char(input_raw_paths: &Vec<String>, c: &char, i: Index) -> String {
    match i {
        All => {
            let joined_paths = input_raw_paths.join(" ");
            debug!("replacing %{c} with {joined_paths} ");
            joined_paths
        }
        Index::Last => {
            let str = input_raw_paths
                .last()
                .unwrap_or(&"".to_string())
                .to_string();
            debug!("replacing %{c} with {str} ");
            str
        }
        Index::Ith(i) => {
            let str = input_raw_paths
                .get(i)
                .map(AsRef::as_ref)
                .unwrap_or("")
                .to_string();
            debug!("replacing %{c} with {str} ");
            str
        }
    }
}

impl DecodeOutputPlaceHolders for RuleDescription {
    type Output = Self;
    fn decode_output_place_holders(&self, outputs: &OutputsAsPaths) -> Self::Output {
        let new_display = self.get_display_str().decode_output_place_holders(outputs);
        RuleDescription::new(self.get_flags().clone(), new_display)
    }
}
impl DecodeInputPlaceHolders for RuleDescription {
    type Output = Self;
    fn decode_input_place_holders(
        &self,
        inputs: &InputsAsPaths,
        secondary_inputs: &InputsAsPaths,
    ) -> Self::Output {
        let new_display = self
            .get_display_str()
            .decode_input_place_holders(inputs, secondary_inputs);
        RuleDescription::new(self.get_flags().clone(), new_display)
    }
}
impl DecodeInputPlaceHolders for Vec<PathExpr> {
    type Output = Self;
    fn decode_input_place_holders(
        &self,
        inputs: &InputsAsPaths,
        secondary_inputs: &InputsAsPaths,
    ) -> Self::Output {
        let mut result = Vec::new();
        self.iter().fold(&mut result, |acc, x| {
            acc.extend(x.decode_input_place_holders(inputs, secondary_inputs));
            acc
        });
        result.cleanup();
        result
    }
}
impl DecodeInputPlaceHolders for &[PathExpr] {
    type Output = Vec<PathExpr>;
    fn decode_input_place_holders(
        &self,
        inputs: &InputsAsPaths,
        secondary_inputs: &InputsAsPaths,
    ) -> Self::Output {
        let mut result = Vec::new();
        self.iter().fold(&mut result, |acc, x| {
            acc.extend(x.decode_input_place_holders(inputs, secondary_inputs));
            acc
        });
        result
    }
}

impl DecodeOutputPlaceHolders for Vec<PathExpr> {
    type Output = Self;
    fn decode_output_place_holders(&self, outputs: &OutputsAsPaths) -> Self::Output {
        let mut result = Vec::new();
        for x in self.iter() {
            result.extend(x.decode_output_place_holders(outputs));
        }
        result
    }
}

impl DecodeOutputPlaceHolders for PathExpr {
    type Output = Vec<PathExpr>;
    fn decode_output_place_holders(&self, outputs: &OutputsAsPaths) -> Self::Output {
        let frep = |d: &str| -> String {
            debug!("replacing %o's from rule string :{}", d);
            replace_io_patterns(d, |pattern, capture| {
                replacer_outputs(pattern, outputs, capture)
            })
        };
        let pe = formatted_pe(frep, self);
        debug!("decoded output paths {:?}", pe);
        pe
    }
}

fn excluded_patterns(
    tup_cwd: &PathDescriptor,
    p: &[PathExpr],
    path_buffers: &impl PathBuffers,
) -> Vec<PathDescriptor> {
    p.iter()
        .filter_map(|x| {
            if let PathExpr::ExcludePattern(pattern) = x {
                let s = "^".to_string() + pattern.as_str();
                Some(path_buffers.add_leaf(tup_cwd, s.as_str()))
            } else {
                None
            }
        })
        .collect()
}

fn paths_from_exprs(
    tup_cwd: &PathDescriptor,
    p: &[PathExpr],
    path_buffers: &impl PathBuffers,
) -> Vec<OutputType> {
    p.split(|x| {
        matches!(
            x,
            &PathExpr::Sp1 | &PathExpr::NL | &PathExpr::ExcludePattern(_)
        )
    })
    .filter(|x| !x.is_empty())
    .filter_map(|x| {
        let path = PathBuf::new().join(x.to_vec().cat());
        path_buffers
            .add_path_from(tup_cwd, path.as_path())
            .inspect_err(|e| {
                log::error!(
                    "Failed to add path {:?} from {:?} due to {:?}",
                    path,
                    tup_cwd,
                    e
                )
            })
            .ok()
            .map(|pid| {
                debug!("constructed path {pid:?} from {x:?}");
                OutputType::new(pid)
            })
    })
    .collect()
}

// replace % specifiers in a target of rule statement which has already been
// deglobbed
impl DecodeInputPlaceHolders for Target {
    type Output = Self;
    fn decode_input_place_holders(
        &self,
        inputs: &InputsAsPaths,
        secondary_inputs: &InputsAsPaths,
    ) -> Self::Output {
        let newprimary = self
            .primary
            .decode_input_place_holders(inputs, secondary_inputs);
        let newsecondary = self
            .secondary
            .decode_input_place_holders(inputs, secondary_inputs);
        Target {
            primary: newprimary,
            secondary: newsecondary,
            bin: self.bin.clone(),
            group: self.group.clone(),
        }
    }
}

impl DecodeInputPlaceHolders for RuleFormula {
    type Output = Self;
    /// rebuild a rule formula with input placeholders filled up
    fn decode_input_place_holders(
        &self,
        inputs: &InputsAsPaths,
        secondary_inputs: &InputsAsPaths,
    ) -> Self::Output {
        debug!(
            "decoding format strings to replace with inputs in Ruleformula:{:?}",
            self
        );
        let new_desc = self
            .get_description()
            .map(|x| x.decode_input_place_holders(inputs, secondary_inputs));
        let new_formula = self
            .get_formula()
            .decode_input_place_holders(inputs, secondary_inputs);
        RuleFormula::new_from_parts(new_desc, new_formula)
    }
}

impl DecodeOutputPlaceHolders for RuleFormula {
    type Output = Self;
    /// rebuild rule by replacing output placeholders such as %o
    fn decode_output_place_holders(&self, outputs: &OutputsAsPaths) -> Self::Output {
        let new_desc = self
            .get_description()
            .map(|x| x.decode_output_place_holders(outputs));
        RuleFormula::new(new_desc, self.formula.decode_output_place_holders(outputs))
    }
}

/// decode input and output placeholders to rebuild a rule
fn get_deglobbed_rule(
    rule_ctx: &RuleContext,
    primary_deglobbed_inps: &[InputResolvedType],
    path_buffers: &impl PathBuffers,
    env: &EnvList,
) -> Result<ResolvedLink, Err> {
    let r = rule_ctx.get_rule_formula();
    let rule_ref = rule_ctx.get_rule_ref();
    let t = rule_ctx.get_target();
    let tup_cwd = rule_ctx.get_tup_cwd();
    let search_dirs = rule_ctx.get_search_dirs();
    let tupfiles_read = rule_ctx.get_tupfiles_read();
    let secondary_deglobbed_inps = rule_ctx.get_secondary_inp();
    debug!("deglobbing tup at dir:{:?}, rule:{:?}", tup_cwd, r.cat());

    let input_as_paths = InputsAsPaths::new(tup_cwd, primary_deglobbed_inps, path_buffers);
    let secondary_inputs_as_paths =
        InputsAsPaths::new(tup_cwd, secondary_deglobbed_inps, path_buffers);
    let mut decoded_target =
        t.decode_input_place_holders(&input_as_paths, &secondary_inputs_as_paths);
    let excluded_targets = excluded_patterns(tup_cwd, &decoded_target.primary, path_buffers);
    let pp = paths_from_exprs(tup_cwd, &decoded_target.primary, path_buffers);

    let df = |x: &OutputType| x.get_id().clone();
    let output_as_paths = OutputsAsPaths::new(pp.iter().map(df).collect(), rule_ref.clone());
    decoded_target.secondary = decoded_target
        .secondary
        .decode_output_place_holders(&output_as_paths);
    let sec_pp = paths_from_exprs(tup_cwd, &decoded_target.secondary, path_buffers);
    let resolved_rule: RuleFormula = r
        .decode_input_place_holders(&input_as_paths, &secondary_inputs_as_paths)
        .decode_output_place_holders(&output_as_paths);

    let bin_desc = t.bin.as_ref().map(|x| {
        if let PathExpr::Bin(x) = x {
            path_buffers.add_bin_path_expr(tup_cwd, x)
        } else {
            Default::default()
        }
    });
    let group = t.group.as_ref().and_then(PathExpr::get_group);
    let group_desc = if let Some((dir, x)) = group {
        let fullp = path_buffers.add_path_from(tup_cwd, dir.as_slice().cat_ref().as_ref());

        let fullp = fullp
            .inspect(|p| debug!("group:{:?}/<{:?}>", p, x.cat()))
            .map_err(|_| {
                PathSearchError(format!(
                    "Failed to join group path {:?} with base directory {:?} for rule: {:?}",
                    tup_cwd,
                    dir.cat(),
                    rule_ref
                ))
            })?;
        Some(path_buffers.add_group_pathexpr(&fullp, x.cat().as_str()))
    } else {
        None
    };

    let rule_formula_desc =
        path_buffers.add_rule(RuleFormulaInstance::new(resolved_rule, rule_ref.clone()));
    Ok(ResolvedLink {
        primary_sources: primary_deglobbed_inps.to_vec(),
        secondary_sources: secondary_deglobbed_inps.to_vec(),
        rule_formula_desc,
        primary_targets: pp.into_iter().map(|x| x.get_id()).collect(),
        secondary_targets: sec_pp.into_iter().map(|x| x.get_id()).collect(),
        excluded_targets,
        bin: bin_desc,
        group: group_desc,
        tup_loc: rule_ref.clone(),
        env: env.clone(),
        search_dirs: search_dirs.to_vec(),
        tupfiles_read: tupfiles_read.to_vec(),
    })
}

/// ResolvedLink represents a rule with its inputs, outputs and command string fully or partially resolved.
/// This means that paths stored here are file paths that are or expected to be in file system.
/// Rule string is also expect to be executable or ready for persistence with all  symbols and variable references resolved
/// Group references are an exception and may not be resolved until all the tupfiles are read.
#[derive(Clone, Debug, Default, PartialEq, Eq, Ord)]
pub struct ResolvedLink {
    /// Inputs that are read by a rule that can be used for %f substitution
    primary_sources: Vec<InputResolvedType>,
    /// Other inputs read by a rule not available for %f substitution
    secondary_sources: Vec<InputResolvedType>,
    /// Rule formula referred to by its descriptor
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
    tup_loc: TupLoc,
    /// Env(environment) needed by this rule
    env: EnvList,
    /// Vpaths
    search_dirs: Vec<PathDescriptor>,
    /// all the tupfiles parsed to build this rule
    tupfiles_read: Vec<PathDescriptor>,
}

impl PartialOrd for ResolvedLink {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
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
            tup_loc: Default::default(),
            env: Default::default(),
            search_dirs: vec![],
            tupfiles_read: vec![],
        }
    }
    /// get a readable string for a Statement, replacing descriptors with paths
    pub fn human_readable(&self) -> String {
        let s = format!("{:?}", self);
        s
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
    pub fn get_env_list(&self) -> &EnvList {
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

    /// returns  tupfile and the rule location
    pub fn get_tup_loc(&self) -> &TupLoc {
        &self.tup_loc
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

    /// files read during the preparation of this rule. These become the dependencies of this rule
    pub fn get_tupfiles_read(&self) -> &Vec<PathDescriptor> {
        &self.tupfiles_read
    }

    #[allow(dead_code)]
    fn add_to_tupfiles_read(&mut self, tupfile: PathDescriptor) {
        self.tupfiles_read.push(tupfile);
    }

    fn reresolve(
        path_searcher: &impl PathSearcher,
        path_buffers: &impl PathBuffers,
        p: &PathDescriptor,
        rule_ref: &TupLoc,
        search_dirs: &[PathDescriptor],
    ) -> Result<Vec<MatchingPath>, Error> {
        let tup_cwd = path_buffers.get_parent_id(&rule_ref.tup_path_desc);
        let rel_path = path_buffers.get_rel_path(p, &tup_cwd);
        let glob_path = GlobPath::build_from(&tup_cwd, p)?;
        debug!("need to resolve file:{:?}", glob_path.get_abs_path());
        let mut glob_paths = vec![glob_path];
        for dir in search_dirs {
            glob_paths.push(GlobPath::build_from(
                &tup_cwd,
                &dir.join(rel_path.as_path())?,
            )?);
        }
        let pes: Vec<MatchingPath> =
            path_searcher.discover_paths(path_buffers, glob_paths.as_slice(), SelOptions::File)?;
        if pes.is_empty() {
            log::error!("Could not resolve :{:?}", path_buffers.get_path(p));
        }
        Ok(pes)
    }
}

/// ResolvedTask represents a task with its inputs, outputs and command string fully or partially resolved.
/// Task need not have any outputs or inputs. It may just be a command to be executed (such as echo).
/// Tasks will be rerun only if the inputs have changed or if the command string has changed or if an output is missing.
/// Outs are determined at runtime by executing the command string and monitoring its output.
/// Unmentioned ins are determined at runtime by monitoring the command string for file accesses. These are used to rerun the task if any of these files change.
/// The command string is expected to be executable or ready for persistence with all  symbols and variable references resolved.
#[derive(Clone, Debug, Default)]
pub struct ResolvedTask {
    deps: Vec<InputResolvedType>,
    task_descriptor: TaskDescriptor,
    loc: TupLoc,
    env: EnvList,
}

impl ResolvedTask {
    /// Create a new ResolvedTask
    pub fn new(
        deps: Vec<InputResolvedType>,
        task_descriptor: TaskDescriptor,
        loc: TupLoc,
        env: EnvList,
    ) -> Self {
        ResolvedTask {
            deps,
            task_descriptor,
            loc,
            env,
        }
    }

    /// get resolved dependencies
    pub fn get_deps(&self) -> &Vec<InputResolvedType> {
        &self.deps
    }
    /// location where the task is defined
    pub fn get_tup_loc(&self) -> &TupLoc {
        &self.loc
    }
    /// returns the descriptor that identifies the task. Use bufferObjects to dereference the descriptor to get taskinstance
    pub fn get_task_descriptor(&self) -> &TaskDescriptor {
        &self.task_descriptor
    }

    /// returns environment associated with this task
    pub fn get_env_list(&self) -> &EnvList {
        &self.env
    }

    /// descriptor of the tupfile where this task is defined
    pub fn get_tupfile_desc(&self) -> TupPathDescriptor {
        self.loc.get_tupfile_desc().clone()
    }
}

// update the groups/bins with the path to primary target and also add secondary targets
impl GatherOutputs for ResolvedLink {
    fn gather_outputs(
        &self,
        output_handler: &mut impl OutputHandler,
        path_buffers: &impl PathBuffers,
    ) -> Result<(), Err> {
        let rule_ref = &self.tup_loc;
        struct PathsWithParent {
            pd: PathDescriptor,
            parent_pd: PathDescriptor,
        }
        let mut children = Vec::new();
        for path_desc in self.get_targets() {
            let path = path_buffers.get_path(path_desc);
            debug!(
                "adding parent for: {:?} to {:?}:{}",
                path,
                rule_ref.get_tupfile_desc().get_path_ref(),
                rule_ref.get_line()
            );
            if path.as_path().is_dir() {
                return Err(Err::OutputIsDir(
                    path_buffers.get_path(path_desc).to_string(),
                    rule_ref.clone(),
                ));
            }
            let rule_ref_inserted = output_handler.add_parent_rule(path_desc, rule_ref.clone());
            if &rule_ref_inserted != rule_ref {
                return Err(Err::MultipleRulesToSameOutput(
                    path_desc.clone(),
                    rule_ref.clone(),
                    rule_ref_inserted.clone(),
                ));
            }
            output_handler.add_output(path_desc);
            children.push(PathsWithParent {
                pd: path_desc.clone(),
                parent_pd: path_buffers.get_parent_id(path_desc),
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
                .find(|x| x.1.parent_pd.ne(&pp.parent_pd))
            {
                (prev, slice) = slice.split_at(r.0 + 1);
            } else {
                slice = &slice[1..]
            }
            output_handler.add_children(&pp.parent_pd, prev.iter().map(|x| x.pd.clone()).collect());
        }
        for path_desc in self.primary_targets.iter() {
            if let Some(ref group_desc) = self.group {
                output_handler.add_group_entry(group_desc, path_desc.clone())
            };
            if let Some(ref bin_desc) = self.bin {
                output_handler.add_bin_entry(bin_desc, path_desc.clone());
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
        tup_desc: &TupPathDescriptor,
        path_searcher: &mut impl PathSearcher,
        path_buffers: &impl PathBuffers,
        other_tupfiles_read: &Vec<PathDescriptor>,
    ) -> Result<ResolvedRules, Err>;
}

impl ResolvedRules {
    /// resolve missing inputs and outputs in all the resolved links
    pub fn resolve_paths(
        &mut self,
        path_searcher: &mut impl PathSearcher,
        path_buffers: &impl PathBuffers,
        _: &Vec<PathDescriptor>,
    ) -> Result<(), Err> {
        let mut resolved_links = Vec::new();
        for resolved_link in self.get_resolved_links().iter() {
            if resolved_link.has_unresolved_inputs() {
                let cur_tup_desc = resolved_link.get_tup_loc().get_tupfile_desc();

                debug!("resolving paths for {:?}", resolved_link);
                let mut art = resolved_link.resolve_paths(
                    cur_tup_desc,
                    path_searcher,
                    path_buffers,
                    resolved_link.get_tupfiles_read(),
                )?;
                resolved_links.extend(art.drain_resolved_links());
            } else {
                resolved_links.push(resolved_link.clone());
            }
        }
        self.set_resolved_links(resolved_links);
        Ok(())
    }
}

/// implementation for ResolvedLink performs unresolved paths in Group inputs using data in taginfo
impl ResolvePaths for ResolvedLink {
    /// the method below replaces
    fn resolve_paths(
        &self,
        tup_desc: &TupPathDescriptor,
        path_searcher: &mut impl PathSearcher,
        path_buffers: &impl PathBuffers,
        tupfiles_read: &Vec<PathDescriptor>,
    ) -> Result<ResolvedRules, Err> {
        let mut rlink: ResolvedLink = self.clone();
        rlink.primary_sources.clear();
        rlink.secondary_sources.clear();
        for i in self.primary_sources.iter() {
            match i {
                InputResolvedType::UnResolvedFile(p) => {
                    let pes = Self::reresolve(
                        path_searcher,
                        path_buffers,
                        &p,
                        rlink.get_tup_loc(),
                        self.search_dirs.as_slice(),
                    )?;
                    rlink
                        .primary_sources
                        .extend(pes.into_iter().map(InputResolvedType::Deglob));
                }
                InputResolvedType::UnResolvedGroupEntry(g) => {
                    if let Some(hs) = path_searcher.get_outs().get().get_group(&g) {
                        for pd in hs {
                            rlink
                                .primary_sources
                                .push(InputResolvedType::GroupEntry(Clone::clone(g), pd.clone()));
                        }
                    } else {
                        log::warn!(
                            "Stale group reference :{:?} at {:?}",
                            g,
                            rlink.get_tup_loc()
                        );
                    }
                }
                _ => rlink.primary_sources.push(i.clone()),
            }
        }

        for i in self.secondary_sources.iter() {
            match i {
                InputResolvedType::UnResolvedFile(p) => {
                    let pes = Self::reresolve(
                        path_searcher,
                        path_buffers,
                        &p,
                        rlink.get_tup_loc(),
                        self.search_dirs.as_slice(),
                    )?;
                    rlink
                        .secondary_sources
                        .extend(pes.into_iter().map(InputResolvedType::Deglob));
                }
                InputResolvedType::UnResolvedGroupEntry(ref g) => {
                    if let Some(hs) = path_searcher.get_outs().get().get_group(g) {
                        for pd in hs {
                            rlink
                                .secondary_sources
                                .push(InputResolvedType::GroupEntry(Clone::clone(g), pd.clone()))
                        }
                    } else {
                        log::warn!(
                            "Stale group reference :{:?} at {:?}",
                            g,
                            rlink.get_tup_loc()
                        );
                    }
                }
                _ => rlink.secondary_sources.push(i.clone()),
            }
        }
        let mut out = OutputHolder::new();
        self.gather_outputs(&mut out, path_buffers)?;
        path_searcher.merge(path_buffers, &mut out)?;
        Ok(ResolvedRules::from(
            vec![rlink],
            vec![],
            tup_desc.clone(),
            tupfiles_read.clone(),
            Default::default()
        ))
    }
}

struct RuleContext<'a, 'b, 'c, 'd> {
    tup_cwd: PathDescriptor,
    rule_formula: &'a RuleFormula,
    rule_ref: &'b TupLoc,
    target: &'a Target,
    secondary_inp: &'c [InputResolvedType],
    search_dirs: &'a [PathDescriptor],
    tupfiles_read: &'d [TupPathDescriptor],
}

impl<'a, 'b, 'c, 'd> RuleContext<'a, 'b, 'c, 'd> {
    fn get_rule_formula(&self) -> &RuleFormula {
        self.rule_formula
    }
    fn get_rule_ref(&self) -> &TupLoc {
        self.rule_ref
    }
    fn get_target(&self) -> &Target {
        self.target
    }
    fn get_secondary_inp(&self) -> &[InputResolvedType] {
        self.secondary_inp
    }
    fn get_tup_cwd(&self) -> &PathDescriptor {
        &self.tup_cwd
    }
    fn get_search_dirs(&self) -> &[PathDescriptor] {
        self.search_dirs
    }

    fn get_tupfiles_read(&self) -> &[TupPathDescriptor] {
        self.tupfiles_read
    }
}

/// deglob rule statement into multiple deglobbed rules, gather deglobbed targets to put in bins/groups
impl LocatedStatement {
    pub(crate) fn resolve_paths(
        &self,
        tup_desc: &TupPathDescriptor,
        path_searcher: &mut impl PathSearcher,
        path_buffers: &impl PathBuffers,
        tupfiles_read: &Vec<PathDescriptor>,
    ) -> Result<(ResolvedRules, OutputHolder), Err> {
        let tup_cwd = tup_desc.get_parent_descriptor();
        let mut deglobbed = Vec::new();
        // use same resolve_groups as input
        let mut output = OutputHolder::new();

        debug!(
            "resolving  rule at dir:{:?} rule: {:?}",
            tup_cwd.get_path_ref(),
            &self
        );
        let mut globs_read = Vec::new();
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
                    search_dirs,
                ),
            loc,
        } = self
        {
            let mut reparsed_primary = Vec::new();
            for primary in s.primary.iter() {
                if let PathExpr::Literal(s) = primary {
                    let pelist = reparse_literal_as_input(s).unwrap_or(vec![s.to_string().into()]);
                    reparsed_primary.extend(pelist);
                    reparsed_primary.push(PathExpr::Sp1);
                } else {
                    reparsed_primary.push(primary.clone());
                }
            }
            let mut reparsed_secondary = Vec::new();
            for secondary in s.secondary.iter() {
                if let PathExpr::Literal(s) = secondary {
                    let pelist = reparse_literal_as_input(s).unwrap_or(vec![s.to_string().into()]);
                    reparsed_secondary.extend(pelist);
                    reparsed_secondary.push(PathExpr::Sp1);
                } else {
                    reparsed_secondary.push(secondary.clone());
                }
            }

            let rule_ref = &TupLoc::new(tup_desc, loc);
            let inpdec = reparsed_primary.decode(
                &tup_cwd,
                path_searcher,
                path_buffers,
                rule_ref,
                &search_dirs,
            )?;
            let secondinpdec = reparsed_secondary.decode(
                &tup_cwd,
                path_searcher,
                path_buffers,
                rule_ref,
                &search_dirs,
            )?;
            let resolver = RuleContext {
                tup_cwd: tup_cwd.clone(),
                rule_formula,
                rule_ref,
                target: t,
                secondary_inp: secondinpdec.as_slice(),
                search_dirs: search_dirs.as_slice(),
                tupfiles_read: tupfiles_read.as_slice(),
            };
            let for_each = s.for_each;
            for input_glob_desc in inpdec.iter().filter_map(|x| x.get_glob_path_desc()) {
                globs_read.push(input_glob_desc);
            }
            if for_each {
                for input in inpdec {
                    if input.is_unresolved() {
                        log::warn!("Unresolved input files found : {:?} for rule:{:?} at  {:?}/Tupfile:{:?}",
                            input,
                            resolver.get_rule_formula(),
                            resolver.get_tup_cwd(),
                            rule_ref);
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
                debug!("Resolved link: {:?}", delink.get_rule_desc().get_name());
                delink.gather_outputs(&mut output, path_buffers)?;
                deglobbed.push(delink);
            }
            path_searcher.merge(path_buffers, &mut output)?;
        }

        let mut tasks = Vec::new();
        if let LocatedStatement {
            statement: Statement::Task(task_detail),
            loc,
        } = self
        {
            let tup_loc = &TupLoc::new(tup_desc, loc);
            let name = task_detail.get_target();
            let deps = task_detail.get_deps();
            let search_dirs = task_detail.get_search_dirs();
            let task_desc = path_buffers
                .try_get_task_desc(&tup_cwd, &name.as_str())
                .ok_or(Err::TaskNotFound(
                    name.as_str().to_string(),
                    tup_loc.clone(),
                ))?;
            let task_inst = path_buffers.get_task(&task_desc);
            {
                let env = task_inst.get_env_list();
                let mut resolved_deps = Vec::new();
                for dep in deps.iter() {
                    let dep =
                        dep.decode(&tup_cwd, path_searcher, path_buffers, tup_loc, &search_dirs)?;
                    resolved_deps.extend(dep);
                }
                let resolved_task = ResolvedTask::new(
                    resolved_deps,
                    task_desc.clone(),
                    tup_loc.clone(),
                    env.clone(),
                );
                tasks.push(resolved_task);
            }
        }

        Ok((
            ResolvedRules::from(deglobbed, tasks, tup_desc.clone(), tupfiles_read.clone(), globs_read),
            output,
        ))
    }
}

impl ResolvePaths for StatementsInFile {
    fn resolve_paths(
        &self,
        tup_desc: &TupPathDescriptor,
        path_searcher: &mut impl PathSearcher,
        path_buffers: &impl PathBuffers,
        other_tupfiles_read: &Vec<PathDescriptor>,
    ) -> Result<ResolvedRules, Err> {
        let mut resolved_rules = ResolvedRules::new(tup_desc.clone());
        debug!("Resolving paths for rules in {:?}", tup_desc.as_ref());
        self.try_for_each(|stmt| -> Result<(), Err> {
            let (art, _) =
                stmt.resolve_paths(tup_desc, path_searcher, path_buffers, other_tupfiles_read)?;
            debug!("{:?}", art);
            resolved_rules.extend(art);
            Ok(())
        })?;
        Ok(resolved_rules)
    }
}

/// `parse_dir' scans and parses all Tupfiles from a directory root, When sucessful it returns de-globbed, decoded links(rules)
pub fn parse_dir(root: &Path) -> Result<(Vec<ResolvedRules>, ReadWriteBufferObjects), Error> {
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
    tupfiles.sort_by(|x, y| x.cmp(y));

    parse_tupfiles(root, &tupfiles)
}

/// parse tupfiles in the order given
pub fn parse_tupfiles(
    root: &Path,
    tupfiles: &Vec<PathBuf>,
) -> Result<(Vec<ResolvedRules>, ReadWriteBufferObjects), Error> {
    let mut artifacts_all = Vec::new();
    debug!("parsing tupfiles in {:?}", root);
    let mut parser = TupParser::<DirSearcher>::try_new_from(root, DirSearcher::new_at(root))?;
    for tup_file_path in tupfiles.iter() {
        let resolved_rules = parser.parse(tup_file_path)?;
        artifacts_all.push(resolved_rules);
    }
    parser.reresolve(&mut artifacts_all)?;
    Ok((artifacts_all, parser.read_write_buffers()))
}

/// retain paths that have pattern in its contents
pub fn paths_with_pattern(
    root: &Path,
    pattern: &str,
    mut paths: Vec<MatchingPath>,
) -> Result<Vec<MatchingPath>, Error> {
    let mut buffer = String::new();
    let pattern = pattern
        .strip_suffix("\"")
        .unwrap_or(pattern)
        .strip_prefix("\"")
        .unwrap_or(pattern);
    let regex = if pattern.contains('%') {
        Some(Regex::new(&to_regex(pattern)).expect("Failed to convert pattern to regex"))
    } else {
        None
    };

    paths.retain(move |path| {
        if let Ok(f) = File::open(root.join(path.get_path().as_path())) {
            let buf = BufReader::new(f);
            buffer.clear();
            buf.lines().any(|line| {
                if let Ok(ref line) = line {
                    regex
                        .as_ref()
                        .map_or_else(|| line.contains(pattern), |re| re.is_match(&line))
                } else {
                    false
                }
            })
        } else {
            false
        }
    });
    Ok(paths)
}
