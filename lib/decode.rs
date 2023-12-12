//! This module handles decoding and de-globbing of rules
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet, LinkedList};
use std::ffi::OsString;
use std::fmt::Formatter;
use std::hash::Hash;
use std::ops::Deref;
use std::path::{Path, PathBuf};

use log::{debug, log_enabled};
use parking_lot::{MappedRwLockReadGuard, RwLockReadGuard};
use pathdiff::diff_paths;
use regex::{Captures, Regex};
use walkdir::{DirEntry, WalkDir};

use crate::buffers::{
    BinDescriptor, BufferObjects, GlobPathDescriptor, GroupPathDescriptor, MyGlob, OutputHolder,
    OutputType, PathBuffers, PathDescriptor, RuleDescriptor, TaskDescriptor, TupPathDescriptor,
};
use crate::errors::{Error as Err, Error};
use crate::paths::{
    ExcludeInputPaths, GlobPath, InputResolvedType, InputsAsPaths, MatchingPath, OutputsAsPaths,
};
use crate::statements::*;
use crate::transform::{get_parent, Artifacts, TupParser};
use crate::{paths, ReadWriteBufferObjects};

/// Trait to discover paths from an external source (such as a database)
pub trait PathSearcher {
    /// Discover paths from glob string
    fn discover_paths(
        &self,
        path_buffers: &mut impl PathBuffers,
        glob_path: &[GlobPath],
    ) -> Result<Vec<MatchingPath>, Error>;

    /// Find Outputs
    fn get_outs(&self) -> &OutputHolder;

    /// Merge outputs from previous outputs
    fn merge(&mut self, p: &impl PathBuffers, o: &impl OutputHandler) -> Result<(), Error>;
}

/// Normal Path packages a PathBuf, giving relative paths wrt current tup directory

/// `TupLoc` keeps track of the current file being processed and rule location.
/// This is mostly useful for error handling to let the user know we ran into problem with a rule at
/// a particular line
#[derive(Debug, Default, PartialEq, Eq, Clone, Hash)]
pub struct TupLoc {
    tup_path_desc: TupPathDescriptor,
    loc: Loc,
}

/// `RuleFormulaInstance` stores both rule formula and its whereabouts(`TupLoc`) in a Tupfile
/// Caller locations are stored in the linked list
#[derive(Debug, Default, PartialEq, Eq, Clone, Hash)]
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
    env: EnvDescriptor,
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

impl TaskInstance {
    ///Create a new TaskInstance
    pub(crate) fn new<P: AsRef<Path>>(
        tup_cwd: P,
        name: &str,
        deps: Vec<PathExpr>,
        recipe: Vec<Vec<PathExpr>>,
        tup_loc: TupLoc,
        search_dirs: Vec<PathDescriptor>,
        env: EnvDescriptor,
    ) -> TaskInstance {
        let name = format!("{}/{}", tup_cwd.as_ref().to_string_lossy(), name);
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
    pub(crate) fn get_env_desc(&self) -> &EnvDescriptor {
        &self.env
    }
}

impl std::fmt::Display for TupLoc {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.tup_path_desc, self.loc)
    }
}

///`Ruleref` constructor and accessors
impl TupLoc {
    /// Construct a RuleRef
    pub fn new(tup_desc: &TupPathDescriptor, loc: &Loc) -> TupLoc {
        TupLoc {
            tup_path_desc: *tup_desc,
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
    /// `RuleFormula` that this object refers to
    pub(crate) fn get_formula(&self) -> &RuleFormula {
        &self.rule_formula
    }
    /// returns `RuleRef' which is the location of the referred rule in a Tupfile
    pub fn get_rule_ref(&self) -> &TupLoc {
        &self.rule_ref.front().unwrap()
    }
}

impl std::fmt::Display for RuleFormulaInstance {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "?{:?}? {:?}", self.rule_ref, self.rule_formula)
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
    fn get_parent_rule(&self, o: &PathDescriptor) -> Option<MappedRwLockReadGuard<'_, TupLoc>>;
    /// parent rule of each output path
    fn get_parent_rules(&self) -> MappedRwLockReadGuard<'_, HashMap<PathDescriptor, TupLoc>>;
    /// Add an entry to the set that holds output paths
    fn add_output(&mut self, pd: PathDescriptor) -> bool;

    /// Add parent rule to a give output path id. Returns false if unsuccessful
    fn add_parent_rule(&mut self, pd: PathDescriptor, rule_ref: TupLoc) -> TupLoc;

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
        glob_path: &[GlobPath],
    ) -> Result<Vec<MatchingPath>, Error> {
        let mut unique_path_descs = HashSet::new();
        let mut pes = Vec::new();
        let matching_outs = self.output_holder.discover_paths(path_buffers, glob_path)?;
        if !matching_outs.is_empty() {
            pes.extend(matching_outs);
            return Ok(pes);
        }
        for glob_path in glob_path {
            let to_match = glob_path.get_abs_path();
            debug!(
                "bp:{:?}, to_match:{:?}",
                glob_path.get_base_abs_path(),
                to_match
            );

            let root = path_buffers.get_root_dir();
            if !glob_path.has_glob_pattern() {
                let mut pes = Vec::new();
                let path_desc = glob_path.get_glob_path_desc();
                debug!("looking for child {:?}", to_match);
                if root.join(to_match).is_file() {
                    pes.push(MatchingPath::new(
                        path_desc,
                        path_buffers.get_path(&path_desc).clone(),
                    ));
                    if log_enabled!(log::Level::Debug) {
                        for pe in pes.iter() {
                            debug!("mp:{:?}", pe);
                        }
                    }
                    return Ok(pes);
                }
            } else {
                let base_path = glob_path.get_base_abs_path();
                if !path_buffers.get_root_dir().join(base_path).is_dir() {
                    debug!("base path {:?} is not a directory", base_path);
                    continue;
                }
                let globs = MyGlob::new(glob_path.get_slash_corrected())?;
                debug!("glob regex used for finding matches {}", globs.re());
                debug!("base path for files matching glob: {:?}", base_path);
                let mut walkdir = WalkDir::new(path_buffers.get_root_dir().join(base_path));
                if glob_path.is_recursive_prefix() {
                    walkdir = walkdir.max_depth(usize::MAX);
                } else {
                    walkdir = walkdir.max_depth(1);
                }
                let len = root.components().count();
                let relative_path = |entry: DirEntry| -> PathBuf {
                    entry
                        .path()
                        .components()
                        .skip(len)
                        .collect::<PathBuf>()
                        .as_path()
                        .to_owned()
                };

                let filtered_paths = walkdir
                    .min_depth(1)
                    .into_iter()
                    .filter_map(move |entry| {
                        entry.ok().filter(|e| e.path().is_file()).map(relative_path)
                    })
                    .filter(|entry| globs.is_match(entry.as_path()));
                let mut paths = filtered_paths.collect::<Vec<_>>();
                paths.sort_by(|a, b| a.cmp(b));
                for path in paths.iter() {
                    let (path_desc, _) = path_buffers.add_abs(path);
                    let captured_globs = globs.group(path);
                    debug!("found path {:?} with captures {:?}", path, captured_globs);
                    pes.push(MatchingPath::with_captures(
                        path_desc,
                        path_buffers.get_path(&path_desc).clone(),
                        glob_path.get_glob_desc(),
                        captured_globs,
                    ));
                    unique_path_descs.insert(path_desc);
                }
                if log_enabled!(log::Level::Debug) {
                    for pe in pes.iter() {
                        debug!("mp_glob:{:?}", pe);
                    }
                }
                if !pes.is_empty() {
                    break;
                }
            }
        }
        let mut matching_outputs = self.output_holder.discover_paths(path_buffers, glob_path)?;
        for pe in matching_outputs.drain(..) {
            debug!("mp_glob:{:?}", pe);
            if unique_path_descs.insert(*pe.path_descriptor()) {
                pes.push(pe);
            }
        }
        Ok(pes)
    }

    fn get_outs(&self) -> &OutputHolder {
        &self.output_holder
    }

    fn merge(&mut self, p: &impl PathBuffers, o: &impl OutputHandler) -> Result<(), Error> {
        OutputHandler::merge(&mut self.output_holder, p, o)
    }
}

/// Decode input paths from file globs, bins(buckets), and groups
pub(crate) trait DecodeInputPaths {
    fn decode(
        &self,
        tup_cwd: &Path,
        path_searcher: &impl PathSearcher,
        path_buffers: &mut impl PathBuffers,
        rule_ref: &TupLoc,
        search_dirs: &Vec<PathDescriptor>,
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
        rule_ref: &TupLoc,
        search_dirs: &Vec<PathDescriptor>,
    ) -> Result<Vec<InputResolvedType>, Err> {
        let mut vs = Vec::new();
        debug!("Decoding input paths of {:?}", &self);

        match self {
            PathExpr::Literal(_) => {
                let pbuf = paths::normalized_path(self);
                let glob_path = GlobPath::new(tup_cwd, pbuf.as_path(), path_buffers)?;
                let abs_path = glob_path.get_abs_path().to_path_buf();
                let mut glob_paths = vec![glob_path];
                for search_dir in search_dirs {
                    let dir = path_buffers.get_path(search_dir).clone();
                    let glob_path = GlobPath::new(dir.as_path(), pbuf.as_path(), path_buffers)?;
                    debug!("glob str: {:?}", glob_path.get_abs_path());
                    glob_paths.push(glob_path);
                }

                let pes = path_searcher.discover_paths(path_buffers, glob_paths.as_slice())?;
                if pes.is_empty() {
                    let (pd, _) = path_buffers.add_abs(abs_path.as_path());
                    vs.push(InputResolvedType::UnResolvedFile(pd));
                } else {
                    vs.extend(pes.into_iter().map(InputResolvedType::Deglob));
                }
            }
            PathExpr::Group(_, _) => {
                let (ref grp_desc, _) =
                    path_buffers.add_group_pathexpr(tup_cwd, self.cat_ref().as_ref());
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
            PathExpr::DeGlob(mp) => {
                vs.push(InputResolvedType::Deglob(mp.clone()));
            }
            PathExpr::TaskRef(name) => {
                if let Some(task_desc) = path_buffers.try_get_task_desc(tup_cwd, name.as_str()) {
                    vs.push(InputResolvedType::TaskRef(*task_desc));
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
        tup_cwd: &Path,
        path_searcher: &impl PathSearcher,
        path_buffers: &mut impl PathBuffers,
        rule_ref: &TupLoc,
        search_dirs: &Vec<PathDescriptor>,
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
    rule_ref: &TupLoc,
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
            let rule_ref = inp.get_rule_ref();
            let d = if d.contains("%f") {
                let input_raw_paths = inp.get_paths();
                if input_raw_paths.is_empty() {
                    return Err(Err::StalePerc('f', rule_ref.clone(), d.to_string()));
                }
                let x1 = input_raw_paths.join(" ");
                debug!("replacing %f with {:?}", x1.as_str());
                d.replace("%f", x1.as_str())
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
            let d = if d.contains("%h") {
                let g = inp
                    .get_glob()
                    .and_then(|x| if x.len() > 1 { x.first() } else { None })
                    .cloned();
                let g = g.ok_or_else(|| Err::StalePerc('h', rule_ref.clone(), d.clone()))?;
                debug!("replacing %h with {:?}", g);
                d.replace("%h", g.as_str())
            } else {
                d
            };
            let d = if d.contains("%g") {
                let g = inp.get_glob().and_then(|x| x.last());
                let g = g.ok_or_else(|| Err::StalePerc('g', rule_ref.clone(), d.clone()))?;
                debug!("replacing %g with {:?}", g.as_str());
                d.replace("%g", g.as_str())
            } else {
                d
            };

            let d = if d.contains("%i") {
                // replace with secondary inputs (order only inputs)
                let sinputsflat = sinp.get_paths();
                if sinp.is_empty() {
                    return Err(Err::StalePerc('i', sinp.get_rule_ref().clone(), d));
                }
                d.replace("%i", sinputsflat.join(" ").as_str())
            } else {
                d
            };
            let d = if PERC_NUM_I.captures(d.as_str()).is_some() {
                // replaced with numbered captures of order only inputs
                if sinp.is_empty() {
                    return Err(Err::StalePercNumberedRef(
                        'i',
                        sinp.get_rule_ref().clone(),
                        d,
                    ));
                }
                let sinputsflat = sinp.get_paths();
                replace_decoded_str(
                    d.as_str(),
                    &sinputsflat,
                    &PERC_NUM_I,
                    &sinp.get_rule_ref(),
                    'i',
                )?
            } else {
                d
            };

            let d = if PERC_NUM_G_RE.captures(d.as_str()).is_some() {
                let captures = inp.get_glob().ok_or(Err::StalePercNumberedRef(
                    'g',
                    inp.get_rule_ref().clone(),
                    d.clone(),
                ))?;
                replace_decoded_str(
                    d.as_str(),
                    captures,
                    &PERC_NUM_G_RE,
                    &inp.get_rule_ref(),
                    'g',
                )?
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
    rule_ref: &TupLoc,
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
                    return Err(Err::StalePerc(
                        'o',
                        outputs.get_rule_ref().clone(),
                        d.to_string(),
                    ));
                }
                d.replace("%o", space_separated_outputs.as_str())
            } else {
                d.to_string()
            };
            let d = if d.contains("%O") {
                if outputs.is_empty() {
                    return Err(Err::StalePerc('O', outputs.get_rule_ref().clone(), d));
                }
                let stem = outputs.get_file_stem().ok_or_else(|| {
                    Err::StalePerc('O', outputs.get_rule_ref().clone(), d.clone())
                })?;
                d.replace("%O", stem.as_str())
            } else {
                d
            };

            let d = if PERC_NUM_O_RE.captures(d.as_str()).is_some() {
                replace_decoded_str(
                    d.as_str(),
                    &outputs.get_paths(),
                    &PERC_NUM_O_RE,
                    &outputs.get_rule_ref(),
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
                    &outputs.get_rule_ref(),
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
        debug!(
            "decoding format strings to replace with inputs in Ruleformula:{:?}",
            self
        );
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
    let search_dirs = rule_ctx.get_search_dirs();
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
    let output_as_paths = OutputsAsPaths::new(pp.iter().map(df).collect(), rule_ref.clone());
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
    let group_desc = t.group.as_ref().map(|x| {
        path_buffers
            .add_group_pathexpr(tup_cwd, x.cat_ref().as_ref())
            .0
    });

    let rule_formula_desc = path_buffers
        .add_rule(RuleFormulaInstance::new(resolved_rule, rule_ref.clone()))
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
        tup_loc: rule_ref.clone(),
        env: env.clone(),
        search_dirs: search_dirs.to_vec(),
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
    tup_loc: TupLoc,
    /// Env(environment) needed by this rule
    env: EnvDescriptor,
    /// Vpaths
    search_dirs: Vec<PathDescriptor>,
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
        }
    }
    /// get a readable string for a Statement, replacing descriptors with paths
    pub fn human_readable(&self, pb_: RwLockReadGuard<BufferObjects>) -> String {
        let s = format!("{:?}", self);
        let pb = pb_.clone();
        let replace_tup_desc = move |selstr: &str| {
            let r = Regex::new(r"TupPathDescriptor\((\d+)\)").unwrap();
            r.replace_all(selstr, move |caps: &regex::Captures| {
                let num = caps.get(1).unwrap().as_str().parse::<usize>().unwrap();
                let path = pb.get_tup_path(&TupPathDescriptor::new(num));
                path.to_string_lossy().to_string()
            })
            .to_string()
        };
        let pb = pb_.clone();
        // replace rule descriptor with rule formula
        let replace_rule_desc = move |selstr: String| {
            let r = Regex::new(r"RuleDescriptor\((\d+)\)").unwrap();
            r.replace_all(selstr.as_ref(), move |caps: &regex::Captures| {
                let num = caps.get(1).unwrap().as_str().parse::<usize>().unwrap();
                let rule_usage = pb.get_rule(&RuleDescriptor::new(num));
                rule_usage.get_rule_str()
            })
            .to_string()
        };
        let pb = pb_.clone();
        // replace group descriptor with group path
        let replace_group_desc = move |selstr: String| {
            let r = Regex::new(r"GroupPathDescriptor\((\d+)\)").unwrap();
            r.replace_all(selstr.as_ref(), move |caps: &regex::Captures| {
                let num = caps.get(1).unwrap().as_str().parse::<usize>().unwrap();
                let path = pb
                    .try_get_group_path(&GroupPathDescriptor::new(num))
                    .unwrap()
                    .as_path();
                path.to_string_lossy().to_string()
            })
            .to_string()
        };
        let pb = pb_.clone();
        // replace bin descriptor with bin name
        let replace_bin_desc = move |selstr: String| {
            let r = Regex::new(r"BinDescriptor\((\d+)\)").unwrap();
            r.replace_all(selstr.as_ref(), move |caps: &regex::Captures| {
                let num = caps.get(1).unwrap().as_str().parse::<usize>().unwrap();
                let path = pb.get_bin_name(&BinDescriptor::new(num));
                path.to_string()
            })
            .to_string()
        };
        let pb = pb_.clone();
        // replace env descriptor with env vars
        let _replace_env_desc = move |selstr: String| {
            let r = Regex::new(r"EnvDescriptor\((\d+)\)").unwrap();
            r.replace_all(selstr.as_ref(), move |caps: &regex::Captures| {
                let num = caps.get(1).unwrap().as_str().parse::<usize>().unwrap();
                let path = pb.try_get_env(&EnvDescriptor::new(num)).unwrap();
                path.getenv()
                    .iter()
                    .map(|(k, v)| format!("{}={}", k, v))
                    .collect::<Vec<String>>()
                    .join(" ")
            })
            .to_string()
        };
        let pb = pb_.clone();
        // replace path descriptor with path
        let r = Regex::new(r"PathDescriptor\((\d+)\)").unwrap();
        let replace_path_desc = move |selstr: String| {
            r.replace_all(selstr.as_ref(), move |caps: &regex::Captures| {
                let num = caps.get(1).unwrap().as_str().parse::<usize>().unwrap();
                let path = pb.get_path(&PathDescriptor::new(num));
                path.as_path().to_string_lossy().to_string()
            })
            .to_string()
        };
        let pb = pb_.clone();
        //  replace glob descriptor with path
        let r = Regex::new(r"GlobPathDescriptor\((\d+)\)").unwrap();
        let replace_glob_desc = move |selstr: String| {
            r.replace_all(selstr.as_ref(), move |caps: &regex::Captures| {
                let num = caps.get(1).unwrap().as_str().parse::<usize>().unwrap();
                let path = pb.get_path(&PathDescriptor::new(num));
                path.as_path().to_string_lossy().to_string()
            })
            .to_string()
        };

        let s = replace_tup_desc(s.as_str());
        let s = replace_rule_desc(s);
        let s = replace_group_desc(s);
        let s = replace_bin_desc(s);
        //let s = replace_env_desc(s);
        let s = replace_glob_desc(s);
        return replace_path_desc(s);
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

    fn reresolve(
        path_searcher: &impl PathSearcher,
        path_buffers: &mut impl PathBuffers,
        p: &PathDescriptor,
        rule_ref: &TupLoc,
        search_dirs: &[PathDescriptor],
    ) -> Result<Vec<MatchingPath>, Error> {
        let tup_cwd = path_buffers
            .get_tup_path(&rule_ref.tup_path_desc)
            .to_path_buf();
        let rel_path = path_buffers.get_rel_path(p, tup_cwd.as_path());
        let glob_path = GlobPath::new(tup_cwd.as_path(), rel_path.as_path(), path_buffers)?;
        debug!("need to resolve file:{:?}", glob_path.get_abs_path());
        let mut glob_paths = vec![glob_path];
        for dir in search_dirs {
            let cwd = path_buffers.get_path(dir).clone();
            let rel_path = path_buffers.get_rel_path(p, cwd.as_path());
            glob_paths.push(GlobPath::new(
                cwd.as_path(),
                rel_path.as_path(),
                path_buffers,
            )?);
        }
        let pes: Vec<MatchingPath> =
            path_searcher.discover_paths(path_buffers, glob_paths.as_slice())?;
        if pes.is_empty() {
            debug!("Could not resolve :{:?}", path_buffers.get_path(p));
            return Err(Error::UnResolvedFile(
                rel_path.as_path().to_string_lossy().to_string(),
                rule_ref.clone(),
            ));
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
    env: EnvDescriptor,
}

impl ResolvedTask {
    /// Create a new ResolvedTask
    pub fn new(
        deps: Vec<InputResolvedType>,
        task_descriptor: TaskDescriptor,
        loc: TupLoc,
        env: EnvDescriptor,
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
    pub fn get_env_desc(&self) -> EnvDescriptor {
        self.env.clone()
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
        path_buffers: &mut impl PathBuffers,
    ) -> Result<(), Err> {
        let rule_ref = &self.tup_loc;
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
                let cur_tup_desc = resolved_link.get_tup_loc().get_tupfile_desc();
                let tup_cwd = path_buffers.get_tup_path(cur_tup_desc).to_path_buf();

                let art = resolved_link.resolve_paths(
                    tup_cwd.as_path(),
                    path_searcher,
                    path_buffers,
                    resolved_link.get_tup_loc().get_tupfile_desc(),
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
                        for pd in hs.deref() {
                            rlink
                                .primary_sources
                                .push(InputResolvedType::GroupEntry(*g, *pd));
                        }
                    } else {
                        return Err(Error::StaleGroupRef(
                            path_buffers.get_input_path_name(i),
                            rlink.get_tup_loc().clone(),
                        ));
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
                        for pd in hs.deref() {
                            rlink
                                .secondary_sources
                                .push(InputResolvedType::GroupEntry(*g, *pd))
                        }
                    } else {
                        return Err(Error::StaleGroupRef(
                            path_buffers.get_input_path_name(i),
                            rlink.get_tup_loc().clone(),
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
        Ok(Artifacts::from(vec![rlink], vec![]))
    }
}

struct RuleContext<'a, 'b, 'c, 'd> {
    tup_cwd: &'d Path,
    rule_formula: &'a RuleFormula,
    rule_ref: &'b TupLoc,
    target: &'a Target,
    secondary_inp: &'c [InputResolvedType],
    search_dirs: &'a [PathDescriptor],
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
    fn get_tup_cwd(&self) -> &Path {
        self.tup_cwd
    }
    fn get_search_dirs(&self) -> &[PathDescriptor] {
        self.search_dirs
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
                    search_dirs,
                ),
            loc,
        } = self
        {
            let rule_ref = &TupLoc::new(tup_desc, loc);
            let inpdec =
                s.primary
                    .decode(tup_cwd, path_searcher, path_buffers, rule_ref, &search_dirs)?;
            let secondinpdec =
                s.secondary
                    .decode(tup_cwd, path_searcher, path_buffers, rule_ref, &search_dirs)?;
            let resolver = RuleContext {
                tup_cwd,
                rule_formula,
                rule_ref,
                target: t,
                secondary_inp: secondinpdec.as_slice(),
                search_dirs: search_dirs.as_slice(),
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

        let mut tasks = Vec::new();
        if let LocatedStatement {
            statement: Statement::Task(name, deps, _, search_dirs),
            loc,
        } = self
        {
            let tup_loc = &TupLoc::new(tup_desc, loc);
            let task_desc = *path_buffers
                .try_get_task_desc(tup_cwd, name.as_str())
                .ok_or(Err::TaskNotFound(
                    name.as_str().to_string(),
                    tup_loc.clone(),
                ))?;
            if let Some(task_inst) = path_buffers.try_get_task(&task_desc).cloned() {
                let env = task_inst.get_env_desc();
                let mut resolved_deps = Vec::new();
                for dep in deps.iter() {
                    let dep =
                        dep.decode(tup_cwd, path_searcher, path_buffers, tup_loc, &search_dirs)?;
                    resolved_deps.extend(dep);
                }
                let resolved_task =
                    ResolvedTask::new(resolved_deps, task_desc, tup_loc.clone(), env.clone());
                tasks.push(resolved_task);
            }
        }

        Ok((Artifacts::from(deglobbed, tasks), output))
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
pub fn parse_dir(root: &Path) -> Result<(Artifacts, ReadWriteBufferObjects), Error> {
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
) -> Result<(Artifacts, ReadWriteBufferObjects), Error> {
    let mut artifacts_all = Artifacts::new();
    let mut parser = TupParser::<DirSearcher>::try_new_from(root, DirSearcher::new())?;
    for tup_file_path in tupfiles.iter() {
        let artifacts = parser.parse(tup_file_path)?;
        artifacts_all.extend(artifacts);
    }
    Ok((
        parser.reresolve(artifacts_all)?,
        parser.read_write_buffers(),
    ))
}
