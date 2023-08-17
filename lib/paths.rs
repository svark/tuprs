//! Module for handling paths and glob patterns in tupfile.
use std::borrow::Cow;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fmt::{Display, Formatter};
use std::path::{Component, Path, PathBuf};

use log::debug;
use path_dedot::ParseDot;
use pathdiff::diff_paths;
use regex::Regex;

use crate::buffers::{
    BinBufferObject, GlobPathDescriptor, GroupBufferObject, MyGlob, PathBufferObject, PathBuffers,
};
use crate::decode::{GroupInputs, RuleRef};
use crate::errors::Error;
use crate::glob::Candidate;
use crate::statements::{CatRef, PathExpr};
use crate::{BinDescriptor, GroupPathDescriptor, PathDescriptor};

/// Normal path holds paths wrt root directory and can be compared with other paths
/// It is used to store paths in a normalized form (slash-corrected) and to compare paths
#[derive(Debug, Default, Eq, PartialEq, Clone, Hash)]
pub struct NormalPath {
    inner: PathBuf,
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
    if num_comps < glob_path.components().count() {
        (prefix, true)
    } else {
        (prefix.parent().unwrap().to_path_buf(), false)
    }
}

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
        //normalize_path(self.as_path()).to_string()
        self.as_path().to_string_lossy().to_string()
    }
}

impl NormalPath {
    /// Construct consuming the given pathbuf
    fn new(p: PathBuf) -> NormalPath {
        if p.as_os_str().is_empty() || p.as_os_str() == "/" || p.as_os_str() == "\\" {
            NormalPath {
                inner: PathBuf::from("."),
            }
        } else {
            NormalPath { inner: p }
        }
    }

    pub(crate) fn new_from_cow_path(p: Cow<Path>) -> NormalPath {
        NormalPath::new_from_cow_str(Candidate::new(p.as_ref()).to_cow_str())
    }
    fn new_from_cow_str(p: Cow<str>) -> NormalPath {
        NormalPath::new(PathBuf::from(p.as_ref()))
    }

    /// Construct a `NormalPath' by joining tup_cwd with path
    pub fn absolute_from(path: &Path, tup_cwd: &Path) -> Self {
        let p1 = Self::cleanup(path, tup_cwd);
        let np = NormalPath::new_from_cow_path(Cow::from(p1));
        debug!("abs:{:?}", np);
        np
    }

    pub(crate) fn cleanup<P: AsRef<Path>>(path: &Path, tup_cwd: P) -> PathBuf {
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

/// Expose the inner path of NormalPath via the `into' call or Path::from
impl<'a> From<&'a NormalPath> for &'a Path {
    fn from(np: &'a NormalPath) -> Self {
        np.as_path()
    }
}

/// A Matching path id discovered using glob matcher along with captured groups
#[derive(Debug, Default, Eq, PartialEq, Clone, Hash)]
pub struct MatchingPath {
    /// path that matched a glob
    path_descriptor: PathDescriptor,
    /// path that matched a glob
    path: NormalPath,
    /// id of the glob pattern that matched this path
    glob_descriptor: Option<GlobPathDescriptor>,
    /// first glob match in the above path
    captured_globs: Vec<String>,
}

impl Display for MatchingPath {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "MatchingPath(path:{:?}, captured_globs:{:?})",
            self.path.as_path(),
            self.captured_globs
        ))
    }
}

impl MatchingPath {
    ///Create a bare matching path with no captured groups
    pub fn new(path_descriptor: PathDescriptor, path: NormalPath) -> MatchingPath {
        MatchingPath {
            path_descriptor,
            path,
            glob_descriptor: None,
            captured_globs: vec![],
        }
    }

    /// Create a `MatchingPath` with captured glob strings.
    pub fn with_captures(
        path_descriptor: PathDescriptor,
        path: NormalPath,
        glob: &GlobPathDescriptor,
        captured_globs: Vec<String>,
    ) -> MatchingPath {
        MatchingPath {
            path_descriptor,
            path,
            glob_descriptor: Some(*glob),
            captured_globs,
        }
    }
    /// Get path descriptor represented by this entry
    pub fn path_descriptor(&self) -> &PathDescriptor {
        &self.path_descriptor
    }

    /// Get Path represented by this entry
    pub fn get_path(&self) -> &Path {
        self.path.as_path()
    }

    /// Get id of the glob pattern that matched this path
    pub fn glob_descriptor(&self) -> Option<GlobPathDescriptor> {
        self.glob_descriptor
    }

    /// Captured globs
    pub(crate) fn get_captured_globs(&self) -> &Vec<String> {
        &self.captured_globs
    }

    // For recursive prefix globs, we need to get the prefix of the glob path
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
    pub fn new<U: Into<usize>>(p: NormalPath, id: U) -> Self {
        IdedPath::<T> {
            p,
            id: (id.into()).into(),
        }
    }
    pub fn as_path(&self) -> &Path {
        self.p.as_path()
    }
    pub fn as_desc(&self) -> &T {
        &self.id
    }
    pub fn from_rel_path(tup_cwd: &Path, p: &Path, path_buffers: &mut impl PathBuffers) -> Self {
        //let tup_cwd = path_buffers.get_root_dir().join(tup_cwd);
        let np = NormalPath::absolute_from(p, tup_cwd);
        let id = path_buffers.add_abs(np.as_path()).0;
        Self::new(np, id)
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
        let (mut base_path, _has_glob) = get_non_pattern_prefix(ided_path.as_path());
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
    pub fn get_glob_path_desc(&self) -> PathDescriptor {
        let gp_desc = usize::from(*self.glob_path.as_desc());
        gp_desc.into()
    }
    /// Id to the glob path from root
    pub fn get_glob_desc(&self) -> &GlobPathDescriptor {
        self.glob_path.as_desc()
    }
    /// Glob path as [Path]
    pub fn get_abs_path(&self) -> &Path {
        self.glob_path.as_path()
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
        let glob_path = self.get_abs_path();
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

    /// Check if the glob path has a recursive prefix
    pub fn is_recursive_prefix(&self) -> bool {
        self.glob.is_recursive_prefix()
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

pub(crate) struct OutputsAsPaths {
    outputs: Vec<PathBuf>,
    rule_ref: RuleRef,
}

impl OutputsAsPaths {
    /// Create a new instance of OutputsAsPaths from a list of paths and a rule reference
    pub(crate) fn new(outputs: Vec<PathBuf>, rule_ref: RuleRef) -> Self {
        Self { outputs, rule_ref }
    }
    /// returns all the outputs as vector of strings
    pub fn get_paths(&self) -> Vec<String> {
        self.outputs
            .iter()
            .map(|x| x.as_path().to_string_lossy().to_string())
            .collect()
    }
    ///  returns the stem portion of each output file. See [Path::file_stem]
    pub fn get_file_stem(&self) -> Option<String> {
        self.outputs
            .first()
            .and_then(|x| x.as_path().file_stem())
            .map(|x| x.to_string_lossy().to_string())
    }
    /// Checks if there are no outputs
    pub fn is_empty(&self) -> bool {
        self.outputs.is_empty()
    }

    pub(crate) fn get_rule_ref(&self) -> &RuleRef {
        &self.rule_ref
    }
}

/// `InputsAsPaths' represents resolved inputs to pass to a rule.
/// Bins are converted to raw paths, groups paths are expanded into a space separated path list
pub struct InputsAsPaths {
    raw_inputs: Vec<NormalPath>,
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

    pub(crate) fn get_rule_ref(&self) -> &RuleRef {
        &self.rule_ref
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
            NormalPath::new_from_cow_path(Cow::Owned(
                diff_paths(x, tup_cwd)
                    .unwrap_or_else(|| panic!("path diff failure {:?} with base:{:?}", x, tup_cwd)),
            ))
        };
        let try_grp = |x: &InputResolvedType| {
            if let &InputResolvedType::GroupEntry(ref grp_desc, _) = x {
                Some((
                    path_buffers.get_group_name(grp_desc),
                    relpath(path_buffers.get_path_from(x)),
                ))
            } else if let &InputResolvedType::UnResolvedGroupEntry(ref grp_desc) = x {
                let grp_name = path_buffers.get_group_name(grp_desc);
                Some((grp_name.clone(), NormalPath::new(PathBuf::from(grp_name))))
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
                .push(x.1.to_string())
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

pub(crate) fn normalized_path(x: &PathExpr) -> PathBuf {
    //  backslashes with forward slashes
    let pbuf = PathBuf::new().join(x.cat_ref().replace('\\', "/").as_str());
    pbuf
    //NormalPath::absolute_from(pbuf.as_path(), tup_cwd).to_path_buf()
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
    pub(crate) fn get_resolved_path<'a, 'b>(&'a self, pbo: &'b PathBufferObject) -> &'b Path {
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
    pub(crate) fn get_resolved_name<'a, 'b>(
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
