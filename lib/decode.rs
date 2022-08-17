use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::fmt::Formatter;
use std::hash::Hash;
use std::path::{Path, PathBuf};
use std::vec;

use glob::{GlobBuilder, GlobMatcher};
use path_absolutize::Absolutize;
use regex::{Captures, Regex};
use walkdir::WalkDir;

use bimap::BiMap;
use errors::Error as Err;
use glob;
use pathdiff::diff_paths;
use statements::*;

#[derive(Debug, Default, Eq, PartialEq, Clone, Hash)]
pub struct NormalPath(PathBuf);

impl NormalPath {
    pub(crate) fn absolute_from(path: &Path, tup_cwd: &Path) -> Self {
        let pbuf = path
            .absolutize_from(tup_cwd)
            .expect(format!("could not absolutize path: {:?}/{:?}", tup_cwd, path).as_str())
            .into();
        NormalPath(pbuf)
    }
}

impl<'a> Into<&'a Path> for &'a NormalPath {
    fn into(self) -> &'a Path {
        self.0.as_path()
    }
}

impl NormalPath {
    pub(crate) fn as_path(&self) -> &Path {
        self.0.as_path()
    }
}

#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct RuleRef {
    tup_path: TupPathDescriptor,
    loc: Loc,
}
impl std::fmt::Display for RuleRef {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:?}: {:?}, {:?}",
            self.tup_path, self.loc.line, self.loc.offset
        )
    }
}

impl RuleRef {
    pub fn new(tup_path: &TupPathDescriptor, loc: &Loc) -> RuleRef {
        RuleRef {
            tup_path: tup_path.clone(),
            loc: loc.clone(),
        }
    }
}
/// ```PathDescriptor``` is an id given to a  folder where tupfile was found
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct PathDescriptor(usize);
/// ```GroupPathDescriptor``` is an id given to a group that appears in a tupfile.
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct GroupPathDescriptor(usize);
/// ```BinDescriptor``` is an id given to a  folder where tupfile was found
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct BinDescriptor(usize);
/// ```TupPathDescriptor``` is an unique id given to a tupfile
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct TupPathDescriptor(usize);

macro_rules! impl_from_usize {
    ($t:ty) => {
        impl From<usize> for $t {
            fn from(i: usize) -> Self {
                Self(i)
            }
        }
        impl Default for $t {
            fn default() -> Self {
                Self(usize::MAX)
            }
        }

        impl $t {
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

//path
#[derive(Debug, Default, Clone)]
pub struct GenPathBufferObject<T: PartialEq + Eq + Hash + Clone>(BiMap<NormalPath, T>);

impl<T> GenPathBufferObject<T>
where
    T: Eq + Clone + Hash + From<usize> + std::fmt::Display,
{
    pub fn new() -> Self {
        GenPathBufferObject(BiMap::new())
    }
    pub fn add_relative(&mut self, pathbuf: &Path, tup_cwd: &Path) -> (T, bool) {
        let np = NormalPath::absolute_from(pathbuf, tup_cwd);
        self.add_normalpath(np)
    }
    pub fn add(&mut self, path: &Path) -> (T, bool) {
        let np = NormalPath(path.into());
        self.add_normalpath(np)
    }

    fn add_normalpath(&mut self, np: NormalPath) -> (T, bool) {
        let l = self.0.len();
        if let Some(prev_index) = self.0.get_by_left(&np) {
            (prev_index.clone(), false)
        } else {
            let _ = self.0.insert(np, l.into());
            (l.into(), true)
        }
    }
    pub fn get(&self, pd: &T) -> &NormalPath {
        self.try_get(pd)
            .expect(format!("path for id:{} not in buffer", pd).as_str())
    }
    pub fn try_get(&self, pd: &T) -> Option<&NormalPath> {
        self.0.get_by_right(pd)
    }
}
pub type TupPathBufferObject = GenPathBufferObject<TupPathDescriptor>;
pub type PathBufferObject = GenPathBufferObject<PathDescriptor>;
pub type GroupBufferObject = GenPathBufferObject<GroupPathDescriptor>;
pub type BinBufferObject = GenPathBufferObject<BinDescriptor>;
impl GroupBufferObject {
    fn get_group_name(&self, group_desc: &GroupPathDescriptor) -> String {
        self.get(group_desc)
            .as_path()
            .file_stem()
            .unwrap()
            .to_string_lossy()
            .to_string()
    }
    pub fn add_relative_group(
        &mut self,
        pathexpr: &PathExpr,
        tup_cwd: &Path,
    ) -> (GroupPathDescriptor, bool) {
        if let PathExpr::Group(v1, v2) = pathexpr {
            let pathbuf = Path::new(v1.cat().as_str()).join(Path::new(v2.cat().as_str()));
            self.add_relative(pathbuf.as_path(), tup_cwd)
        } else {
            (Default::default(), false)
        }
    }
}
impl BinBufferObject {
    // add /insert an binId-path pair in binbuffer
    pub fn add_relative_bin(
        &mut self,
        pathexpr: &PathExpr,
        tup_cwd: &Path,
    ) -> (BinDescriptor, bool) {
        if let PathExpr::Bin(v1) = pathexpr {
            let bin_as_path = Path::new(v1);
            self.add_relative(bin_as_path, tup_cwd)
        } else {
            (Default::default(), false)
        }
    }
}
// maps to paths corresponding to bin names, or group names

#[derive(Debug, Default)]
pub struct OutputTagInfo {
    pub output_files: HashSet<PathDescriptor>,
    pub bins: HashMap<BinDescriptor, HashSet<PathDescriptor>>, // paths accumulated in a bin
    pub groups: HashMap<GroupPathDescriptor, HashSet<PathDescriptor>>, // paths accumulated in a group
    pub parent_rule: HashMap<PathDescriptor, RuleRef>, // track the parent rule that generates a output file
}
impl OutputTagInfo {
    pub fn merge_group_tags(&mut self, new_outputs: &mut OutputTagInfo) -> Result<(), Err> {
        for (k, new_paths) in new_outputs.groups.iter_mut() {
            self.groups
                .entry(k.clone())
                .or_insert(HashSet::new())
                .extend(new_paths.iter().map(|x| x.clone()));
            self.checked_merge_parent_rules(&mut new_outputs.parent_rule, new_paths)?;
        }
        Ok(())
    }
    pub fn merge_bin_tags(&mut self, other: &mut OutputTagInfo) -> Result<(), Err> {
        for (k, new_paths) in other.bins.iter_mut() {
            self.bins
                .entry(k.clone())
                .or_insert(HashSet::new())
                .extend(new_paths.iter().map(|x| x.clone()));
            self.checked_merge_parent_rules(&mut other.parent_rule, new_paths)?;
        }
        Ok(())
    }
    pub fn merge_output_files(&mut self, new_outputs: &mut OutputTagInfo) -> Result<(), Err> {
        self.output_files
            .extend(new_outputs.output_files.iter().map(|x| x.clone()));
        self.checked_merge_parent_rules(&mut new_outputs.parent_rule, &new_outputs.output_files)
    }

    fn checked_merge_parent_rules(
        &mut self,
        new_parent_rule: &mut HashMap<PathDescriptor, RuleRef>,
        new_paths: &HashSet<PathDescriptor>,
    ) -> Result<(), Err> {
        for new_path in new_paths.iter() {
            let newparent = new_parent_rule
                .get(&new_path)
                .expect("parent rule not found");
            match self.parent_rule.entry(new_path.clone()) {
                Entry::Occupied(pe) => {
                    if pe.get() != newparent {
                        return Err(Err::MultipleRulesToSameOutput(
                            new_path.clone(),
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

    pub fn new() -> OutputTagInfo {
        Default::default()
    }
    // discover outputs matching glob in the same tupfile
    pub fn outputs_matching_glob(
        &self,
        pbo: &PathBufferObject,
        glob: &MyGlob,
        vs: &mut Vec<MatchingPath>,
    ) {
        let mut pushoutput = |v: &HashSet<_>| {
            for pd in v.iter() {
                if let Some(np) = pbo.try_get(pd) {
                    let p: &Path = np.into();
                    if glob.is_match(p) {
                        vs.push(MatchingPath::with_captures(pd.clone(), glob.group(p, 1)))
                    }
                }
            }
        };
        for (_, v) in self.bins.iter() {
            pushoutput(v)
        }
        for (_, v) in self.groups.iter() {
            pushoutput(v)
        }
        pushoutput(&self.output_files);
    }
}
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
pub struct MyGlob {
    matcher: GlobMatcher,
}

impl MyGlob {
    pub fn new(path_pattern: &str) -> Result<Self, crate::errors::Error> {
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

    pub fn is_match<P: AsRef<Path>>(&self, path: P) -> bool {
        self.matcher.is_match(path)
    }

    // get ith capturing group from matched path
    pub fn group<P: AsRef<Path>>(&self, path: P, i: usize) -> Option<String> {
        self.matcher.group(path, i)
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
    pub fn as_path<'a>(&self, pbo: &'a PathBufferObject) -> &'a Path {
        pbo.get(&self.path_descriptor).into()
    }
}

fn discover_inputs_from_glob(
    glob_path: &Path,
    outputs: &OutputTagInfo,
    pbo: &mut PathBufferObject,
) -> Result<Vec<MatchingPath>, crate::errors::Error> {
    let (mut base_path, recurse) = get_non_pattern_prefix(glob_path);
    let mut to_match = glob_path;
    let pbuf: PathBuf;
    if base_path.eq(&PathBuf::new()) {
        base_path = base_path.join(".");
        pbuf = Path::new(".").join(glob_path);
        to_match = &pbuf;
    }
    let globs = MyGlob::new(to_match.to_string_lossy().as_ref())?;
    let mut walkdir = WalkDir::new(base_path.as_path());
    if !recurse {
        walkdir = walkdir.max_depth(1);
    }
    let filtered_paths = walkdir.into_iter().filter_map(|e| e.ok()).filter(|entry| {
        let match_path = entry.path(); //.strip_prefix(tup_cwd).unwrap();
        globs.is_match(match_path)
    });
    let mut pes = Vec::new();
    for matching in filtered_paths {
        let path = matching.path();
        let (path_desc, _) = pbo.add(path);
        pes.push(MatchingPath::with_captures(path_desc, globs.group(path, 1)));
    }
    // discover inputs from previous outputs
    outputs.outputs_matching_glob(pbo, &globs, &mut pes);
    Ok(pes)
}

// Types of decoded input to rules which includes
// files in glob, group paths, bin entries
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum InputResolvedType {
    Deglob(MatchingPath),
    GroupEntry(GroupPathDescriptor, PathDescriptor),
    UnResolvedGroupEntry(GroupPathDescriptor, PathDescriptor),
    BinEntry(BinDescriptor, PathDescriptor),
}

// resolved paths
pub fn get_resolved_path<'a, 'b>(input_glob: &'a InputResolvedType, pbo: &'b PathBufferObject) -> &'b Path {
    match input_glob {
        InputResolvedType::Deglob(e) => pbo.get(e.path_descriptor()).as_path(),
        InputResolvedType::GroupEntry(_, p) => pbo.get(p).as_path(),
        InputResolvedType::BinEntry(_, p) => pbo.get(p).as_path(),
        InputResolvedType::UnResolvedGroupEntry(_,_,) => Path::new(""),
    }
}
// directory under which the group/bin or path resolved path appears
fn get_glob_dir<'a, 'b>(input_glob: &'a InputResolvedType, pbo: &'b PathBufferObject) -> &'b Path {
    match input_glob {
        InputResolvedType::Deglob(e) => pbo.get(e.path_descriptor()).as_path().parent().unwrap(),
        InputResolvedType::GroupEntry(_, p) => pbo.get(p).as_path(),
        InputResolvedType::BinEntry(_, p) => pbo.get(p).as_path(),
        InputResolvedType::UnResolvedGroupEntry(_,p,) => pbo.get(p).as_path(),
    }
}

// resolved names
fn get_resolved_name<'a, 'b>(input_glob: &'a InputResolvedType, pbo: &PathBufferObject, gbo: &'b GroupBufferObject, bbo: &'b BinBufferObject) -> String {
    match input_glob {
        InputResolvedType::Deglob(e) => pbo.get(e.path_descriptor()).as_path().file_name().unwrap().to_string_lossy().to_string(),
        InputResolvedType::GroupEntry(g, _) => gbo.get(g).0.to_string_lossy().to_string(),
        InputResolvedType::BinEntry(b, _) => bbo.get(b).0.to_string_lossy().to_string(),
        InputResolvedType::UnResolvedGroupEntry(g,_) => gbo.get(g).0.to_string_lossy().to_string()
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

// Get matched glob in the input to a rule
fn as_glob_match(inpg: &InputResolvedType) -> Option<String> {
    match inpg {
        InputResolvedType::Deglob(e) => (e).first_group.as_ref().map(|s| s.clone()),
        _ => None,
    }
}

pub trait ExcludeInputPaths {
    fn exclude(
        &self,
        deglobbed: Vec<InputResolvedType>,
        pbo: &PathBufferObject,
    ) -> Vec<InputResolvedType>;
}
impl ExcludeInputPaths for PathExpr {
    fn exclude(
        &self,
        deglobbed: Vec<InputResolvedType>,
        pbo: &PathBufferObject,
    ) -> Vec<InputResolvedType> {
        match self {
            PathExpr::ExcludePattern(patt) => {
                let re = Regex::new(patt).ok();
                if let Some(ref re) = re {
                    let matches = |i: &InputResolvedType| {
                        let s = get_resolved_path(i, pbo).to_str();
                        if let Some(s) = s {
                            re.captures(s).is_some()
                        } else {
                            false
                        }
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
#[derive(Debug, Clone)]
pub struct BufferObjects {
    pub(crate) pbo: PathBufferObject,
    pub(crate) gbo: GroupBufferObject,
    pub(crate) bbo: BinBufferObject,
    pub(crate) tbo: TupPathBufferObject,
}

impl BufferObjects {
    pub fn add_tup(&mut self, p: &Path) -> (TupPathDescriptor, bool) {
        self.tbo.add(p)
    }
    pub fn add_path(&mut self, p: &Path, tup_cwd: &Path) -> (PathDescriptor, bool) {
        self.pbo.add(&p.absolutize_from(tup_cwd).unwrap())
    }
    pub fn add_group_path(&mut self, p: &PathExpr, tup_cwd: &Path) -> (GroupPathDescriptor, bool) {
        self.gbo.add_relative_group(p, tup_cwd)
    }

    pub fn add_bin_path(&mut self, p: &PathExpr, tup_cwd: &Path) -> (BinDescriptor, bool) {
        self.bbo.add_relative_bin(p, tup_cwd)
    }

    pub fn get_path_buffer_object(&self) -> &PathBufferObject {
        return &self.pbo;
    }

    pub fn get_bin_buffer_object(&self) -> &BinBufferObject {
        return &self.bbo;
    }

    pub fn get_group_buffer_object(&self) -> &GroupBufferObject {
        return &self.gbo;
    }

    pub fn get_name(&self, i:  &InputResolvedType ) -> String {
        get_resolved_name(i, &self.pbo, &self.gbo, &self.bbo)
    }

    pub fn get_dir(&self, i: &InputResolvedType) -> &Path {
        get_glob_dir(i, &self.pbo)
    }
}

impl Default for BufferObjects {
    fn default() -> Self {
        BufferObjects {
            pbo: Default::default(),
            gbo: Default::default(),
            bbo: Default::default(),
            tbo: Default::default(),
        }
    }
}

// Decode input paths from file globs, bins(buckets), and groups
pub trait DecodeInputPaths {
    fn decode(
        &self,
        tup_cwd: &Path,
        tag_info: &OutputTagInfo,
        bo: &mut BufferObjects,
    ) -> Result<Vec<InputResolvedType>, Err>;
}

// Decode input paths in RvalGeneral
impl DecodeInputPaths for PathExpr {
    // convert globs into regular paths, remember that matched groups
    fn decode(
        &self,
        tup_cwd: &Path,
        tag_info: &OutputTagInfo,
        bo: &mut BufferObjects,
    ) -> Result<Vec<InputResolvedType>, Err> {
        let mut vs = Vec::new();
        match self {
            PathExpr::Literal(_) => {
                let path_buf = normalized_path(tup_cwd, self);
                let pes = discover_inputs_from_glob(path_buf.as_path(), tag_info, &mut bo.pbo)?;
                for pe in pes {
                    vs.push(InputResolvedType::Deglob(pe))
                }
            }
            PathExpr::Group(_, _) => {
                let grp_desc = bo.add_group_path(&self, tup_cwd).0;

                if let Some(paths) = tag_info.groups.get(&grp_desc) {
                    for p in paths {
                        vs.push(InputResolvedType::GroupEntry(grp_desc.clone(), p.clone()))
                    }
                }
            }
            PathExpr::Bin(_) => {
                let bin_desc = bo.add_bin_path(&self, tup_cwd).0;

                if let Some(paths) = tag_info.bins.get(&bin_desc) {
                    for p in paths {
                        vs.push(InputResolvedType::BinEntry(bin_desc.clone(), p.clone()))
                    }
                }
            }
            _ => {}
        }
        return Ok(vs);
    }
}
// decode input paths
impl DecodeInputPaths for Vec<PathExpr> {
    fn decode(
        &self,
        tup_cwd: &Path,
        tag_info: &OutputTagInfo,
        bo: &mut BufferObjects,
    ) -> Result<Vec<InputResolvedType>, Err> {
        // gather locations where exclude patterns show up
        let excludeindices: Vec<_> = self
            .iter()
            .enumerate()
            .filter(|pi| matches!(&pi.1, &PathExpr::ExcludePattern(_)))
            .map(|ref pi| pi.0)
            .collect();
        // ....
        let decoded: Result<Vec<_>, _> = self
            .iter()
            // .inspect(|x| eprintln!("before decode {:?}", x))
            .map(|x| x.decode(tup_cwd, &tag_info, bo))
            // .inspect(|x| eprintln!("after {:?}", x))
            .collect();
        let filter_out_excludes =
            |(i, ips): (usize, Vec<InputResolvedType>)| -> Vec<InputResolvedType> {
                // find the immediately following exclude pattern
                let pp = excludeindices.partition_point(|&j| j <= i);
                if pp < excludeindices.len() {
                    // remove paths that match exclude pattern
                    let v = self.as_slice();
                    let exclude_regex = &v[excludeindices[pp]];
                    exclude_regex.exclude(ips, &bo.pbo)
                } else {
                    ips
                }
            };
        Ok(decoded?
            .into_iter()
            .enumerate()
            .map(filter_out_excludes)
            .flatten()
            .collect())
    }
}

// decode input paths

trait GatherOutputs {
    fn gather_outputs(&self, oti: &mut OutputTagInfo) -> Result<(), Err>;
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

pub struct InputsAsPaths {
    raw_inputs: Vec<PathBuf>,
    grps_by_name: HashMap<String, String>,
    raw_inputs_glob_match: Option<InputResolvedType>,
    rule_ref: RuleRef,
}
impl InputsAsPaths {
    pub fn get_group_paths(&self, grp_name: &str) -> Option<&String> {
        self.grps_by_name.get(grp_name)
    }

    pub fn get_file_names(&self) -> Vec<String> {
        self.raw_inputs
            .iter()
            .filter_map(|f| f.file_name())
            .map(|x| x.to_string_lossy().to_string())
            .collect()
    }
    pub fn get_parent_names(&self) -> Vec<String> {
        self.raw_inputs
            .iter()
            .filter_map(|f| f.parent())
            .map(|x| x.to_string_lossy().to_string())
            .collect()
    }
    pub fn parent_folder_name(&self) -> Option<String> {
        self.raw_inputs
            .iter()
            .filter_map(|f| f.parent())
            .filter_map(|f| f.file_name())
            .map(|x| x.to_string_lossy().to_string())
            .next()
    }

    pub fn get_paths(&self) -> Vec<String> {
        self.raw_inputs
            .iter()
            .map(|x| x.to_string_lossy().to_string())
            .collect()
    }

    pub fn get_extension(&self) -> Option<String> {
        self.raw_inputs
            .first()
            .and_then(|x| x.extension())
            .map(|x| x.to_string_lossy().to_string())
    }
    pub fn get_file_stem(&self) -> Vec<String> {
        self.raw_inputs
            .iter()
            .filter_map(|x| x.file_stem())
            .map(|x| x.to_string_lossy().to_string())
            .collect()
    }

    pub fn get_glob(&self) -> Option<String> {
        self.raw_inputs_glob_match
            .as_ref()
            .and_then(|x| as_glob_match(x))
    }

    pub fn is_empty(&self) -> bool {
        self.raw_inputs.is_empty()
    }
}
impl InputsAsPaths {
    pub fn new(
        tup_cwd: &Path,
        inp: &Vec<InputResolvedType>,
        bo: &BufferObjects,
        rule_ref: RuleRef,
    ) -> InputsAsPaths {
        let isnotgrp = |x: &InputResolvedType| !matches!(x, &InputResolvedType::GroupEntry(_, _));
        let relpath = |x| diff_paths(x, tup_cwd).expect("path diff failure");
        let try_grp = |x: &InputResolvedType| {
            if let &InputResolvedType::GroupEntry(ref grp_desc, _) = x {
                Some((
                    bo.gbo.get_group_name(grp_desc),
                    relpath(get_resolved_path(x, &bo.pbo)),
                ))
            } else {
                None
            }
        };
        let allnongroups: Vec<_> = inp
            .iter()
            .filter(|&x| isnotgrp(x))
            .map(|x| relpath(get_resolved_path(x, &bo.pbo)).to_path_buf())
            .collect();
        let mut namedgroupitems: HashMap<_, Vec<String>> = HashMap::new();
        for x in inp.iter().filter_map(|x| try_grp(x)) {
            namedgroupitems
                .entry(x.0)
                .or_insert(Default::default())
                .push(x.1.to_string_lossy().to_string())
        }
        let namedgroupitems = namedgroupitems
            .drain()
            .map(|(s, v)| (s, v.join(" ")))
            .collect();
        InputsAsPaths {
            raw_inputs: allnongroups,
            grps_by_name: namedgroupitems,
            raw_inputs_glob_match: inp.first().map(|x| x.clone()),
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

            let replacer = |caps: &Captures| {
                let c = caps
                    .get(1)
                    .ok_or(Err::StaleGroupRef("unknown".to_string(), rule_ref.clone()))?;
                inputs
                    .get_group_paths(c.as_str())
                    .map(|x| x.clone())
                    .ok_or(Err::StaleGroupRef(c.as_str().to_string(), rule_ref.clone()))
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
                    i = i + 1;
                    r.as_str()
                })
                .to_string();

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
                    .ok_or(Err::StalePerc('e', rule_ref.clone()))?;
                d.replace("%e", ext.as_str())
            } else {
                d
            };
            let d = if d.contains("%d") {
                let parent_name = inp
                    .parent_folder_name()
                    .ok_or(Err::StalePerc('d', rule_ref.clone()))?;
                d.replace("%d", parent_name.as_str())
            } else {
                d
            };
            let d = if d.contains("%g") {
                let glb = inp
                    .get_glob()
                    .ok_or(Err::StalePerc('g', rule_ref.clone()))?;
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
            PathExpr::Literal(frep(inputs, secondary_inputs, s)?.to_string())
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
                .ok_or(Err::StalePercNumberedRef(c, rule_ref.clone()))
        })
        .collect();
    let reps = reps?;
    let mut i: usize = 0;
    let s = perc_b_re.replace(decoded_str, |_: &Captures| {
        let r = reps[i];
        i = i + 1;
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
                    .ok_or(Err::StalePerc('O', outputs.rule_ref.clone()))?;
                d.replace("%O", stem.as_str())
            } else {
                d.to_string()
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
                d.to_string()
            };
            Ok(d)
        };
        Ok(if let PathExpr::Literal(s) = self {
            PathExpr::Literal(frep(s)?)
        } else {
            self.clone()
        })
    }
}

fn normalized_path(tup_cwd: &Path, x: &PathExpr) -> PathBuf {
    let pbuf = PathBuf::new().join(x.cat_ref().replace('\\', "/").as_str());
    if tup_cwd.eq(Path::new(".")) {
        pbuf
    } else {
        pbuf.absolutize_from(tup_cwd).unwrap().to_path_buf()
    }
}
fn paths_from_exprs(tup_cwd: &Path, p: &Vec<PathExpr>) -> Vec<OutputType> {
    p.split(|x| matches!(x, &PathExpr::Sp1))
        .map(|x| {
            if x.is_empty() {
                OutputType::new(PathBuf::new())
            } else {
                let path = PathBuf::new().join(&x.to_vec().cat());
                let pathbuf = if !tup_cwd.eq(Path::new(".")) {
                    path.as_path()
                        .absolutize_from(tup_cwd)
                        .unwrap()
                        .to_path_buf()
                } else {
                    path
                };
                OutputType::new(pathbuf)
            }
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
        sinputs: &InputsAsPaths,
    ) -> Result<Self, Err> {
        Ok(RuleFormula {
            description: self
                .description
                .decode_input_place_holders(inputs, sinputs)?,
            formula: self.formula.decode_input_place_holders(inputs, sinputs)?,
        })
    }
}

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
    tup_cwd: &Path,
    t: &Target,
    r: &RuleFormula,
    rule_ref: &RuleRef,
    primary_deglobbed_inps: Vec<InputResolvedType>,
    secondary_deglobbed_inps: Vec<InputResolvedType>,
    bo: &mut BufferObjects,
) -> Result<ResolvedLink, Err> {
    let input_as_paths =
        InputsAsPaths::new(tup_cwd, &primary_deglobbed_inps, &bo, rule_ref.clone());
    let secondary_inputs_as_paths =
        InputsAsPaths::new(tup_cwd, &secondary_deglobbed_inps, &bo, rule_ref.clone());
    let mut decoded_target =
        t.decode_input_place_holders(&input_as_paths, &secondary_inputs_as_paths)?;
    let pp = paths_from_exprs(tup_cwd, &t.primary);
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
    let sec_pp = paths_from_exprs(tup_cwd, &t.secondary);
    let resolved_rule: RuleFormula = r
        .decode_input_place_holders(&input_as_paths, &secondary_inputs_as_paths)?
        .decode_output_place_holders(&output_as_paths)?;

    let bin_desc = t
        .bin
        .as_ref()
        .map(|x| bo.bbo.add_relative_bin(x, tup_cwd).0);
    let group_desc = t
        .group
        .as_ref()
        .map(|x| bo.gbo.add_relative_group(x, tup_cwd).0);
    let l = ResolvedLink {
        primary_sources: primary_deglobbed_inps,
        secondary_sources: secondary_deglobbed_inps,
        rule_formula: resolved_rule,
        primary_target: pp
            .into_iter()
            .map(|x| bo.pbo.add_relative(x.as_path(), tup_cwd).0)
            .collect(),
        secondary_targets: sec_pp
            .into_iter()
            .map(|x| bo.pbo.add_relative(x.as_path(), tup_cwd).0)
            .collect(),
        bin: bin_desc,
        group: group_desc,
        rule_ref: rule_ref.clone(),
    };
    Ok(l)
}

pub struct ResolvedLink {
    pub primary_sources: Vec<InputResolvedType>,
    pub secondary_sources: Vec<InputResolvedType>,
    pub rule_formula: RuleFormula,
    pub primary_target: Vec<PathDescriptor>,
    pub secondary_targets: Vec<PathDescriptor>,
    pub group: Option<GroupPathDescriptor>,
    pub bin: Option<BinDescriptor>,
    pub rule_ref: RuleRef,
}

// update the groups/bins with the path to primary target and also add secondary targets
impl GatherOutputs for ResolvedLink {
    fn gather_outputs(&self, oti: &mut OutputTagInfo) -> Result<(), Err> {
        let rule_ref = &self.rule_ref;
        for path_desc in self
            .primary_target
            .iter()
            .chain(self.secondary_targets.iter())
        {
            let e = oti.parent_rule.entry(path_desc.clone());
            match e {
                Entry::Occupied(p) => {
                    return Err(Err::MultipleRulesToSameOutput(
                        path_desc.clone(),
                        rule_ref.clone(),
                        p.get().clone(),
                    ));
                }
                Entry::Vacant(p) => p.insert(rule_ref.clone()),
            };
            oti.output_files.insert(path_desc.clone());
        }
        for path_desc in self.primary_target.iter() {
            if let Some(ref group_desc) = self.group {
                oti.groups
                    .entry(group_desc.clone())
                    .or_insert(HashSet::new())
                    .insert(path_desc.clone());
            };
            if let Some(ref bin_name) = self.bin {
                oti.bins
                    .entry(bin_name.clone())
                    .or_insert(HashSet::new())
                    .insert(path_desc.clone());
            };
        }
        Ok(())
    }
}

pub trait ResolvePaths {
    fn resolve_paths(
        &self,
        tupfile: &Path,
        taginfo: &OutputTagInfo,
        bo: &mut BufferObjects,
        tup_desc: &TupPathDescriptor,
    ) -> Result<(Vec<ResolvedLink>, OutputTagInfo), Err>;
}

/// deglob rule statement into multiple deglobbed rules, gather deglobbed targets to put in the bins/groups
impl ResolvePaths for LocatedStatement {
    fn resolve_paths(
        &self,
        tupfile: &Path,
        taginfo: &OutputTagInfo,
        bo: &mut BufferObjects,
        tup_desc: &TupPathDescriptor,
    ) -> Result<(Vec<ResolvedLink>, OutputTagInfo), Err> {
        let mut deglobbed = Vec::new();
        let mut output: OutputTagInfo = Default::default();
        let tupcwd = if tupfile.is_dir() {
            tupfile
        } else {
            tupfile.parent().unwrap()
        };
        if let LocatedStatement {
            statement:
                Statement::Rule(Link {
                    source: s,
                    target: t,
                    rule_formula,
                    pos: _pos,
                }),
            loc,
        } = self
        {
            let rule_ref = RuleRef::new(&tup_desc, loc);
            let inpdec = s.primary.decode(tupcwd, &taginfo, bo)?;
            let secondinpdec = s.secondary.decode(tupcwd, &taginfo, bo)?;
            let for_each = s.for_each;
            if for_each {
                for input in inpdec {
                    let vis = vec![input];
                    let delink = get_deglobbed_rule(
                        tupcwd,
                        &t,
                        &rule_formula,
                        &rule_ref,
                        vis,
                        secondinpdec.clone(),
                        bo,
                    )?;
                    deglobbed.push(delink);
                    {
                        deglobbed.last().map(|x| x.gather_outputs(&mut output));
                    }
                }
            } else {
                let vis: Vec<_> = inpdec.into_iter().collect();
                let delink = get_deglobbed_rule(
                    tupcwd,
                    &t,
                    &rule_formula,
                    &rule_ref,
                    vis,
                    secondinpdec.clone(),
                    bo,
                )?;
                deglobbed.push(delink);
                {
                    deglobbed.last().map(|x| x.gather_outputs(&mut output));
                }
            }
        }
        Ok((deglobbed, output))
    }
}

impl ResolvePaths for Vec<LocatedStatement> {
    fn resolve_paths(
        &self,
        tupfile: &Path,
        taginfo: &OutputTagInfo,
        bo: &mut BufferObjects,
        tbo: &TupPathDescriptor,
    ) -> Result<(Vec<ResolvedLink>, OutputTagInfo), Err> {
        let mut vs = Vec::new();
        let mut alltaginfos = OutputTagInfo::new();
        for stmt in self.iter() {
            let (ref mut stmts, ref mut outputtaginfo) =
                stmt.resolve_paths(tupfile, taginfo, bo, tbo)?;
            alltaginfos.merge_group_tags(outputtaginfo)?;
            alltaginfos.merge_bin_tags(outputtaginfo)?;
            alltaginfos.merge_output_files(outputtaginfo)?;
            vs.append(stmts);
        }
        Ok((vs, alltaginfos))
    }
}
