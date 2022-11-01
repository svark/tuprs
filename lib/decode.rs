use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::fmt::Formatter;
use std::hash::Hash;
use std::path::{Path, PathBuf};

use glob::{GlobBuilder, GlobMatcher};
use jwalk::WalkDir;
use path_absolutize::Absolutize;
use regex::{Captures, Regex};

use bimap::hash::{LeftValues, RightValues};
use bimap::BiMap;
use errors::Error as Err;
use glob;
use log::log;
use log::Level::Debug;
use pathdiff::diff_paths;
use statements::*;
use transform::SubstMap;

#[derive(Debug, Default, Eq, PartialEq, Clone, Hash)]
pub struct NormalPath(PathBuf);

impl NormalPath {
    pub fn new(p: PathBuf) -> NormalPath {
        NormalPath(p)
    }
    pub fn absolute_from(path: &Path, tup_cwd: &Path) -> Self {
        let pbuf = path
            .absolutize_from(tup_cwd)
            .expect(format!("could not absolutize path: {:?}/{:?}", tup_cwd, path).as_str())
            .into();
        NormalPath(pbuf)
    }
    pub fn as_path(&self) -> &Path {
        self.0.as_path()
    }
    pub fn get_str(&self) -> String {
        self.as_path().to_string_lossy().to_string()
    }
}

impl<'a> Into<&'a Path> for &'a NormalPath {
    fn into(self) -> &'a Path {
        self.0.as_path()
    }
}

#[derive(Debug, Default, PartialEq, Eq, Clone, Hash)]
pub struct RuleRef {
    tup_path: TupPathDescriptor,
    loc: Loc,
}

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
    pub fn get_line(&self) -> u32 {
        self.loc.line
    }
    pub fn get_dir_desc(&self) -> &TupPathDescriptor {
        return &self.tup_path;
    }

    pub fn get_tup_path<'a, 'b>(&'a self, bo: &'b BufferObjects) -> &'b Path {
        bo.get_tup_buffer_object()
            .get(self.get_dir_desc())
            .as_path()
    }
}

impl RuleFormulaUsage {
    pub fn new(rule_formula: RuleFormula, rule_ref: RuleRef) -> RuleFormulaUsage {
        RuleFormulaUsage {
            rule_formula,
            rule_ref,
        }
    }
    pub fn get_formula(&self) -> &RuleFormula {
        &self.rule_formula
    }
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

#[derive(Debug, PartialEq, Eq, Clone, Hash, Copy)]
pub struct RuleDescriptor(usize);

macro_rules! impl_from_usize {
    ($t:ty) => {
        impl From<usize> for $t {
            fn from(i: usize) -> Self {
                Self(i)
            }
        }
        impl Into<usize> for $t {
            fn into(self) -> usize {
                self.0
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
impl_from_usize!(RuleDescriptor);

//path
#[derive(Debug, Default, Clone)]
pub struct GenPathBufferObject<T: PartialEq + Eq + Hash + Clone>(BiMap<NormalPath, T>);

#[derive(Debug, Default, Clone)]
pub struct GenEnvBufferObject<T: PartialEq + Eq + Hash + Clone>(BiMap<Env, T>, usize);

#[derive(Debug, Default, Clone)]
pub struct GenRuleBufferObject<T: PartialEq + Eq + Hash + Clone>(BiMap<RuleFormulaUsage, T>);

impl<T> GenEnvBufferObject<T>
where
    T: Eq + Clone + Hash + From<usize> + std::fmt::Display,
{
    pub fn new(start: usize) -> Self {
        GenEnvBufferObject(BiMap::new(), start)
    }
    pub fn add_env(&mut self, env: Env) -> (T, bool) {
        let l = self.1;
        if let Some(prev_index) = self.0.get_by_left(&env) {
            (prev_index.clone(), false)
        } else {
            let _ = self.0.insert(env, l.into());
            self.1 = self.1 + 1;
            (l.into(), true)
        }
    }
    pub fn has_env(&mut self, var: &String) -> bool {
        let start = self.1;
        if let Some(rvalue) = self.0.get_by_right(&(start - 1).into()) {
            rvalue.contains(var)
        } else {
            false
        }
    }

    pub fn get_env(&self) -> LeftValues<'_, Env, T> {
        self.0.left_values()
    }

    pub fn get(&self, pd: &T) -> &Env {
        self.try_get(pd)
            .expect(format!("env for id:{} not in buffer", pd).as_str())
    }

    pub fn try_get(&self, pd: &T) -> Option<&Env> {
        self.0.get_by_right(pd)
    }

    pub fn try_get_id(&self, env: &Env) -> Option<&T> {
        self.0.get_by_left(env)
    }
}

impl<T> GenPathBufferObject<T>
where
    T: Eq + Clone + Hash + From<usize> + std::fmt::Display,
{
    pub fn new() -> Self {
        GenPathBufferObject(BiMap::new())
    }
    pub fn add_relative(&mut self, pathbuf: &Path, tup_cwd: &Path) -> (T, bool) {
        let np = NormalPath::absolute_from(pathbuf, tup_cwd);
        self.add_normal_path(np)
    }
    pub fn add<P: AsRef<Path>>(&mut self, path: P) -> (T, bool) {
        let np = NormalPath(path.as_ref().into());
        self.add_normal_path(np)
    }

    pub fn add_normal_path_with_id(&mut self, np: NormalPath, id: usize) -> (T, bool) {
        if let Some(prev_index) = self.0.get_by_left(&np) {
            (prev_index.clone(), false)
        } else {
            let _ = self.0.insert(np, id.into());
            (id.into(), true)
        }
    }
    pub fn get_paths(&self) -> LeftValues<'_, NormalPath, T> {
        self.0.left_values()
    }
    pub fn get_ids(&self) -> RightValues<'_, NormalPath, T> {
        self.0.right_values()
    }

    fn add_normal_path(&mut self, np: NormalPath) -> (T, bool) {
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

    pub fn try_get_id(&self, path: &NormalPath) -> Option<&T> {
        self.0.get_by_left(path)
    }
}
pub type TupPathBufferObject = GenPathBufferObject<TupPathDescriptor>;
pub type PathBufferObject = GenPathBufferObject<PathDescriptor>;
pub type EnvBufferObject = GenEnvBufferObject<EnvDescriptor>;
pub type GroupBufferObject = GenPathBufferObject<GroupPathDescriptor>;
pub type BinBufferObject = GenPathBufferObject<BinDescriptor>;
pub type RuleBufferObject = GenRuleBufferObject<RuleDescriptor>;

impl GroupBufferObject {
    fn get_group_name(&self, group_desc: &GroupPathDescriptor) -> String {
        self.get(group_desc)
            .as_path()
            .file_stem()
            .unwrap()
            .to_string_lossy()
            .to_string()
    }
    pub fn add_relative_group_by_path(
        &mut self,
        grp_path: &Path,
        tup_cwd: &Path,
    ) -> (GroupPathDescriptor, bool) {
        self.add_relative(grp_path, tup_cwd)
    }
    pub fn add_relative_group(
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
}

impl RuleBufferObject {
    pub fn add_rule(&mut self, r: RuleFormulaUsage) -> (RuleDescriptor, bool) {
        let l = self.0.len();
        if let Some(prev_index) = self.0.get_by_left(&r) {
            (prev_index.clone(), false)
        } else {
            let _ = self.0.insert(r, l.into());
            (l.into(), true)
        }
    }

    pub fn get_id(&self, r: &RuleFormulaUsage) -> Option<&RuleDescriptor> {
        self.0.get_by_left(r)
    }

    pub fn get_rule(&self, id: &RuleDescriptor) -> Option<&RuleFormulaUsage> {
        self.0.get_by_right(id)
    }
}
impl BinBufferObject {
    // add /insert an binId-path pair in bin buffer
    pub fn add_relative_bin(
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
// maps to paths corresponding to bin names, or group names

#[derive(Debug, Default, Clone)]
pub struct OutputTagInfo {
    pub output_files: HashSet<PathDescriptor>,
    pub bins: HashMap<BinDescriptor, HashSet<PathDescriptor>>, // paths accumulated in a bin
    pub groups: HashMap<GroupPathDescriptor, HashSet<PathDescriptor>>, // paths accumulated in a group
    pub parent_rule: HashMap<PathDescriptor, RuleRef>, // track the parent rule that generates a output file
    pub resolve_groups: bool,
}
impl OutputTagInfo {
    fn merge_group_tags(&mut self, new_outputs: &OutputTagInfo) -> Result<(), Err> {
        for (k, new_paths) in new_outputs.groups.iter() {
            self.groups
                .entry(k.clone())
                .or_insert(HashSet::new())
                .extend(new_paths.iter().map(|x| x.clone()));
            self.merge_parent_rules(&new_outputs.parent_rule, new_paths)?;
        }
        Ok(())
    }
    fn merge_bin_tags(&mut self, other: &OutputTagInfo) -> Result<(), Err> {
        for (k, new_paths) in other.bins.iter() {
            self.bins
                .entry(k.clone())
                .or_insert(HashSet::new())
                .extend(new_paths.iter().map(|x| x.clone()));
            self.merge_parent_rules(&other.parent_rule, new_paths)?;
        }
        Ok(())
    }

    pub fn merge(&mut self, out: &OutputTagInfo) -> Result<(), Err> {
        self.merge_group_tags(out)?;
        self.merge_output_files(out)?;
        self.merge_bin_tags(out)
    }
    fn merge_output_files(&mut self, new_outputs: &OutputTagInfo) -> Result<(), Err> {
        self.output_files
            .extend(new_outputs.output_files.iter().map(|x| x.clone()));
        self.merge_parent_rules(&new_outputs.parent_rule, &new_outputs.output_files)
    }

    fn merge_parent_rules(
        &mut self,
        new_parent_rule: &HashMap<PathDescriptor, RuleRef>,
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
        OutputTagInfo {
            resolve_groups: true,
            ..Default::default()
        }
    }
    pub fn new_no_resolve_groups() -> OutputTagInfo {
        Default::default()
    }

    pub fn clearbins(&mut self) {
        self.bins.clear()
    }
    // discover outputs matching glob in the same tupfile
    pub fn outputs_matching_glob(
        &self,
        pbo: &PathBufferObject,
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
                    if let Some(np) = pbo.try_get(pd) {
                        let p: &Path = np.into();
                        if glob.is_match(p) && hs.insert(*pd) {
                            vs.push(MatchingPath::with_captures(pd.clone(), glob.group(p, 1)))
                        }
                    }
                }
            });
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

pub(crate) fn discover_inputs_from_glob(
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
        let (path_desc, _) = pbo.add(path.clone());
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
pub fn get_resolved_path<'a, 'b>(
    input_glob: &'a InputResolvedType,
    pbo: &'b PathBufferObject,
) -> &'b Path {
    match input_glob {
        InputResolvedType::Deglob(e) => pbo.get(e.path_descriptor()).as_path(),
        InputResolvedType::GroupEntry(_, p) => pbo.get(p).as_path(),
        InputResolvedType::BinEntry(_, p) => pbo.get(p).as_path(),
        InputResolvedType::UnResolvedGroupEntry(_, _) => Path::new(""),
    }
}
// directory under which the group/bin or path resolved path appears
fn get_glob_dir<'a, 'b>(input_glob: &'a InputResolvedType, pbo: &'b PathBufferObject) -> &'b Path {
    match input_glob {
        InputResolvedType::Deglob(e) => pbo.get(e.path_descriptor()).as_path().parent().unwrap(),
        InputResolvedType::GroupEntry(_, p) => pbo.get(p).as_path(),
        InputResolvedType::BinEntry(_, p) => pbo.get(p).as_path(),
        InputResolvedType::UnResolvedGroupEntry(_, p) => pbo.get(p).as_path(),
    }
}

// resolved names
fn get_resolved_name<'a, 'b>(
    input_glob: &'a InputResolvedType,
    pbo: &PathBufferObject,
    gbo: &'b GroupBufferObject,
    bbo: &'b BinBufferObject,
) -> String {
    match input_glob {
        InputResolvedType::Deglob(e) => pbo
            .get(e.path_descriptor())
            .as_path()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string(),
        InputResolvedType::GroupEntry(g, _) => gbo.get(g).0.to_string_lossy().to_string(),
        InputResolvedType::BinEntry(b, _) => bbo.get(b).0.to_string_lossy().to_string(),
        InputResolvedType::UnResolvedGroupEntry(g, _) => gbo.get(g).0.to_string_lossy().to_string(),
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
#[derive(Debug, Clone, Default)]
pub struct BufferObjects {
    pub(crate) pbo: PathBufferObject,
    pub(crate) gbo: GroupBufferObject,
    pub(crate) bbo: BinBufferObject,
    pub(crate) tbo: TupPathBufferObject,
    pub(crate) ebo: EnvBufferObject,
    pub(crate) rbo: RuleBufferObject,
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

    pub fn add_rule(&mut self, r: RuleFormulaUsage) -> (RuleDescriptor, bool) {
        self.rbo.add_rule(r)
    }

    pub fn get_path_buffer_object(&self) -> &PathBufferObject {
        return &self.pbo;
    }

    pub fn get_mut_path_buffer_object(&mut self) -> &mut PathBufferObject {
        return &mut self.pbo;
    }
    pub fn get_mut_tup_buffer_object(&mut self) -> &mut TupPathBufferObject {
        return &mut self.tbo;
    }

    pub fn get_mut_env_buffer_object(&mut self) -> &mut EnvBufferObject {
        return &mut self.ebo;
    }

    pub fn get_env_buffer_object(&self) -> &EnvBufferObject {
        return &self.ebo;
    }

    pub fn get_bin_buffer_object(&self) -> &BinBufferObject {
        return &self.bbo;
    }

    pub fn get_group_buffer_object(&self) -> &GroupBufferObject {
        return &self.gbo;
    }

    pub fn get_mut_group_buffer_object(&mut self) -> &mut GroupBufferObject {
        return &mut self.gbo;
    }

    pub fn get_mut_rule_buffer_object(&mut self) -> &mut RuleBufferObject {
        return &mut self.rbo;
    }

    pub fn get_rule_buffer_object(&self) -> &RuleBufferObject {
        return &self.rbo;
    }
    pub fn get_tup_buffer_object(&self) -> &TupPathBufferObject {
        return &self.tbo;
    }

    pub fn get_name(&self, i: &InputResolvedType) -> String {
        get_resolved_name(i, &self.pbo, &self.gbo, &self.bbo)
    }

    pub fn get_dir(&self, i: &InputResolvedType) -> &Path {
        get_glob_dir(i, &self.pbo)
    }

    pub fn get_rule(&self, id: &RuleDescriptor) -> &RuleFormulaUsage {
        self.rbo
            .get_rule(id)
            .expect(&*format!("unable to fetch rule formula for id:{}", id))
    }

    pub fn try_get_rule(&self, id: &RuleDescriptor) -> Option<&RuleFormulaUsage> {
        self.rbo.get_rule(id)
    }
}

// Decode input paths from file globs, bins(buckets), and groups
pub trait DecodeInputPaths {
    fn decode(
        &self,
        tup_cwd: &Path,
        tag_info: &OutputTagInfo,
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
        tag_info: &OutputTagInfo,
        bo: &mut BufferObjects,
        rule_ref: &RuleRef,
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
            PathExpr::Group(p, _) => {
                let grp_desc = bo.add_group_path(&self, tup_cwd).0;
                if tag_info.resolve_groups {
                    if let Some(paths) = tag_info.groups.get(&grp_desc) {
                        for p in paths {
                            vs.push(InputResolvedType::GroupEntry(grp_desc.clone(), p.clone()))
                        }
                    } else {
                        let (pd, _) = bo.pbo.add_relative(Path::new(&*p.cat()), tup_cwd);
                        vs.push(InputResolvedType::UnResolvedGroupEntry(
                            grp_desc.clone(),
                            pd,
                        ))
                    }
                } else {
                    let (pd, _) = bo.pbo.add_relative(Path::new(&*p.cat()), tup_cwd);
                    vs.push(InputResolvedType::UnResolvedGroupEntry(
                        grp_desc.clone(),
                        pd,
                    ))
                }
            }
            PathExpr::Bin(b) => {
                let bin_desc = bo.add_bin_path(&self, tup_cwd).0;
                if let Some(paths) = tag_info.bins.get(&bin_desc) {
                    for p in paths {
                        vs.push(InputResolvedType::BinEntry(bin_desc.clone(), p.clone()))
                    }
                } else {
                    return Err(crate::errors::Error::StaleBinRef(
                        b.clone(),
                        rule_ref.clone(),
                    ));
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
        rule_ref: &RuleRef,
    ) -> Result<Vec<InputResolvedType>, Err> {
        // gather locations where exclude patterns show up
        let excludeindices: Vec<_> = self
            .iter()
            .enumerate()
            .filter(|pi| matches!(&pi.1, &PathExpr::ExcludePattern(_)))
            .map(|ref pi| pi.0)
            .collect();
        // now collect decoded pathexprs that form inputs
        let decoded: Result<Vec<_>, _> = self
            .iter()
            // .inspect(|x| eprintln!("before decode {:?}", x))
            .map(|x| x.decode(tup_cwd, &tag_info, bo, &rule_ref))
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
    groups_by_name: HashMap<String, String>,
    raw_inputs_glob_match: Option<InputResolvedType>,
    rule_ref: RuleRef,
}
impl InputsAsPaths {
    pub fn get_group_paths(&self, grp_name: &str) -> Option<&String> {
        if grp_name.starts_with("<") {
            self.groups_by_name.get(grp_name)
        } else {
            self.groups_by_name.get(&*format!("<{}>", grp_name))
        }
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
        inp: &[InputResolvedType],
        bo: &BufferObjects,
        rule_ref: RuleRef,
    ) -> InputsAsPaths {
        let isnotgrp = |x: &InputResolvedType| {
            !matches!(x, &InputResolvedType::GroupEntry(_, _))
                && !matches!(x, &InputResolvedType::UnResolvedGroupEntry(_, _))
        };
        let relpath = |x| diff_paths(x, tup_cwd).expect("path diff failure");
        let try_grp = |x: &InputResolvedType| {
            if let &InputResolvedType::GroupEntry(ref grp_desc, _) = x {
                Some((
                    bo.gbo.get_group_name(grp_desc),
                    relpath(get_resolved_path(x, &bo.pbo)),
                ))
            } else if let &InputResolvedType::UnResolvedGroupEntry(ref grp_desc, _) = x {
                let grp_name = bo.gbo.get_group_name(grp_desc);
                Some((grp_name.clone(), Path::new(&*grp_name).to_path_buf()))
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
            groups_by_name: namedgroupitems,
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

pub fn decode_group_captures(
    inputs: &InputsAsPaths,
    rule_ref: &RuleRef,
    d: String,
) -> Result<String, Err> {
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
        .filter(|x| !x.is_empty())
        .map(|x| {
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
    tup_cwd: &Path,
    t: &Target,
    r: &RuleFormula,
    rule_ref: &RuleRef,
    primary_deglobbed_inps: &[InputResolvedType],
    secondary_deglobbed_inps: &[InputResolvedType],
    bo: &mut BufferObjects,
    env: &EnvDescriptor,
) -> Result<ResolvedLink, Err> {
    let rstr = r.cat();
    log!(
        Debug,
        "deglobiing tup at dir:{:?}, rule:{:?}",
        tup_cwd,
        rstr
    );

    let input_as_paths = InputsAsPaths::new(tup_cwd, primary_deglobbed_inps, &bo, rule_ref.clone());
    let secondary_inputs_as_paths =
        InputsAsPaths::new(tup_cwd, secondary_deglobbed_inps, &bo, rule_ref.clone());
    let mut decoded_target =
        t.decode_input_place_holders(&input_as_paths, &secondary_inputs_as_paths)?;
    let pp = paths_from_exprs(tup_cwd, &decoded_target.primary);
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
    let sec_pp = paths_from_exprs(tup_cwd, &decoded_target.secondary);
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

    let rule_formula_desc = bo
        .add_rule(RuleFormulaUsage::new(resolved_rule, rule_ref.clone()))
        .0;
    let l = ResolvedLink {
        primary_sources: primary_deglobbed_inps.to_vec(),
        secondary_sources: secondary_deglobbed_inps.to_vec(),
        rule_formula_desc,
        primary_targets: pp
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
        env: env.clone(),
    };
    Ok(l)
}
#[derive(Clone, Debug, Default)]
pub struct ResolvedLink {
    pub primary_sources: Vec<InputResolvedType>,
    pub secondary_sources: Vec<InputResolvedType>,
    pub rule_formula_desc: RuleDescriptor,
    pub primary_targets: Vec<PathDescriptor>,
    pub secondary_targets: Vec<PathDescriptor>,
    pub group: Option<GroupPathDescriptor>,
    pub bin: Option<BinDescriptor>,
    pub rule_ref: RuleRef,
    pub env: EnvDescriptor,
}

impl ResolvedLink {
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

    pub fn get_env_desc(&self) -> &EnvDescriptor {
        &self.env
    }
    pub fn get_rule_desc(&self) -> &RuleDescriptor {
        &self.rule_formula_desc
    }
    pub fn get_group_desc(&self) -> Option<&GroupPathDescriptor> {
        self.group.as_ref()
    }
    pub fn get_bin_desc(&self) -> Option<&BinDescriptor> {
        self.bin.as_ref()
    }
    pub fn get_env<'a, 'b>(&'a self, bo: &'b BufferObjects) -> &'b Env {
        bo.get_env_buffer_object().get(&self.env)
    }
    pub fn get_rule_formula<'a, 'b>(&'a self, bo: &'b BufferObjects) -> &'b RuleFormulaUsage {
        bo.get_rule(self.get_rule_desc())
    }

    pub fn get_rule_ref(&self) -> &RuleRef {
        &self.rule_ref
    }

    pub fn get_group_as_path<'a, 'b>(&'a self, bo: &'b BufferObjects) -> Option<&'b NormalPath> {
        self.group
            .as_ref()
            .and_then(|g| bo.get_group_buffer_object().try_get(g))
    }
    pub fn get_bin<'a, 'b>(&'a self, bo: &'b BufferObjects) -> Option<&'b NormalPath> {
        self.bin
            .as_ref()
            .and_then(|ref b| bo.get_bin_buffer_object().try_get(b))
    }
}

// update the groups/bins with the path to primary target and also add secondary targets
impl GatherOutputs for ResolvedLink {
    fn gather_outputs(&self, oti: &mut OutputTagInfo) -> Result<(), Err> {
        let rule_ref = &self.rule_ref;
        for path_desc in self
            .primary_targets
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
        for path_desc in self.primary_targets.iter() {
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

pub trait ExpandRun {
    fn expand_run(&self, m: &mut SubstMap, bo: &mut BufferObjects) -> Vec<Self>
    where
        Self: Sized;
}

impl ResolvePaths for Vec<ResolvedLink> {
    fn resolve_paths(
        &self,
        tupfile: &Path,
        taginfo: &OutputTagInfo,
        bo: &mut BufferObjects,
        tup_desc: &TupPathDescriptor,
    ) -> Result<(Vec<ResolvedLink>, OutputTagInfo), Err> {
        let mut out = taginfo.clone();
        let mut rlinks = Vec::new();
        for rlink in self.iter() {
            let (r, mut o) = rlink.resolve_paths(tupfile, &out, bo, tup_desc)?;
            for f in o.output_files.iter() {
                out.parent_rule.remove(f); // to avoid conflicts with the same undecoded rule as we  merge
            }
            out.merge(&mut o)?;
            rlinks.extend(r);
        }
        Ok((rlinks, out))
    }
}

// this is for debug purposes
impl ResolvePaths for ResolvedLink {
    fn resolve_paths(
        &self,
        tup_cwd: &Path,
        taginfo: &OutputTagInfo,
        bo: &mut BufferObjects,
        _tup_desc: &TupPathDescriptor,
    ) -> Result<(Vec<ResolvedLink>, OutputTagInfo), Err> {
        let mut rlink: ResolvedLink = self.clone();
        rlink.primary_sources.clear();
        rlink.secondary_sources.clear();
        for i in self.primary_sources.iter() {
            match i {
                InputResolvedType::UnResolvedGroupEntry(g, _) => {
                    if let Some(hs) = taginfo.groups.get(&g) {
                        for pd in hs {
                            rlink
                                .primary_sources
                                .push(InputResolvedType::GroupEntry(g.clone(), pd.clone()));
                        }
                    } else {
                        return Err(crate::errors::Error::StaleGroupRef(
                            bo.get_name(i),
                            rlink.get_rule_ref().clone(),
                        ));
                    }
                }
                _ => rlink.primary_sources.push(i.clone()),
            }
        }

        for i in self.secondary_sources.iter() {
            match i {
                InputResolvedType::UnResolvedGroupEntry(ref g, _) => {
                    if let Some(hs) = taginfo.groups.get(&g) {
                        for pd in hs {
                            rlink
                                .secondary_sources
                                .push(InputResolvedType::GroupEntry(g.clone(), pd.clone()))
                        }
                    } else {
                        return Err(crate::errors::Error::StaleGroupRef(
                            bo.get_name(i),
                            rlink.get_rule_ref().clone(),
                        ));
                    }
                }
                _ => rlink.secondary_sources.push(i.clone()),
            }
        }
        let rule_ref = self.get_rule_ref();
        let rule_str = self.get_rule_formula(bo).get_formula().cat();
        if GRPRE.is_match(rule_str.as_str()) {
            let mut primary_inps =
                InputsAsPaths::new(tup_cwd, &rlink.primary_sources[..], bo, rule_ref.clone());
            let secondary_inps =
                InputsAsPaths::new(tup_cwd, &rlink.secondary_sources[..], bo, rule_ref.clone());
            primary_inps
                .groups_by_name
                .extend(secondary_inps.groups_by_name);
            let rs = decode_group_captures(&primary_inps, rule_ref, rule_str)?;
            let r = RuleFormula::new_from_raw(rs.as_str());
            let (rule_desc, _) = bo
                .get_mut_rule_buffer_object()
                .add_rule(RuleFormulaUsage::new(r, rule_ref.clone()));
            rlink.rule_formula_desc = rule_desc;
        }
        let mut out = OutputTagInfo::new();
        self.gather_outputs(&mut out)?;
        Ok((vec![rlink], out))
    }
}

/// deglob rule statement into multiple deglobbed rules, gather deglobbed targets to put in bins/groups
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
        // use same resolve_groups as input
        output.resolve_groups = taginfo.resolve_groups;
        let tupcwd = if tupfile.is_dir() {
            tupfile
        } else {
            tupfile.parent().unwrap()
        };
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
            let rule_ref = RuleRef::new(&tup_desc, loc);
            let inpdec = s.primary.decode(tupcwd, &taginfo, bo, &rule_ref)?;
            let secondinpdec = s.secondary.decode(tupcwd, &taginfo, bo, &rule_ref)?;
            let for_each = s.for_each;
            if for_each {
                for input in inpdec {
                    let delink = get_deglobbed_rule(
                        tupcwd,
                        &t,
                        &rule_formula,
                        &rule_ref,
                        core::slice::from_ref(&input),
                        secondinpdec.as_slice(),
                        bo,
                        env,
                    )?;
                    delink.gather_outputs(&mut output)?;
                    deglobbed.push(delink);
                }
            } else {
                let delink = get_deglobbed_rule(
                    tupcwd,
                    &t,
                    &rule_formula,
                    &rule_ref,
                    inpdec.as_slice(),
                    secondinpdec.as_slice(),
                    bo,
                    env,
                )?;
                delink.gather_outputs(&mut output)?;
                deglobbed.push(delink);
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
        let mut alltaginfos = taginfo.clone();
        alltaginfos.resolve_groups = taginfo.resolve_groups;
        for stmt in self.iter() {
            let stmtstr = stmt.cat();
            log!(Debug, "final resolve of {}", stmtstr);
            let (ref mut stmts, ref mut out) =
                stmt.resolve_paths(tupfile, &alltaginfos, bo, tbo)?;
            alltaginfos.merge(out)?;
            vs.append(stmts);
        }
        Ok((vs, alltaginfos))
    }
}
