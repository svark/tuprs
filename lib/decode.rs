use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::vec;

use glob::{Glob, GlobBuilder, GlobMatcher};
use path_absolutize::Absolutize;
use regex::{bytes, Captures, Error, Regex};
use walkdir::WalkDir;

use errors::Error as Err;
use statements::*;

// maps to paths corresponding to bin names, or group names
#[derive(Debug, Default)]
pub struct OutputTagInfo {
    pub buckettags: HashMap<String, Vec<PathBuf>>,
    pub grouptags: HashMap<String, Vec<PathBuf>>,
}
impl OutputTagInfo {
    pub fn merge_group_tags(&mut self, other: &mut OutputTagInfo) {
        for (k, v) in other.grouptags.iter_mut() {
            if let Some(vorig) = self.grouptags.get_mut(k) {
                vorig.append(v);
            } else {
                self.grouptags.insert(k.clone(), v.clone());
            }
        }
    }

    pub fn merge_bin_tags(&mut self, other: &mut OutputTagInfo) {
        for (k, v) in other.buckettags.iter_mut() {
            if let Some(vorig) = self.buckettags.get_mut(k) {
                vorig.append(v)
            } else {
                self.buckettags.insert(k.clone(), v.clone());
            }
        }
    }
    pub fn new() -> OutputTagInfo {
        Default::default()
    }
}
#[derive(Debug, Default)]
pub struct PathEntry {
    path: PathBuf, // path that matched a glob
    entry: String, // first glob match in the above path
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
pub struct PathGlob {
    matcher: GlobMatcher,
    glob_pattern: Glob,
    // loc : Loc
}

impl PathGlob {
    pub fn new(path: &Path, loc: Loc) -> Result<Self, crate::errors::Error> {
        let to_glob_error =
            |e: &globset::Error| crate::errors::Error::GlobError(e.kind().to_string(), loc.clone());
        let pathstr = path.to_string_lossy();
        let glob_pattern = GlobBuilder::new(pathstr.as_ref())
            .literal_separator(true)
            .capture_globs(true)
            .build()
            .map_err(|e| to_glob_error(&e))?;
        let matcher = glob_pattern.compile_matcher();
        Ok(PathGlob {
            matcher,
            glob_pattern,
        })
    }

    pub fn is_match<P: AsRef<Path>>(&self, path: P) -> bool {
        self.matcher.is_match(path)
    }

    fn regex(&self) -> &str {
        self.glob_pattern.regex()
    }

    pub fn group<P: AsRef<Path>>(&self, path: P) -> String {
        let regexp = bytes::Regex::new(self.regex()).unwrap();
        let lossy_str = path.as_ref().to_string_lossy();
        if let Some(c) = regexp.captures(lossy_str.as_bytes()) {
            if let Some(m) = c.get(1) {
                if let Ok(s) = std::str::from_utf8(m.as_bytes()) {
                    s.to_string()
                } else {
                    lossy_str.to_string()
                }
            } else {
                lossy_str.to_string()
            }
        } else {
            lossy_str.to_string()
        }
    }
}

impl PartialEq for PathGlob {
    fn eq(&self, other: &Self) -> bool {
        self.glob_pattern.eq(&other.glob_pattern)
    }
}

impl Eq for PathGlob {}

impl std::fmt::Display for PathGlob {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        self.glob_pattern.fmt(f)
    }
}

fn discover_inputs_from_glob(
    glob_path: &Path,
    loc: &Loc,
) -> Result<Vec<PathEntry>, crate::errors::Error> {
    let (mut base_path, recurse) = get_non_pattern_prefix(glob_path);
    let mut to_match = glob_path;
    let pbuf: PathBuf;
    if base_path.eq(&PathBuf::new()) {
        base_path = base_path.join(".");
        pbuf = Path::new(".").join(glob_path);
        to_match = &pbuf;
    }
    let globs = PathGlob::new(to_match, loc.clone())?;
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
        pes.push(PathEntry::with_captures(
            path.to_path_buf(),
            globs.group(path),
        ));
    }
    Ok(pes)
}

impl PathEntry {
    pub(crate) fn with_captures(path: PathBuf, entry: String) -> PathEntry {
        PathEntry { path, entry }
    }
    /// Get path represented by this entry
    pub fn path(&self) -> &Path {
        &self.path
    }
}
impl Into<PathBuf> for PathEntry {
    fn into(self) -> PathBuf {
        self.path
    }
}

impl AsRef<Path> for PathEntry {
    fn as_ref(&self) -> &Path {
        self.path.as_ref()
    }
}
// Types of decoded input to rules which includes
// files in glob, group paths, bin entries
#[derive(Debug)]
pub enum InputGlobType {
    Deglob(PathEntry),
    GroupEntry(String, PathBuf),
    BinEntry(String, PathBuf),
}

impl ToString for InputGlobType {
    fn to_string(&self) -> String {
        match self {
            InputGlobType::Deglob(e) => e.path().to_str().unwrap_or_default().to_string(),
            InputGlobType::GroupEntry(_, p) => p.to_str().unwrap_or_default().to_string(),
            InputGlobType::BinEntry(_, p) => p.to_str().unwrap_or_default().to_string(),
        }
    }
}

type OutputType = PathBuf;
// get the path that InputGlobType refers to
fn as_path(inpg: &InputGlobType) -> &Path {
    match inpg {
        InputGlobType::Deglob(e) => e.path(),
        InputGlobType::GroupEntry(_, p) => p.as_path(),
        InputGlobType::BinEntry(_, p) => p.as_path(),
    }
}

// Get matched glob in the input to a rule
fn as_glob_match(inpg: &InputGlobType) -> String {
    match inpg {
        InputGlobType::Deglob(e) => e.entry.clone(),
        _ => String::new(),
    }
}

pub trait ExcludeInputPaths {
    fn exclude(&self, deglobbed: Vec<InputGlobType>) -> Vec<InputGlobType>;
}
impl ExcludeInputPaths for PathExpr {
    fn exclude(&self, deglobbed: Vec<InputGlobType>) -> Vec<InputGlobType> {
        match self {
            PathExpr::ExcludePattern(patt) => {
                let re = Regex::new(patt).ok();
                if let Some(ref re) = re {
                    let matches = |i: &InputGlobType| {
                        let s = as_path(i).to_str();
                        if let Some(s) = s {
                            re.captures(s).is_some()
                        } else {
                            false
                        }
                    };
                    deglobbed.into_iter().filter(matches).collect()
                } else {
                    deglobbed
                }
            }
            _ => deglobbed,
        }
    }
}
// Decode input paths from file globs, bins(buckets), and groups
pub trait DecodeInputPaths {
    fn decode(
        &self,
        tupcwd: &Path,
        loc: &Loc,
        taginfo: &OutputTagInfo,
    ) -> Result<Vec<InputGlobType>, Err>;
}

// Decode input paths in RvalGeneral
impl DecodeInputPaths for PathExpr {
    // convert globs into regular paths, remember that matched groups
    fn decode(
        &self,
        tup_cwd: &Path,
        loc: &Loc,
        taginfo: &OutputTagInfo,
    ) -> Result<Vec<InputGlobType>, Err> {
        let mut vs = Vec::new();
        match self {
            PathExpr::Literal(_) => {
                let path_buf = normalized_path(tup_cwd, self);
                let pes = discover_inputs_from_glob(path_buf.as_path(), loc)?;
                for pe in pes {
                    vs.push(InputGlobType::Deglob(pe))
                }
            }
            PathExpr::Group(_, _) => {
                let grp_name = self.cat();
                if let Some(paths) = taginfo.grouptags.get(grp_name.as_str()) {
                    for p in paths {
                        vs.push(InputGlobType::GroupEntry(grp_name.clone(), p.to_path_buf()))
                    }
                }
            }
            PathExpr::Bin(str) => {
                if let Some(paths) = taginfo.buckettags.get(str.as_str()) {
                    for p in paths {
                        vs.push(InputGlobType::BinEntry(str.clone(), p.to_path_buf()))
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
        tupcwd: &Path,
        loc: &Loc,
        taginfo: &OutputTagInfo,
    ) -> Result<Vec<InputGlobType>, Err> {
        // gather locations where exclude patterns show up
        let excludeindices: Vec<_> = self
            .iter()
            .enumerate()
            .filter(|pi| matches!(&pi.1, &PathExpr::ExcludePattern(_)))
            .map(|ref pi| pi.0)
            .collect();
        // ....
        let filteroutexcludes = |(i, ips): (usize, Vec<InputGlobType>)| -> Vec<InputGlobType> {
            // find the immediately following exclude pattern
            let pp = excludeindices.partition_point(|&j| j <= i);
            if pp < excludeindices.len() {
                // remove paths that match exclude pattern
                let v = self.as_slice();
                let exclude_regex = &v[excludeindices[pp]];
                exclude_regex.exclude(ips)
            } else {
                ips
            }
        };
        let decoded: Result<Vec<_>, _> = self
            .iter()
            //.inspect(|x| eprintln!("before decode {:?}", x))
            .map(|x| x.decode(tupcwd, loc, &taginfo))
            .collect();
        Ok(decoded?
            .into_iter()
            .enumerate()
            .map(filteroutexcludes)
            .flatten()
            .collect())
        //.inspect(|x| eprintln!("after {:?}", x))
    }
}

// decode input paths

trait GatherOutputs {
    fn gather_outputs(&self, oti: &mut OutputTagInfo);
}

trait DecodeInputPlaceHolders {
    fn decode_input_place_holders(&self, inputs: &Vec<&InputGlobType>) -> Self;
}
trait DecodeOutputPlaceHolders {
    fn decode_output_place_holders(&self, outputs: &Vec<&OutputType>) -> Self;
}
trait DecodeOrderOnlyInputPlaceHolders {
    fn decode_order_only_input_place_holders(&self, orderonlyinputs: &Vec<&InputGlobType>) -> Self;
}
impl DecodeInputPlaceHolders for PathExpr {
    fn decode_input_place_holders(&self, inputs: &Vec<&InputGlobType>) -> Self {
        let frep = |inp: &Vec<&InputGlobType>, d: &str| {
            let isnotgrp = |x: &InputGlobType| !matches!(x, &InputGlobType::GroupEntry(_, _));
            let isgrp = |x: &InputGlobType, name: &str| {
                if let &InputGlobType::GroupEntry(ref grpname, _) = x {
                    name.eq(grpname.as_str())
                } else {
                    false
                }
            };
            // capture all inputs other than groups.
            let allnongroups: Vec<_> = inp
                .iter()
                .filter(|&x| isnotgrp(x))
                .map(|&x| x.to_string())
                .collect();

            let nongroupsprocessed = |f: &dyn Fn(&InputGlobType) -> String| -> Vec<String> {
                inp.iter().filter(|&x| isnotgrp(x)).map(|&x| f(x)).collect()
            };
            // each group is accessed by its name in the place holder
            let namedgroupitems = |name: &str| -> Vec<String> {
                inp.iter()
                    .filter(|&x| isgrp(x, name)) // groups matching name
                    .map(|x| x.to_string())
                    .collect()
            };
            let space_separated_inputs = allnongroups.join(" ");
            let mut decoded_str = String::from(d);
            // replace %f and %[num]f
            decoded_str = decoded_str.replace("%f", space_separated_inputs.as_str());
            let perfre = Regex::new(r"%([1-9]+[0-9]*)f");
            decoded_str = replace_decoded_str(&decoded_str, allnongroups, perfre);

            let perc_b_re = Regex::new(r"%([0-9]*)b");
            if perc_b_re.unwrap().captures(decoded_str.as_str()).is_some() {
                let fnames: Vec<String> = nongroupsprocessed(&|f: &InputGlobType| {
                    as_path(f)
                        .file_name()
                        .and_then(|x| x.to_str())
                        .unwrap_or("")
                        .to_string()
                });
                decoded_str = decoded_str.replace("%b", fnames.join(" ").as_str());
                let perc_b_re = Regex::new(r"%([1-9]+[0-9]*)b");
                decoded_str = replace_decoded_str(&decoded_str, fnames, perc_b_re);
            }
            let grpre = Regex::new(r"%<([^ ]+)>");
            decoded_str = grpre
                .unwrap()
                .replace(decoded_str.as_str(), |caps: &Captures| {
                    namedgroupitems(&caps[1]).join(" ")
                })
                .to_string();

            let per_cap_b_re = Regex::new(r"%([0-9]*)B");
            if per_cap_b_re
                .unwrap()
                .captures(decoded_str.as_str())
                .is_some()
            {
                let fnameswoe = nongroupsprocessed(&|f| {
                    as_path(f)
                        .file_stem()
                        .map(|x| x.to_string_lossy().to_string())
                        .unwrap_or("".to_string())
                });
                decoded_str = decoded_str.replace("%B", fnameswoe.join(" ").as_str());
                let perc_cap_b_re = Regex::new(r"%([1-9]+[0-9]*)B");
                decoded_str = replace_decoded_str(&decoded_str, fnameswoe, perc_cap_b_re);
            }

            if let Some(&i) = inp.first() {
                let path = as_path(i);
                let glb = as_glob_match(i);
                decoded_str = decoded_str
                    .replace("%g", glb.as_str())
                    .replace(
                        "%e",
                        path.extension().and_then(|x| x.to_str()).unwrap_or(""),
                    )
                    .replace(
                        "%d",
                        path.parent()
                            .and_then(|x| x.file_name())
                            .and_then(|x| x.to_str())
                            .unwrap_or(""),
                    );
            }
            decoded_str
        };
        if let PathExpr::Literal(s) = self {
            PathExpr::Literal(frep(inputs, s).to_string())
        } else {
            self.clone()
        }
    }
}

fn replace_decoded_str(
    decoded_str: &String,
    file_names: Vec<String>,
    perc_b_re: Result<Regex, Error>,
) -> String {
    perc_b_re
        .unwrap()
        .replace(decoded_str.as_str(), |caps: &Captures| {
            caps[1]
                .parse::<usize>()
                .map(|i| file_names[i].clone())
                .unwrap_or("".to_string())
        })
        .to_string()
}

impl DecodeOrderOnlyInputPlaceHolders for PathExpr {
    fn decode_order_only_input_place_holders(&self, orderonlyinputs: &Vec<&InputGlobType>) -> Self {
        let allinputs: Vec<_> = orderonlyinputs
            .into_iter()
            .map(|&x| x.to_string())
            .collect();
        let space_separated_order_only_inputs = allinputs.join(" ");
        let frep = |d: &str| -> String {
            let mut decoded_str = String::from(d);
            decoded_str = decoded_str.replace("%i", space_separated_order_only_inputs.as_str());
            let re = Regex::new(r"%([1-9][0-9]*)i"); // pattern for matching numbered inputs
            replace_decoded_str(&decoded_str, allinputs, re)
        };
        if let PathExpr::Literal(s) = self {
            PathExpr::Literal(frep(s))
        } else {
            self.clone()
        }
    }
}
impl DecodeInputPlaceHolders for Vec<PathExpr> {
    fn decode_input_place_holders(&self, inputs: &Vec<&InputGlobType>) -> Self {
        self.iter()
            .map(|x| x.decode_input_place_holders(inputs))
            .collect()
    }
}
impl DecodeOutputPlaceHolders for Vec<PathExpr> {
    fn decode_output_place_holders(&self, outputs: &Vec<&OutputType>) -> Self {
        self.iter()
            .map(|x| x.decode_output_place_holders(outputs))
            .collect()
    }
}
impl DecodeOrderOnlyInputPlaceHolders for Vec<PathExpr> {
    fn decode_order_only_input_place_holders(&self, orderonlyinputs: &Vec<&InputGlobType>) -> Self {
        self.iter()
            .map(|x| x.decode_order_only_input_place_holders(orderonlyinputs))
            .collect()
    }
}

impl DecodeOutputPlaceHolders for PathExpr {
    fn decode_output_place_holders(&self, outputs: &Vec<&OutputType>) -> Self {
        let alloutputs: Vec<_> = outputs
            .into_iter()
            .map(|x| x.to_str().unwrap_or("").to_string())
            .collect();
        let space_separated_outputs = alloutputs.join(" ");
        let frep = |d: &str| {
            d.replace("%o", space_separated_outputs.as_str()).replace(
                "%O",
                outputs
                    .first()
                    .and_then(|x| x.file_stem())
                    .and_then(|x| x.to_str())
                    .unwrap_or("%O"),
            )
        };
        if let PathExpr::Literal(s) = self {
            PathExpr::Literal(frep(s))
        } else {
            self.clone()
        }
    }
}

fn primary_path(tgt: &Target) -> PathBuf {
    PathBuf::from(tgt.primary.cat())
}

fn normalized_path(tup_cwd: &Path, x: &PathExpr) -> PathBuf {
    let pbuf = PathBuf::new().join(x.cat_ref().replace('\\', "/").as_str());
    if tup_cwd.eq(Path::new(".")) {
        pbuf
    } else {
        pbuf.absolutize_from(tup_cwd).unwrap().to_path_buf()
    }
}
fn paths_from_exprs(tup_cwd: &Path, p: &Vec<PathExpr>) -> Vec<PathBuf> {
    p.split(|x| matches!(x, &PathExpr::Sp1))
        .map(|x| {
            let path = PathBuf::new().join(&x.to_vec().cat());
            if !tup_cwd.eq(Path::new(".")) {
                path.as_path()
                    .absolutize_from(tup_cwd)
                    .unwrap()
                    .to_path_buf()
            } else {
                path
            }
        })
        .collect()
}

fn primary_output_paths(tup_cwd: &Path, tgt: &Target) -> Vec<PathBuf> {
    paths_from_exprs(tup_cwd, &tgt.primary)
}

fn convert_back_to_pathexprs(inpdec: &Vec<&InputGlobType>) -> Vec<PathExpr> {
    inpdec
        .iter()
        .map(|&x| vec![PathExpr::from(x.to_string()), PathExpr::Sp1])
        .flatten()
        .collect()
}

fn convert_to_pathexprs_x(
    tup_cwd: &Path,
    inpdec: &Vec<InputGlobType>,
    _: &Loc,
) -> Result<Vec<PathExpr>, Err> {
    let res: Result<Vec<_>, _> = inpdec
        .iter()
        .map(|x| -> Result<Vec<PathExpr>, Err> {
            let fullpath = as_path(x).absolutize_from(tup_cwd).unwrap();
            Ok(vec![
                PathExpr::Literal(fullpath.to_string_lossy().to_string()),
                PathExpr::Sp1,
            ])
        })
        .collect();
    Ok(res?.into_iter().flatten().collect())
}

// replace % specifiers in a target of rule statement which has already been
// deglobbed
impl DecodeInputPlaceHolders for Target {
    fn decode_input_place_holders(&self, inputs: &Vec<&InputGlobType>) -> Self {
        let newprimary = self.primary.decode_input_place_holders(inputs);
        let newsecondary = self.secondary.decode_input_place_holders(inputs);
        Target {
            primary: newprimary,
            secondary: newsecondary,
            exclude_pattern: self.exclude_pattern.clone(),
            bin: self.bin.clone(),
            group: self.group.clone(),
        }
    }
}
impl DecodeOutputPlaceHolders for Target {
    fn decode_output_place_holders(&self, outputs: &Vec<&OutputType>) -> Self {
        let newprimary = self.primary.clone();
        let newsecondary = self.secondary.decode_output_place_holders(outputs);
        Target {
            primary: newprimary,
            secondary: newsecondary,
            exclude_pattern: self.exclude_pattern.clone(),
            bin: self.bin.clone(),
            group: self.group.clone(),
        }
    }
}
impl DecodeOrderOnlyInputPlaceHolders for Target {
    fn decode_order_only_input_place_holders(&self, orderonlyinputs: &Vec<&InputGlobType>) -> Self {
        let newprimary = self
            .primary
            .decode_order_only_input_place_holders(orderonlyinputs);
        let newsecondary = self
            .secondary
            .decode_order_only_input_place_holders(orderonlyinputs);
        Target {
            primary: newprimary,
            secondary: newsecondary,
            exclude_pattern: self.exclude_pattern.clone(),
            bin: self.bin.clone(),
            group: self.group.clone(),
        }
    }
}

// reconstruct a rule formula that has placeholders filled up
impl DecodeInputPlaceHolders for RuleFormula {
    fn decode_input_place_holders(&self, inputs: &Vec<&InputGlobType>) -> Self {
        RuleFormula {
            description: PathExpr::Literal(self.description.clone())
                .decode_input_place_holders(inputs)
                .cat(),
            formula: self.formula.decode_input_place_holders(inputs),
        }
    }
}

impl DecodeOrderOnlyInputPlaceHolders for RuleFormula {
    fn decode_order_only_input_place_holders(&self, inputs: &Vec<&InputGlobType>) -> RuleFormula {
        RuleFormula {
            description: PathExpr::Literal(self.description.clone())
                .decode_order_only_input_place_holders(inputs)
                .cat(),
            formula: self.formula.decode_order_only_input_place_holders(inputs),
        }
    }
}
impl DecodeOutputPlaceHolders for RuleFormula {
    fn decode_output_place_holders(&self, outputs: &Vec<&OutputType>) -> Self {
        RuleFormula {
            description: PathExpr::Literal(self.description.clone())
                .decode_output_place_holders(outputs)
                .cat(),
            formula: self.formula.decode_output_place_holders(outputs),
        }
    }
}
fn get_deglobbed_rule(
    tupcwd: &Path,
    t: &Target,
    r: &RuleFormula,
    pos: &(u32, usize),
    sinputs: &Vec<PathExpr>,
    vis: &Vec<&InputGlobType>,
) -> Statement {
    let mut tc = t.decode_input_place_holders(&vis);
    let pp = primary_output_paths(tupcwd, &t);
    let primary_output_paths: Vec<&OutputType> = pp.iter().collect();
    tc.secondary = tc
        .secondary
        .decode_output_place_holders(&primary_output_paths);

    //todo: is this needed: tc.group.map(|x| x.decode_input_place_holders(&vis));

    // now track the outputs that fall in a group or bin
    let rfc: RuleFormula = r
        .decode_input_place_holders(&vis)
        .decode_output_place_holders(&primary_output_paths);

    let inputc = convert_back_to_pathexprs(vis);
    let src = Source {
        primary: inputc,
        secondary: sinputs.clone(),
        for_each: false,
    }; // single source input
       // tc.tags
    Statement::Rule(Link {
        source: src,
        target: tc,
        rule_formula: rfc,
        pos: *pos,
    })
}

// update the groups with the path to primary target
fn updatetags(tgt: &Target, taginfo: &mut OutputTagInfo) {
    let pathb = primary_path(tgt);
    let ref firstgroupname = tgt.group;
    if let Some(grpname) = firstgroupname {
        // let pb = PathBuf::from(?grouppathstr);
        let grpnamestr = grpname.cat();
        if let Some(paths) = taginfo.grouptags.get_mut(&grpnamestr) {
            paths.push(pathb.clone());
        } else {
            taginfo.grouptags.insert(grpnamestr, vec![pathb.clone()]);
        }
    }
    let bin = tgt.bin.as_ref().map(|x| x.cat());
    if let Some(bin_name) = bin {
        if let Some(paths) = taginfo.buckettags.get_mut(&bin_name) {
            paths.push(pathb);
        } else {
            taginfo.buckettags.insert(bin_name.clone(), vec![pathb]);
        }
    }
}
pub trait PathDecoder {
    fn decode(
        &self,
        tupfile: &Path,
        taginfo: &OutputTagInfo,
    ) -> Result<(Vec<LocatedStatement>, OutputTagInfo), Err>;
}

// deglob rule statement into multiple deglobbed rules, update the buckets corresponding to the deglobed targets
impl PathDecoder for LocatedStatement {
    fn decode(
        &self,
        tupfile: &Path,
        taginfo: &OutputTagInfo,
    ) -> Result<(Vec<LocatedStatement>, OutputTagInfo), Err> {
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
                    rule_formula: r,
                    pos,
                }),
            loc,
        } = self
        {
            let inpdec = s.primary.decode(tupcwd, loc, &taginfo)?;
            let secondinpdec = s.secondary.decode(tupcwd, loc, &taginfo)?;
            let for_each = s.for_each;
            let secondaryinputsasref: Vec<&InputGlobType> = secondinpdec.iter().collect();
            let ref sinputs = convert_to_pathexprs_x(tupcwd, &secondinpdec, &loc)?;
            let t = t.decode_order_only_input_place_holders(&secondaryinputsasref);
            let r = r.decode_order_only_input_place_holders(&secondaryinputsasref);
            if for_each {
                for input in inpdec {
                    let vis = vec![&input];
                    deglobbed.push(LocatedStatement::new(
                        get_deglobbed_rule(tupcwd, &t, &r, pos, sinputs, &vis),
                        loc.clone(),
                    ));
                    if let Some(&LocatedStatement {
                        statement: Statement::Rule(Link { ref target, .. }),
                        ..
                    }) = deglobbed.last()
                    {
                        updatetags(&target, &mut output);
                    }
                }
            } else {
                let vis: Vec<&_> = inpdec.iter().collect();
                deglobbed.push(LocatedStatement::new(
                    get_deglobbed_rule(tupcwd, &t, &r, pos, sinputs, &vis),
                    loc.clone(),
                ));
                if let Some(&LocatedStatement {
                    statement: Statement::Rule(Link { ref target, .. }),
                    ..
                }) = deglobbed.last()
                {
                    updatetags(&target, &mut output);
                }
            }
        } else {
            deglobbed.push(self.clone())
        }
        Ok((deglobbed, output))
    }
}

impl PathDecoder for Vec<LocatedStatement> {
    fn decode(
        &self,
        tupfile: &Path,
        taginfo: &OutputTagInfo,
    ) -> Result<(Vec<LocatedStatement>, OutputTagInfo), Err> {
        let mut vs = Vec::new();
        let mut alltaginfos = OutputTagInfo::new();
        for stmt in self.iter() {
            let (ref mut stmts, ref mut outputtaginfo) = stmt.decode(tupfile, taginfo)?;
            alltaginfos.merge_group_tags(outputtaginfo);
            alltaginfos.merge_bin_tags(outputtaginfo);
            vs.append(stmts);
        }
        Ok((vs, alltaginfos))
    }
}
