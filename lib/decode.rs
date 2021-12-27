use glob::{glob, Entry};
use regex::{Captures, Error, Regex};
use statements::*;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

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
    path: PathBuf, // if no globs here
    entry: Option<Entry>,
}
impl PathEntry {
    pub(crate) fn new(path: PathBuf) -> PathEntry {
        PathEntry { path, entry: None }
    }
    pub(crate) fn with_captures(path: PathBuf, entry: Entry) -> PathEntry {
        PathEntry {
            path,
            entry: Some(entry),
        }
    }
    /// Get path represented by this entry
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn group(&self, n: usize) -> Option<&OsStr> {
        self.entry.as_ref().and_then(|ref x| x.group(n))
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
    Group(String, PathBuf),
    Bin(String, PathBuf),
}

impl ToString for InputGlobType {
    fn to_string(&self) -> String {
        match self {
            InputGlobType::Deglob(e) => e.path().to_str().unwrap_or_default().to_string(),
            InputGlobType::Group(_, p) => p.to_str().unwrap_or_default().to_string(),
            InputGlobType::Bin(_, p) => p.to_str().unwrap_or_default().to_string(),
        }
    }
}

type OutputType = PathBuf;
// get the path that InputGlobType refers to
fn as_path(inpg: &InputGlobType) -> &Path {
    match inpg {
        InputGlobType::Deglob(e) => e.path(),
        InputGlobType::Group(_, p) => p.as_path(),
        InputGlobType::Bin(_, p) => p.as_path(),
    }
}

// Get matched glob in the input to a rule
fn as_glob_match(inpg: &InputGlobType) -> String {
    match inpg {
        InputGlobType::Deglob(e) => e
            .group(1)
            .and_then(|x| x.to_str())
            .map(|x| x.to_string())
            .unwrap_or(String::new()),
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
    fn decode(&self, tupcwd: &Path, taginfo: &OutputTagInfo) -> Vec<InputGlobType>;
}

// Decode input paths in RvalGeneral
impl DecodeInputPaths for PathExpr {
    // convert globs into regular paths, remember that matched groups
    fn decode(&self, tupcwd: &Path, taginfo: &OutputTagInfo) -> Vec<InputGlobType> {
        let mut vs = Vec::new();
        // deglob * patterns,
        match self {
            PathExpr::Literal(src) => {
                for src in src.split_whitespace() {
                    if let Some(pos) = src.rfind('*') {
                        let (first, last) = src.split_at(pos);
                        let mut bstr: String = first.to_string();
                        bstr.push_str("(*)"); // replace * with (*) to capture the glob see doc for capturing_glob::glob
                        bstr.push_str(&last[1..]);

                        for entry in glob(tupcwd.join(bstr.as_str()).to_str().unwrap())
                            .expect("Failed to read glob pattern")
                            .into_iter()
                            .filter_map(|x| x.ok())
                        {
                            let p = entry.path().to_path_buf();
                            vs.push(InputGlobType::Deglob(PathEntry::with_captures(p, entry)));
                        }
                    } else {
                        vs.push(InputGlobType::Deglob(PathEntry::new(
                            Path::new(src).to_path_buf(),
                        )))
                    }
                }
            }
            PathExpr::Group(_, _) => {
                let grp_name = self.cat();
                if let Some(paths) = taginfo.grouptags.get(grp_name.as_str()) {
                    for p in paths {
                        vs.push(InputGlobType::Group(grp_name.clone(), p.to_path_buf()))
                    }
                }
            }
            PathExpr::Bucket(str) => {
                if let Some(paths) = taginfo.buckettags.get(str.as_str()) {
                    for p in paths {
                        vs.push(InputGlobType::Bin(str.clone(), p.to_path_buf()))
                    }
                }
            }
            _ => {}
        }
        return vs;
    }
}
// decode input paths
impl DecodeInputPaths for Vec<PathExpr> {
    fn decode(&self, tupcwd: &Path, taginfo: &OutputTagInfo) -> Vec<InputGlobType> {
        // gather locations where exclude patterns show up
        let excludeindices: Vec<_> = self
            .iter()
            .enumerate()
            .filter(|pi| matches!(&pi.1, &PathExpr::ExcludePattern(_)))
            .map(|ref pi| pi.0)
            .collect();
        // ....
        let filteroutexcludes = |(i, ips)| {
            // find exclude patterns after current glob pattern
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
        self.iter()
            //.inspect(|x| eprintln!("before decode {:?}", x))
            .map(|x| x.decode(tupcwd, &taginfo))
            //.inspect(|x| eprintln!("after {:?}", x))
            .enumerate()
            .map(filteroutexcludes)
            .flatten()
            .collect()
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
    fn decode_input_place_holders(&self, input: &Vec<&InputGlobType>) -> PathExpr {
        let frep = |inp: &Vec<&InputGlobType>, d: &str| {
            let isnotgrp = |x: &InputGlobType| !matches!(x, &InputGlobType::Group(_, _));
            let isgrp = |x: &InputGlobType, name: &str| {
                if let &InputGlobType::Group(ref grpname, _) = x {
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
                        .and_then(|x| x.to_str())
                        .unwrap_or("")
                        .to_string()
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
            PathExpr::Literal(frep(input, s).to_string())
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
            let re = Regex::new(r"%([1-9][0-9]*)i");
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
    fn decode_input_place_holders(&self, input: &Vec<&InputGlobType>) -> Self {
        self.iter()
            .map(|x| x.decode_input_place_holders(input))
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
                /*
                %O
                    The name of the output file without the extension.
                     This only works in the extra-outputs section if there is exactly one output file specified.
                     A use-case for this is if you have a !-macro that generates files not specified on the command
                     line, but are based off of the output that is named. For example, if a linker creates a map
                      file by taking the specified output "foo.so", removing the ".so" and adding ".map", then you
                      may want a !-macro like so:
                    !ldmap = |> ld ... -o %o |> | %O.map
                    : foo1.o foo2.o |> !ldmap |> foo.so
                                     */
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
fn primary_paths(tupcwd: &Path, tgt: &Target) -> Vec<PathBuf> {
    tgt.primary
        .split(|x| matches!(x, &PathExpr::Sp1))
        .map(|x| tupcwd.join(x.to_vec().cat()))
        .collect()
}

fn convert_to_pathexprs(tupcwd: &Path, inpdec: &Vec<&InputGlobType>) -> Vec<PathExpr> {
    inpdec
        .iter()
        .map(|&x| {
            vec![
                PathExpr::Literal(tupcwd.join(x.to_string()).to_str().unwrap().to_string()),
                PathExpr::Sp1,
            ]
        })
        .flatten()
        .collect()
}
fn convert_to_pathexprs_x(tupcwd: &Path, inpdec: &Vec<InputGlobType>) -> Vec<PathExpr> {
    inpdec
        .iter()
        .map(|ref x| {
            vec![
                PathExpr::Literal(tupcwd.join(x.to_string()).to_str().unwrap().to_string()),
                PathExpr::Sp1,
            ]
        })
        .flatten()
        .collect()
}

// replace % specifiers in a target of rule statement which has already been
// deglobbed
impl DecodeInputPlaceHolders for Target {
    fn decode_input_place_holders(&self, input: &Vec<&InputGlobType>) -> Target {
        let newprimary = self.primary.decode_input_place_holders(input);
        let newsecondary = self.secondary.decode_input_place_holders(input);
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
    fn decode_input_place_holders(&self, inputs: &Vec<&InputGlobType>) -> RuleFormula {
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
    secondaryinputsasref: &Vec<&InputGlobType>,
    sinputs: &Vec<PathExpr>,
    vis: &Vec<&InputGlobType>,
) -> Statement {
    let mut tc = t
        .decode_input_place_holders(&vis)
        .decode_order_only_input_place_holders(&secondaryinputsasref);
    let pp = primary_paths(tupcwd, &t);
    let primary_output_paths: Vec<&OutputType> = pp.iter().collect();
    tc.secondary = tc
        .secondary
        .decode_output_place_holders(&primary_output_paths);

    //todo: is this needed: tc.group.map(|x| x.decode_input_place_holders(&vis));

    // now track the outputs that fall in a group or bin
    let rfc: RuleFormula = r
        .decode_input_place_holders(&vis)
        .decode_order_only_input_place_holders(&secondaryinputsasref)
        .decode_output_place_holders(&primary_output_paths);

    let inputc = convert_to_pathexprs(tupcwd, vis);
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
pub trait DeGlobber
{
    fn deglob_and_decode(&self, tupfile: &Path, taginfo: &OutputTagInfo)
    -> (Vec<Statement>, OutputTagInfo);
}

// deglob rule statement into multiple deglobbed rules, update the buckets corresponding to the deglobed targets
impl DeGlobber for Statement {
    fn deglob_and_decode(
        &self,
        tupfile: &Path,
        taginfo: &OutputTagInfo,
    ) -> (Vec<Statement>, OutputTagInfo) {
        let mut deglobbed = Vec::new();
        let mut output: OutputTagInfo = Default::default();
        let tupcwd = tupfile.parent().unwrap();
        if let Statement::Rule(Link {
            source: s,
            target: t,
            rule_formula: r,
            pos,
        }) = self
        {
            let inpdec = s.primary.decode(tupcwd, &taginfo);
            let secondinpdec = s.secondary.decode(tupcwd, &taginfo);
            let for_each = s.for_each;
            let secondaryinputsasref: Vec<&InputGlobType> = secondinpdec.iter().collect();
            let ref sinputs = convert_to_pathexprs_x(tupcwd, &secondinpdec);
            if for_each {
                for input in inpdec {
                    let vis = vec![&input];
                    deglobbed.push(get_deglobbed_rule(
                        tupcwd,
                        &t,
                        r,
                        pos,
                        &secondaryinputsasref,
                        sinputs,
                        &vis,
                    ));
                    if let Some(&Statement::Rule(Link {
                        source: _,
                        ref target,
                        ..
                    })) = deglobbed.last()
                    {
                        updatetags(&target, &mut output);
                    }
                }
            } else {
                let vis: Vec<&_> = inpdec.iter().collect();
                deglobbed.push(get_deglobbed_rule(
                    tupcwd,
                    &t,
                    r,
                    pos,
                    &secondaryinputsasref,
                    sinputs,
                    &vis,
                ));
                if let Some(&Statement::Rule(Link {
                    source: _,
                    ref target,
                    ..
                })) = deglobbed.last()
                {
                    updatetags(&target, &mut output);
                }
            }
        } else {
            deglobbed.push(self.clone())
        }
        (deglobbed, output)
    }
}

impl DeGlobber for Vec<Statement> {
    fn deglob_and_decode(
        &self,
        tupfile: &Path,
        taginfo: &OutputTagInfo,
    ) -> (Vec<Statement>, OutputTagInfo) {
        let mut vs = Vec::new();
        let mut alltaginfos = OutputTagInfo::new();
        for stmt in self.iter() {
           let (ref mut stmts, ref mut outputtaginfo) = stmt.deglob_and_decode(tupfile, taginfo);
            alltaginfos.merge_group_tags( outputtaginfo);
            alltaginfos.merge_bin_tags(outputtaginfo);
            vs.append(stmts);
        }
        (vs,alltaginfos)
    }
}