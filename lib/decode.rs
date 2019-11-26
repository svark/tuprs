use glob::{glob, Entry};
use statements::*;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
// maps to paths corresponding to bin names, or group names
#[derive(Debug)]
pub struct OutputTagInfo {
    pub buckettags: HashMap<String, Vec<PathBuf>>,
    pub grouptags: HashMap<String, Vec<PathBuf>>,
}

// Types of decoded input to rules which includes
// files in glob, group paths, bucket entries
#[derive(Debug)]
pub enum InputGlobType {
    Deglob(Entry),
    Group(String, PathBuf),
    Bucket(String, PathBuf),
}

type OutputGlobType = PathBuf;
// get the path that InputGlobType refers to
fn as_path(inpg: &InputGlobType) -> &Path {
    match inpg {
        InputGlobType::Deglob(e) => e.path(),
        InputGlobType::Group(_, p) => p.as_path(),
        InputGlobType::Bucket(_, p) => p.as_path(),
    }
}

// Get matched glob in the input to a rule
fn as_glob(inpg: &InputGlobType) -> String {
    match inpg {
        InputGlobType::Deglob(e) => e.group(1).unwrap().to_str().unwrap().to_string(),
        _ => "".to_string(),
    }
}

// Decode input paths from file globs, bins(buckets), and groups
pub trait DecodeInputPaths {
    fn decode(&self, taginfo: &OutputTagInfo) -> Vec<InputGlobType>;
}

// Decode input paths in RvalGeneral
impl DecodeInputPaths for RvalGeneral {
    // convert globs into regular paths, remember that matched groups
    fn decode(&self, taginfo: &OutputTagInfo) -> Vec<InputGlobType> {
        let mut vs: Vec<InputGlobType> = Vec::new();
        match self {
            RvalGeneral::Literal(src) => {
                for src in src.split_whitespace() {
                    if let Some(pos) = src.rfind('*') {
                        let (first, last) = src.split_at(pos);
                        let mut bstr: String = first.to_string();
                        bstr.push_str("(*)"); // replace * with (*) to capture the glob
                        bstr.push_str(&last[1..]);
                        for entry in glob(bstr.as_str())
                            .expect("Failed to read glob pattern")
                            .into_iter()
                            .filter_map(|x| x.ok())
                        {
                            vs.push(InputGlobType::Deglob(entry));
                        }
                    } else {
                        let g = glob(src).expect("Failed to read glob pattern");
                        for p in g.into_iter().filter_map(|x| x.ok()) {
                            vs.push(InputGlobType::Deglob(p))
                        }
                    }
                }
            }
            RvalGeneral::Group(grp) => {
                for rval in grp {
                    if let RvalGeneral::Literal(grp_name) = rval {
                        if let Some(paths) = taginfo.grouptags.get(grp_name) {
                            for p in paths {
                                vs.push(InputGlobType::Group(grp_name.clone(), p.to_path_buf()))
                            }
                        }
                    }
                    break; // only the first one since we expect subst process to have been done
                }
            }
            RvalGeneral::Bucket(str) => {
                if let Some(paths) = taginfo.buckettags.get(str) {
                    for p in paths {
                        vs.push(InputGlobType::Bucket(str.clone(), p.to_path_buf()))
                    }
                }
            }
            _ => {}
        }
        return vs;
    }
}
impl DecodeInputPaths for Vec<RvalGeneral> {
    fn decode(&self, taginfo: &OutputTagInfo) -> Vec<InputGlobType> {
        self.iter().map(|x| x.decode(&taginfo)).flatten().collect()
    }
}

impl DecodeInputPaths for Statement {
    fn decode(&self, taginfo: &OutputTagInfo) -> Vec<InputGlobType> {
        if let Statement::Rule(Link { s, .. }) = self {
            let inputs = s.primary.decode(taginfo);
            inputs
        } else {
            Vec::new()
        }
    }
}

trait GatherOutputs {
    fn gather_outputs(&self, oti: &mut OutputTagInfo);
}

trait DecodePlaceHolders {
    fn decode_place_holders(&self, input: &InputGlobType, output: &Option<OutputGlobType>) -> Self;
}

impl DecodePlaceHolders for RvalGeneral {
    fn decode_place_holders(
        &self,
        input: &InputGlobType,
        output: &Option<OutputGlobType>,
    ) -> RvalGeneral {
        let frep = |d: &str| {
            let path = as_path(&input);
            let grp = as_glob(&input);
            d.replace("%f", path.to_str().unwrap())
                .replace("%B", path.file_stem().unwrap().to_str().unwrap())
                .replace("%g", grp.as_str())
                .replace("%b", path.file_name().unwrap().to_str().unwrap())
                .replace("%e", path.extension().unwrap().to_str().unwrap())
                .replace(
                    "%o",
                    output
                        .as_ref()
                        .unwrap_or(&PathBuf::new())
                        .as_path()
                        .to_str()
                        .unwrap(),
                )
                .replace(
                    "%O",
                    output
                        .as_ref()
                        .unwrap_or(&PathBuf::new())
                        .parent()
                        .unwrap_or(&PathBuf::new())
                        .file_stem()
                        .unwrap()
                        .to_str()
                        .unwrap(),
                )
                .replace(
                    "%d",
                    path.parent()
                        .unwrap()
                        .file_name()
                        .unwrap()
                        .to_str()
                        .unwrap(),
                )
        };
        if let RvalGeneral::Literal(s) = self {
            RvalGeneral::Literal(frep(s).to_string())
        } else {
            self.clone()
        }
    }
}
impl DecodePlaceHolders for Vec<RvalGeneral> {
    fn decode_place_holders(
        &self,
        input: &InputGlobType,
        output: &Option<OutputGlobType>,
    ) -> Vec<RvalGeneral> {
        self.iter()
            .map(|x| x.decode_place_holders(input, output))
            .collect()
    }
}
fn primary_path(tgt: &Target) -> PathBuf {
    PathBuf::from(tostr_cat(&tgt.primary))
}

// replace % specifiers in a rule statement target which has already been
// deglobbed
impl DecodePlaceHolders for Target {
    fn decode_place_holders(&self, input: &InputGlobType, _: &Option<OutputGlobType>) -> Target {
        let newprimary = self.primary.decode_place_holders(input, &None);
        let newsecondary = self
            .secondary
            .decode_place_holders(input, &Some(PathBuf::from(tostr_cat(&newprimary))));
        Target {
            primary: newprimary,
            secondary: newsecondary,
            tag: self.tag.clone(),
        }
    }
}
// deglob rule statement into multiple deglobbed rules
pub fn deglobrule(stmt: &Statement, taginfo: &mut OutputTagInfo) -> Vec<Statement> {
    let mut deglobbed = Vec::new();
    if let Statement::Rule(Link { s, t, r }) = stmt {
        for input in stmt.decode(&taginfo) {
            let tc = t.decode_place_holders(&input, &None);
            let rfc = r.decode_place_holders(&input, &Some(primary_path(&tc)));
            let inputc = vec![RvalGeneral::Literal(
                as_path(&input).to_str().unwrap().to_string(),
            )];
            let src = Source {
                primary: inputc,
                secondary: s.secondary.clone(),
                foreach: false,
            };
            // tc.tags
            deglobbed.push(Statement::Rule(Link {
                s: src,
                t: tc,
                r: rfc,
            }))
        }
    }
    deglobbed
}
// update the groups with the path to primary target
pub fn updategrouptags(tgt: &Target, taginfo: &mut OutputTagInfo) {
    let pathb = primary_path(tgt);
    // let grouppathstr = tostr_cat(&tgt.tag);
    let firstgroupname = tgt.tag.iter().find_map(|x| {
        if let RvalGeneral::Group(grp) = x {
            Some(grp)
        } else {
            None
        }
    });
    if let Some(grpname) = firstgroupname {
        let grpnamestr = tostr_cat(grpname);
        // let pb = PathBuf::from(grouppathstr);
        if let Some(paths) = taginfo.grouptags.get_mut(&grpnamestr) {
            paths.push(pathb);
        } else {
            taginfo.grouptags.insert(grpnamestr, vec![pathb]);
        }
    }
}

// update the bins (buckets) with the path to primary target
pub fn updatebuckets(tgt: &Target, taginfo: &mut OutputTagInfo) {
    let pathb = primary_path(tgt);
    let firstbinname = tgt.tag.iter().find_map(|x| {
        if let RvalGeneral::Bucket(bin) = x {
            Some(bin)
        } else {
            None
        }
    });
    if let Some(binname) = firstbinname {
        if let Some(paths) = taginfo.buckettags.get_mut(binname) {
            paths.push(pathb);
        } else {
            taginfo.buckettags.insert(binname.clone(), vec![pathb]);
        }
    }
}

// reconstruct a rule formula that has placeholders filled up
impl DecodePlaceHolders for RuleFormula {
    fn decode_place_holders(
        &self,
        input: &InputGlobType,
        output: &Option<OutputGlobType>,
    ) -> RuleFormula {
        RuleFormula {
            description: tostr(
                &RvalGeneral::Literal(self.description.clone()).decode_place_holders(input, output),
            ),
            formula: self.formula.decode_place_holders(input, output),
        }
    }
}
