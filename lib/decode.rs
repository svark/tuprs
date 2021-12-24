use glob::{glob, Entry};
use statements::*;
use std::collections::HashMap;
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

fn as_grp(inpg: &InputGlobType) -> String {
    match inpg {
        InputGlobType::Group(name, _) => name.clone(),
        _ => "".to_string(),
    }
}

// Decode input paths from file globs, bins(buckets), and groups
pub trait DecodeInputPaths {
    fn decode(&self, taginfo: &OutputTagInfo) -> Vec<InputGlobType>;
}

// Decode input paths in RvalGeneral
impl DecodeInputPaths for PathExpr {
    // convert globs into regular paths, remember that matched groups
    fn decode(&self, taginfo: &OutputTagInfo) -> Vec<InputGlobType> {
        let mut vs: Vec<InputGlobType> = Vec::new();
        match self {
            PathExpr::Literal(src) => {
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
            PathExpr::Group(_,_) => {
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
                        vs.push(InputGlobType::Bucket(str.clone(), p.to_path_buf()))
                    }
                }
            }
            _ => {}
        }
        return vs;
    }
}
impl DecodeInputPaths for Vec<PathExpr> {
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

impl DecodePlaceHolders for PathExpr {
    fn decode_place_holders(
        &self,
        input: &InputGlobType,
        output: &Option<OutputGlobType>,
    ) -> PathExpr {
        let frep = |d: &str| {
            let path = as_path(&input);
            let glb = as_glob(&input);
            let grp = "%<".to_string() + as_grp(&input).as_str() + ">";
            d.replace("%f", path.to_str().unwrap())
                .replace("%B", path.file_stem().unwrap().to_str().unwrap())
                .replace("%g", glb.as_str())
                .replace(grp.as_str(), path.to_str().unwrap())
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
        if let PathExpr::Literal(s) = self {
            PathExpr::Literal(frep(s).to_string())
        } else {
            self.clone()
        }
    }
}
impl DecodePlaceHolders for Vec<PathExpr> {
    fn decode_place_holders(
        &self,
        input: &InputGlobType,
        output: &Option<OutputGlobType>,
    ) -> Vec<PathExpr> {
        self.iter()
            .map(|x| x.decode_place_holders(input, output))
            .collect()
    }
}
fn primary_path(tgt: &Target) -> PathBuf {
    PathBuf::from(tgt.primary.cat())
}

// replace % specifiers in a rule statement target which has already been
// deglobbed
impl DecodePlaceHolders for Target {
    fn decode_place_holders(&self, input: &InputGlobType, _: &Option<OutputGlobType>) -> Target {
        let newprimary = self.primary.decode_place_holders(input, &None);
        let newsecondary = self
            .secondary
            .decode_place_holders(input, &Some(PathBuf::from(newprimary.cat())));
        Target {
            primary: newprimary,
            secondary: newsecondary,
            bin: self.bin.clone(),
            group: self.group.clone(),
        }
    }
}
// deglob rule statement into multiple deglobbed rules, update the buckets corresponding to the deglobed targets
pub fn deglobrule(stmt: &Statement, taginfo: &OutputTagInfo) -> (Vec<Statement>, OutputTagInfo) {
    let mut deglobbed = Vec::new();
    let mut output: OutputTagInfo = Default::default();
    if let Statement::Rule(Link { s, t, r, pos }) = stmt {
        let inpdec = s.primary.decode(&taginfo);
        let secondinpdec = s.secondary.decode(&taginfo);
        let ref mut sinputs = Vec::new();
        for sinput in secondinpdec {
            sinputs.push(PathExpr::Literal(
                as_path(&sinput).to_str().unwrap().to_string(),
            ));
        }
        for input in inpdec {
            let tc = t.decode_place_holders(&input, &None);
            let rfc = r.decode_place_holders(&input, &Some(primary_path(&tc)));
            updatetags(&tc, &mut output);
            let inputc = vec![PathExpr::Literal(
                as_path(&input).to_str().unwrap().to_string(),
            )];
            let src = Source {
                primary: inputc,
                secondary: sinputs.clone(),
                foreach: false,
            }; // single source input
               // tc.tags
            deglobbed.push(Statement::Rule(Link {
                s: src,
                t: tc,
                r: rfc,
                pos: *pos,
            }))
        }
    } else {
        deglobbed.push(stmt.clone())
    }
    (deglobbed, output)
}
// update the groups with the path to primary target
fn updatetags(tgt: &Target, taginfo: &mut OutputTagInfo) {
    let pathb = primary_path(tgt);
    let ref firstgroupname = tgt.group;
    if let Some(grpname) = firstgroupname {
        let grpnamestr = grpname.cat();
        // let pb = PathBuf::from(grouppathstr);
        if let Some(paths) = taginfo.grouptags.get_mut(&grpnamestr) {
            paths.push(pathb.clone());
        } else {
            taginfo.grouptags.insert(grpnamestr, vec![pathb.clone()]);
        }
    }
    let ref firstbinname = tgt.bin.clone().map(|x| x.cat());
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
            description: PathExpr::Literal(self.description.clone())
                .decode_place_holders(input, output)
                .cat(),
            formula: self.formula.decode_place_holders(input, output),
        }
    }
}
