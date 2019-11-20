use parser::parse_tupfile;
use parser::{locate_file, locate_tuprules};
use platform::*;
use statements::*;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub enum StatementContext {
    Export,
    Preload,
    Error,
    Link { source: PathBuf, dest: PathBuf },
    Other,
}

pub struct SubstMap {
    pub expr_map: HashMap<String, String>,
    pub rexpr_map: HashMap<String, String>,
    pub conf_map: HashMap<String, String>,
    pub rule_map: HashMap<String, Link>,
    pub cur_file: PathBuf,
    pub sc: StatementContext,
}

impl Default for SubstMap {
    fn default() -> SubstMap {
        SubstMap {
            expr_map: HashMap::new(),
            rexpr_map: HashMap::new(),
            conf_map: HashMap::new(),
            rule_map: HashMap::new(),
            cur_file: PathBuf::new(),
            sc: StatementContext::Other,
        }
    }
}

pub trait Subst {
    fn subst(&self, m: &mut SubstMap) -> Self;
}

pub trait ExpandMacro {
    fn hasref(&self) -> bool;
    fn expand(&self, m: &mut SubstMap) -> Self;
}

fn is_empty(rval: &RvalGeneral) -> bool {
    if let RvalGeneral::Literal(s) = rval {
        s.trim().len() == 0
    } else {
        false
    }
}

impl Subst for RvalGeneral {
    fn subst(&self, m: &mut SubstMap) -> Self {
        match self {
            &RvalGeneral::DollarExpr(ref x) => {
                if let Some(val) = m.expr_map.get(x.as_str()) {
                    RvalGeneral::Literal(val.to_string())
                } else if !x.contains("%") {
                    RvalGeneral::Literal("".to_owned())
                } else {
                    self.clone()
                }
            }
            &RvalGeneral::AtExpr(ref x) => {
                if let Some(val) = m.conf_map.get(x.as_str()) {
                    RvalGeneral::Literal(val.to_string())
                } else if !x.contains("%") {
                    RvalGeneral::Literal("".to_owned())
                } else {
                    self.clone()
                }
            }
            &RvalGeneral::AmpExpr(ref x) => {
                if let Some(val) = m.rexpr_map.get(x.as_str()) {
                    RvalGeneral::Literal(val.to_string())
                } else if !x.contains("%") {
                    RvalGeneral::Literal("".to_owned())
                } else {
                    self.clone()
                }
            }

            &RvalGeneral::Group(ref xs) => {
                RvalGeneral::Group(xs.into_iter().map(|x| x.subst(m)).collect())
            }
            &RvalGeneral::InlineComment(_) => RvalGeneral::Literal("".to_owned()),
            _ => self.clone(),
        }
    }
}

impl Subst for Vec<RvalGeneral> {
    fn subst(&self, m: &mut SubstMap) -> Self {
        self.iter()
            .map(|x| x.subst(m))
            .filter(|x| !is_empty(x))
            .collect()
    }
}
impl Subst for Source {
    fn subst(&self, m: &mut SubstMap) -> Self {
        Source {
            primary: self.primary.subst(m),
            foreach: self.foreach,
            secondary: self.secondary.subst(m),
        }
    }
}
use std::ops::AddAssign;
impl AddAssign for Source {
    fn add_assign(&mut self, other: Self) {
        let mut o = other;
        self.primary.append(&mut o.primary);
        self.secondary.append(&mut o.secondary);
        self.foreach |= o.foreach;
    }
}

impl AddAssign for Target {
    fn add_assign(&mut self, other: Self) {
        let mut o = other;
        self.primary.append(&mut o.primary);
        self.secondary.append(&mut o.secondary);
        self.tag.append(&mut o.tag);
    }
}

impl Subst for Target {
    fn subst(&self, m: &mut SubstMap) -> Self {
        Target {
            primary: self.primary.subst(m),
            secondary: self.secondary.subst(m),
            tag: self.tag.clone(),
        }
    }
}
impl Subst for RuleFormula {
    fn subst(&self, m: &mut SubstMap) -> Self {
        RuleFormula {
            description: self.description.clone(), // todo : convert to rval and subst here as well,
            formula: self.formula.subst(m),
        }
    }
}
// replace occurences of a macro ref with link data from previous assignments in namedrules
impl ExpandMacro for Link {
    fn hasref(&self) -> bool {
        for rval in self.r.formula.iter() {
            if let RvalGeneral::MacroRef(_) = *rval {
                return true;
            }
        }
        false
    }
    fn expand(&self, m: &mut SubstMap) -> Self {
        let mut source = self.s.clone();
        let mut target = self.t.clone();
        let mut desc = self.r.description.clone();
        let mut formulae = Vec::new();
        let emptylink: Link = Default::default();
        for rval in self.r.formula.iter() {
            match rval {
                &RvalGeneral::MacroRef(ref name) => {
                    let explink = m.rule_map.get(name.as_str()).unwrap_or(&emptylink);
                    source += explink.s.clone();
                    target += explink.t.clone();
                    desc += explink.r.description.as_str();
                    formulae.append(&mut explink.r.formula.clone());
                }
                _ => formulae.push(rval.clone()),
            }
        }
        Link {
            s: source,
            t: target,
            r: RuleFormula {
                description: desc,
                formula: formulae,
            },
        }
    }
}

fn get_parent(cur_file: &Path) -> PathBuf {
    PathBuf::from(cur_file.parent().unwrap().to_str().unwrap())
}

// load the conf variables in tup.config in the root directory
pub fn load_conf_vars(filename: &Path) -> HashMap<String, String> {
    let mut conf_vars: HashMap<String, String> = HashMap::new();

    if let Some(conf_file) = locate_file(filename, "tup.config") {
        if let Some(fstr) = conf_file.to_str() {
            for stmt in parse_tupfile(fstr).iter() {
                match stmt {
                    Statement::LetExpr { left, right, .. } => {
                        if left.name.starts_with("CONFIG_") {
                            conf_vars.insert(left.name[7..].to_string(), tostr_cat(right));
                        }
                    }
                    _ => (),
                }
            }
        }
    }
    if !conf_vars.contains_key("TUP_PLATFORM") {
        conf_vars.insert("TUP_PLATFORM".to_owned(), get_platform());
    }
    if !conf_vars.contains_key("TUP_ARCH") {
        conf_vars.insert("TUP_ARCH".to_owned(), get_arch());
    }

    // @(TUP_PLATFORM)
    //     TUP_PLATFORM is a special @-variable. If CONFIG_TUP_PLATFORM is not set in the tup.config file, it has a default value according to the platform that tup itself was compiled in. Currently the default value is one of "linux", "solaris", "macosx", "win32", or "freebsd".
    //     @(TUP_ARCH)
    //     TUP_ARCH is another special @-variable. If CONFIG_TUP_ARCH is not set in the tup.config file, it has a default value according to the processor architecture that tup itself was compiled in. Currently the default value is one of "i386", "x86_64", "powerpc", "powerpc64", "ia64", "alpha", "sparc", "arm64", or "arm".

    conf_vars
}
pub fn set_cwd(filename: &Path, m: &mut SubstMap) -> PathBuf {
    let cf = m.cur_file.clone();
    m.cur_file = filename.to_path_buf();
    // println!("{:?}", get_parent(m.cur_file.as_path()).to_str().unwrap_or("empty"));
    let ref mut def_vars = m.expr_map;
    if let Some(p) = get_parent(m.cur_file.as_path()).to_str() {
        def_vars.remove("TUP_CWD");
        def_vars.insert("TUP_CWD".to_owned(), p.to_owned());
    }
    cf
}

impl Subst for Link {
    fn subst(&self, m: &mut SubstMap) -> Self {
        Link {
            s: self.s.subst(m),
            t: self.t.subst(m),
            r: self.r.subst(m),
        }
    }
}
// substitute variables in a sequence of statements from previous assignments
// update variable assignments into substmap as you go.
impl Subst for Vec<Statement> {
    fn subst(&self, m: &mut SubstMap) -> Vec<Statement> {
        let mut newstats = Vec::new();
        for statement in self.iter() {
            match statement {
                Statement::LetExpr {
                    left,
                    right,
                    is_append,
                } => {
                    let &app = is_append;
                    let subst_right = tostr_cat(&right.subst(m));
                    let curright = if app {
                        match m.expr_map.get(left.name.as_str()) {
                            Some(prevright) => prevright.to_string() + " " + subst_right.as_str(),
                            _ => subst_right,
                        }
                    } else {
                        subst_right
                    };
                    m.expr_map.insert(left.name.clone(), curright);
                }
                Statement::LetRefExpr {
                    left,
                    right,
                    is_append,
                } => {
                    let &app = is_append;
                    let prefix = vec![
                        RvalGeneral::DollarExpr("TUP_CWD".to_owned()),
                        RvalGeneral::Literal("/".to_owned()),
                    ]
                    .subst(m);
                    let subst_right = tostr_cat(&prefix) + tostr_cat(&right.subst(m)).as_str();
                    let curright = if app {
                        match m.rexpr_map.get(left.name.as_str()) {
                            Some(prevright) => prevright.to_string() + " " + subst_right.as_str(),
                            _ => subst_right,
                        }
                    } else {
                        subst_right
                    };
                    m.rexpr_map.insert(left.name.clone(), curright);
                }

                Statement::IfElseEndIf {
                    eq,
                    then_statements,
                    else_statements,
                } => {
                    let e = EqCond {
                        lhs: eq.lhs.subst(m),
                        rhs: eq.rhs.subst(m),
                        not_cond: eq.not_cond,
                    };
                    if tostr_cat(&e.lhs) == tostr_cat(&e.rhs) && !e.not_cond {
                        newstats.append(&mut then_statements.subst(m));
                    } else {
                        newstats.append(&mut else_statements.subst(m));
                    }
                }
                Statement::IfDef {
                    checked_var,
                    then_statements,
                    else_statements,
                } => {
                    let cvar = RvalGeneral::AtExpr(checked_var.0.name.clone());
                    if is_empty(&cvar.subst(m)) == checked_var.1 {
                        newstats.append(&mut then_statements.subst(m));
                    } else {
                        newstats.append(&mut else_statements.subst(m));
                    }
                }

                Statement::IncludeRules => {
                    let parent = get_parent(m.cur_file.as_path());
                    if let Some(f) = locate_tuprules(parent.as_path()) {
                        let include_stmts = parse_tupfile(f.to_str().unwrap());
                        m.cur_file = f;
                        newstats.append(&mut include_stmts.subst(m));
                    }
                }
                Statement::Include(s) => {
                    let s = s.subst(m);
                    let scat = tostr_cat(&s);
                    let longp = get_parent(m.cur_file.as_path());
                    let pscat = Path::new(scat.as_str());
                    let fullp = longp.join(pscat);
                    let p = if pscat.is_relative() {
                        fullp.as_path()
                    } else {
                        pscat
                    };
                    if p.is_file() {
                        let include_stmmts = parse_tupfile(p.to_str().unwrap());
                        let cf = set_cwd(p, m);
                        newstats.append(&mut include_stmmts.subst(m));
                        set_cwd(cf.as_path(), m);
                    }
                }
                Statement::Rule(link) => {
                    let mut l = link.clone();
                    while l.hasref() {
                        l = l.expand(m); // expand all nested macro refs
                    }
                    newstats.push(Statement::Rule(l.subst(m)));
                }
                // dont subst inside a macro assignment
                // just update the rule_map
                Statement::MacroAssignment(name, link) => {
                    m.rule_map.insert(name.clone(), link.clone());
                }
                Statement::Err(v) => {
                    let v = v.subst(m);
                    eprintln!("{}\n", tostr_cat(&v).as_str());
                    break;
                }
                Statement::Preload(v) => {
                    newstats.push(Statement::Preload(v.subst(m)));
                }
                Statement::Export(ex) => {
                    newstats.push(Statement::Export(ex.subst(m)));
                }
                Statement::Run(r) => {
                    newstats.push(Statement::Export(r.subst(m)));
                }
                Statement::Comment(_) => {
                    // ignore
                }
            }
        }
        newstats
    }
}
// extract the literals in the list of generals deglob the strings, replace %f,
// %B etc and create rules per match for 'foreach' expressions
// pub fn deglob(statement: &Statement) -> Vec<Statement> {
//     let mut deglobbed = Vec::new();
//     if let Statement::Rule(Link { s, t, r }) = statement {
//         if s.foreach {
//             let paths = s
//                 .primary
//                 .iter()
//                 .filter_map(|x| {
//                     if let RvalGeneral::Literal(src) = x {
//                         let mut vs = Vec::new();
//                         for src in src.split_whitespace() {
//                             if let Some(pos) = src.rfind('*') {
//                                 let (first, last) = src.split_at(pos);
//                                 let mut bstr: String = first.to_string();
//                                 bstr.push_str("(*)"); // replace * with (*) to capture the glob
//                                 bstr.push_str(&last[1..]);
//                                 let g = glob(bstr.as_str()).expect("Failed to read glob pattern");
//                                 for p in g.into_iter().filter_map(|x| x.ok()) {
//                                     vs.push(p);
//                                 }
//                             } else {
//                                 let g = glob(src).expect("Failed to read glob pattern");
//                                 for p in g.into_iter().filter_map(|x| x.ok()) {
//                                     vs.push(p)
//                                 }
//                             }
//                         }
//                         Some(vs)
//                     } else {
//                         None
//                     }
//                 })
//                 .flatten();
//             for p in paths {
//                 let path = p.path();
//                 let mut tc = t.clone();
//                 let frep = |d: &str| {
//                     d.replace("%i", path.to_str().unwrap())
//                         .replace("%B", path.file_stem().unwrap().to_str().unwrap())
//                         .replace("%g", p.group(1).unwrap().to_str().unwrap())
//                         .replace("%b", path.file_name().unwrap().to_str().unwrap())
//                         .replace("%e", path.extension().unwrap().to_str().unwrap())
//                         .replace(
//                             "%d",
//                             path.parent()
//                                 .unwrap()
//                                 .file_name()
//                                 .unwrap()
//                                 .to_str()
//                                 .unwrap(),
//                         )
//                 };
//                 tc.primary = tc
//                     .primary
//                     .iter()
//                     .filter_map(|x| {
//                         if let RvalGeneral::Literal(s) = x {
//                             Some(RvalGeneral::Literal(frep(s).to_string()))
//                         } else {
//                             None
//                         }
//                     })
//                     .collect();
//                 let mut rc = r.clone();
//                 rc.description = frep(r.description.as_str());

//                 rc.formula = r
//                     .formula
//                     .iter()
//                     .filter_map(|x| {
//                         if let RvalGeneral::Literal(s) = x {
//                             Some(RvalGeneral::Literal(frep(s).to_string()))
//                         } else {
//                             None
//                         }
//                     })
//                     .collect();

//                 let newsrc = Source {
//                     primary: vec![RvalGeneral::Literal(path.to_str().unwrap().to_string())],
//                     foreach: false,
//                     secondary: s.secondary.clone(),
//                 };
//                 deglobbed.push(Statement::Rule(Link {
//                     s: newsrc,
//                     t: tc,
//                     r: rc,
//                 }));
//             }
//         }
//     } else {
//         deglobbed.push(statement.clone());
//     }
//     return deglobbed;
// }
