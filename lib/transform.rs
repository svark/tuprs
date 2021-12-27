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
    pub expr_map: HashMap<String, Vec<String> >,
    pub rexpr_map: HashMap<String, Vec<String> >,
    pub conf_map: HashMap<String, Vec<String> >,
    pub rule_map: HashMap<String, Link>,
    pub cur_file: PathBuf,
    pub sc: StatementContext,
    pub waitforpercs : bool,
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
            waitforpercs : true,
        }
    }
}

impl SubstMap {
    pub fn new(conf_map: &HashMap<String, Vec<String> >, cur_file: &Path) -> Self {
        let mut def_vars = HashMap::new();
        if let Some(p) = get_parent(cur_file).to_str() {
            def_vars.insert("TUP_CWD".to_owned(), vec![p.to_owned()]);
        }
        SubstMap {
            conf_map: conf_map.clone(),
            expr_map: def_vars,
            ..SubstMap::default()
        }
    }
}

pub trait Subst {
    fn subst(&self, m: &mut SubstMap) -> Self;
}

pub trait ExpandMacro {
    fn has_ref(&self) -> bool;
    fn expand(&self, m: &mut SubstMap) -> Self;
}

fn is_empty(rval: &PathExpr) -> bool {
    if let PathExpr::Literal(s) = rval {
        s.len() == 0
    } else {
        false
    }
}
trait Deps {
    fn input_groups(&self) -> Vec<String>;
    fn output_groups(&self) -> Vec<String>;
}
// scan for group tags in a vec of rvalgenerals
impl Deps for Vec<PathExpr> {
    fn input_groups(&self) -> Vec<String> {
        let mut inps = Vec::new();
        for rval in self.iter() {
            if let PathExpr::Group(_,_) = rval {
                let name = rval.cat();
                inps.push(name)
            }
        }
        inps
    }
    // dont distinguish between input and output at this level
    fn output_groups(&self) -> Vec<String> {
        self.input_groups()
    }
}
impl Deps for Statement {
    fn input_groups(&self) -> Vec<String> {
        if let Statement::Rule(Link { source: s, .. }) = self {
            let mut inp_groups_prim = s.primary.input_groups();
            let mut inp_groups_sec = s.secondary.input_groups();
            inp_groups_prim.append(&mut inp_groups_sec);
            inp_groups_prim
        } else {
            Vec::new()
        }
    }

    fn output_groups(&self) -> Vec<String> {
        if let Statement::Rule(Link { source: _s, target: t, .. }) = self {
            let mut out_groups_prim = t.primary.output_groups();
            let mut out_groups_sec = t.secondary.output_groups();
            out_groups_prim.append(&mut out_groups_sec);
            out_groups_prim
        } else {
            Vec::new()
        }
    }
}
impl PathExpr {
    fn subst(&self, m: &mut SubstMap) -> Vec<PathExpr> {
        match self{
            &PathExpr::DollarExpr(ref x) => {
                if let Some(val) = m.expr_map.get(x.as_str()) {
                    val.iter()
                        .map(|x| PathExpr::from(x.clone()))
                        .intersperse(PathExpr::Sp1)
                        .collect()
                } else if !x.contains("%") {
                    vec![PathExpr::from("".to_owned())] // postpone subst until placeholders are fixed
                } else {
                    vec![self.clone()]
                }
            }
            &PathExpr::AtExpr(ref x) => {
                if let Some(val) = m.conf_map.get(x.as_str()) {
                    val.iter().map(|x| PathExpr::from(x.clone()))
                        .intersperse(PathExpr::Sp1)
                        .collect()
                } else if !x.contains("%") {
                    vec![PathExpr::Literal("".to_owned())]
                } else {
                    vec![self.clone()]
                }
            }
            &PathExpr::AmpExpr(ref x) => {
                if let Some(val) = m.rexpr_map.get(x.as_str()) {
                    val.iter().map(|x| PathExpr::from(x.clone())).collect()
                } else if !x.contains("%") {
                    vec![PathExpr::Literal("".to_owned())]
                } else {
                    vec![self.clone()]
                }
            }

            &PathExpr::Group(ref xs, ref ys) => {
                vec![PathExpr::Group(xs.iter().map(|x| x.subst(m)).flatten().collect(),
                                ys.iter().map(|y| y.subst(m)).flatten().collect())]
            }
            /*&PathExpr::Sp1 => {
                PathExpr::Literal(" ".to_string())
            }*/
            _ => vec![self.clone()],
        }
    }
}

impl Subst for Vec<PathExpr> {
    fn subst(&self, m: &mut SubstMap) -> Self {
        self.iter()
            .map(|x| x.subst(m))
            .flatten()
            .filter(|x| !is_empty(x))
            .collect()
    }
}
impl Subst for Source {
    fn subst(&self, m: &mut SubstMap) -> Self {
        Source {
            primary: self.primary.subst(m),
            for_each: self.for_each,
            secondary: self.secondary.subst(m),
        }
    }
}
use std::ops::AddAssign;
impl AddAssign for Source {
    fn add_assign(&mut self, other: Self) {
        let mut o = other;
        self.primary.strip_trailing_ws();
        self.primary.append(&mut o.primary);
        self.secondary.strip_trailing_ws();
        self.secondary.append(&mut o.secondary);
        self.for_each |= o.for_each;
    }
}

impl AddAssign for Target {
    fn add_assign(&mut self, other: Self) {
        let mut o = other;
        self.primary.strip_trailing_ws();
        self.primary.append(&mut o.primary);

        self.secondary.strip_trailing_ws();
        self.secondary.append(&mut o.secondary);

        self.group = self.group.clone().or(o.group);
        self.bin = self.bin.clone().or(o.bin);
    }
}
fn takefirst(o: &Option<PathExpr>, m: &mut SubstMap ) -> Option<PathExpr> {
    if let &Some(ref pe) = o {
        pe.subst(m).first().cloned()
    } else
    {
        None
    }
}
impl Subst for Target {
    fn subst(&self, m: &mut SubstMap) -> Self {
        Target {
            primary: self.primary.subst(m),
            secondary: self.secondary.subst(m),
            exclude_pattern: self.exclude_pattern.clone(),
            group: takefirst(&self.group, m),
            bin: takefirst(&self.bin, m),
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
    fn has_ref(&self) -> bool {
        for rval in self.rule_formula.formula.iter() {
            if let PathExpr::MacroRef(_) = *rval {
                return true;
            }
        }
        false
    }
    fn expand(&self, m: &mut SubstMap) -> Self {
        let mut source = self.source.clone();
        let mut target = self.target.clone();
        let mut desc = self.rule_formula.description.clone();
        let pos = self.pos;
        let mut formulae = Vec::new();
        for pathexpr in self.rule_formula.formula.iter() {
            match pathexpr {
                &PathExpr::MacroRef(ref name) => {
                    if let Some(explink) = m.rule_map.get(name.as_str()) {
                        source += explink.source.clone();
                        target += explink.target.clone();
                        desc += explink.rule_formula.description.as_str();
                        //formulae.strip_trailing_ws();
                        let mut r = explink.rule_formula.formula.clone();
                        r.strip_trailing_ws();
                        formulae.append(&mut r);
                    }else {
                        eprintln!("ignored missing macro definition for :{}", name);
                    }
                }
                _ => formulae.push(pathexpr.clone()),
            }
        }
        Link {
            source,
            target,
            rule_formula: RuleFormula {
                description: desc,
                formula: formulae,
            },
            pos,
        }
    }
}

fn get_parent(cur_file: &Path) -> PathBuf {
    PathBuf::from(cur_file.parent().unwrap().to_str().unwrap())
}
// strings in pathexpr that are space separated
fn tovecstring(right: &Vec<PathExpr>) -> Vec<String> {
    right.split(|x| x == &PathExpr::Sp1)
        .map(|x| x.to_vec().cat())
        .collect()
}
// load the conf variables in tup.config in the root directory
pub fn load_conf_vars(filename: &Path) -> HashMap<String, Vec<String> > {
    let mut conf_vars= HashMap::new();

    if let Some(conf_file) = locate_file(filename, "tup.config") {
        if let Some(fstr) = conf_file.to_str() {
            for stmt in parse_tupfile(fstr).iter() {
                match stmt {
                    Statement::LetExpr { left, right, .. } => {
                        if left.name.starts_with("CONFIG_") {
                            conf_vars.insert(left.name[7..].to_string(), tovecstring(right));
                        }
                    }
                    _ => (),
                }
            }
        }
    }
    if !conf_vars.contains_key("TUP_PLATFORM") {
        conf_vars.insert("TUP_PLATFORM".to_owned(), vec![get_platform()]);
    }
    if !conf_vars.contains_key("TUP_ARCH") {
        conf_vars.insert("TUP_ARCH".to_owned(), vec![get_arch()]);
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
        def_vars.insert("TUP_CWD".to_owned(), vec![p.to_owned()]);
    }
    cf
}

impl Subst for Link {
    fn subst(&self, m: &mut SubstMap) -> Self {
        Link {
            source: self.source.subst(m),
            target: self.target.subst(m),
            rule_formula: self.rule_formula.subst(m),
            pos: self.pos,
        }
    }
}
// substitute variables in a sequence of statements from previous assignments
// update variable assignments into substmap as you go.
impl Subst for Vec<Statement> {
    fn subst(&self, m: &mut SubstMap) -> Vec<Statement> {
        let mut newstats = Vec::new();
        //let sp1 = PathExpr::Sp1;
        for statement in self.iter() {
            match statement {
                Statement::LetExpr {
                    left,
                    right,
                    is_append,
                } => {
                    let &app = is_append;
                    let subst_right : Vec<_> = right.split(|x| x == &PathExpr::Sp1)
                        .map(|x| x.to_vec().subst(m).cat())
                        .collect();

                    let curright: Vec<String> = if app {
                        match m.expr_map.get(left.name.as_str()) {
                            Some(prevright) =>
                                prevright.iter().map(|x| x.clone())
                                    .chain( subst_right)
                                    .collect(),
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
                        PathExpr::DollarExpr("TUP_CWD".to_owned()),
                        PathExpr::Literal("/".to_owned()),
                    ]
                    .subst(m).cat();
                    let subst_right : Vec<String> = right.split(|x| x == &PathExpr::Sp1)
                        .map(|x| prefix.clone() + x.to_vec().subst(m).cat().as_str())
                        .collect();

                    //let subst_right = prefix.cat() + (right.subst(m)).cat().as_str();
                    let curright = if app {
                        match m.rexpr_map.get(left.name.as_str()) {
                            Some(prevright) =>
                                prevright.iter().map(|x| x.clone())
                                    .chain( subst_right)
                                    .collect(),
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
                    if e.lhs.cat().eq(&e.rhs.cat()) && !e.not_cond {
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
                    let cvar = PathExpr::AtExpr(checked_var.0.name.clone());
                    if cvar.subst(m).iter().any(|x| is_empty(x)) == checked_var.1 {
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
                    let scat = &s.cat();
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
                    while l.has_ref() {
                        l = l.expand(m); // expand all nested macro refs
                    }
                    newstats.push(Statement::Rule(l.subst(m)));
                }
                // dont subst inside a macro assignment
                // just update the rule_map
                Statement::MacroAssignment(name, link) => {
                    let l = link.clone();
                    m.rule_map.insert(name.clone(), l);
                }
                Statement::Err(v) => {
                    let v = v.subst(m);
                    eprintln!("{}\n", &v.cat().as_str());
                    break;
                }
                Statement::Preload(v) => {
                    newstats.push(Statement::Preload(v.subst(m)));
                }
                Statement::Export(_) => {
                    newstats.push(statement.clone());
                }
                Statement::Import(_,_) => {
                    newstats.push(statement.clone());
                }
                Statement::Run(r) => {
                    newstats.push(Statement::Run(r.subst(m)));
                }
                Statement::Comment => {
                    // ignore
                }
            }
        }
        newstats
    }
}
