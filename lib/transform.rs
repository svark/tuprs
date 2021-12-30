use daggy::{petgraph, Dag, NodeIndex};
use errors::Error as Err;
use parser::parse_tupfile;
use parser::{locate_file, locate_tuprules};
use platform::*;
use statements::*;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;
pub enum StatementContext {
    Export,
    Preload,
    Error,
    Link { source: PathBuf, dest: PathBuf },
    Other,
}

pub struct SubstMap {
    pub expr_map: HashMap<String, Vec<String>>,
    pub rexpr_map: HashMap<String, Vec<String>>,
    pub conf_map: HashMap<String, Vec<String>>,
    pub rule_map: HashMap<String, Link>,
    pub cur_file: PathBuf,
    pub sc: StatementContext,
    pub waitforpercs: bool,
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
            waitforpercs: true,
        }
    }
}

impl SubstMap {
    pub fn new(conf_map: &HashMap<String, Vec<String>>, cur_file: &Path) -> Self {
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
    fn subst(&self, m: &mut SubstMap) -> Result<Self, Err>
    where
        Self: Sized;
}

pub trait ExpandMacro {
    fn has_ref(&self) -> bool;
    fn expand(&self, m: &mut SubstMap) -> Result<Self, Err>
    where
        Self: Sized;
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
    fn input_bins(&self) -> Vec<String>;

    fn output_groups(&self) -> Vec<String>;
    fn output_bins(&self) -> Vec<String>;
}
// scan for group tags in a vec of rvalgenerals
impl Deps for Vec<PathExpr> {
    fn input_groups(&self) -> Vec<String> {
        let mut inps = Vec::new();
        for rval in self.iter() {
            if let PathExpr::Group(_, _) = rval {
                let name = rval.cat();
                inps.push(name)
            }
        }
        inps
    }

    fn input_bins(&self) -> Vec<String> {
        let mut inps = Vec::new();
        for rval in self.iter() {
            if let PathExpr::Bin(_) = rval {
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

    fn output_bins(&self) -> Vec<String> {
        self.input_bins()
    }
}

impl Deps for LocatedStatement {
    fn input_groups(&self) -> Vec<String> {
        let mut allinputgrps = Vec::new();
        if let &Statement::Rule(Link { source: ref s, .. }) = self.getstatement() {
            allinputgrps.append(&mut s.primary.input_groups());
            allinputgrps.append(&mut s.secondary.input_groups());
        }
        allinputgrps
    }

    fn input_bins(&self) -> Vec<String> {
        let mut allinputbins = Vec::new();
        if let &Statement::Rule(Link { source: ref s, .. }) = self.getstatement() {
            allinputbins.append(&mut s.primary.input_bins());
            allinputbins.append(&mut s.secondary.input_bins());
        }
        allinputbins
    }

    fn output_groups(&self) -> Vec<String> {
        let mut alloutputgroups = Vec::new();
        let stmt = self.getstatement();
        if let &Statement::Rule(Link { target: ref t, .. }) = stmt {
            if let Target {
                group: Some(grp), ..
            } = t
            {
                alloutputgroups.push(grp.cat());
            }
        }
        alloutputgroups
    }

    fn output_bins(&self) -> Vec<String> {
        let mut alloutputbins = Vec::new();
        let stmt = self.getstatement();
        if let &Statement::Rule(Link { target: ref t, .. }) = stmt {
            if let Target { bin: Some(bin), .. } = t {
                alloutputbins.push(bin.cat());
            }
        }
        alloutputbins
    }
}
impl Deps for Vec<LocatedStatement> {
    fn input_groups(&self) -> Vec<String> {
        let mut allinputgrps = Vec::new();
        for l in self.into_iter() {
            if let &Statement::Rule(Link { source: ref s, .. }) = l.getstatement() {
                allinputgrps.append(&mut s.primary.input_groups());
                allinputgrps.append(&mut s.secondary.input_groups());
            }
        }
        allinputgrps
    }

    fn input_bins(&self) -> Vec<String> {
        let mut allinputbins = Vec::new();
        for l in self.into_iter() {
            if let &Statement::Rule(Link { source: ref s, .. }) = l.getstatement() {
                allinputbins.append(&mut s.primary.input_bins());
                allinputbins.append(&mut s.secondary.input_bins());
            }
        }
        allinputbins
    }

    fn output_groups(&self) -> Vec<String> {
        let mut alloutputgroups = Vec::new();
        for l in self.into_iter() {
            let stmt = l.getstatement();
            if let &Statement::Rule(Link { target: ref t, .. }) = stmt {
                if let Target {
                    group: Some(grp), ..
                } = t
                {
                    alloutputgroups.push(grp.cat());
                }
            }
        }
        alloutputgroups
    }

    fn output_bins(&self) -> Vec<String> {
        let mut alloutputbins = Vec::new();
        for l in self.into_iter() {
            let stmt = l.getstatement();
            if let &Statement::Rule(Link { target: ref t, .. }) = stmt {
                if let Target { bin: Some(bin), .. } = t {
                    alloutputbins.push(bin.cat());
                }
            }
        }
        alloutputbins
    }
}

impl PathExpr {
    // substitute a single pathexpr into an array of literal pathexpr
    // SFINAE holds
    fn subst(&self, m: &mut SubstMap) -> Vec<PathExpr> {
        match self {
            &PathExpr::DollarExpr(ref x) => {
                if let Some(val) = m.expr_map.get(x.as_str()) {
                    intersperse_sp1(val)
                } else if !x.contains("%") {
                    vec![PathExpr::from("".to_owned())] // postpone subst until placeholders are fixed
                } else {
                    vec![self.clone()]
                }
            }
            &PathExpr::AtExpr(ref x) => {
                if let Some(val) = m.conf_map.get(x.as_str()) {
                    intersperse_sp1(val)
                } else if !x.contains("%") {
                    vec![PathExpr::Literal("".to_owned())]
                } else {
                    vec![self.clone()]
                }
            }
            &PathExpr::AmpExpr(ref x) => {
                if let Some(val) = m.rexpr_map.get(x.as_str()) {
                    intersperse_sp1(val)
                    // val.iter().map(|x| PathExpr::from(x.clone())).collect()
                } else if !x.contains("%") {
                    vec![PathExpr::Literal("".to_owned())]
                } else {
                    vec![self.clone()]
                }
            }

            &PathExpr::Group(ref xs, ref ys) => {
                vec![PathExpr::Group(
                    xs.iter().map(|x| x.subst(m)).flatten().collect(),
                    ys.iter().map(|y| y.subst(m)).flatten().collect(),
                )]
            }
            _ => vec![self.clone()],
        }
    }
}

// creates Pathexprs separated by PathExpr::Sp1
// this is implementation of rust nightly feature intersperse on Iter
fn intersperse_sp1(val: &Vec<String>) -> Vec<PathExpr> {
    let mut vs = Vec::new();
    for pe in val.iter().map(|x| PathExpr::from(x.clone())) {
        vs.push(pe);
        vs.push(PathExpr::Sp1);
    }
    vs.pop();
    vs
}

impl Subst for Vec<PathExpr> {
    fn subst(&self, m: &mut SubstMap) -> Result<Self, Err> {
        let mut newpe: Vec<_> = self
            .iter()
            .map(|x| x.subst(m))
            .flatten()
            .filter(|x| !is_empty(x))
            .collect();
        newpe.strip_trailing_ws();
        Ok(newpe)
    }
}
impl Subst for Source {
    fn subst(&self, m: &mut SubstMap) -> Result<Self, Err> {
        Ok(Source {
            primary: self.primary.subst(m)?,
            for_each: self.for_each,
            secondary: self.secondary.subst(m)?,
        })
    }
}
use decode::{OutputTagInfo, PathDecoder};
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
fn takefirst(o: &Option<PathExpr>, m: &mut SubstMap) -> Result<Option<PathExpr>, Err> {
    if let &Some(ref pe) = o {
        Ok(pe.subst(m).first().cloned())
    } else {
        Ok(None)
    }
}
impl Subst for Target {
    fn subst(&self, m: &mut SubstMap) -> Result<Self, Err> {
        Ok(Target {
            primary: self.primary.subst(m)?,
            secondary: self.secondary.subst(m)?,
            exclude_pattern: self.exclude_pattern.clone(),
            group: takefirst(&self.group, m)?,
            bin: takefirst(&self.bin, m)?,
        })
    }
}
impl Subst for RuleFormula {
    fn subst(&self, m: &mut SubstMap) -> Result<Self, Err> {
        Ok(RuleFormula {
            description: self.description.clone(), // todo : convert to rval and subst here as well,
            formula: self.formula.subst(m)?,
        })
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
    fn expand(&self, m: &mut SubstMap) -> Result<Self, Err> {
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
                    } else {
                        return Err(Err::UnknownMacroRef(
                            name.clone(),
                            Loc::new(pos.0, pos.1 as u32),
                        ));
                    }
                }
                _ => formulae.push(pathexpr.clone()),
            }
        }
        Ok(Link {
            source,
            target,
            rule_formula: RuleFormula {
                description: desc,
                formula: formulae,
            },
            pos,
        })
    }
}

fn get_parent(cur_file: &Path) -> PathBuf {
    PathBuf::from(cur_file.parent().unwrap().to_str().unwrap())
}
// strings in pathexpr that are space separated
fn tovecstring(right: &Vec<PathExpr>) -> Vec<String> {
    right
        .split(|x| x == &PathExpr::Sp1)
        .map(|x| x.to_vec().cat())
        .collect()
}
// load the conf variables in tup.config in the root directory
pub fn load_conf_vars(
    filename: &Path,
) -> Result<HashMap<String, Vec<String>>, crate::errors::Error> {
    let mut conf_vars = HashMap::new();

    if let Some(conf_file)  = Path::new(filename).parent().map(|x| x.join( "tup.config")) {
        if conf_file.is_file() {
            if let Some(fstr) = conf_file.to_str() {
                for LocatedStatement { statement, .. } in parse_tupfile(fstr)?.iter() {
                    match statement {
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
    }
    // @(TUP_PLATFORM)
    //     TUP_PLATFORM is a special @-variable. If CONFIG_TUP_PLATFORM is not set in the tup.config file, it has a default value according to the platform that tup itself was compiled in. Currently the default value is one of "linux", "solaris", "macosx", "win32", or "freebsd".
    //     @(TUP_ARCH)
    //     TUP_ARCH is another special @-variable. If CONFIG_TUP_ARCH is not set in the tup.config file, it has a default value according to the processor architecture that tup itself was compiled in. Currently the default value is one of "i386", "x86_64", "powerpc", "powerpc64", "ia64", "alpha", "sparc", "arm64", or "arm".
    if !conf_vars.contains_key("TUP_PLATFORM") {
        conf_vars.insert("TUP_PLATFORM".to_owned(), vec![get_platform()]);
    }
    if !conf_vars.contains_key("TUP_ARCH") {
        conf_vars.insert("TUP_ARCH".to_owned(), vec![get_arch()]);
    }

    Ok(conf_vars)
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
    fn subst(&self, m: &mut SubstMap) -> Result<Self, Err> {
        Ok(Link {
            source: self.source.subst(m)?,
            target: self.target.subst(m)?,
            rule_formula: self.rule_formula.subst(m)?,
            pos: self.pos,
        })
    }
}
// substitute variables in a sequence of statements from previous assignments
// update variable assignments into substmap as you go.
impl Subst for Vec<LocatedStatement> {
    fn subst(&self, m: &mut SubstMap) -> Result<Vec<LocatedStatement>, Err> {
        let mut newstats = Vec::new();
        //let sp1 = PathExpr::Sp1;
        for statement in self.iter() {
            let ref loc = statement.loc;
            match &statement.statement {
                Statement::LetExpr {
                    left,
                    right,
                    is_append,
                } => {
                    let &app = is_append;
                    let subst_right: Vec<_> = right
                        .split(|x| x == &PathExpr::Sp1)
                        .map(|x| {
                            x.to_vec()
                                .subst(m)
                                .expect("subst failure in let expr")
                                .cat()
                        })
                        .collect();

                    let curright: Vec<String> = if app {
                        match m.expr_map.get(left.name.as_str()) {
                            Some(prevright) => prevright
                                .iter()
                                .map(|x| x.clone())
                                .chain(subst_right)
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
                    .subst(m)
                    .expect("no errors expected in subst of TUP_CWD")
                    .cat();
                    let subst_right: Vec<String> = right
                        .split(|x| x == &PathExpr::Sp1)
                        .map(|x| {
                            prefix.clone()
                                + x.to_vec()
                                    .subst(m)
                                    .expect("no errors expected in subst")
                                    .cat()
                                    .as_str()
                        })
                        .collect();

                    //let subst_right = prefix.cat() + (right.subst(m)).cat().as_str();
                    let curright = if app {
                        match m.rexpr_map.get(left.name.as_str()) {
                            Some(prevright) => prevright
                                .iter()
                                .map(|x| x.clone())
                                .chain(subst_right)
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
                        lhs: eq.lhs.subst(m).expect("no errors expected in subst"),
                        rhs: eq.rhs.subst(m).expect("no errors expected in subst"),
                        not_cond: eq.not_cond,
                    };
                    if e.lhs.cat().eq(&e.rhs.cat()) && !e.not_cond {
                        newstats.append(&mut then_statements.subst(m)?);
                    } else {
                        newstats.append(&mut else_statements.subst(m)?);
                    }
                }
                Statement::IfDef {
                    checked_var,
                    then_statements,
                    else_statements,
                } => {
                    let cvar = PathExpr::AtExpr(checked_var.0.name.clone());
                    if cvar.subst(m).iter().any(|x| is_empty(x)) == checked_var.1 {
                        newstats.append(&mut then_statements.subst(m)?);
                    } else {
                        newstats.append(&mut else_statements.subst(m)?);
                    }
                }

                Statement::IncludeRules => {
                    let parent = get_parent(m.cur_file.as_path());
                    if let Some(f) = locate_tuprules(parent.as_path()) {
                        let include_stmts = parse_tupfile(f.to_str().unwrap())?;
                        m.cur_file = f;
                        newstats.append(&mut include_stmts.subst(m)?);
                    }
                }
                Statement::Include(s) => {
                    let s = s.subst(m)?;
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
                        let include_stmmts = parse_tupfile(p.to_str().unwrap())?;
                        let cf = set_cwd(p, m);
                        newstats.append(&mut include_stmmts.subst(m)?);
                        set_cwd(cf.as_path(), m);
                    }
                }
                Statement::Rule(link) => {
                    let mut l = link.clone();
                    while l.has_ref() {
                        l = l.expand(m)?; // expand all nested macro refs
                    }
                    newstats.push(LocatedStatement::new(
                        Statement::Rule(l.subst(m)?),
                        loc.clone(),
                    ));
                }
                // dont subst inside a macro assignment
                // just update the rule_map
                Statement::MacroAssignment(name, link) => {
                    let l = link.clone();
                    m.rule_map.insert(name.clone(), l);
                }
                Statement::Err(v) => {
                    let v = v.subst(m)?;
                    eprintln!("{}\n", &v.cat().as_str());
                    break;
                }
                Statement::Preload(v) => {
                    newstats.push(LocatedStatement::new(
                        Statement::Preload(v.subst(m)?),
                        loc.clone(),
                    ));
                }
                Statement::Export(_) => {
                    newstats.push(statement.clone());
                }
                Statement::Import(_, _) => {
                    newstats.push(statement.clone());
                }
                Statement::Run(r) => {
                    newstats.push(LocatedStatement::new(
                        Statement::Run(r.subst(m)?),
                        loc.clone(),
                    ));
                }
                Statement::Comment => {
                    // ignore
                }
            }
        }
        Ok(newstats)
    }
}
pub struct ParsedStatements {
    tupfile: PathBuf,
    statements: Vec<LocatedStatement>,
}

impl ParsedStatements {
    pub fn get_tupfile(&self) -> &Path {
        self.tupfile.as_path()
    }
    pub fn get_statements(&self) -> &Vec<LocatedStatement> {
        &self.statements
    }
}
pub fn parse_dir(root: &Path) -> Result<Vec<ParsedStatements>, crate::errors::Error> {
    let mut dag: Dag<u32, u32> = Dag::new();
    let mut provided_by: HashMap<_, Vec<_>> = HashMap::new();
    let mut required_by: HashMap<_, Vec<_>> = HashMap::new();
    let mut tupfiles = Vec::new();
    for entry in WalkDir::new(root)
        .follow_links(true)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let f_name = entry.file_name().to_string_lossy().as_ref().to_string();
        if f_name.as_str().eq("Tupfile") {
            let tupfilepath = entry.path().to_string_lossy().as_ref().to_string();
            tupfiles.push(tupfilepath);
        }
    }
    let rootfolder =
        locate_file(root, "Tupfile.ini").ok_or(crate::errors::Error::RootNotFound)?;
    let confvars = load_conf_vars(rootfolder.as_path())?;
    let mut rules = Vec::new();
    let mut ids = Vec::new();
    for tupfilepath in tupfiles.iter() {
        ids.push(dag.node_count());
        let stmts = parse_tupfile(tupfilepath.as_str())?;
        let p = Path::new(tupfilepath);
        let mut m = SubstMap::new(&confvars, p);
        let stmts = stmts.subst(&mut m)?;
        for l in &stmts {
            let stmt = l.getstatement();
            if let &Statement::Rule(Link {
                source: ref s,
                target: ref t,
                ..
            }) = stmt
            {
                let n = dag.add_node(1);
                for group in s.primary.input_groups() {
                    required_by.entry(group + "?G").or_default().push(n);
                }
                for bin in s.primary.input_bins() {
                    required_by
                        .entry(bin + tupfilepath + "?B")
                        .or_default()
                        .push(n);
                }
                for group in s.secondary.input_groups() {
                    required_by.entry(group + "?G").or_default().push(n);
                }
                for bin in s.secondary.input_bins() {
                    required_by
                        .entry(bin + tupfilepath + "?B")
                        .or_default()
                        .push(n);
                }
                if let Some(pe) = &t.group {
                    provided_by.entry(pe.cat() + "?G").or_default().push(n);
                }
                if let Some(pe) = &t.bin {
                    provided_by
                        .entry(pe.cat() + tupfilepath + "?B")
                        .or_default()
                        .push(n);
                }
            }
        }
        rules.push(ParsedStatements {
            statements: stmts,
            tupfile: p.to_path_buf(),
        });
    }
    ids.push(dag.node_count());
    let statement_from_id = |i: NodeIndex| {
        let mut x = ids.partition_point(|&j| j < i.index());
        if ids[x] > i.index() {
            x = x - 1;
        }
        (&rules[x].tupfile, &rules[x].statements[i.index() - ids[x]])
    };
    for (group, nodeids) in required_by.iter() {
        if let Some(pnodeids) = provided_by.get(group) {
            for pnodeid in pnodeids {
                for nodeid in nodeids {
                    dag.update_edge(*pnodeid, *nodeid, 1).map_err(|_| {
                        crate::errors::Error::DependencyCycle(
                            {
                                let (tupfile, stmt) = statement_from_id(*pnodeid);
                                format!(
                                    "tupfile:{}, and rule:{}",
                                    tupfile.to_string_lossy(),
                                    stmt.cat()
                                )
                            },
                            {
                                let (tupfile, stmt) = statement_from_id(*nodeid);
                                format!(
                                    "tupfile:{}, and rule:{}",
                                    tupfile.to_string_lossy(),
                                    stmt.cat()
                                )
                            },
                        )
                    })?;
                }
            }
        }
    }
    let nodes: Vec<_> = petgraph::algo::toposort(&dag, None).map_err(|e| {
        crate::errors::Error::DependencyCycle("".to_string(), {
            let (tupfile, stmt) = statement_from_id(e.node_id());
            format!(
                "tupfile:{}, and rule:{}",
                tupfile.to_string_lossy(),
                stmt.cat()
            )
        })
    })?;
    let mut outputtags = OutputTagInfo::new();
    let mut lstats = Vec::new();
    for tupnodeid in nodes {
        let (tupfile, statement) = statement_from_id(tupnodeid);
        //let mut sm = SubstMap::new(&HashMap::new(), tupfile);
        //sm.waitforpercs = false;
        let (stmts, ref mut newoutputtags) = statement.decode(tupfile, &outputtags)?;
        outputtags.merge_group_tags(newoutputtags);
        outputtags.merge_bin_tags(newoutputtags);
        lstats.push(ParsedStatements {
            statements: stmts,
            tupfile: tupfile.clone(),
        });
    }
    Ok(lstats)
}
