//! This module has datastructures and methods to transform Statements to Statements with substitutions and expansions
use errors::Error as Err;
use parser::locate_tuprules;
use parser::{parse_statements_until_eof, parse_tupfile, Span};
use platform::*;
use statements::*;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
/// SubstMap holds maps tracking current state of variable replacements as we read a tupfile
#[derive(Debug, Clone, Default)]
pub(crate) struct SubstMap {
    /// vals to be substituted
    pub(crate) expr_map: HashMap<String, Vec<String>>,
    /// rvals to be substituted
    pub(crate) rexpr_map: HashMap<String, Vec<String>>,
    /// configuration values read from tup.config
    pub(crate) conf_map: HashMap<String, Vec<String>>,
    /// Macro assignments waiting for subst
    pub(crate) rule_map: HashMap<String, Link>,
    /// Tup file being read
    pub(crate) cur_file: PathBuf,
    /// unique descriptor for tupfile
    pub(crate) cur_file_desc: TupPathDescriptor,
    /// environment variables imported thus far
    pub(crate) imported_env_map: HashMap<String, String>,
    /// pre-load these dirs
    pub(crate) load_dirs: Vec<PathDescriptor>,
    /// current state of env variables to be passed to rules for execution
    pub(crate) cur_env_desc: EnvDescriptor,
}

/// Accessor and constructors of SubstMap
impl SubstMap {
    /// Initialize SubstMap for var-subst-ing `cur_file'
    pub fn new(
        conf_map: &HashMap<String, Vec<String>>,
        cur_file: &Path,
        bo: &mut BufferObjects,
    ) -> Self {
        let mut def_vars = HashMap::new();
        if let Some(p) = get_parent(cur_file).to_str() {
            def_vars.insert("TUP_CWD".to_owned(), vec![p.to_owned()]);
        }
        let mut def_exported = HashMap::new();
        #[cfg(target_os = "windows")]
        let keys: Vec<&str> = vec![
            /* NOTE: Please increment PARSER_VERSION if these are modified */
            "PATH",
            "HOME",
            /* Basic Windows variables */
            "COMSPEC",
            "PATHEXT",
            "SYSTEMROOT",
            "USERNAME",
            "WINDIR",
            /* Visual Studio variables */
            "DevEnvDir",
            "INCLUDE",
            "LIB",
            "LIBPATH",
            "TEMP",
            "TMP",
            "VCINSTALLDIR",
            "=VS[0-9]+COMNTOOLS",
            "OS",
            "NUMBER_OF_PROCESSORS",
            "PROCESSOR_ARCHITECTURE",
            "PROCESSOR_IDENTIFIER",
            "PROCESSOR_LEVEL",
            "PROCESSOR_REVISION",
            "PYTHONPATH",
            "VSINSTALLDIR",
            "VCTOOLSINSTALLDIR",
            "VCTOOLSREDISTDIR",
            "VCTOOLSVERSION",
            /* NOTE: Please increment PARSER_VERSION if these are modified */
        ];
        #[cfg(not(target_os = "windows"))]
        let keys = vec!["PATH", "HOME"];

        for k in keys.iter() {
            if k.starts_with('=') {
                let k = k.trim_start_matches('=');
                let mut inserted = false;
                if let Ok(rb) = regex::RegexBuilder::new(k).build() {
                    if let Some(needle) = std::env::vars().find(|v| rb.is_match(v.0.as_str())) {
                        def_exported.insert(needle.0, needle.1);
                        inserted = true;
                    }
                }
                if !inserted {
                    def_exported.insert(k.to_string(), std::env::var(k).unwrap_or("".to_string()));
                }
            } else {
                def_exported.insert(k.to_string(), std::env::var(k).unwrap_or("".to_string()));
            }
        }

        let mut smap = SubstMap {
            conf_map: conf_map.clone(),
            expr_map: def_vars,
            imported_env_map: def_exported.clone(),
            cur_file: cur_file.to_path_buf(),
            ..SubstMap::default()
        };

        switch_dir(cur_file, &mut smap, bo);
        let env = Env::new(def_exported);
        smap.cur_env_desc = bo.ebo.add_env(env).0;
        smap
    }

    /// add env var to environment
    pub fn add_var(&mut self, bo: &mut BufferObjects, var: String) {
        if !bo.ebo.has_env(&var) {
            let mut env = bo.ebo.get(&self.cur_env_desc).clone();
            env.add(var);
            let (id, _) = bo.ebo.add_env(env);
            self.cur_env_desc = id;
        }
    }

    /// return the tupfile being parsed
    pub(crate) fn get_cur_file(&self) -> &Path {
        &self.cur_file
    }

    /// return the folder containing Tupfile being parsed
    pub(crate) fn get_tup_dir(&self) -> &Path {
        self.cur_file
            .parent()
            .expect("could not find current tup dir")
    }

    /// Get folder that hosts tup file as a descriptor
    pub(crate) fn get_cur_file_desc(&self) -> &TupPathDescriptor {
        &self.cur_file_desc
    }
}
impl ExpandRun for Statement {
    /// expand_run adds Statements returned by executing a shell command. Rules that are output from the command should be in the regular format for rules that Tup supports
    /// see docs for how the environment is picked.
    fn expand_run(&self, m: &mut SubstMap, bo: &mut BufferObjects) -> Vec<Statement> {
        let mut vs: Vec<Statement> = Vec::new();
        match self {
            Statement::Preload(v) => {
                let dir = v.cat();
                let p = Path::new(dir.as_str());

                let (dirid, _) = bo.add_path_from(p, m.get_tup_dir());
                {
                    m.load_dirs.push(dirid);
                }
            }
            Statement::Run(script_args) => {
                if let Some(script) = script_args.first() {
                    let mut cmd = std::process::Command::new(script.cat().as_str());
                    for arg_expr in script_args.iter().skip(1) {
                        let arg = arg_expr.cat();
                        let arg = arg.trim();
                        if arg.contains('*') {
                            let arg_path = Path::new(arg);
                            let outs = OutputTagInfo::new();
                            {
                                let matches =
                                    discover_inputs_from_glob(m.get_tup_dir(), arg_path, &outs, bo)
                                        .expect(&*format!("error matching glob pattern {}", arg));
                                for ofile in matches {
                                    let p = ofile.as_path(bo);
                                    cmd.arg(
                                        p.to_string_lossy().to_string().as_str().replace('\\', "/"),
                                    );
                                }
                            }
                        } else if !arg.is_empty() {
                            cmd.arg(arg);
                        }
                    }
                    let env = bo.get_env(&m.cur_env_desc);
                    cmd.envs(env.getenv()).current_dir(m.get_tup_dir());
                    //println!("running {:?}", cmd);
                    let output = cmd.stdout(Stdio::piped()).output().expect(&*format!(
                        "Failed to execute tup run {} in Tupfile : {}",
                        script_args.cat().as_str(),
                        m.get_tup_dir().to_string_lossy().to_string().as_str()
                    ));
                    //println!("status:{}", output.status);
                    let contents = output.stdout;
                    //println!("{}", String::from_utf8(contents.clone()).unwrap_or("".to_string()));
                    let lstmts = parse_statements_until_eof(Span::new(contents.as_bytes()))
                        .expect("failed to parse output of tup run");
                    let lstmts = lstmts
                        .subst(m, bo)
                        .expect("subst failure in generated tup rules");
                    for located_stmt in lstmts {
                        vs.push(located_stmt.move_statement());
                    }
                }
            }
            _ => vs.push(self.clone()),
        }
        vs
    }
}

impl ExpandRun for Vec<LocatedStatement> {
    /// discover more rules to add by running shell commands
    fn expand_run(&self, m: &mut SubstMap, bo: &mut BufferObjects) -> Vec<Self>
    where
        Self: Sized,
    {
        self.iter()
            .map(|l| {
                l.get_statement()
                    .expand_run(m, bo)
                    .iter()
                    .map(|s| LocatedStatement::new(s.clone(), l.getloc().clone()))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<Self>>()
    }
}

/// trait that a method to run variable substitution on different parts of tupfile
pub(crate) trait Subst {
    fn subst(&self, m: &mut SubstMap, bo: &mut BufferObjects) -> Result<Self, Err>
    where
        Self: Sized;
}

/// trait to substitute macro references in rules
pub(crate) trait ExpandMacro {
    /// check if path expr or a derived object has references to a macro
    fn has_ref(&self) -> bool;
    /// method to perform macro expansion based on currently stored macros in SubstMap
    fn expand(&self, m: &mut SubstMap) -> Result<Self, Err>
    where
        Self: Sized;
}

/// Check if a PathExpr is empty
fn is_empty(rval: &PathExpr) -> bool {
    if let PathExpr::Literal(s) = rval {
        s.len() == 0
    } else {
        false
    }
}

impl PathExpr {
    /*fn uses_env(&self, m: &mut SubstMap) -> Option<&String> {
        match self {
            &PathExpr::DollarExpr(ref x) => {
                if m.imported_env_map.get(x.as_str()).is_some() {
                    Some(x)
                } else {
                    None
                }
            }
            _ => None,
        }
    }*/

    /// substitute a single pathexpr into an array of literal pathexpr
    /// SFINAE holds
    fn subst(&self, m: &mut SubstMap) -> Vec<PathExpr> {
        match self {
            &PathExpr::DollarExpr(ref x) => {
                if let Some(val) = m.expr_map.get(x.as_str()) {
                    intersperse_sp1(val)
                } else if let Some(val) = m.imported_env_map.get(x.as_str()) {
                    vec![PathExpr::from(val.clone())]
                } else if x.contains("%") {
                    vec![self.clone()]
                } else {
                    vec![PathExpr::from("".to_owned())] // postpone subst until placeholders are fixed
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

/// creates `PathExpr' array separated by PathExpr::Sp1
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
    /// call subst on each path expr and flatten/cleanup the output.
    fn subst(&self, m: &mut SubstMap, _: &mut BufferObjects) -> Result<Self, Err> {
        let mut newpe: Vec<_> = self
            .iter()
            .map(|x| x.subst(m))
            .flatten()
            .filter(|x| !is_empty(x))
            .collect();
        newpe.cleanup();
        Ok(newpe)
    }
}
impl Subst for Source {
    /// call subst on each path expr and flatten/cleanup the input.
    fn subst(&self, m: &mut SubstMap, bo: &mut BufferObjects) -> Result<Self, Err> {
        Ok(Source {
            primary: self.primary.subst(m, bo)?,
            for_each: self.for_each,
            secondary: self.secondary.subst(m, bo)?,
        })
    }
}
use decode::{
    discover_inputs_from_glob, BufferObjects, ExpandRun, OutputTagInfo, PathDescriptor,
    ResolvePaths, ResolvedLink, RuleRef, TupPathDescriptor,
};
use log::debug;
use nom::AsBytes;
use scriptloader::parse_script;
use std::ops::AddAssign;
use std::process::Stdio;

impl AddAssign for Source {
    /// append more sources
    fn add_assign(&mut self, other: Self) {
        let mut o = other;
        self.primary.cleanup();
        self.primary.append(&mut o.primary);
        self.secondary.cleanup();
        self.secondary.append(&mut o.secondary);
        self.for_each |= o.for_each;
    }
}

impl AddAssign for Target {
    /// append more targets
    fn add_assign(&mut self, other: Self) {
        let mut o = other;
        self.primary.cleanup();
        self.primary.append(&mut o.primary);

        self.secondary.cleanup();
        self.secondary.append(&mut o.secondary);

        self.group = self.group.clone().or(o.group);
        self.bin = self.bin.clone().or(o.bin);
    }
}

/// substitute only first pathexpr using SubstMap
fn takefirst(o: &Option<PathExpr>, m: &mut SubstMap) -> Result<Option<PathExpr>, Err> {
    if let &Some(ref pe) = o {
        Ok(pe.subst(m).first().cloned())
    } else {
        Ok(None)
    }
}

impl Subst for Target {
    /// run variable substitution on `Target'
    fn subst(&self, m: &mut SubstMap, bo: &mut BufferObjects) -> Result<Self, Err> {
        Ok(Target {
            primary: self.primary.subst(m, bo)?,
            secondary: self.secondary.subst(m, bo)?,
            exclude_pattern: self.exclude_pattern.clone(),
            group: takefirst(&self.group, m)?,
            bin: takefirst(&self.bin, m)?,
        })
    }
}
impl Subst for RuleFormula {
    /// run variable substitution on `RuleFormula'
    fn subst(&self, m: &mut SubstMap, bo: &mut BufferObjects) -> Result<Self, Err> {
        Ok(RuleFormula {
            description: self.description.clone(), // todo : convert to rval and subst here as well,
            formula: self.formula.subst(m, bo)?,
        })
    }
}
impl ExpandMacro for Link {
    /// checks if a macro ref exists in rule formula
    fn has_ref(&self) -> bool {
        for rval in self.rule_formula.formula.iter() {
            if let PathExpr::MacroRef(_) = *rval {
                return true;
            }
        }
        false
    }
    /// replace occurences of a macro ref with link data from previous assignments in namedrules
    /// For a well-formed tupfile, SubstMap is expected to have been populated with macro assignment
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
                        if desc.is_empty() {
                            desc = explink.rule_formula.description.clone();
                        }
                        let mut r = explink.rule_formula.formula.clone();
                        r.cleanup();
                        formulae.append(&mut r);
                    } else {
                        return Err(Err::UnknownMacroRef(
                            name.clone(),
                            RuleRef::new(&m.get_cur_file_desc(), &Loc::new(pos.0, pos.1 as u32)),
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

/// parent folder path for a given tupfile
pub(crate) fn get_parent(cur_file: &Path) -> PathBuf {
    PathBuf::from(cur_file.parent().unwrap().to_str().expect(&*format!(
        "unable to find parent folder for tup file:{:?}",
        cur_file
    )))
}

/// parent folder path as a string slice
pub(crate) fn get_parent_str(cur_file: &Path) -> &str {
    cur_file.parent().unwrap().to_str().expect(&*format!(
        "unable to find parent folder for tup file:{:?}",
        cur_file
    ))
}

/// strings in pathexpr that are space separated
fn tovecstring(right: &Vec<PathExpr>) -> Vec<String> {
    right
        .split(|x| x == &PathExpr::Sp1)
        .map(|x| x.to_vec().cat())
        .collect()
}
/// load the conf variables in tup.config in the root directory
/// TUP_PLATFORM and TUP_ARCH are automatically assigned based on how this program is built
pub fn load_conf_vars(
    filename: &Path,
) -> Result<HashMap<String, Vec<String>>, crate::errors::Error> {
    let mut conf_vars = HashMap::new();

    if let Some(conf_file) = Path::new(filename).parent().map(|x| x.join("tup.config")) {
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

/// set the current TUP_CWD in expression map in SubstMap as we switch to reading a included file
pub(crate) fn set_cwd(filename: &Path, m: &mut SubstMap, bo: &mut BufferObjects) -> PathBuf {
    debug!("reading {:?}", filename);
    let cf = switch_dir(filename, m, bo);
    let ref mut def_vars = m.expr_map;
    let p = get_parent_str(m.cur_file.as_path());
    {
        def_vars.remove("TUP_CWD");
        def_vars.insert("TUP_CWD".to_owned(), vec![p.to_owned()]);
    }
    cf
}

/// update `SubstMap' to point to newer file that is being read (like in include statement)
fn switch_dir(filename: &Path, m: &mut SubstMap, bo: &mut BufferObjects) -> PathBuf {
    let cf = m.cur_file.clone();
    m.cur_file = filename.to_path_buf();
    let (d, _) = bo.add_tup(filename);
    m.cur_file_desc = d;
    cf
}

impl Subst for Link {
    /// recursively substitute variables inside a link
    fn subst(&self, m: &mut SubstMap, bo: &mut BufferObjects) -> Result<Self, Err> {
        Ok(Link {
            source: self.source.subst(m, bo)?,
            target: self.target.subst(m, bo)?,
            rule_formula: self.rule_formula.subst(m, bo)?,
            pos: self.pos,
        })
    }
}

/// Implement `subst' method for statements. As the statements are processed, this keeps
/// track of variables assigned so far and replaces variables occurrences in $(Var) or &(Var) or @(Var)
impl Subst for Vec<LocatedStatement> {
    /// `subst' accumulates variable assignments in various maps in SubstMap and replaces occurences of them in subsequent statements
    fn subst(&self, m: &mut SubstMap, bo: &mut BufferObjects) -> Result<Self, Err> {
        let mut newstats = Vec::new();
        for statement in self.iter() {
            let ref loc = statement.getloc();
            match statement.get_statement() {
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
                                .subst(m, bo)
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
                    .subst(m, bo)
                    .expect("no errors expected in subst of TUP_CWD")
                    .cat();
                    let subst_right: Vec<String> = right
                        .split(|x| x == &PathExpr::Sp1)
                        .map(|x| {
                            prefix.clone()
                                + x.to_vec()
                                    .subst(m, bo)
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
                        lhs: eq.lhs.subst(m, bo).expect("no errors expected in subst"),
                        rhs: eq.rhs.subst(m, bo).expect("no errors expected in subst"),
                        not_cond: eq.not_cond,
                    };
                    if e.lhs.cat().eq(&e.rhs.cat()) && !e.not_cond {
                        newstats.append(&mut then_statements.subst(m, bo)?);
                    } else {
                        newstats.append(&mut else_statements.subst(m, bo)?);
                    }
                }
                Statement::IfDef {
                    checked_var,
                    then_statements,
                    else_statements,
                } => {
                    let cvar = PathExpr::AtExpr(checked_var.0.name.clone());
                    if cvar.subst(m).iter().any(|x| is_empty(x)) == checked_var.1 {
                        newstats.append(&mut then_statements.subst(m, bo)?);
                    } else {
                        newstats.append(&mut else_statements.subst(m, bo)?);
                    }
                }

                Statement::IncludeRules => {
                    let parent = get_parent(m.cur_file.as_path());
                    if let Some(f) = locate_tuprules(parent.as_path()) {
                        let include_stmts = parse_tupfile(f.as_path())?;
                        //m.cur_file = f;
                        switch_dir(f.as_path(), m, bo);
                        newstats.append(&mut include_stmts.subst(m, bo)?);
                    }
                }
                Statement::Include(s) => {
                    let s = s.subst(m, bo)?;
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
                        let include_stmmts = parse_tupfile(p)?;
                        let cf = set_cwd(p, m, bo);
                        newstats.append(&mut include_stmmts.subst(m, bo)?);
                        set_cwd(cf.as_path(), m, bo);
                    }
                }
                Statement::Rule(link, _) => {
                    let mut l = link.clone();
                    while l.has_ref() {
                        l = l.expand(m)?; // expand all nested macro refs
                    }
                    let env_desc = m.cur_env_desc.clone();
                    newstats.push(LocatedStatement::new(
                        Statement::Rule(l.subst(m, bo)?, env_desc),
                        **loc,
                    ));
                }
                // dont subst inside a macro assignment
                // just update the rule_map
                Statement::MacroAssignment(name, link) => {
                    let l = link.clone();
                    m.rule_map.insert(name.clone(), l);
                }
                Statement::Err(v) => {
                    let v = v.subst(m, bo)?;
                    eprintln!("{}\n", &v.cat().as_str());
                    break;
                }
                Statement::Preload(v) => {
                    newstats.push(LocatedStatement::new(
                        Statement::Preload(v.subst(m, bo)?),
                        **loc,
                    ));
                }
                Statement::Export(var) => {
                    m.add_var(bo, var.clone());
                    //newstats.push(statement.clone());
                }
                Statement::Import(_, _) => {
                    newstats.push(statement.clone());
                }
                Statement::Run(r) => {
                    newstats.push(LocatedStatement::new(
                        Statement::Run(r.subst(m, bo)?),
                        **loc,
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

/// `ResolvedLinksInTupfile' stores all links in a tupfile
pub struct ResolvedLinksInTupFile {
    tupfile: PathBuf,
    resolved_links: Vec<ResolvedLink>,
}

/// Constructors and accessors  for `ResolvedLinksInTupFile'
impl ResolvedLinksInTupFile {
    /// constructor for parsed statements from a tupfile and resolved links
    pub fn new(tupfile: PathBuf, statements: Vec<ResolvedLink>) -> ResolvedLinksInTupFile {
        ResolvedLinksInTupFile {
            tupfile,
            resolved_links: statements,
        }
    }
    /// return tup file path
    pub fn get_tupfile(&self) -> &Path {
        self.tupfile.as_path()
    }

    /// resolved link at index `i'
    pub fn get_statement(&self, i: usize) -> &ResolvedLink {
        &self.resolved_links[i]
    }
    ///  all the resolved links in the parsed statements we have with us
    pub fn get_statements(&self) -> &Vec<ResolvedLink> {
        &self.resolved_links
    }
}

/// `parse_tup' is a parser for a Tupfile or Tupfile.lua
/// Inputs are config vars, Tupfile\[.lua\] path and a buffer in which to store descriptors for files.
/// The parser returns  resolved rules,  outputs of rules packaged in OutputTagInfo and updated buffer objects.
/// See [BufferObjects]
pub fn parse_tup<P: AsRef<Path>>(
    confvars: &HashMap<String, Vec<String>>,
    tup_file_path: P,
    mut bo: BufferObjects,
) -> Result<(Vec<ResolvedLink>, OutputTagInfo, BufferObjects), crate::errors::Error> {
    let mut m = SubstMap::new(&confvars, tup_file_path.as_ref(), &mut bo);
    if let Some("lua") = tup_file_path.as_ref().extension().and_then(OsStr::to_str) {
        // wer are not going to  resolve group paths during the first phase of parsing.
        let output_tag_info = OutputTagInfo::new_no_resolve_groups();
        parse_script(tup_file_path.as_ref(), m, bo, output_tag_info)
    } else {
        let stmts = parse_tupfile(tup_file_path.as_ref())?;
        let stmts = stmts.subst(&mut m, &mut bo)?;
        let output_tag_info = OutputTagInfo::new_no_resolve_groups();
        let stmts = stmts
            .expand_run(&mut m, &mut bo)
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        let (rlinks, o) = stmts.resolve_paths(
            tup_file_path.as_ref(),
            &output_tag_info,
            &mut bo,
            m.get_cur_file_desc(),
        )?;
        Ok((rlinks, o, bo))
    }
}
