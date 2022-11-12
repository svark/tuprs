//! This module has datastructures and methods to transform Statements to Statements with substitutions and expansions
use errors::Error as Err;
use parser::locate_tuprules;
use parser::{parse_statements_until_eof, parse_tupfile, Span};
use platform::*;
use statements::*;
use std::borrow::Cow;
use std::cell::{Ref, RefCell, RefMut};
use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
/// SubstState holds maps tracking current state of variable replacements as we read a tupfile
#[derive(Debug, Clone, Default)]
pub(crate) struct SubstState {
    /// vals to be substituted
    pub(crate) expr_map: HashMap<String, Vec<String>>,
    /// rvals to be substituted
    pub(crate) rexpr_map: HashMap<String, Vec<String>>,
    /// configuration values read from tup.config
    pub(crate) conf_map: HashMap<String, Vec<String>>,
    /// Macro assignments waiting for subst
    pub(crate) rule_map: HashMap<String, Link>,
    /// Tupfile being read
    pub(crate) tup_base_path: PathBuf,
    /// Tupfile or an included file being read
    pub(crate) cur_file: PathBuf,
    /// unique descriptor for tupfile
    pub(crate) cur_file_desc: TupPathDescriptor,
    /// pre-load these dirs
    pub(crate) load_dirs: Vec<PathDescriptor>,
    /// current state of env variables to be passed to rules for execution
    pub(crate) cur_env_desc: EnvDescriptor,
}

impl SubstState {}

// Default Env to feed into every tupfile
fn init_env() -> Env {
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
                def_exported.insert(k.to_string(), std::env::var(k).unwrap_or_default());
            }
        } else {
            def_exported.insert(k.to_string(), std::env::var(k).unwrap_or_default());
        }
    }
    Env::new(def_exported)
}

/// Accessor and constructors of SubstState
impl SubstState {
    /// Initialize SubstState for var-subst-ing `cur_file'
    pub fn new(
        conf_map: &HashMap<String, Vec<String>>,
        cur_file: &Path,
        cur_file_desc: TupPathDescriptor,
        cur_env_desc: EnvDescriptor,
    ) -> Self {
        let mut def_vars = HashMap::new();
        let dir = get_parent_str(cur_file);
        def_vars.insert("TUP_CWD".to_owned(), vec![dir.to_owned()]);

        let smap = SubstState {
            conf_map: conf_map.clone(),
            expr_map: def_vars,
            cur_file: cur_file.to_path_buf(),
            tup_base_path: cur_file.to_path_buf(),
            cur_file_desc,
            cur_env_desc,
            ..SubstState::default()
        };

        smap
    }

    pub(crate) fn set_env(&mut self, ed: EnvDescriptor) {
        self.cur_env_desc = ed;
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
    fn expand_run(&self, m: &mut SubstState, bo: &mut BufferObjects) -> Vec<Statement> {
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
                            let outs = OutputAssocs::new();
                            {
                                let matches =
                                    discover_inputs_from_glob(m.get_tup_dir(), arg_path, &outs, bo)
                                        .expect(&*format!("error matching glob pattern {}", arg));
                                for ofile in matches {
                                    let p = ofile.as_path(bo.deref());
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
    fn expand_run(&self, m: &mut SubstState, bo: &mut BufferObjects) -> Vec<Self>
    where
        Self: Sized,
    {
        self.iter()
            .map(|l| {
                l.get_statement()
                    .expand_run(m, bo)
                    .iter()
                    .map(|s| LocatedStatement::new(s.clone(), *l.getloc()))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<Self>>()
    }
}

/// trait that a method to run variable substitution on different parts of tupfile
pub(crate) trait Subst {
    fn subst(&self, m: &mut SubstState, bo: &mut BufferObjects) -> Result<Self, Err>
    where
        Self: Sized;
}

/// trait to substitute macro references in rules
pub(crate) trait ExpandMacro {
    /// check if path expr or a derived object has references to a macro
    fn has_ref(&self) -> bool;
    /// method to perform macro expansion based on currently stored macros in SubstState
    fn expand(&self, m: &mut SubstState) -> Result<Self, Err>
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
    /*fn uses_env(&self, m: &mut SubstState) -> Option<&String> {
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
    fn subst(&self, m: &mut SubstState) -> Vec<PathExpr> {
        match self {
            PathExpr::DollarExpr(ref x) => {
                if let Some(val) = m.expr_map.get(x.as_str()) {
                    intersperse_sp1(val)
                } else if x.contains('%') {
                    vec![self.clone()]
                } else {
                    vec![PathExpr::from("".to_owned())] // postpone subst until placeholders are fixed
                }
            }
            PathExpr::AtExpr(ref x) => {
                if let Some(val) = m.conf_map.get(x.as_str()) {
                    intersperse_sp1(val)
                } else if !x.contains('%') {
                    vec![PathExpr::Literal("".to_owned())]
                } else {
                    vec![self.clone()]
                }
            }
            PathExpr::AmpExpr(ref x) => {
                if let Some(val) = m.rexpr_map.get(x.as_str()) {
                    intersperse_sp1(val)
                    // val.iter().map(|x| PathExpr::from(x.clone())).collect()
                } else if !x.contains('%') {
                    vec![PathExpr::from("".to_owned())]
                } else {
                    vec![self.clone()]
                }
            }

            PathExpr::Group(ref xs, ref ys) => {
                vec![PathExpr::Group(
                    xs.iter().flat_map(|x| x.subst(m)).collect(),
                    ys.iter().flat_map(|y| y.subst(m)).collect(),
                )]
            }
            _ => vec![self.clone()],
        }
    }
}

/// creates `PathExpr' array separated by PathExpr::Sp1
fn intersperse_sp1(val: &[String]) -> Vec<PathExpr> {
    let mut vs = Vec::new();
    for pe in val.iter().map(|x| PathExpr::from(x.clone())) {
        vs.push(pe);
        vs.push(PathExpr::Sp1);
    }
    vs.pop();
    vs
}

trait SubstPEs {
    fn subst_pe(&self, m: &mut SubstState) -> Result<Self, Err>
    where
        Self: Sized;
}

impl SubstPEs for Vec<PathExpr> {
    /// call subst on each path expr and flatten/cleanup the output.
    fn subst_pe(&self, m: &mut SubstState) -> Result<Self, Err> {
        let mut newpe: Vec<_> = self
            .iter()
            .flat_map(|x| x.subst(m))
            .filter(|x| !is_empty(x))
            .collect();
        newpe.cleanup();
        Ok(newpe)
    }
}

impl Subst for Source {
    /// call subst on each path expr and flatten/cleanup the input.
    fn subst(&self, m: &mut SubstState, _bo: &mut BufferObjects) -> Result<Self, Err> {
        Ok(Source {
            primary: self.primary.subst_pe(m)?,
            for_each: self.for_each,
            secondary: self.secondary.subst_pe(m)?,
        })
    }
}
use bimap::hash::{Iter, RightValues};
use decode::{
    discover_inputs_from_glob, normalize_path, BufferObjects, ExpandRun, GroupPathDescriptor,
    InputResolvedType, NormalPath, OutputAssocs, PathDescriptor, ResolvePaths, ResolvedLink,
    RuleDescriptor, RuleFormulaUsage, RuleRef, TupPathDescriptor,
};
use log::debug;
use nom::AsBytes;
use pathdiff::diff_paths;
use scriptloader::parse_script;
use std::ops::{AddAssign, Deref, DerefMut};
use std::process::Stdio;
use std::rc::Rc;
use std::vec::Drain;

impl AddAssign for Source {
    /// append more sources
    fn add_assign(&mut self, other: Self) {
        let mut o = other;
        self.primary.cleanup();
        self.primary.append(&mut o.primary);
        self.secondary.cleanup();
        self.secondary.append(&mut o.secondary);
        if o.for_each {
            self.for_each = o.for_each;
        }
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

/// substitute only first pathexpr using SubstState
fn takefirst(o: &Option<PathExpr>, m: &mut SubstState) -> Result<Option<PathExpr>, Err> {
    if let &Some(ref pe) = o {
        Ok(pe.subst(m).first().cloned())
    } else {
        Ok(None)
    }
}

impl Subst for Target {
    /// run variable substitution on `Target'
    fn subst(&self, m: &mut SubstState, _bo: &mut BufferObjects) -> Result<Self, Err> {
        Ok(Target {
            primary: self.primary.subst_pe(m)?,
            secondary: self.secondary.subst_pe(m)?,
            exclude_pattern: self.exclude_pattern.clone(),
            group: takefirst(&self.group, m)?,
            bin: takefirst(&self.bin, m)?,
        })
    }
}
impl Subst for RuleFormula {
    /// run variable substitution on `RuleFormula'
    fn subst(&self, m: &mut SubstState, _b: &mut BufferObjects) -> Result<Self, Err> {
        Ok(RuleFormula {
            description: self.description.clone(), // todo : convert to rval and subst here as well,
            formula: self.formula.subst_pe(m)?,
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
    /// For a well-formed tupfile, SubstState is expected to have been populated with macro assignment
    fn expand(&self, m: &mut SubstState) -> Result<Self, Err> {
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
                            RuleRef::new(m.get_cur_file_desc(), &Loc::new(pos.0, pos.1 as u32)),
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
pub(crate) fn get_parent(cur_file: &Path) -> &Path {
    cur_file.parent().expect(&*format!(
        "unable to find parent folder for tup file:{:?}",
        cur_file
    ))
}

/// parent folder path as a string slice
pub(crate) fn get_parent_str(cur_file: &Path) -> String {
    normalize_path(cur_file.parent().unwrap())
}

/// strings in pathexpr that are space separated
fn tovecstring(right: &[PathExpr]) -> Vec<String> {
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
                    if let Statement::LetExpr { left, right, .. } = statement {
                        if left.name.starts_with("CONFIG_") {
                            conf_vars.insert(left.name[7..].to_string(), tovecstring(right));
                        }
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

/// set the current TUP_CWD in expression map in SubstState as we switch to reading a included file
pub(crate) fn set_cwd(filename: &Path, m: &mut SubstState, bo: &mut BufferObjects) -> PathBuf {
    debug!("reading {:?}", filename);
    let cf = switch_dir(filename, m, bo);
    let def_vars = &mut m.expr_map;

    let diff = diff_paths(m.cur_file.as_path(), m.tup_base_path.as_path()).unwrap();
    let p = get_parent_str(diff.as_path());
    {
        def_vars.remove("TUP_CWD");
        def_vars.insert("TUP_CWD".to_owned(), vec![p]);
    }
    cf
}

/// update `SubstState' to point to newer file that is being read (like in include statement)
fn switch_dir(filename: &Path, m: &mut SubstState, bo: &mut BufferObjects) -> PathBuf {
    let cf = m.cur_file.clone();
    m.cur_file = filename.to_path_buf();
    let (d, _) = bo.add_tup(filename);
    m.cur_file_desc = d;
    cf
}

impl Subst for Link {
    /// recursively substitute variables inside a link
    fn subst(&self, m: &mut SubstState, bo: &mut BufferObjects) -> Result<Self, Err> {
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
    /// `subst' accumulates variable assignments in various maps in SubstState and replaces occurrences of them in subsequent statements
    fn subst(&self, m: &mut SubstState, bo: &mut BufferObjects) -> Result<Self, Err> {
        let mut newstats = Vec::new();
        for statement in self.iter() {
            let loc = statement.getloc();
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
                                .subst_pe(m)
                                .expect("subst failure in let expr")
                                .cat()
                        })
                        .collect();

                    let curright: Vec<String> = if app {
                        match m.expr_map.get(left.name.as_str()) {
                            Some(prevright) => {
                                prevright.iter().cloned().chain(subst_right).collect()
                            }
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
                    .subst_pe(m)
                    .expect("no errors expected in subst of TUP_CWD")
                    .cat();
                    let subst_right: Vec<String> = right
                        .split(|x| x == &PathExpr::Sp1)
                        .map(|x| {
                            prefix.clone()
                                + x.to_vec()
                                    .subst_pe(m)
                                    .expect("no errors expected in subst")
                                    .cat()
                                    .as_str()
                        })
                        .collect();

                    //let subst_right = prefix.cat() + (right.subst(m)).cat().as_str();
                    let curright = if app {
                        match m.rexpr_map.get(left.name.as_str()) {
                            Some(prevright) => {
                                prevright.iter().cloned().chain(subst_right).collect()
                            }
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
                        lhs: eq.lhs.subst_pe(m).expect("no errors expected in subst"),
                        rhs: eq.rhs.subst_pe(m).expect("no errors expected in subst"),
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
                    if cvar.subst(m).iter().any(is_empty) == checked_var.1 {
                        newstats.append(&mut then_statements.subst(m, bo)?);
                    } else {
                        newstats.append(&mut else_statements.subst(m, bo)?);
                    }
                }

                Statement::IncludeRules => {
                    let parent = get_parent(m.cur_file.as_path());
                    if let Some(f) = locate_tuprules(parent) {
                        let include_stmts = parse_tupfile(f.as_path())?;
                        //m.cur_file = f;
                        switch_dir(f.as_path(), m, bo);
                        newstats.append(&mut include_stmts.subst(m, bo)?);
                    }
                }
                Statement::Include(s) => {
                    let s = s.subst_pe(m)?;
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
                        *loc,
                    ));
                }
                // dont subst inside a macro assignment
                // just update the rule_map
                Statement::MacroAssignment(name, link) => {
                    let l = link.clone();
                    m.rule_map.insert(name.clone(), l);
                }
                Statement::Err(v) => {
                    let v = v.subst_pe(m)?;
                    eprintln!("{}\n", &v.cat().as_str());
                    break;
                }
                Statement::Preload(v) => {
                    newstats.push(LocatedStatement::new(
                        Statement::Preload(v.subst_pe(m)?),
                        *loc,
                    ));
                }
                Statement::Export(var) => {
                    if let Some(id) = bo.add_env_var(var.clone(), &m.cur_env_desc) {
                        m.set_env(id);
                    }
                }
                Statement::Import(var, envval) => {
                    if let Some(val) = envval.clone().or_else(|| std::env::var(var).ok()) {
                        m.expr_map.entry(String::from(var)).or_default().push(val);
                    }
                    newstats.push(statement.clone());
                }
                Statement::Run(r) => {
                    newstats.push(LocatedStatement::new(Statement::Run(r.subst_pe(m)?), *loc));
                }
                Statement::Comment => {
                    // ignore
                }
            }
        }
        Ok(newstats)
    }
}

/// TupParser parser for a file containing tup file syntax
/// Inputs are config vars, Tupfile\[.lua\] path and a buffer in which to store descriptors for files.
/// The parser returns  resolved rules,  outputs of rules packaged in OutputTagInfo and updated buffer objects.

#[derive(Debug, Clone, Default)]
pub struct TupParser {
    bo: Rc<RefCell<BufferObjects>>,
    config_vars: HashMap<String, Vec<String>>,
}

impl TupParser {}

impl TupParser {}

/// Artifacts represent rules and their outputs that the parser gathers.
#[derive(Debug, Clone, Default)]
pub struct Artifacts {
    resolved_links: Vec<ResolvedLink>,
    outs: OutputAssocs,
}

impl Artifacts {
    /// Empty constructor for `Artifacts`
    pub fn new() -> Artifacts {
        Artifacts::default()
    }
    /// Builds Artifacts from  [ResolvedLink]s [OutputAssocs]
    pub fn from(resolved_links: Vec<ResolvedLink>, outs: OutputAssocs) -> Artifacts {
        Artifacts {
            resolved_links,
            outs,
        }
    }

    /// Return the number of resolved links.
    pub fn len(&self) -> usize {
        self.resolved_links.len()
    }
    ///Merges outputs from parsing one tupfile  with the next. All the new links will be extended.
    pub fn merge(&mut self, mut artifacts: Artifacts) -> Result<(), crate::errors::Error> {
        self.outs.merge(&artifacts.outs)?;
        self.resolved_links.extend(artifacts.drain_resolved_links());
        Ok(())
    }
    pub(crate) fn get_resolved_link(&self, i: usize) -> &ResolvedLink {
        &self.resolved_links[i]
    }
    /// divulges secrets of all the resolved links returned by the parser,
    pub(crate) fn drain_resolved_links(&mut self) -> Drain<'_, ResolvedLink> {
        self.resolved_links.drain(..)
    }
    /// divulges secrets of all the resolved links returned by the parser,
    pub fn get_resolved_links(&self) -> &Vec<ResolvedLink> {
        &self.resolved_links
    }

    pub(crate) fn acquire_groups(&mut self, outs: &OutputAssocs) {
        self.outs.acquire_groups(outs.get_groups().clone())
    }

    pub(crate) fn get_outs(&self) -> &OutputAssocs {
        return &self.outs;
    }
    /// Returns the output files from all the rules found after current parsing sesssion
    pub fn get_output_files(&self) -> &HashSet<PathDescriptor> {
        self.outs.get_output_files()
    }

    /// Returns a vector over slices of resolved links grouped by the tupfile that generated them
    pub fn rules_by_tup(&self) -> Vec<&'_ [ResolvedLink]> {
        self.resolved_links
            .as_slice()
            .group_by(|x, y| {
                x.get_rule_ref().get_tupfile_desc() == y.get_rule_ref().get_tupfile_desc()
            })
            .collect::<Vec<_>>()
    }

    /// Returns a slice over resolved links that the parser found so far.
    pub fn get_rules(&self) -> &[ResolvedLink] {
        return self.resolved_links.as_slice();
    }
    /// get parent rule that generated an output file with given id.
    pub fn get_parent_rule(&self, p0: &PathDescriptor) -> Option<&RuleRef> {
        self.outs.get_parent_rule(p0)
    }
    /// Add a new path entry against a group with `group_desc`
    pub fn add_group_entry(&mut self, group_desc: &GroupPathDescriptor, pd: PathDescriptor) {
        self.outs.add_group_entry(group_desc, pd)
    }
}

/// Represents an opens  buffer that is ready to be read for all data that stored with an id during parsing.
/// such as (rules, paths, groups, bins) stored during parsing.
pub struct ReadBufferObjects<'a> {
    bo: Ref<'a, BufferObjects>,
}

/// Represents an open buffer ready to write in the parser's buffers
pub struct WriteBufferObjects<'a> {
    bo: RefMut<'a, BufferObjects>,
}

impl<'a> WriteBufferObjects<'a> {
    /// add a  path to parser's buffer and return its unique id.
    /// If it already exists in its buffers boolean returned will be false
    pub fn add_path_from_root(&mut self, p: &Path) -> (PathDescriptor, bool) {
        self.bo.add_path_from_root(p)
    }
}

impl ReadBufferObjects<'_> {
    /// Returns an iterator over all the (grouppath, groupid) pairs stored in buffers during parsing
    pub fn get_group_iter(&self) -> Iter<'_, NormalPath, GroupPathDescriptor> {
        self.bo.group_iter()
    }

    /// returns the rule corresponding to ruledescriptor
    pub fn get_rule(&self, rd: &RuleDescriptor) -> &RuleFormulaUsage {
        self.bo.get_rule(rd)
    }
    /// Return resolved input type in the string form.
    pub fn get_input_path_str(&self, i: &InputResolvedType) -> String {
        self.bo.get_input_path_str(i)
    }
    /// Return the file path corresponding to its id
    pub fn get_path(&self, p0: &PathDescriptor) -> &NormalPath {
        self.bo.get_path(p0)
    }
    /// Returns the tup file path corresponding to its id
    pub fn get_tup_path(&self, p0: &TupPathDescriptor) -> &Path {
        self.bo.get_tup_path(p0)
    }
    /// Iterator over all the group ids
    pub fn get_group_descriptors(&self) -> RightValues<'_, NormalPath, GroupPathDescriptor> {
        self.bo.get_group_descs()
    }
}
impl TupParser {
    /// Constructor a new Tupfile parser.
    pub fn new() -> TupParser {
        TupParser {
            bo: Rc::new(RefCell::from(BufferObjects::default())),
            config_vars: HashMap::new(),
        }
    }
    /// Construct at the given rootdir and using config vars
    pub fn new_from<P: AsRef<Path>>(
        root_dir: P,
        config_vars: HashMap<String, Vec<String>>,
    ) -> TupParser {
        TupParser {
            bo: Rc::new(RefCell::from(BufferObjects::new(root_dir))),
            config_vars,
        }
    }

    /// Fetch the parser's read buffer for reading in id-ed data that it holds
    pub fn read_buf(&self) -> ReadBufferObjects {
        ReadBufferObjects {
            bo: self.borrow_ref(),
        }
    }

    /// Fetch the parsers's write buffer for writing id-object pairs
    pub fn write_buf(&self) -> WriteBufferObjects {
        WriteBufferObjects {
            bo: self.borrow_mut_ref(),
        }
    }

    pub(crate) fn borrow_ref(&self) -> Ref<BufferObjects> {
        return self.bo.deref().borrow();
    }
    pub(crate) fn borrow_mut_ref(&self) -> RefMut<BufferObjects> {
        return self.bo.deref().borrow_mut();
    }

    /// Primary APi to parse a tupfile or lua file. Parser gathers rules, groups, bins and  its file refernces it finds in tupfile.
    /// These are all referenced by their ids that generated  on the fly.
    /// Upon success the parser returns `Artifacts` that holds  references  to all the resolved outputs by their ids
    /// The parser currently also allows you to read its buffers (id-objec pairs) and even update its based on externally saved data via `ReadBufferObjects` and `WriteBufObjects`
    /// See [Artifacts]
    pub fn parse<P: AsRef<Path>>(
        &mut self,
        tup_file_path: P,
    ) -> Result<Artifacts, crate::errors::Error> {
        let (tup_desc, env_desc) = {
            let mut boref = self.borrow_mut_ref();
            let (tup_desc, _) = boref.add_tup(tup_file_path.as_ref());
            let env = init_env();
            let (env_desc, _) = boref.add_env(Cow::Borrowed(&env));
            (tup_desc, env_desc)
        };

        let mut m = SubstState::new(
            &self.config_vars,
            tup_file_path.as_ref(),
            tup_desc,
            env_desc,
        );
        if let Some("lua") = tup_file_path.as_ref().extension().and_then(OsStr::to_str) {
            // wer are not going to  resolve group paths during the first phase of parsing.
            parse_script(tup_file_path.as_ref(), m, self.bo.clone())
        } else {
            let stmts = parse_tupfile(tup_file_path.as_ref())?;
            let mut bo_ref_mut = self.borrow_mut_ref();
            let stmts = stmts.subst(&mut m, bo_ref_mut.deref_mut())?;
            let output_tag_info = OutputAssocs::new_no_resolve_groups();
            let stmts = stmts
                .expand_run(&mut m, bo_ref_mut.deref_mut())
                .into_iter()
                .flatten()
                .collect::<Vec<_>>();
            stmts.resolve_paths(
                tup_file_path.as_ref(),
                &output_tag_info,
                bo_ref_mut.deref_mut(),
                m.get_cur_file_desc(),
            )
        }
    }

    /// Re-resolve for resolved groups that were left unresolved  in the first round of parsing
    pub fn reresolve(&mut self, arts: Artifacts) -> Result<Artifacts, crate::errors::Error> {
        let pbuf = PathBuf::new();
        let mut boref = self.borrow_mut_ref();
        arts.get_resolved_links().resolve_paths(
            pbuf.as_path(),
            arts.get_outs(),
            boref.deref_mut(),
            &TupPathDescriptor::new(0),
        )
    }
}

/// locate a file by its name relative to current tup file path by recursively going up the directory tree
pub fn locate_file(cur_tupfile: &Path, file_to_loc: &str) -> Option<PathBuf> {
    let mut cwd = cur_tupfile;
    let pb: PathBuf;
    if cur_tupfile.is_dir() {
        pb = cur_tupfile.join("Tupfile");
        cwd = &pb;
    }
    while let Some(parent) = cwd.parent() {
        let p = parent.join(file_to_loc);
        if p.is_file() {
            return Some(p);
        }
        cwd = parent;
    }
    None
}
