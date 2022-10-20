use daggy::{petgraph, Dag, NodeIndex};
use errors::Error as Err;
use jwalk::WalkDir;
use parser::{locate_file, locate_tuprules};
use parser::{parse_statements_until_eof, parse_tupfile, Span};
use platform::*;
use statements::*;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
#[derive(Debug, Clone)]
pub enum StatementContext {
    Export,
    Import,
    Preload,
    Error,
    Link { source: PathBuf, dest: PathBuf },
    Other,
}
#[derive(Debug, Clone)]
pub struct SubstMap {
    pub expr_map: HashMap<String, Vec<String>>,
    pub rexpr_map: HashMap<String, Vec<String>>,
    pub conf_map: HashMap<String, Vec<String>>,
    pub rule_map: HashMap<String, Link>, // Macro assignments waiting for subst
    pub cur_file: PathBuf,
    pub cur_file_desc: TupPathDescriptor,
    pub sc: StatementContext,
    pub waitforpercs: bool,
    pub imported_env_map: HashMap<String, String>,
    pub exported_env_map: HashMap<String, String>,
    pub load_dirs: Vec<PathDescriptor>,
    pub cur_env_desc : EnvDescriptor,
    pub ebo: EnvBufferObject,
}

impl Default for SubstMap {
    fn default() -> SubstMap {
        SubstMap {
            expr_map: HashMap::new(),
            rexpr_map: HashMap::new(),
            conf_map: HashMap::new(),
            rule_map: HashMap::new(),
            cur_file: PathBuf::new(),
            cur_file_desc: TupPathDescriptor::default(),
            sc: StatementContext::Other,
            waitforpercs: true,
            imported_env_map: HashMap::new(),
            exported_env_map: HashMap::new(),
            load_dirs: vec![],
            cur_env_desc: EnvDescriptor::default(),
            ebo: EnvBufferObject::new(0)
        }
    }
}

impl SubstMap {
    pub fn new(conf_map: &HashMap<String, Vec<String>>, cur_file: &Path) -> Self {
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
        let mut keys = vec!["PATH", "HOME"];

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
            ..SubstMap::default()
        };
        let env = Env::new(def_exported);
        smap.cur_env_desc = smap.ebo.add_env(env).0;
        smap
    }
    pub fn get_mut_env_buffer_object(&mut self) -> &mut EnvBufferObject {
        return &mut self.ebo;
    }

    pub fn add_var(&mut self, var: String)
    {
        if !self.ebo.has_env(&var) {
            let mut env = self.ebo.get(&self.cur_env_desc).clone();
            env.add(var);
            let (id, _) = self.ebo.add_env(env);
            self.cur_env_desc = id;
        }
    }

    pub fn get_env_buffer_object(&self) -> &EnvBufferObject {
        return &self.ebo;
    }

    fn get_tup_dir(&self) -> &Path {
        self.cur_file
            .parent()
            .expect("could not find current tup dir")
    }
}
impl ExpandRun for Statement {
    fn expand_run(&self, m: &mut SubstMap, pbo: &mut PathBufferObject) -> Vec<Self> {
        let mut vs: Vec<Statement> = Vec::new();
        match self {
            Statement::Preload(v) => {
                let dir = v.cat();
                let p = Path::new(dir.as_str());

                let (dirid, _) = pbo.add_relative(p, m.get_tup_dir());
                {
                    m.load_dirs.push(dirid);
                }
            }
            Statement::Run(scriptargs) => {
                if let Some(script) = scriptargs.first() {
                    let mut cmd = std::process::Command::new(script.cat().as_str());
                    for arg_expr in scriptargs.iter().skip(1) {
                        let arg = arg_expr.cat();
                        let arg = arg.trim();
                        if arg.contains('*') {
                            let arg_path = join_path_raw(m.get_tup_dir(), Path::new(arg));
                            let outs = OutputTagInfo::new();
                            {
                                let matches =
                                    discover_inputs_from_glob(arg_path.as_path(), &outs, pbo)
                                        .expect(&*format!("error matching glob pattern {}", arg));
                                for ofile in matches {
                                    let p = ofile.as_path(pbo);
                                    cmd.arg(p.to_string_lossy().to_string().as_str().replace('\\', "/"));
                                }
                            }
                        } else if !arg.is_empty() {
                            cmd.arg(arg);
                        }
                    }
                    cmd.envs(m.exported_env_map.iter())
                        .current_dir(m.get_tup_dir());
                    //println!("running {:?}", cmd);
                    let output = cmd.stdout(Stdio::piped()).output().expect(&*format!(
                        "Failed to execute tup run {} in Tupfile : {}",
                        scriptargs.cat().as_str(),
                        m.get_tup_dir().to_string_lossy().to_string().as_str()
                    ));
                    //println!("status:{}", output.status);
                    let contents = output.stdout;
                    //println!("{}", String::from_utf8(contents.clone()).unwrap_or("".to_string()));
                    let lstmts = parse_statements_until_eof(Span::new(contents.as_bytes()))
                        .expect("failed to parse output of tup run");
                    let lstmts = lstmts
                        .subst(m)
                        .expect("subst failure in generated tup rules");
                    for located_stmt in lstmts {
                        vs.push(located_stmt.statement);
                    }
                }
            }
            _ => vs.push(self.clone()),
        }
        vs
    }
}

impl ExpandRun for Vec<LocatedStatement> {
    fn expand_run(&self, m: &mut SubstMap, pbo: &mut PathBufferObject) -> Vec<Self>
    where
        Self: Sized,
    {
        self.iter()
            .map(|l| {
                l.statement
                    .expand_run(m, pbo)
                    .iter()
                    .map(|s| LocatedStatement {
                        statement: s.clone(),
                        loc: l.loc,
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<Self>>()
    }
}

pub trait Subst {
    fn subst(&self, m: &mut SubstMap) -> Result<Self, Err>
    where
        Self: Sized;
}
pub trait SubstEnv {
    fn subst_env(&mut self, old_id: &EnvDescriptor, new_id: &EnvDescriptor)
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
pub trait Deps {
    fn input_groups(&self, tup_cwd: &Path, groups: &mut Vec<String>);
    fn input_bins(&self, tup_cwd: &Path, bins: &mut Vec<String>);

    // files that are possibly outputs of other rules
    fn input_gen_files(&self, tup_cwd: &Path, gen_files: &mut Vec<String>);

    fn output_groups(&self, tup_cwd: &Path, groups: &mut Vec<String>);
    fn output_bins(&self, tup_cwd: &Path, bins: &mut Vec<String>);
    fn output_gen_files(&self, tup_cwd: &Path, gen_files: &mut Vec<String>);
}
fn join_path_raw<P: AsRef<Path>>(tup_cwd: &Path, path: P) -> NormalPath {
    NormalPath::absolute_from(path.as_ref(), tup_cwd)
}
fn join_path<P: AsRef<Path>>(tup_cwd: &Path, path: P) -> String {
    join_path_raw(tup_cwd, path)
        .as_path()
        .to_string_lossy()
        .to_string()
}

fn input_bin(tup_cwd: &Path, inps: &mut Vec<String>, pathexpr: &PathExpr) {
    if let PathExpr::Bin(v1) = pathexpr {
        let name = join_path(tup_cwd, v1);
        inps.push(name);
    }
}
fn input_group(tup_cwd: &Path, inps: &mut Vec<String>, pathexpr: &PathExpr) {
    if let PathExpr::Group(v1, v2) = pathexpr {
        let v1str = &v1.cat();
        let v2str = &v2.cat();
        let group_path = Path::new(v1str).join(Path::new(v2str));
        let name = join_path(tup_cwd, group_path.as_path());
        inps.push(name);
    }
}
// scan for group tags in a vec of rvalgenerals
// deps are gathered from non-ws pathexpr
impl Deps for Vec<PathExpr> {
    fn input_groups(&self, tup_cwd: &Path, groups: &mut Vec<String>) {
        for pathexpr in self.iter() {
            input_group(tup_cwd, groups, pathexpr);
        }
    }
    fn input_bins(&self, tup_cwd: &Path, bins: &mut Vec<String>) {
        for pathexpr in self.iter() {
            input_bin(tup_cwd, bins, pathexpr)
        }
    }

    fn input_gen_files(&self, tup_cwd: &Path, gen_files: &mut Vec<String>) {
        for pathexpr in self.iter() {
            let pestring = pathexpr.cat_ref();
            if !pestring.is_empty() {
                gen_files.push(join_path(tup_cwd, pestring))
            }
        }
    }
    // dont distinguish between input and output at this point
    fn output_groups(&self, tup_cwd: &Path, groups: &mut Vec<String>) {
        self.input_groups(tup_cwd, groups)
    }
    fn output_bins(&self, tup_cwd: &Path, bins: &mut Vec<String>) {
        self.input_bins(tup_cwd, bins)
    }

    fn output_gen_files(&self, tup_cwd: &Path, gen_files: &mut Vec<String>) {
        self.input_gen_files(tup_cwd, gen_files)
    }
}

impl Deps for LocatedStatement {
    fn input_groups(&self, tup_cwd: &Path, groups: &mut Vec<String>) {
        if let Some(s) = rule_source(self) {
            s.primary.input_groups(tup_cwd, groups);
            s.secondary.input_groups(tup_cwd, groups);
        }
    }

    fn input_bins(&self, tup_cwd: &Path, bins: &mut Vec<String>) {
        if let Some(s) = rule_source(self) {
            s.primary.input_bins(tup_cwd, bins);
            s.secondary.input_bins(tup_cwd, bins);
        }
    }

    fn input_gen_files(&self, tup_cwd: &Path, gen_files: &mut Vec<String>) {
        if let Some(s) = rule_source(self) {
            s.primary.input_gen_files(tup_cwd, gen_files);
            s.secondary.input_gen_files(tup_cwd, gen_files);
        }
    }

    fn output_groups(&self, tup_cwd: &Path, groups: &mut Vec<String>) {
        if let Some(Target {
            group: Some(group), ..
        }) = rule_target(self)
        {
            input_group(tup_cwd, groups, group);
        }
    }

    fn output_bins(&self, tup_cwd: &Path, bins: &mut Vec<String>) {
        if let Some(Target { bin: Some(bin), .. }) = rule_target(self) {
            input_bin(tup_cwd, bins, bin);
        }
    }

    fn output_gen_files(&self, tup_cwd: &Path, gen_files: &mut Vec<String>) {
        if let Some(t) = rule_target(self) {
            t.primary.output_gen_files(tup_cwd, gen_files);
            t.secondary.output_gen_files(tup_cwd, gen_files);
        }
    }
}
/*
impl Deps for Vec<LocatedStatement> {
    fn input_groups(&self, tup_cwd: &Path, groups: &mut Vec<String>) {
        self.into_iter().map(|x| x.input_groups(tup_cwd, groups));
    }

    fn input_bins(&self, tup_cwd: &Path, bins: &mut Vec<String>) {
        self.into_iter().map(|x| x.input_bins(tup_cwd, bins));
    }

    fn input_gen_files(&self, tup_cwd: &Path, gen_files: &mut Vec<String>) {
        self.into_iter()
            .map(|x| x.input_gen_files(tup_cwd, gen_files));
    }

    fn output_groups(&self, tup_cwd: &Path, groups: &mut Vec<String>) {
        self.into_iter().map(|x| x.output_groups(tup_cwd, groups));
    }

    fn output_bins(&self, tup_cwd: &Path, bins: &mut Vec<String>) {
        self.into_iter().map(|x| x.output_bins(tup_cwd, bins));
    }

    fn output_gen_files(&self, tup_cwd: &Path, gen_files: &mut Vec<String>) {
        self.into_iter()
            .map(|x| x.output_gen_files(tup_cwd, gen_files));
    }
} */

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
    // substitute a single pathexpr into an array of literal pathexpr
    // SFINAE holds
    fn subst(&self, m: &mut SubstMap) -> Vec<PathExpr> {
        match self {
            &PathExpr::DollarExpr(ref x) => {
                if let Some(val) = m.expr_map.get(x.as_str()) {
                    intersperse_sp1(val)
                } else if let Some(val) = m.imported_env_map.get(x.as_str()) {
                    vec![PathExpr::from(val.clone())]
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
// call subst on each path expr and flatten/cleanup the output.
impl Subst for Vec<PathExpr> {
    fn subst(&self, m: &mut SubstMap) -> Result<Self, Err> {
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
    fn subst(&self, m: &mut SubstMap) -> Result<Self, Err> {
        Ok(Source {
            primary: self.primary.subst(m)?,
            for_each: self.for_each,
            secondary: self.secondary.subst(m)?,
        })
    }
}
use decode::{discover_inputs_from_glob, BufferObjects, ExpandRun, NormalPath, OutputTagInfo, PathBufferObject, PathDescriptor, ResolvePaths, ResolvedLink, RuleRef, TupPathDescriptor, EnvBufferObject};
use nom::AsBytes;
use scriptloader::parse_script;
use std::ops::AddAssign;
use std::process::Stdio;

impl AddAssign for Source {
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
                        if desc.is_empty() {
                            desc = explink.rule_formula.description.clone();
                        }
                        let mut r = explink.rule_formula.formula.clone();
                        r.cleanup();
                        formulae.append(&mut r);
                    } else {
                        return Err(Err::UnknownMacroRef(
                            name.clone(),
                            RuleRef::new(&m.cur_file_desc, &Loc::new(pos.0, pos.1 as u32)),
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

impl SubstEnv for Statement {
    fn subst_env(&mut self, old_id: &EnvDescriptor, new_id: &EnvDescriptor) {
         match self{
            Statement::Rule(_, e) => {
                if e == old_id {
                    e.setid(new_id)
                }
            }
            _ => {}
        }
    }
}

impl SubstEnv for Vec<LocatedStatement> {
    fn subst_env(&mut self, old_id: &EnvDescriptor, new_id: &EnvDescriptor)  {
       for  s in self.iter_mut() {
           s.statement.subst_env(old_id, new_id);
       }
    }
}
// substitute variables in a sequence of statements from previous assignments
// update variable assignments into substmap as you go.
impl Subst for Vec<LocatedStatement> {
    fn subst(&self, m: &mut SubstMap) -> Result<Vec<LocatedStatement>, Err> {
        let mut newstats = Vec::new();
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
                Statement::Rule(link, _) => {
                    let mut l = link.clone();
                    while l.has_ref() {
                        l = l.expand(m)?; // expand all nested macro refs
                    }
                    let env_desc = m.cur_env_desc.clone();
                    newstats.push(LocatedStatement::new(
                        Statement::Rule(l.subst(m)?, env_desc),
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
                Statement::Export(var) => {
                    m.add_var(var.clone());
                    //newstats.push(statement.clone());
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
    pub fn new(tupfile: PathBuf, statements: Vec<LocatedStatement>) -> ParsedStatements {
        ParsedStatements {
            tupfile,
            statements,
        }
    }
    pub fn get_tupfile(&self) -> &Path {
        self.tupfile.as_path()
    }
    pub fn get_statement(&self, i: usize) -> &LocatedStatement {
        &self.statements[i]
    }
    pub fn get_statements(&self) -> &Vec<LocatedStatement> {
        &self.statements
    }
}
pub fn parse_tup(
    confvars: &HashMap<String, Vec<String>>,
    tupfilepath: &str,
    bo: &mut BufferObjects
) -> Result<Vec<LocatedStatement>, crate::errors::Error> {
    let tup_file_path = Path::new(tupfilepath);
    let mut m = SubstMap::new(&confvars, tup_file_path);
    m.cur_file = tup_file_path.to_path_buf();
    if tupfilepath.ends_with(".lua") {
        let mut links = parse_script(tup_file_path, m, bo)?;
        let mut stmts: Vec<_> = links.0
            .drain(..)
            .map(|l| {
                let loc = Loc::new(l.0.pos.0, 0);
                LocatedStatement {
                    statement: Statement::Rule(l.0, l.1),
                    loc,
                }
            })
            .collect();
        bo.import_env_buffers(links.1, &mut stmts);
        Ok(stmts)
    } else {
        let stmts = parse_tupfile(tupfilepath)?;
        let stmts = stmts.subst(&mut m)?;
        let mut stmts = stmts
            .expand_run(&mut m, bo.get_mut_path_buffer_object())
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        bo.import_env_buffers(m.ebo, &mut stmts);
        Ok(stmts)
    }
}
// scan and parse all Tupfile, return deglobbed, decoded links
pub fn parse_dir(root: &Path) -> Result<Vec<ResolvedLink>, crate::errors::Error> {
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
        } else if f_name.as_str().eq("Tupfile.lua") {
            let tupfilepath = entry.path().to_string_lossy().as_ref().to_string();
            tupfiles.push(tupfilepath);
        }
    }
    let rootfolder = locate_file(root, "Tupfile.ini").ok_or(crate::errors::Error::RootNotFound)?;
    let confvars = load_conf_vars(rootfolder.as_path())?;
    let mut rules = Vec::new();
    let mut ids = Vec::new();
    let mut dag: Dag<u32, u32> = Dag::new();
    let mut bo = BufferObjects::default();
    for tupfilepath in tupfiles.iter() {
        ids.push(dag.node_count());
        let stmts = parse_tup(&confvars, tupfilepath.as_str(), &mut bo)?;
        let tup_file_path = Path::new(tupfilepath);
        let tup_cwd = tup_file_path.parent().expect("tup file parent not found");
        let mut groups = Vec::new();
        let mut bins = Vec::new();
        for l in stmts.iter().filter(|l| is_rule(l)) {
            let n = dag.add_node(1);
            l.input_groups(tup_cwd, &mut groups);
            groups.drain(..).for_each(|group| {
                required_by
                    .entry("?G".to_owned() + group.as_str())
                    .or_default()
                    .push(n)
            });
            l.input_bins(tup_cwd, &mut bins);
            bins.drain(..).for_each(|bin| {
                required_by
                    .entry("?B".to_owned() + bin.as_str())
                    .or_default()
                    .push(n)
            });
            l.output_groups(tup_cwd, &mut groups);
            groups.drain(..).for_each(|grp| {
                provided_by
                    .entry("?G".to_owned() + grp.as_str())
                    .or_default()
                    .push(n)
            });
            l.output_bins(tup_cwd, &mut bins);
            bins.drain(..).for_each(|bin| {
                provided_by
                    .entry("?B".to_owned() + bin.as_str())
                    .or_default()
                    .push(n)
            });
        }
        rules.push(ParsedStatements::new(tup_file_path.to_path_buf(), stmts));
    }
    ids.push(dag.node_count());
    let statement_from_id = |i: NodeIndex| {
        let mut x = ids.partition_point(|&j| j < i.index());
        if ids[x] > i.index() {
            x -= 1;
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
    // We dont yet have decoded paths and so cannot correctly specify
    // dependencies between rules in the same tupfile
    // To kickstart the decoding process, add dependencies within each tupfile between successive rules.
    // if this causes cyclic deps we ignore them.
    for slic in ids.as_slice().windows(2) {
        for nid in (slic[0] + 1)..slic[1] {
            let _res = dag.update_edge(NodeIndex::new(nid - 1), NodeIndex::new(nid), 1);
        }
        // ignore cylic deps at this point, these are soft constraints..
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
        let (tupdesc, _) = bo.tbo.add(tupfile);
        let (resolved_links, ref mut newoutputtags) =
            statement.resolve_paths(tupfile, &outputtags, &mut bo, &tupdesc)?;
        outputtags.merge_group_tags(newoutputtags)?;
        outputtags.merge_bin_tags(newoutputtags)?;
        lstats.extend(resolved_links.into_iter());
    }
    Ok(lstats)
}
