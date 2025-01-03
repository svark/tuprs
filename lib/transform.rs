//! This module has data structures and methods to transform Statements to Statements with substitutions and expansions
use std::borrow::Cow;
use std::collections::{BTreeSet, HashMap};
use std::ffi::{OsStr, OsString};
use std::io::BufWriter;
use std::ops::ControlFlow::Continue;
use std::ops::{AddAssign, ControlFlow, Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::Once;
use std::vec::Drain;

use crate::buffers::{
    BufferObjects, EnvDescriptor, EnvList, GenBufferObject, GlobPathDescriptor, GroupBufferObject,
    GroupPathDescriptor, OutputHolder, PathBuffers, PathDescriptor, RelativeDirEntry,
    RuleDescriptor, TaskDescriptor, TupPathDescriptor,
};
use crate::decode::{
    paths_with_pattern, DecodeInputPlaceHolders, PathSearcher, ResolvePaths, ResolvedLink,
    ResolvedTask, RuleFormulaInstance, TaskInstance, TupLoc,
};
use crate::errors::Error::{IoError, RootNotFound};
use crate::errors::{Error as Err, Error};
use crate::parser::{parse_statements_until_eof, parse_tupfile, Span};
use crate::paths::{GlobPath, InputResolvedType, InputsAsPaths};
use crate::paths::{MatchingPath, NormalPath};
use crate::platform::*;
use crate::scriptloader::parse_script;
use crate::statements::DollarExprs;
use crate::statements::PathExpr::DollarExprs as DExpr;
use crate::statements::*;
use crate::transform::ParseContext::Expression;
use crate::writer::{cat_literals, words_from_pelist};
use crossbeam::channel::{Receiver, Sender};
use log::debug;
use nom::AsBytes;
use parking_lot::{RwLock, RwLockReadGuard, RwLockWriteGuard};

fn shell<S: AsRef<OsStr>>(cmd: S) -> std::process::Command {
    let shell = {
        static SHELL: RwLock<Option<OsString>> = RwLock::new(None);
        static START: Once = Once::new();

        START.call_once(|| {
            let mut shell = SHELL.write();
            *shell = Some(
                std::env::var_os("SHELL").unwrap_or_else(|| OsString::from(String::from("sh"))),
            );
        });

        SHELL.read()
    };

    let mut command = std::process::Command::new(shell.as_ref().unwrap());

    command.arg("-c");
    command.arg(cmd);

    command
}
fn value_is_non_empty(s: &Vec<String>) -> bool {
    let len = s.len();
    match len {
        len if len > 1 => true,
        len if len == 1 => !s[0].is_empty(),
        _ => false,
    }
}
fn pe_value_is_non_empty(s: &Vec<PathExpr>) -> bool {
    let len = s.len();
    debug!("variable_value_is_non_empty_pe:{:?}", s);
    match len {
        len if len > 1 => true,
        len if len == 1 => !s.first().unwrap().is_empty(),
        _ => false,
    }
}

/// Statements to resolve with their current parse state
pub struct StatementsToResolve {
    /// Statements to resolve
    statements: Vec<LocatedStatement>,
    /// State of parsing so far
    parse_state: ParseState,
}

impl StatementsToResolve {
    pub(crate) fn new(statements: Vec<LocatedStatement>, parse_state: ParseState) -> Self {
        StatementsToResolve {
            statements,
            parse_state,
        }
    }
    /// return parsed tupfile whose statements are to be resolved
    pub fn get_tup_desc(&self) -> &TupPathDescriptor {
        &self.parse_state.cur_file_desc
    }
    /// Get parse state after tupfile parsing.
    pub fn fetch_var(&self, var: &String) -> Option<String> {
        self.parse_state.expr_map.get(var).map(|x| x.cat())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum ParseContext {
    Statement,
    Expression,
}

impl Default for ParseContext {
    fn default() -> Self {
        ParseContext::Statement
    }
}

/// ParseState holds maps tracking current state of variable replacements as we read a tupfile
#[derive(Debug, Clone, Default)]
pub(crate) struct ParseState {
    /// tupfile variables to be substituted
    pub(crate) expr_map: HashMap<String, Vec<PathExpr>>,
    // defined functions
    pub(crate) func_map: HashMap<String, Vec<PathExpr>>,
    /// configuration values read from tup.config
    pub(crate) conf_map: HashMap<String, Vec<String>>,
    /// Macro assignments waiting for subst
    pub(crate) rule_map: HashMap<String, Link>,
    /// Tupfile being read
    pub(crate) tup_base_path: TupPathDescriptor,
    /// Tupfile or an included file being read
    pub(crate) cur_file: PathBuf,
    /// unique descriptor for tupfile
    pub(crate) cur_file_desc: TupPathDescriptor,
    /// preload these dirs
    pub(crate) load_dirs: Vec<PathDescriptor>,
    /// current state of env variables to be passed to rules for execution
    pub(crate) cur_env_desc: EnvList,
    /// Cache of statements from previously read Tupfiles
    pub(crate) statement_cache: Arc<RwLock<HashMap<TupPathDescriptor, Vec<LocatedStatement>>>>,
    /// Buffers to store files, groups, bins, env with its id.
    pub(crate) path_buffers: Arc<BufferObjects>,
    /// tracks the context of parsing for substitutions
    pub(crate) parse_context: ParseContext,
    /// history of included files parsed so far
    pub(crate) tup_files_read: Vec<TupPathDescriptor>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct CallArgsMap {
    // call args
    pub(crate) call_args: HashMap<String, String>,
}

impl CallArgsMap {
    pub(crate) fn new() -> Self {
        CallArgsMap {
            call_args: HashMap::new(),
        }
    }
    pub(crate) fn insert(&mut self, k: String, v: String) {
        self.call_args.insert(k, v);
    }
    pub(crate) fn get(&self, k: &str) -> Option<&String> {
        self.call_args.get(k)
    }
}
// Default Env to feed into every tupfile
fn init_env() -> Vec<Env> {
    let mut def_exported = BTreeSet::new(); // for stable iteration
    #[cfg(target_os = "windows")]
    let keys: Vec<&str> = vec![
        /* NOTE: Please increment PARSER_VERSION if these are modified */
        "PATH",
        "HOME",
        /* Basic Windows variables */
        "COMSPEC",
        "PATHEXT",
        "SYSTEMROOT",
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
                    def_exported.insert(Env::from(needle.0, needle.1));
                    inserted = true;
                }
            }
            if inserted {
                if let Some(val) = std::env::var(k).ok() {
                    def_exported.insert(Env::from(k.to_string(), val));
                }
            }
        } else if let Some(val) = std::env::var(k).ok() {
            def_exported.insert(Env::from(k.to_string(), val.clone()));
        }
    }
    def_exported.into_iter().collect()
}

/// Accessor and constructors of ParseState
impl ParseState {
    /// Initialize ParseState for var-substitution in given file `cur_file_desc`
    pub fn new(
        conf_map: &HashMap<String, Vec<String>>,
        cur_file_desc: TupPathDescriptor,
        cur_env_desc: Vec<EnvDescriptor>,
        statement_cache: Arc<RwLock<HashMap<TupPathDescriptor, Vec<LocatedStatement>>>>,
        bo: Arc<BufferObjects>,
    ) -> Self {
        let mut def_vars = HashMap::new();
        let cur_file = bo.get_path(&cur_file_desc).clone();
        let dir = cur_file_desc.get_parent_descriptor();
        def_vars.insert(
            "TUP_CWD".to_owned(),
            vec![MatchingPath::new(dir.clone(), PathDescriptor::default()).into()],
        );
        log::debug!("TUP_CWD:{}", dir);
        let rel_path_to_root = cur_file_desc
            .get_path_to_root()
            .to_string_lossy()
            .to_string();
        log::debug!("TUP_ROOT:{}", rel_path_to_root);
        def_vars.insert(
            "TUP_ROOT".to_owned(),
            vec![MatchingPath::new(PathDescriptor::default(), dir).into()],
        );
        let mut tup_files_read = Vec::new();
        tup_files_read.push(cur_file_desc.clone());
        let tupconfig = PathDescriptor::default();
        let tupconfig = tupconfig.join_leaf("tup.config");
        tup_files_read.push(tupconfig); // tup.config is always a dependency whether it exists or not

        ParseState {
            conf_map: conf_map.clone(),
            expr_map: def_vars,
            cur_file: cur_file.clone().to_path_buf(),
            tup_base_path: cur_file_desc.clone(),
            cur_file_desc,
            cur_env_desc: EnvList::from(cur_env_desc),
            statement_cache: statement_cache.clone(),
            path_buffers: bo,
            ..ParseState::default()
        }
    }
    /// Evaluate a variable and return its value. Eager evaluation is preferred over lazy evaluation.
    /// Lazy evaluation is done for functions and `tupconfig` assignments in `conf_map`.
    /// Environment variable values are directly returned if the key is not found in `expr_map`, `func_map`, or `conf_map`.
    /// If the evaluation fails, an empty string is returned.
    /// Once evaluated, it is stored in `expr_map`.
    pub(crate) fn extract_evaluated_var(
        &mut self,
        v: &str,
        path_searcher: &impl PathSearcher,
    ) -> Vec<PathExpr> {
        debug!("evaluating var: {:?}", v);
        self.expr_map
            .get(v)
            .cloned()
            .inspect(|x| debug!("eager extract_evaluated_var: {:?}", x))
            .or_else(|| {
                self.func_map.remove(v).map(|val| {
                    let evaluated_val = val.subst_pe(self, path_searcher);
                    self.assign_eager(v, evaluated_val.clone(), path_searcher);
                    evaluated_val
                })
            })
            .inspect(|x| debug!("lazy extract_evaluated_var: {:?}", x))
            .or_else(|| {
                self.conf_map.remove(v).map(|val| {
                    let mut val = val.join(" ");
                    if !val.ends_with("\n") {
                        val.push('\n');
                    }
                    let pelist = crate::parser::parse_pelist_till_line_end_with_ws(Span::new(
                        val.as_bytes(),
                    ))
                    .map(|x| x.1 .0)
                    .unwrap_or(vec![]);
                    let res = pelist.subst_pe(self, path_searcher);
                    self.assign_eager(v, res.clone(), path_searcher);
                    res
                })
            })
            .inspect(|x| debug!("lazy (conf) extract_evaluated_var: {:?}", x))
            .or_else(|| {
                self.get_env_value(v).map(|val| {
                    let r = to_pelist(val);
                    debug!("env value for {:?} is {:?}", v, r);
                    r
                })
            })
            .inspect(|x| debug!("env extract_evaluated_var: {:?}", x))
            .unwrap_or_else(|| {
                log::warn!("No substitution found for {}", v);
                vec![Default::default()]
            })
    }
    pub(crate) fn add_env(&mut self, p0: &EnvDescriptor) {
        self.cur_env_desc.add(p0.clone())
    }

    pub(crate) fn get_envs(&mut self) -> HashMap<String, String> {
        self.cur_env_desc.get_key_value_pairs()
    }

    pub(crate) fn get_env_value(&self, key: &str) -> Option<String> {
        self.cur_env_desc
            .find_key(key)
            .map(|env| env.get().get_val_str().to_string())
    }
    // add to load dir
    pub(crate) fn add_load_dir(&mut self, p0: PathDescriptor) {
        if !self.load_dirs.contains(&p0) {
            self.load_dirs.push(p0);
        }
    }

    // Dump all variable to a file
    pub(crate) fn dump_vars(&self, path: &Path) -> Result<(), Error> {
        use std::io::Write;
        let mut f = std::fs::File::create(path).map_err(|e| crate::errors::Error::IoError(e,String::from("Unable to dump config"), Loc::new(0,0, 0)))?;
        let mut f = BufWriter::new(f);
        for (k, v) in self.expr_map.iter() {
            let res = write!(f, "{}:={}", k, v.cat());
            if let Err(e) = res {
                return Err(IoError(e, String::from("Could write to config"), Loc::new(0,0, 0)));
            }
        }
        for (k, v) in self.func_map.iter() {
            let res = writeln!(f, "{}={}", k, v.cat());
            if let Err(e) = res {
                return Err(IoError(e, String::from("Could write to config"), Loc::new(0,0, 0)));
            }
        }
        Ok(())
    }

    pub(crate) fn get_tupfiles_read(&self) -> &Vec<PathDescriptor> {
        &self.tup_files_read
    }
    pub(crate) fn add_path_to_tupfiles_read(&mut self, p0: PathBuf) {
        let id = self.path_buffers.add_abs(p0).unwrap();
        self.tup_files_read.push(id);
    }

    pub(crate) fn get_statements_from_cache(
        &self,
        tup_desc: &TupPathDescriptor,
    ) -> Option<Vec<LocatedStatement>> {
        let x = self.statement_cache.deref().read();
        x.get(tup_desc).cloned()
    }
    /// returns the Tupfile being parsed (not the included file)
    pub(crate) fn get_tup_base_dir(&self) -> PathDescriptor {
        self.tup_base_path.get_parent_descriptor()
    }
    pub(crate) fn get_tup_base_file(&self) -> PathDescriptor {
        self.tup_base_path.clone()
    }

    pub(crate) fn replace_tup_cwd(&mut self, dir: MatchingPath) -> Option<Vec<PathExpr>> {
        let v = self.expr_map.remove("TUP_CWD");
        self.expr_map
            .insert("TUP_CWD".to_string(), vec![dir.into()]);
        v
    }

    pub fn with_path_buffers_do<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&BufferObjects) -> R,
    {
        f(self.path_buffers.deref())
    }
    pub fn get_path_buffers(&self) -> Arc<BufferObjects> {
        self.path_buffers.clone()
    }

    pub fn switch_tupfile_and_process<T>(
        &mut self,
        tupfile_desc: &PathDescriptor,
        process: impl FnOnce(&mut Self) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let old_cur_file = self.get_cur_file_desc().clone();
        self.add_to_tupfiles_read(tupfile_desc);
        self.set_cwd(tupfile_desc)?;
        let res = process(self);
        self.set_cwd(&old_cur_file)?;
        res
    }

    pub fn add_to_tupfiles_read(&mut self, tupfile_desc: &PathDescriptor) {
        self.tup_files_read.push(tupfile_desc.clone());
    }

    /// Initialize ParseState for var-subst-ing `cur_file' with no conf_map.
    /// This is useful for testing.
    pub fn new_at<P: AsRef<Path>>(cur_file: P) -> Self {
        let mut def_vars = HashMap::new();
        let pbuffers = Arc::new(BufferObjects::new(get_parent(cur_file.as_ref())));
        let cur_file_desc = pbuffers.add_tup(cur_file.as_ref());
        let tup_dir = cur_file_desc.get_parent_descriptor();
        let cur_file = cur_file_desc.get_path_ref().as_path().to_path_buf();
        def_vars.insert(
            "TUP_CWD".to_owned(),
            vec![MatchingPath::new(tup_dir, PathDescriptor::default()).into()],
        );
        def_vars.insert(
            "TUP_ROOT".to_owned(),
            vec![MatchingPath::new(
                PathDescriptor::default(),
                cur_file_desc.get_parent_descriptor(),
            )
            .into()],
        );

        ParseState {
            expr_map: def_vars,
            cur_file: cur_file.clone(),
            tup_base_path: cur_file_desc.clone(),
            cur_file_desc,
            path_buffers: pbuffers,
            ..ParseState::default()
        }
    }
    /// set the current TUP_CWD, TUP_ROOT in expression map in ParseState as we switch to reading an included file
    pub fn set_cwd(&mut self, tupfile: &PathDescriptor) -> Result<(), Error> {
        if tupfile.eq(&self.cur_file_desc) {
            return Ok(());
        }
        let old_tup_dir = self.get_tup_dir_desc();

        self.cur_file_desc = tupfile.clone();
        debug!(
            "switching to:{:?} from: {:?}",
            self.cur_file_desc, old_tup_dir
        );
        if self.get_tup_dir_desc() != old_tup_dir {
            let diff = RelativeDirEntry::new(self.get_tup_base_dir(), self.get_tup_dir_desc());
            let diff_path = diff.get_path();
            debug!("new tup_cwd {}", diff_path);
            self.replace_tup_cwd(
                MatchingPath::new(self.get_tup_dir_desc(), self.get_tup_base_dir()).into(),
            );
        } else {
            debug!("no change in cwd!");
        }
        Ok(())
    }

    /// return the tupfile being parsed
    pub(crate) fn get_cur_file(&self) -> &Path {
        self.cur_file_desc.get_path_ref().as_path()
    }

    // get directory of the tupfile being parsed
    pub(crate) fn get_tup_dir_desc(&self) -> PathDescriptor {
        self.get_cur_file_desc().get_parent_descriptor()
    }

    /// Get descritptor of the tup file being parsed
    pub(crate) fn get_cur_file_desc(&self) -> &TupPathDescriptor {
        &self.cur_file_desc
    }

    /// Add statements to cache.
    fn add_statements_to_cache(
        &mut self,
        tup_desc: &TupPathDescriptor,
        mut vs: Vec<LocatedStatement>,
    ) {
        vs.retain_mut(|x| !x.is_comment());
        self.statement_cache
            .deref()
            .write()
            .entry(tup_desc.clone())
            .or_insert(vs);
    }

    pub(crate) fn append_assign_lazy(&mut self, v: &str, val: Vec<PathExpr>) {
        if let Some(vals) = self.func_map.get_mut(v) {
            if !vals.is_empty() {
                vals.push(PathExpr::Sp1);
            }
            vals.extend(val);
        } else {
            self.func_map.insert(v.to_string(), val);
        }
    }
    /// convert path expression list to a vector of strings after evaluating them
    fn eval_right(
        &mut self,
        right: &Vec<PathExpr>,
        path_searcher: &impl PathSearcher,
    ) -> Vec<PathExpr> {
        let mut ps = self.clone();
        ps.parse_context = Expression; // provide a local context where we can evaluate expressions,
                                       // without affecting the parent ParseState
        let mut subst_right_pe: Vec<_> = right
            .iter()
            .flat_map(|x| x.subst(&mut ps, path_searcher))
            .collect();
        subst_right_pe.cleanup();
        debug!("eval_right: {:?}", subst_right_pe);
        subst_right_pe // even if there is single empty string with no spaces we keep it as it is
    }

    fn append_assign_eager(
        &mut self,
        v: &str,
        right: Vec<PathExpr>,
        path_searcher: &impl PathSearcher,
    ) {
        let val = self.eval_right(&right, path_searcher);
        if let Some(vals) = self.expr_map.get_mut(v) {
            if log::log_enabled!(log::Level::Debug) {
                debug!("append assign of {:?} over existing value:{:?}", v, val);
            }
            if pe_value_is_non_empty(vals) {
                vals.push(PathExpr::Sp1);
            }
            vals.extend(val.into_iter());
            vals.cleanup();
        } else if !val.is_empty() {
            debug!(
                "eager assign of {:?} to {:?} with not previously set val",
                v,
                val.cat()
            );
            self.expr_map.insert(v.to_string(), val);
        }
    }

    pub(crate) fn assign_eager(
        &mut self,
        v: &str,
        right: Vec<PathExpr>,
        path_searcher: &impl PathSearcher,
    ) {
        debug!("assigning {:?} to {:?}", v, right);
        let val = self.eval_right(&right, path_searcher);
        if let Some(vals) = self.expr_map.get_mut(v) {
            if log::log_enabled!(log::Level::Debug) {
                debug!(
                    "overwrite {:?} having existing value:{:?} with {:?}",
                    v, vals, val
                );
            }
            *vals = val;
        } else {
            debug!(
                "eager assign of {:?} to \"{:?}\" with no previously set val",
                v, val
            );
            self.expr_map.insert(v.to_string(), val);
        }
        self.func_map.remove(v);
    }
    pub(crate) fn assign_lazy(&mut self, v: &str, right: Vec<PathExpr>) {
        if let Some(vals) = self.func_map.get_mut(v) {
            debug!(
                "overwrite {:?} having existing value:{:?} with {:?}",
                v, vals, right
            );
            *vals = right;
        } else {
            debug!("no previous value for {:?} so assigning lazily", v);
            self.func_map.insert(v.to_string(), right);
        }
    }

    pub(crate) fn append_assign(
        &mut self,
        v: &str,
        right: Vec<PathExpr>,
        path_searcher: &impl PathSearcher,
    ) {
        if self.expr_map.contains_key(v) {
            self.append_assign_eager(v, right, path_searcher);
        } else {
            debug!("no previous value for {:?} so assigning lazily", v);
            self.append_assign_lazy(v, right);
        }
    }

    pub(crate) fn conditional_assign(&mut self, v: &str, right: Vec<PathExpr>) {
        if self.is_var_defined(v) {
            if log::log_enabled!(log::Level::Debug) {
                debug!("skip empty assign of {:?} ?= {:?}", v, right);
                if self.expr_map.contains_key(v) {
                    debug!(
                        "existing value:{:?}",
                        self.expr_map.get(v).unwrap_or(&vec![])
                    );
                } else {
                    debug!(
                        "existing value:{:?}",
                        self.func_map.get(v).unwrap_or(&vec![])
                    );
                }
            }
            return;
        }
        debug!("empty assignment of : {:?} ?= {:?}", v, right);
        self.append_assign_lazy(v, right);
    }

    //https://www.gnu.org/software/make/manual/make.html#Conditional-Syntax
    pub(crate) fn is_var_defined(&self, v: &str) -> bool {
        self.expr_map.contains_key(v) && pe_value_is_non_empty(self.expr_map.get(v).unwrap())
            || self.func_map.contains_key(v) && self.func_map.get(v).unwrap().len() > 0
            || self.conf_map.contains_key(v) && value_is_non_empty(self.conf_map.get(v).unwrap())
    }
}

/// Method to expand tup `run` statement to discover new rules to add
/// run is expected to echo regular rule statements which we add to list of rules during the `subst` phase.
trait ExpandRun {
    fn expand_run(
        &mut self,
        parse_state: &mut ParseState,
        path_searcher: &impl PathSearcher,
    ) -> Result<(), Error>
    where
        Self: Sized;
}

impl Statement {
    /// expand_run adds Statements returned by executing a shell command. Rules that are output from the command should be in the regular format for rules that Tup supports
    /// see docs for how the environment is picked.
    fn expand_run(
        &self,
        parse_state: &mut ParseState,
        path_searcher: &impl PathSearcher,
        loc: &Loc,
    ) -> Result<Vec<LocatedStatement>, Error> {
        let rule_ref = TupLoc::new(&parse_state.cur_file_desc, loc);

        let path_buffers = parse_state.get_path_buffers();
        let path_buffers = path_buffers.deref();
        match self {
            Statement::Run(script_args) => {
                if let Some(script) = script_args.first() {
                    let mut acnt = 0;
                    let mut cmd = if !cfg!(windows)
                        || Path::new(script.cat_ref().as_ref()).extension()
                            == Some(OsStr::new("sh"))
                        || script.cat_ref() == "sh"
                    {
                        acnt = (script.cat_ref() == "sh").into();
                        std::process::Command::new("sh")
                    } else {
                        std::process::Command::new("cmd.exe")
                    };
                    for arg_expr in script_args.iter().skip(acnt) {
                        let arg = arg_expr.cat_ref();
                        let arg = arg.trim();
                        if arg.contains('*') {
                            let p =
                                path_buffers.add_path_from(&parse_state.get_tup_dir_desc(), arg)?;
                            let glob_path =
                                GlobPath::build_from(&parse_state.get_tup_dir_desc(), &p)?;
                            let glob_path_desc = glob_path.get_glob_path_desc();
                            let rel_path = RelativeDirEntry::new(
                                parse_state.get_tup_dir_desc(),
                                glob_path_desc,
                            );
                            let mut glob_paths = vec![glob_path];
                            for dir_desc in parse_state.load_dirs.iter() {
                                let glob_path =
                                    GlobPath::build_from_relative_desc(dir_desc, &rel_path)?;
                                glob_paths.push(glob_path);
                            }
                            let matches = path_searcher
                                .discover_paths(path_buffers, glob_paths.as_slice())
                                .unwrap_or_else(|_| panic!("error matching glob pattern {}", arg));

                            debug!("expand_run num files from glob:{:?}", matches.len());
                            for ofile in matches {
                                let p = RelativeDirEntry::new(
                                    parse_state.get_tup_dir_desc(),
                                    ofile.path_descriptor(),
                                );
                                cmd.arg(p.get_path().as_path());
                            }
                        } else if !arg.is_empty() {
                            cmd.arg(arg);
                        }
                    }
                    let envs = parse_state.get_envs();
                    let tupdir = parse_state.get_tup_dir_desc();
                    let dir = path_buffers
                        .get_root_dir()
                        .join(tupdir.get_path_ref().as_path().as_os_str());
                    if cmd.get_args().len() != 0 {
                        cmd.envs(envs).current_dir(dir.as_path());

                        debug!("running {:?} to fetch more rules", cmd);
                        let output = cmd
                            .stdout(Stdio::piped())
                            .stderr(Stdio::piped())
                            .output()
                            .unwrap_or_else(|_| {
                                panic!(
                                    "Failed to execute tup run {} in Tupfile : {:?} at pos:{:?}",
                                    script_args.cat().as_str(),
                                    dir.as_os_str(),
                                    loc
                                )
                            });
                        //println!("status:{}", output.status);
                        let contents = output.stdout;
                        if !output.stderr.is_empty() {
                            return Err(Error::RunError(
                                rule_ref,
                                std::str::from_utf8(output.stderr.as_slice())
                                    .unwrap()
                                    .to_string(),
                            ));
                        }
                        debug!(
                            "contents: \n {}",
                            String::from_utf8(contents.clone()).unwrap_or_default()
                        );
                        let err = String::from_utf8(output.stderr.clone()).unwrap_or_default();
                        if err.len() > 0 {
                            log::error!(
                            "error from executing run statement \n {} \n in Tupfile in dir: {:?} at pos:{:?}",
                            String::from_utf8(output.stderr).unwrap_or_default(),
                            dir.as_os_str(),
                            loc
                        );
                        }

                        let lstmts = parse_statements_until_eof(Span::new(contents.as_slice()))
                            .expect("failed to parse output of tup run");
                        let lstmts = lstmts
                            .subst(parse_state, path_searcher)
                            .expect("subst failure in generated tup rules");
                        return Ok(lstmts);
                    } else {
                        eprintln!("Warning tup run arguments are empty in Tupfile in dir:{:?} at pos:{:?}", dir, loc);
                    }
                }
            }
            _ => {}
        }
        Ok(vec![])
    }
}

impl ExpandRun for Vec<LocatedStatement> {
    /// discover more rules to add by running shell commands
    fn expand_run(
        &mut self,
        parse_state: &mut ParseState,
        path_searcher: &impl PathSearcher,
    ) -> Result<(), Error>
    where
        Self: Sized,
    {
        let mut from = 0 as usize;
        while let Some((i, ls)) = self[from..].iter().enumerate().find(|(_, ls)| ls.is_run()) {
            {
                let l = ls.get_statement().clone();
                let stmts = l.expand_run(parse_state, path_searcher, ls.get_loc())?;
                self.splice(i..i + 1, stmts);
                from = i + 1;
            }
        }
        self.retain(|x| !x.is_run());
        Ok(())
    }
}

/// trait that a method to run variable substitution on different parts of tupfile
pub(crate) trait Subst {
    fn subst(
        &self,
        parse_state: &mut ParseState,
        path_searcher: &impl PathSearcher,
    ) -> Result<Self, Err>
    where
        Self: Sized;
}

/// trait to substitute macro references in rules
pub(crate) trait ExpandMacro {
    /// check if path expr or a derived object has references to a macro
    fn has_ref(&self) -> bool;
    /// method to perform macro expansion based on currently stored macros in ParseState
    fn expand(&self, m: &mut ParseState) -> Result<Self, Err>
    where
        Self: Sized;
}

impl PathExpr {
    fn subst_ca(&self, m: &mut CallArgsMap) -> PathExpr {
        match self {
            DExpr(ref x) => x.subst_callargs(m),
            PathExpr::Quoted(ref x) => PathExpr::Quoted(x.subst_callargs(m)),
            PathExpr::Group(ref xs, ref ys) => {
                let newxs = xs.subst_callargs(m);
                let newys = ys.subst_callargs(m);
                debug!("grpdir:{:?} grpname:{:?}", newxs, newys);
                PathExpr::Group(newxs, newys)
            }
            _ => self.clone(),
        }
    }
    /// substitute a single pathexpr into an array of literal pathexpr
    /// SFINAE holds

    fn subst(&self, m: &mut ParseState, path_searcher: &impl PathSearcher) -> Vec<PathExpr> {
        match self {
            PathExpr::DollarExprs(ref x) => x.subst(m, path_searcher),
            PathExpr::AtExpr(ref x) => {
                if let Some(val) = m.conf_map.get(x.as_str()) {
                    intersperse_sp1(val.iter().cloned())
                } else {
                    log::warn!("atexpr {} not found", x);
                    vec![PathExpr::default()]
                }
            }

            PathExpr::Quoted(ref x) => {
                vec![PathExpr::Quoted(x.subst_pe(m, path_searcher))]
            }
            PathExpr::Group(ref xs, ref ys) => {
                let newxs = xs.subst_pe(m, path_searcher);
                let newys = ys.subst_pe(m, path_searcher);
                debug!("grpdir:{:?} grpname:{:?}", newxs, newys);
                vec![PathExpr::Group(newxs, newys)]
            }

            _ => vec![self.clone()],
        }
    }
}

pub(crate) fn to_regex(pat: &str) -> String {
    let mut regex_pattern = String::new();
    for c in pat.chars() {
        match c {
            '%' => regex_pattern.push_str("(.*)"),
            '?' => regex_pattern.push_str("(.)"),
            '.' => regex_pattern.push_str(r"\."),
            '$' => regex_pattern.push_str(r"\$"),
            '^' => regex_pattern.push_str(r"\^"),
            '+' => regex_pattern.push_str(r"\+"),
            '*' => regex_pattern.push_str(r"\*"),
            '\\' => regex_pattern.push_str(r"\\"),
            '{' => regex_pattern.push_str(r"\{"),
            '}' => regex_pattern.push_str(r"\}"),
            '(' => regex_pattern.push_str(r"\("),
            ')' => regex_pattern.push_str(r"\)"),
            _ => regex_pattern.push(c),
        }
    }
    regex_pattern.push('$');
    log::debug!("formed regex: {} from {}", regex_pattern, pat);
    regex_pattern
}

/// Discover paths that match glob pattern and have pattern in its contents
fn discover_paths_with_pattern(
    psx: &impl PathSearcher,
    path_buffers: &impl PathBuffers,
    glob: &[GlobPath],
    pattern: &str,
) -> Result<Vec<MatchingPath>, Error> {
    let paths = psx.discover_paths(path_buffers, glob)?;
    paths_with_pattern(psx.get_root(), &pattern, paths)
}

fn to_regex_replacement(pat: &str) -> String {
    let mut regex_pattern = String::new();
    let mut index = 1;
    for c in pat.chars() {
        match c {
            '%' => {
                regex_pattern.push_str(format!("${}", index).as_str());
                index += 1;
            }
            _ => regex_pattern.push(c),
        }
    }
    regex_pattern
}

impl DollarExprs {
    fn subst_callargs(&self, m: &mut CallArgsMap) -> PathExpr {
        match self {
            DollarExprs::DollarExpr(x) => {
                if let Some(val) = m.get(x.as_str()) {
                    PathExpr::from(val.clone())
                } else {
                    PathExpr::DollarExprs(DollarExprs::DollarExpr(x.clone()))
                }
            }
            DollarExprs::AddPrefix(ref vs, ref prefix) => {
                let vs = vs.subst_callargs(m);
                let prefix = prefix.subst_callargs(m);
                DExpr(DollarExprs::AddPrefix(vs, prefix))
            }
            DollarExprs::AddSuffix(ref vs, ref suffix) => {
                let vs = vs.subst_callargs(m);
                let suffix = suffix.subst_callargs(m);
                DExpr(DollarExprs::AddSuffix(vs, suffix))
            }
            DollarExprs::Filter(ref filter, ref vs) => {
                let vs = vs.subst_callargs(m);
                let filter = filter.subst_callargs(m);
                DExpr(DollarExprs::Filter(filter, vs))
            }
            DollarExprs::Subst(ref from, ref to, ref vs) => {
                let vs = vs.subst_callargs(m);
                let to = to.subst_callargs(m);
                let from = from.subst_callargs(m);
                DExpr(DollarExprs::Subst(from, to, vs))
            }
            DollarExprs::PatSubst(ref from, ref to, ref vs) => {
                let vs = vs.subst_callargs(m);
                let to = to.subst_callargs(m);
                let from = from.subst_callargs(m);
                DExpr(DollarExprs::PatSubst(from, to, vs))
            }
            DollarExprs::FilterOut(ref filter, ref vs) => {
                let vs = vs.subst_callargs(m);
                let filter = filter.subst_callargs(m);
                DExpr(DollarExprs::FilterOut(filter, vs))
            }
            DollarExprs::ForEach(s, ref vs, ref body) => {
                let vs = vs.subst_callargs(m);
                let body = body.subst_callargs(m);
                DExpr(DollarExprs::ForEach(s.clone(), vs, body))
            }
            DollarExprs::FindString(ref needle, ref text) => {
                let needle = needle.subst_callargs(m);
                let text = text.subst_callargs(m);
                DExpr(DollarExprs::FindString(needle, text))
            }
            DollarExprs::WildCard(ref glob) => {
                let glob = glob.subst_callargs(m);
                DExpr(DollarExprs::WildCard(glob))
            }
            DollarExprs::Strip(ref vs) => {
                let vs = vs.subst_callargs(m);
                DExpr(DollarExprs::Strip(vs))
            }
            DollarExprs::NotDir(ref vs) => {
                let vs = vs.subst_callargs(m);
                DExpr(DollarExprs::NotDir(vs))
            }
            DollarExprs::Dir(ref vs) => {
                let vs = vs.subst_callargs(m);
                DExpr(DollarExprs::Dir(vs))
            }
            DollarExprs::AbsPath(ref vs) => {
                let vs = vs.subst_callargs(m);
                DExpr(DollarExprs::AbsPath(vs))
            }
            DollarExprs::BaseName(ref vs) => {
                let vs = vs.subst_callargs(m);
                DExpr(DollarExprs::BaseName(vs))
            }
            DollarExprs::RealPath(ref vs) => {
                let vs = vs.subst_callargs(m);
                DExpr(DollarExprs::RealPath(vs))
            }
            DollarExprs::Word(ref n, ref vs) => {
                let vs = vs.subst_callargs(m);
                DExpr(DollarExprs::Word(*n, vs))
            }

            DollarExprs::FirstWord(ref vs) => {
                let vs = vs.subst_callargs(m);
                DExpr(DollarExprs::FirstWord(vs))
            }
            DollarExprs::If(ref cond, ref if_part, ref else_part) => {
                debug!(
                    "if cond:{:?} if_part:{:?} else_part:{:?}",
                    cond, if_part, else_part
                );
                let cond = cond.subst_callargs(m);
                let if_part = if_part.subst_callargs(m);
                let else_part = else_part.subst_callargs(m);
                debug!(
                    "if cond:{:?} if_part:{:?} else_part:{:?}",
                    cond, if_part, else_part
                );
                DExpr(DollarExprs::If(cond, if_part, else_part))
            }
            DollarExprs::Call(ref name, ref args) => {
                let args: Vec<_> = args.iter().map(|x| x.subst_callargs(m)).collect();
                DExpr(DollarExprs::Call(name.clone(), args))
            }
            DollarExprs::Shell(ref vs) => {
                let vs = vs.subst_callargs(m);
                DExpr(DollarExprs::Shell(vs))
            }

            DollarExprs::Eval(ref e) => {
                let vs = e.subst_callargs(m);
                DExpr(DollarExprs::Eval(vs))
            }
            DollarExprs::GrepFiles(ref pattern, ref glob) => {
                let pattern = pattern.subst_callargs(m);
                let glob = glob.subst_callargs(m);
                log::debug!("grepfiles pattern:{:?} glob:{:?}", pattern, glob,);
                DExpr(DollarExprs::GrepFiles(pattern, glob))
            }
            DollarExprs::Format(spec, body) => {
                let spec = spec.subst_callargs(m);
                let body = body.subst_callargs(m);
                DExpr(DollarExprs::Format(spec, body))
            }
            DollarExprs::StripPrefix(ref prefix, ref vs) => {
                let prefix = prefix.subst_callargs(m);
                let vs = vs.subst_callargs(m);
                DExpr(DollarExprs::StripPrefix(prefix, vs))
            }
            DollarExprs::Message(msg, l) => {
                let msg = msg.subst_callargs(m);
                DExpr(DollarExprs::Message(msg, l.clone()))
            }
        }
    }
    fn subst(&self, m: &mut ParseState, path_searcher: &impl PathSearcher) -> Vec<PathExpr> {
        match self {
            DollarExprs::DollarExpr(x) => {
                debug!("substituting {}", x.as_str());
                let res = m.extract_evaluated_var(x.as_str(), path_searcher);
                log::debug!("result of subst:{:?}", res);
                res
            }
            DollarExprs::Subst(ref from, ref to, ref vs) => {
                let vs = vs.subst_pe(m, path_searcher);
                let to = to.subst_pe(m, path_searcher);
                let to = to.cat();
                let from_ = from.subst_pe(m, path_searcher);
                let from = from_.cat();
                if from.len() > 0 {
                    let mut result = Vec::new();
                    debug!("subst from:{:?} to:{:?} in:{:?}", from, to, vs);
                    let inp = vs.as_slice();
                    inp.cat_ref()
                        .replace(&from, to.as_ref())
                        .split_whitespace()
                        .for_each(|x| {
                            result.push(PathExpr::from(x.to_owned()));
                            result.push(PathExpr::Sp1);
                        });
                    result.pop();
                    debug!("subst result:{:?}", result);
                    result
                } else {
                    vs
                }
            }

            DollarExprs::Format(ref spec, ref body) => {
                let mut body = body.subst_pe(m, path_searcher);
                body.cleanup();
                let body = trim_list(&body);
                debug!("formatting body:{:?}", body);
                let mut spec = spec.subst_pe(m, path_searcher);
                spec.cleanup();
                debug!("formatting spec:{:?}", spec);
                let mut result = Vec::new();
                for body_frag in body.split(PathExpr::is_ws) {
                    let body_frag_str = body_frag.cat_ref();
                    let inputs = InputsAsPaths::new_from_raw(
                        &m.get_tup_dir_desc(),
                        body_frag_str,
                        m.get_path_buffers().as_ref(),
                    );
                    if !inputs.is_empty() {
                        let v = spec.decode_input_place_holders(&inputs, &Default::default());
                        let vstr = v.as_slice();
                        let cow_vstr = vstr.cat_ref();
                        log::debug!("formatted string:{}", cow_vstr.as_ref());
                        let mut pelist = crate::parser::reparse_literal_as_input(cow_vstr.as_ref())
                            .unwrap_or_default();
                        pelist.cleanup();
                        log::debug!("formatted pelist:{:?}", pelist);
                        pelist.iter().for_each(|x| {
                            result.push(x.clone());
                            result.push(PathExpr::Sp1);
                        });
                    }
                }
                result.pop();
                result
            }
            DollarExprs::StripPrefix(ref prefix, ref body) => {
                let prefix = prefix.subst_pe(m, path_searcher);
                let body = body.subst_pe(m, path_searcher);
                let body = trim_list(&body);
                let prefix = trim_list(&prefix);
                let prefix = prefix.cat_ref();
                let mut result = Vec::new();
                for body_frag in body.split(PathExpr::is_ws) {
                    if body_frag.is_empty() {
                        log::debug!("empty body frag");
                        continue;
                    }
                    let mut body_frag_str = body_frag.first().unwrap().cat_ref();
                    for p in prefix.split(" ") {
                        if body_frag_str.as_ref().starts_with(p) {
                            let body_frag_str_ = body_frag_str.as_ref().strip_prefix(p).unwrap();
                            body_frag_str = body_frag_str_.to_string().into();
                            break;
                        }
                    }
                    if !body_frag_str.is_empty() {
                        result.push(PathExpr::from(body_frag_str.to_string()));
                    }
                    result.extend(body_frag[1..].iter().cloned());
                    result.push(PathExpr::Sp1);
                }
                result.pop();
                result.cleanup();
                result
            }
            DollarExprs::Filter(ref filter, ref body) => {
                let body = body.subst_pe(m, path_searcher);
                let filter: Vec<PathExpr> = filter.subst_pe(m, path_searcher);
                debug!("body:{:?} on which we filter:{:?}", body, filter);
                let filtered_tokens = body.split(PathExpr::is_ws).filter(|&target| {
                    if filter
                        .iter()
                        .any(|f| Self::pelist_check_is_match(target, f))
                    {
                        true
                    } else {
                        false
                    }
                });

                //.collect();
                let mut body = Vec::new();
                let mut first = true;
                for pe in filtered_tokens {
                    if !first {
                        body.push(PathExpr::Sp1);
                    } else {
                        first = false;
                    }
                    body.extend(pe.iter().cloned());
                }

                body.cleanup();
                debug!("Filtered body:{:?}", body);
                body
            }
            DollarExprs::FilterOut(ref filter, ref body) => {
                let body = body.subst_pe(m, path_searcher);
                let filter: Vec<PathExpr> = filter.subst_pe(m, path_searcher);
                debug!("body to filter-out:{:?} using pattern:{:?}", body, filter);
                let filtered_tokens = body.split(PathExpr::is_ws).filter(|&target| {
                    if !filter
                        .iter()
                        .any(|f| Self::pelist_check_is_match(target, f))
                    {
                        true
                    } else {
                        false
                    }
                });
                let mut first = true;
                let mut body = Vec::new();
                for pe in filtered_tokens {
                    if !first {
                        body.push(PathExpr::Sp1);
                    } else {
                        first = false;
                    }
                    body.extend(pe.iter().cloned());
                }

                body.cleanup();
                debug!("Filtered out body:{:?}", body);
                body
            }
            DollarExprs::ForEach(var, list, body) => {
                let mut list = list.subst_pe(m, path_searcher);
                if list.is_empty() {
                    log::warn!("Empty suffix values for {} in {:?}", var, m.get_cur_file());
                    return vec![];
                }
                //let body = body.subst_pe(m);
                let body_str = body.cat() + "\n";
                debug!("eval foreach body as statements:\n{:?}", body_str);

                let stmts = parse_statements_until_eof(Span::new(body_str.as_bytes()))
                    .expect("failed to parse body of for-each");
                debug!("stmts:{:?}", stmts);
                let mut vs_updated = Vec::new();
                for l in list.iter_mut() {
                    if let PathExpr::Literal(ref s) = l {
                        let oldval = m.expr_map.insert(var.clone(), vec![s.clone().into()]);

                        let mut vs = Self::subst_as_statements(
                            m,
                            path_searcher,
                            body_str.clone(),
                            stmts.clone(),
                        );
                        if !vs.is_empty() {
                            vs.push(PathExpr::NL);
                        }
                        debug!(
                            "substed list var {}={} in foreach body :\n{:?}",
                            var.as_str(),
                            s.as_str(),
                            vs
                        );
                        debug!("$seen:{}", m.expr_map.get("seen").unwrap_or(&vec![]).cat());
                        vs_updated.extend(vs);
                        if let Some(v) = oldval {
                            m.expr_map.insert(var.clone(), v);
                        } else {
                            m.expr_map.remove(var);
                        }
                    }
                }
                if vs_updated.ends_with(&[PathExpr::Sp1]) || vs_updated.ends_with(&[PathExpr::NL]) {
                    vs_updated.pop();
                }
                vs_updated.cleanup();
                vs_updated
            }

            DollarExprs::WildCard(glob) => {
                // wild cards are not expanded in the substitution phase

                let glob = trim_list(&glob);
                if glob.cat_ref().contains(" ") && !glob.contains(&PathExpr::Sp1) {
                    log::debug!("wildcard glob contains spaces and is not a list");
                }
                debug!("wildcard to expand:{:?}", glob.cat());
                let mut result = Vec::new();
                for glob in glob.split(PathExpr::is_ws) {
                    let gstr = m
                        .switch_tupfile_and_process(&m.get_tup_base_file(), |m| {
                            // Wildcards are special : set the current directory to the directory of the tupfile being processed and then evaluate the glob
                            debug!("^substing wildcard glob..");
                            Ok(glob.subst_pe(m, path_searcher).cat())
                        })
                        .unwrap();
                    debug!("wildcard glob expanded{:?}", gstr);
                    if !gstr.is_empty() {
                        let dir = m.get_tup_base_dir(); // wildcards are evaluated w.r.t tup base dir (tupfile being parsed as opposed to one of its includes)
                        debug!("relative to {:?}", dir.get_path_ref());
                        //let ldirs = m.load_dirs.clone();
                        let r = m.with_path_buffers_do(|path_buffers_mut| {
                            let p = path_buffers_mut
                                .add_path_from(&dir, gstr.as_str())
                                .unwrap_or_else(|e| {
                                    panic!("failed to add path from {:?} due to {}", dir, e);
                                });
                            let glob_path = GlobPath::build_from(&dir, &p)
                                .expect("Failed to build a glob path");
                            //let glob_paths = vec![glob_path];
                            let glob_path_desc = glob_path.get_glob_path_desc();
                            let rel_path = RelativeDirEntry::new(dir.clone(), glob_path_desc);
                            debug!("rel_path:{:?}", rel_path);
                            /* wildcard in makefile does not look for files in vpath or other search dirs unless.
                            for dir_desc in ldirs.iter() {
                                let glob_path =
                                    GlobPath::build_from_relative_desc(dir_desc, &rel_path)
                                        .expect("Failed to build a glob path");
                                debug!("looking for path in {:?}", glob_path);
                                glob_paths.push(glob_path); // other directories in which to look for paths
                            }*/
                            let paths = path_searcher
                                .discover_paths(path_buffers_mut, std::slice::from_ref(&glob_path))
                                .unwrap_or_else(|e| {
                                    log::warn!("Error while globbing {:?}: {}", glob_path, e);
                                    vec![]
                                });
                            let res = vec![];
                            let mut res = paths.into_iter().fold(res, |mut acc, x| {
                                acc.push(PathExpr::DeGlob(x));
                                acc.push(PathExpr::Sp1);
                                acc
                            });
                            res.pop();
                            res
                        });
                        result.extend(r);
                        result.push(PathExpr::Sp1);
                    }
                }
                result.pop();
                result
            }
            DollarExprs::Strip(ref vs) => {
                // strip trailing and leading spaces
                debug!("stripping {:?} of leading and trailing ws", vs);
                let vs = vs.subst_pe(m, path_searcher);
                let vs_str = vs.cat();
                debug!("stripped to {:?}", vs_str.trim());
                vec![vs_str.trim().to_owned().into()]
            }

            DollarExprs::FindString(ref needle, ref text) => {
                let vs = text.subst_pe(m, path_searcher);
                let needle = needle
                    .subst_pe(m, path_searcher)
                    .drain(..)
                    .filter(PathExpr::is_literal)
                    .collect::<Vec<_>>();
                if needle.is_empty() {
                    return vec![];
                }
                let maybe_has = vs.iter().find(|x| {
                    let s = x.cat_ref();
                    if !s.is_empty() {
                        for f in needle.iter() {
                            if let PathExpr::Literal(ref f) = f {
                                if s.contains(f.as_str()) {
                                    return true;
                                }
                            }
                        }
                    }
                    false
                });
                if maybe_has.is_some() {
                    needle
                } else {
                    vec![]
                }
            }
            DollarExprs::RealPath(ref vs) => {
                let vs = vs.subst_pe(m, path_searcher);
                let tup_dir = m.get_tup_dir_desc();
                vs.split(PathExpr::is_ws)
                    .filter_map(|v| {
                        let s = v.cat();
                        if !s.is_empty() {
                            let p = Path::new(s.as_str());
                            let real_path = tup_dir.join(p).unwrap_or_else(|e| {
                                panic!("failed to get real path from path: {:?} due to {}", p, e);
                            });
                            let x = real_path.get_path_ref().to_string().into();
                            Some(x)
                        } else {
                            None
                        }
                    })
                    .collect()
            }
            DollarExprs::BaseName(ref vs) => {
                let vs = vs.subst_pe(m, path_searcher);
                vs.split(PathExpr::is_ws)
                    .filter_map(|v| {
                        let s = cat_literals(v);
                        if !s.is_empty() {
                            let p = Path::new(s.as_str());
                            let base_name = p.file_stem().unwrap_or_else(|| {
                                panic!("failed to get base name from path: {:?}", p)
                            });
                            Some(base_name.to_string_lossy().to_string().into())
                        } else {
                            None
                        }
                    })
                    .collect()
            }
            DollarExprs::AbsPath(ref vs) => {
                DollarExprs::RealPath(vs.clone()).subst(m, path_searcher)
            }
            DollarExprs::NotDir(ref vs) => {
                debug!("evaluating not dir on {:?}", vs);
                let vs = vs.subst_pe(m, path_searcher);
                let res = vs
                    .split(PathExpr::is_ws)
                    .filter_map(|v| {
                        let s = cat_literals(v);
                        if !s.is_empty() {
                            let p = Path::new(s.as_str());
                            let file_name = p.file_name().unwrap_or_else(|| {
                                panic!("failed to get base name from path: {:?}", p)
                            });
                            Some(file_name.to_string_lossy().to_string().into())
                        } else {
                            None
                        }
                    })
                    .collect();
                debug!("result of notdir:{:?}", res);
                res
            }
            DollarExprs::Dir(ref vs) => {
                let vs = vs.subst_pe(m, path_searcher);
                fn has_trailing_slash(path: &Path) -> bool {
                    path.as_os_str()
                        .to_str()
                        .map_or(false, |s| s.ends_with('/'))
                }
                let vs = vs
                    .split(PathExpr::is_ws)
                    .filter_map(|v| {
                        let s = cat_literals(v);
                        if !s.is_empty() {
                            let p = Path::new(s.as_str());
                            Some(if has_trailing_slash(p) {
                                let mut dirpart = p.to_string_lossy().to_string();
                                dirpart.push('_');
                                PathExpr::from(get_parent_with_fsep(dirpart.as_str()).to_string())
                            } else {
                                PathExpr::from(get_parent_with_fsep(p).to_string())
                            })
                        } else {
                            None
                        }
                    })
                    .collect();
                vs
            }

            DollarExprs::FirstWord(ref vs) => {
                let vs = vs.subst_pe(m, path_searcher);
                let next = |x: &[PathExpr]| -> Vec<PathExpr> {
                    let mut words: Vec<_> = words_from_pelist(x);
                    // find the index-th word in s
                    let word: Vec<PathExpr> = words
                        .drain(..)
                        .nth(0)
                        .map(|x| vec![x.into()])
                        .unwrap_or_else(|| {
                            log::warn!("failed to get first word from input: {:?}", vs.cat());
                            vec![]
                        });
                    word
                };
                next(&vs)
            }
            DollarExprs::Word(index, ref vs) => {
                let vs = vs.subst_pe(m, path_searcher);
                if *index < 0 {
                    panic!("negative index in word");
                }
                let next = |x: &[PathExpr]| -> Vec<PathExpr> {
                    let words: Vec<_> = words_from_pelist(x);
                    let word = words
                        .iter()
                        .nth(*index as usize)
                        .map(|x| x.to_owned())
                        .unwrap_or_else(|| {
                            log::warn!(
                                "failed to get {}-th word from path: {:?}",
                                index,
                                words.join(" ")
                            );
                            "".to_string()
                        });
                    if word.is_empty() {
                        vec![]
                    } else {
                        vec![PathExpr::from(word)]
                    }
                };
                next(&vs)
            }

            DollarExprs::AddPrefix(ref prefix, ref vs) => {
                let vs = vs.subst_pe(m, path_searcher);
                let mut prefix = prefix.subst_pe(m, path_searcher);
                prefix.cleanup();
                debug!("addprefix:{:?} on {:?}", prefix, vs);
                let next = |x: &[PathExpr]| -> Vec<PathExpr> {
                    let mut words: Vec<_> = words_from_pelist(x);
                    words
                        .drain(..)
                        .filter_map(|s| {
                            if !s.is_empty() {
                                let mut prefixed = prefix.clone();
                                prefixed.push(s.into());
                                Some(prefixed)
                            } else {
                                None
                            }
                        })
                        .collect::<Vec<_>>()
                        .join(&PathExpr::Sp1)
                };
                next(&vs)
            }
            DollarExprs::AddSuffix(ref suffix, ref vs) => {
                let vs = vs.subst_pe(m, path_searcher);
                let mut sfx = suffix.subst_pe(m, path_searcher);
                sfx.cleanup();
                let next = |x: &[PathExpr]| -> Vec<PathExpr> {
                    let mut words: Vec<_> = words_from_pelist(x);
                    words
                        .drain(..)
                        .filter_map(|s| {
                            if !s.is_empty() {
                                let suffixed: Vec<_> = std::iter::once(PathExpr::from(s))
                                    .chain(sfx.iter().cloned())
                                    .collect();
                                Some(suffixed)
                            } else {
                                None
                            }
                        })
                        .collect::<Vec<_>>()
                        .join(&PathExpr::Sp1)
                };
                next(&vs)
            }
            DollarExprs::PatSubst(pat, rep, target) => {
                let pat_pe = pat.subst_pe(m, path_searcher);
                let rep_pe = rep.subst_pe(m, path_searcher);
                let target = target.subst_pe(m, path_searcher);
                let words = words_from_pelist(target.as_slice());
                let pat: String = to_regex(words_from_pelist(pat_pe.as_slice()).join(" ").as_str());
                let pat_regex = regex::Regex::new(pat.as_str()).unwrap();
                let rep: String =
                    to_regex_replacement(words_from_pelist(rep_pe.as_slice()).join(" ").as_str());
                debug!("pattern:{}, and its replacement:{}", pat, rep);
                let mut ts: Vec<String> = Vec::new();
                for word in words {
                    if pat_regex.is_match(word.as_str()) {
                        let replacement = pat_regex.replace(word.as_str(), rep.as_str());
                        if !replacement.is_empty() {
                            ts.push(replacement.as_ref().to_owned());
                        } else {
                            ts.push(word);
                        }
                    } else {
                        ts.push(word);
                    }
                }
                debug!("input with pattern replaced:{:?}", ts);
                intersperse_sp1(ts.into_iter())
            }
            DollarExprs::Call(ref name, args) => {
                let args: Vec<_> = args.iter().map(|x| x.subst_pe(m, path_searcher)).collect();

                let name = name.subst_pe(m, path_searcher);
                let func_name: String = name
                    .cat()
                    .chars()
                    .take_while(|x| !x.is_whitespace())
                    .collect();
                debug!("calling function: {}", func_name);
                if let Some(body) = m.func_map.get(&func_name) {
                    debug!("wht args: {:?}", args);
                    debug!("body: {:?}", body);

                    let mut call_args_map = CallArgsMap::new();
                    let mut prefixed_args = Vec::new();
                    for (i, mut arg) in args.iter().cloned().enumerate() {
                        let arg_name = format!("{}", i + 1);
                        arg.insert(0, PathExpr::from(format!("__arg{}__=", i + 1)));
                        prefixed_args.extend(arg);
                        prefixed_args.push(PathExpr::NL);
                        call_args_map.insert(arg_name, format!("$(__arg{}__)", i + 1))
                    }

                    let lines = body;
                    debug!("call lines: {:?}", lines);
                    let substed_lines: Vec<_> = prefixed_args
                        .iter()
                        .chain(lines.into_iter())
                        .map(|l| l.subst_ca(&mut call_args_map))
                        .collect();

                    substed_lines
                } else {
                    eprintln!("function {} not found", func_name);
                    vec![]
                }
            }

            DollarExprs::If(cond, then_part, else_part) => {
                let cond = cond.subst_pe(m, path_searcher);
                let cond = cond.cat();
                if cond.is_empty() {
                    let else_part_str = else_part.cat() + "\n";
                    let else_part = parse_statements_until_eof(Span::new(else_part_str.as_bytes()))
                        .unwrap_or_else(|e| {
                            panic!(
                                "failed to parse else part of if statement: {:?} with error: {}",
                                else_part, e
                            )
                        });
                    Self::subst_as_statements(m, path_searcher, else_part_str, else_part)
                } else {
                    let then_part_str = then_part.cat() + "\n";
                    let then_part = parse_statements_until_eof(Span::new(then_part_str.as_bytes()))
                        .unwrap_or_else(|e| {
                            panic!(
                                "failed to parse then part of if statement: {:?} with error: {}",
                                then_part_str.as_str(),
                                e
                            )
                        });
                    Self::subst_as_statements(m, path_searcher, then_part_str, then_part)
                }
            }
            DollarExprs::Eval(pes) => {
                debug!("eval before subst: {:?}", pes);
                // let subst_val = pes.subst_pe(m, path_searcher);
                if m.parse_context == Expression {
                    let mut val = pes.cat();
                    val.push('\n');
                    debug!("evaluating {}", val);
                    let stmts = parse_statements_until_eof(Span::new(val.as_bytes()))
                        .unwrap_or_else(|e| {
                            panic!(
                                "failed to parse eval body statements statement: {:?} with error: {}",
                                val.as_str(), e
                            )
                        });
                    Self::subst_as_statements(m, path_searcher, val, stmts)
                } else {
                    pes.subst_pe(m, path_searcher)
                }
            }
            DollarExprs::Shell(cmd) => {
                let subst_val = cmd.subst_pe(m, path_searcher);
                let args = subst_val.cat();
                eprintln!("Running shell command:{}", args);
                eprintln!(
                    "consider rewriting in a configuration step and access it here as an env"
                );
                // run sh -c over the args and process stdout
                let child = shell(args).stdout(Stdio::piped()).spawn();
                let outstr = {
                    child
                        .map_err(|e| {
                            Error::new_path_search_error(format!("failed to spawn shell: {}", e))
                        })
                        .and_then(|ch| {
                            ch.wait_with_output()
                                .map_err(|e| {
                                    Error::new_path_search_error(format!(
                                        "failed to get output :{}",
                                        e
                                    ))
                                })
                                .and_then(|output| -> Result<String, Error> {
                                    Ok(std::str::from_utf8(output.stdout.as_bytes())
                                        .unwrap_or("")
                                        .to_owned())
                                })
                        })
                        .unwrap_or(String::new())
                };
                debug!("shell evaluated to {}", outstr);

                vec![PathExpr::from(outstr)]
            }
            DollarExprs::GrepFiles(pattern, glob_pattern) => {
                // grep for pattern in files matching glob_pattern in dirs
                let pattern = pattern.subst_pe(m, path_searcher);
                let glob_pattern = glob_pattern.subst_pe(m, path_searcher);
                let pattern = pattern.cat();
                let glob_pattern = glob_pattern.cat();
                let mut glob_paths = Vec::new();
                let tup_cwd = m.get_tup_dir_desc();
                let paths = m.with_path_buffers_do(|path_buffers_mut| {
                    let dirid = tup_cwd;
                    let p = m
                        .path_buffers
                        .add_path_from(&dirid, glob_pattern.as_str())
                        .unwrap_or_else(|e| {
                            panic!("failed to add path from {:?} due to {}", dirid, e);
                        });
                    let glob_path = GlobPath::build_from(&dirid, &p).expect(&*format!(
                        "Failed to build a glob path:{}",
                        glob_pattern.as_str()
                    ));
                    glob_paths.push(glob_path); // other directories in which to look for paths

                    let paths = discover_paths_with_pattern(
                        path_searcher,
                        path_buffers_mut,
                        glob_paths.as_slice(),
                        pattern.as_str(),
                    )
                    .unwrap_or_else(|e| {
                        log::warn!("Error while globbing {:?}: {}", glob_paths, e);
                        vec![]
                    });
                    paths
                });
                paths
                    .into_iter()
                    .map(|x| PathExpr::DeGlob(x))
                    .collect::<Vec<_>>()
            }
            DollarExprs::Message(msg, l) => {
                let msg = msg.subst_pe(m, path_searcher);
                let msg = msg.cat();
                match l {
                    Level::Warning => log::warn!("{}", msg),
                    Level::Error => {
                        panic!("{}", msg)
                    }
                    Level::Info => log::info!("{}", msg),
                }
                vec![]
            }
        }
    }

    fn pelist_check_is_match(target: &[PathExpr], pattern: &PathExpr) -> bool {
        let target_as_str = target.cat_ref();
        debug!(
            "finding a match for pattern:{:?} in target:{:?}",
            pattern, target_as_str
        );
        Self::check_is_match(&target_as_str, pattern)
    }
    fn check_is_match(target_tok: &Cow<str>, pattern: &PathExpr) -> bool {
        if let PathExpr::Literal(ref f) = pattern {
            let pat = f.as_str();
            if pat.contains("%") {
                let pat_str: String = to_regex(pat);
                debug!(
                    "checking if glob: {:?} not matches target: {:?}",
                    pat_str, target_tok
                );
                if regex::Regex::new(pat_str.as_str())
                    .unwrap()
                    .is_match(target_tok.as_ref())
                {
                    debug!(
                        "found a match for {} in {:?}",
                        pat_str.as_str(),
                        target_tok.as_ref()
                    );
                    return true;
                }
            } else if target_tok.contains(pat) {
                debug!(
                    "found a match for pattern:{:?} in target:{:?}",
                    pat, target_tok
                );
                return true;
            }
        }
        false
    }

    fn subst_as_statements(
        m: &mut ParseState,
        path_searcher: &impl PathSearcher,
        val: String,
        stmts_: Vec<LocatedStatement>,
    ) -> Vec<PathExpr> {
        debug!("eval stmts before subst: {:?} with val:{}", stmts_, val);
        let mut stmts = stmts_.subst(m, path_searcher).unwrap_or_else(|e| {
            panic!(
                "failed to subst eval body statements statement: {:?} with error: {}",
                val.as_str(),
                e
            )
        });
        debug!("eval stmts after subst: {:?}", stmts);
        stmts.cleanup();

        // let v: Vec<_> = stmts.iter().map(|x| x.cat()).collect();
        //let str = v.join(" ");
        let mut result = Vec::new();
        for stmt in stmts.iter() {
            let pelist = match stmt.get_statement() {
                Statement::EvalBlock(eb) => eb.clone(),
                _ => to_pelist(stmt.cat()),
            };
            result.extend(pelist);
        }
        debug!("eval returned {}", result.as_slice().cat_ref());
        result
    }
}

fn trim_list(p0: &Vec<PathExpr>) -> &[PathExpr] {
    match p0.as_slice() {
        &[PathExpr::Sp1, ref elt @ ..] => elt,
        &[PathExpr::NL, ref elt @ ..] => elt,
        &[ref elt @ .., PathExpr::Sp1] => elt,
        &[ref elt @ .., PathExpr::NL] => elt,
        _ => p0.as_slice(),
    }
}

/// creates [PathExpr] array separated by PathExpr::Sp1
pub(crate) fn intersperse_sp1<I>(val: I) -> Vec<PathExpr>
where
    I: Iterator<Item = String>,
{
    let mut vs: Vec<PathExpr> = Vec::new();
    let mut lines = Vec::new();
    for pe in val {
        for line in pe.split(|c| c == '\n' || c == '\r') {
            lines.push(PathExpr::from(line.to_owned()));
            lines.push(PathExpr::NL);
        }
        lines.pop();
        vs.extend(lines.drain(..));
        vs.push(PathExpr::Sp1);
    }
    vs.pop();
    vs
}

pub(crate) fn to_pelist(s: String) -> Vec<PathExpr> {
    let pe_list = intersperse_sp1(
        s.split(|c: char| c == ' ' || c == '\t')
            .map(ToOwned::to_owned),
    );
    debug!("to_pelist: {:?}", pe_list);
    pe_list
}

trait SubstPEs {
    type Output;
    fn subst_pe(&self, m: &mut ParseState, path_searcher: &impl PathSearcher) -> Self::Output
    where
        Self: Sized;
}

trait CallArgs {
    type Output;
    fn subst_callargs(&self, m: &mut CallArgsMap) -> <Self as CallArgs>::Output
    where
        Self: Sized;
}

impl SubstPEs for Vec<PathExpr> {
    type Output = Self;
    /// call subst on each path expr and flatten/cleanup the output.
    fn subst_pe(&self, m: &mut ParseState, path_searcher: &impl PathSearcher) -> Self {
        let mut newpe: Vec<_> = self
            .iter()
            .flat_map(|x| x.subst(m, path_searcher))
            .collect();
        newpe.cleanup();
        newpe
    }
}
impl SubstPEs for &[PathExpr] {
    type Output = Vec<PathExpr>;
    /// call subst on each path expr and flatten/cleanup the output.
    fn subst_pe(&self, m: &mut ParseState, path_searcher: &impl PathSearcher) -> Self::Output {
        let mut newpe: Vec<_> = self
            .iter()
            .flat_map(|x| x.subst(m, path_searcher))
            .collect();
        newpe.cleanup();
        newpe
    }
}

impl CallArgs for Vec<PathExpr> {
    /// call subst on each path expr and flatten/cleanup the output.
    type Output = Vec<PathExpr>;
    fn subst_callargs(&self, m: &mut CallArgsMap) -> Self {
        let mut newpe: Vec<_> = self
            .iter()
            .map(|x| x.subst_ca(m))
            .filter(|x| !x.is_empty())
            .collect();
        newpe.cleanup();
        newpe
    }
}

impl SubstPEs for Source {
    type Output = Self;

    /// call subst on each path expr and flatten/cleanup the input.
    fn subst_pe(&self, m: &mut ParseState, path_searcher: &impl PathSearcher) -> Self {
        Source {
            primary: self.primary.subst_pe(m, path_searcher),
            for_each: self.for_each,
            secondary: self.secondary.subst_pe(m, path_searcher),
        }
    }
}

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
        if !o.primary.is_empty() {
            self.primary.push(PathExpr::Sp1);
            self.primary.append(&mut o.primary);
        }
        self.primary.cleanup();

        self.secondary.cleanup();
        if !o.secondary.is_empty() {
            self.secondary.push(PathExpr::Sp1);
            self.secondary.append(&mut o.secondary);
        }

        self.group = self.group.clone().or(o.group);
        self.bin = self.bin.clone().or(o.bin);
    }
}

/// substitute only first pathexpr using ParseState
fn takefirst(
    o: Option<&PathExpr>,
    m: &mut ParseState,
    path_searcher: &impl PathSearcher,
) -> Result<Option<PathExpr>, Err> {
    if let Some(pe) = o {
        Ok(pe.subst(m, path_searcher).first().cloned())
    } else {
        Ok(None)
    }
}

impl SubstPEs for Target {
    type Output = Self;
    /// run variable substitution on `Target'
    fn subst_pe(&self, m: &mut ParseState, path_searcher: &impl PathSearcher) -> Self {
        let primary = self.primary.subst_pe(m, path_searcher);
        let secondary = self.secondary.subst_pe(m, path_searcher);
        debug!(
            "subst_pe: primary: {:?}, secondary: {:?}",
            primary, secondary
        );
        Target {
            primary,
            secondary,
            group: takefirst(self.group.as_ref(), m, path_searcher).unwrap_or_default(),
            bin: takefirst(self.bin.as_ref(), m, path_searcher).unwrap_or_default(),
        }
    }
}
impl SubstPEs for RuleFormula {
    type Output = Self;
    /// run variable substitution on `RuleFormula'
    fn subst_pe(&self, m: &mut ParseState, path_searcher: &impl PathSearcher) -> Self {
        RuleFormula {
            description: self.description.clone(), // todo : convert to rval and subst here as well,
            formula: self.formula.subst_pe(m, path_searcher),
        }
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
    /// For a well-formed tupfile, ParseState is expected to have been populated with macro assignment
    fn expand(&self, m: &mut ParseState) -> Result<Self, Err> {
        let mut source = self.source.clone();
        let mut target = self.target.clone();
        let mut desc = self.rule_formula.get_description().cloned();
        let pos = self.pos;
        let mut formulae = Vec::new();
        for pathexpr in self.rule_formula.formula.iter() {
            match pathexpr {
                &PathExpr::MacroRef(ref name) => {
                    debug!(
                        "Expanding macro name:{}\n in rule: {:?}",
                        name, self.rule_formula
                    );
                    if let Some(explink) = m.rule_map.get(name.as_str()) {
                        source += explink.source.clone();
                        target += explink.target.clone();
                        if explink.rule_formula.get_description().is_some() {
                            desc = explink.rule_formula.description.clone();
                        }
                        let mut r = explink.rule_formula.formula.clone();
                        r.cleanup();
                        formulae.append(&mut r);
                    } else {
                        return Err(Err::UnknownMacroRef(
                            name.clone(),
                            TupLoc::new(m.get_cur_file_desc(), &pos),
                        ));
                    }
                }
                _ => formulae.push(pathexpr.clone()),
            }
        }
        Ok(Link {
            source,
            target,
            rule_formula: RuleFormula::new_from_parts(desc, formulae),
            pos,
        })
    }
}
/// parent folder path for a given tupfile
pub fn get_parent(cur_file: &Path) -> Cow<Path> {
    if cur_file.eq(OsStr::new("/"))
        || cur_file.eq(OsStr::new("."))
        || cur_file.as_os_str().is_empty()
    {
        return Cow::Owned(PathBuf::from("."));
    }
    let p = cur_file
        .parent()
        .unwrap_or_else(|| panic!("unable to find parent folder for tup file:{:?}", cur_file));
    if p.as_os_str().is_empty() {
        Cow::Owned(PathBuf::from("."))
    } else {
        Cow::Borrowed(p)
    }
}

/// parent folder path as a string slice
pub fn get_parent_with_fsep<P: AsRef<Path>>(cur_file: P) -> NormalPath {
    NormalPath::new_from_cow_path(cur_file.as_ref().parent().unwrap().into())
}

/// strings in pathexpr that are space separated
fn tovecstring(right: &[PathExpr]) -> Vec<String> {
    right
        .split(|x| matches!(x, &PathExpr::Sp1 | &PathExpr::NL))
        .map(|x| x.to_vec().cat())
        .collect()
}

/// load config vars from tup.config file
/// Also sets TUP_PLATFORM and TUP_ARCH if they are not set in the config file
/// File format is similar to tupfile, but it may not exist
pub fn load_conf_vars(conf_file: PathBuf) -> Result<HashMap<String, Vec<String>>, Error> {
    let mut conf_vars = HashMap::new();
    if conf_file.is_file() {
        for LocatedStatement { statement, .. } in parse_tupfile(conf_file.as_path())?.iter() {
            if let Statement::AssignExpr { left, right, .. } = statement {
                if let Some(rest) = left.name.strip_prefix("CONFIG_") {
                    log::warn!("conf var:{} = {}", rest, right.cat());
                    conf_vars.insert(rest.to_string(), tovecstring(right.as_slice()));
                } else {
                    log::warn!("conf var:{} = {}", left.name, right.cat());
                    conf_vars.insert(left.name.clone(), tovecstring(right.as_slice()));
                }
            } else if let Statement::Import(e, v) = statement {
                // import the environment variable `e` into the tupfile as `e` with the value `v` if environment variable `e` is not set.
                // this is not used as  env var but as a variable .

                if let Ok(val) = std::env::var(e) {
                    conf_vars.insert(e.clone(), vec![val]);
                } else if let Some(val) = v.clone() {
                    if !val.is_empty() {
                        conf_vars.insert(e.clone(), vec![val]);
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
        conf_vars.insert("TUP_PLATFORM".to_owned(), vec![get_platform().into()]);
    }
    if !conf_vars.contains_key("TUP_ARCH") {
        conf_vars.insert("TUP_ARCH".to_owned(), vec![get_arch().into()]);
    }
    if !conf_vars.contains_key("TUP_UNAME") {
        conf_vars.insert("TUP_UNAME".to_owned(), vec![get_uname().into()]);
    }

    Ok(conf_vars)
}

/// load the conf variables in tup.config in the root directory
/// TUP_PLATFORM and TUP_ARCH are automatically assigned based on how this program is built
pub fn load_conf_vars_relative_to(root: &Path) -> Result<HashMap<String, Vec<String>>, Error> {
    debug!("attempting loading conf vars from tup.config at {:?}", root);
    let conf_file = root.join("tup.config");
    //debug!("loading conf vars from tup.config at {:?}", root);
    let conf_vars = load_conf_vars(conf_file)?;
    Ok(conf_vars)
}

impl SubstPEs for Link {
    type Output = Self;
    /// recursively substitute variables inside a link
    fn subst_pe(&self, m: &mut ParseState, path_searcher: &impl PathSearcher) -> Self {
        Link {
            source: self.source.subst_pe(m, path_searcher),
            target: self.target.subst_pe(m, path_searcher),
            rule_formula: self.rule_formula.subst_pe(m, path_searcher),
            pos: self.pos,
        }
    }
}

impl SubstPEs for EqCond {
    type Output = Self;
    fn subst_pe(&self, m: &mut ParseState, path_searcher: &impl PathSearcher) -> Self
    where
        Self: Sized,
    {
        EqCond {
            lhs: self.lhs.subst_pe(m, path_searcher),
            rhs: self.rhs.subst_pe(m, path_searcher),
            not_cond: self.not_cond,
        }
    }
}

impl SubstPEs for Condition {
    type Output = Self;
    fn subst_pe(&self, m: &mut ParseState, path_searcher: &impl PathSearcher) -> Self
    where
        Self: Sized,
    {
        match self {
            Condition::EqCond(ref eq) => Condition::EqCond(eq.subst_pe(m, path_searcher)),
            _ => self.clone(),
        }
    }
}
impl Subst for CondThenStatements {
    fn subst(
        &self,
        parse_state: &mut ParseState,
        path_searcher: &impl PathSearcher,
    ) -> Result<Self, Err>
    where
        Self: Sized,
    {
        Ok(CondThenStatements {
            cond: self.cond.subst_pe(parse_state, path_searcher),
            then_statements: self.then_statements.subst(parse_state, path_searcher)?,
        })
    }
}

impl LocatedStatement {
    pub(crate) fn subst(
        &self,
        parse_state: &mut ParseState,
        path_searcher: &impl PathSearcher,
    ) -> Result<Vec<LocatedStatement>, Error> {
        let mut newstats = Vec::new();
        let loc = self.get_loc();
        debug!("subst statement: {:?}", &self);
        match self.get_statement() {
            Statement::AssignExpr {
                left,
                right,
                assignment_type,
            } => {
                Self::subst_assign(
                    parse_state,
                    path_searcher,
                    left,
                    right.clone(),
                    assignment_type,
                );
            }

            Statement::IfElseEndIf {
                then_elif_statements,
                else_statements,
            } => {
                Self::subst_if_else_endif(
                    parse_state,
                    path_searcher,
                    &mut newstats,
                    then_elif_statements,
                    else_statements,
                )?;
            }

            Statement::IncludeRules => {
                Self::subst_include_rules(parse_state, path_searcher, &mut newstats, loc)?;
            }
            Statement::Include(s) => {
                self.subst_include(parse_state, path_searcher, &mut newstats, s)?;
            }
            Statement::Rule(link, _, _) => {
                Self::subst_rule(parse_state, path_searcher, &mut newstats, loc, link)?;
            }
            // dont subst inside a macro assignment
            // just update the rule_map
            Statement::MacroRule(name, link) => {
                let l = link.clone();
                parse_state.rule_map.insert(name.clone(), l);
            }
            Statement::Message(v, level) => {
                let v = v.subst_pe(parse_state, path_searcher);
                eprintln!("{}\n", &v.cat().as_str());
                if level == &Level::Error {
                    return Err(Error::UserError(
                        v.cat().as_str().to_string(),
                        TupLoc::new(&parse_state.cur_file_desc, loc),
                    ));
                }
            }
            Statement::Preload(paths) => {
                Self::add_load_dirs(parse_state, path_searcher, loc, paths)?;
            }
            Statement::Export(var) => {
                let id =
                    parse_state.with_path_buffers_do(|bo| bo.add_env_var(Env::new(var.clone())));
                // we add this even if env var does not have a value yet.
                // this is to make sure the tup file is reparsed when the env var is set.
                parse_state.add_env(&id);
            }
            Statement::Import(var, envval) => {
                if let Some(val) = envval.clone().or_else(|| std::env::var(var).ok()) {
                    parse_state.with_path_buffers_do(|bo| {
                        bo.add_env_var(Env::from(var.clone(), val));
                    })
                }
                newstats.push(self.clone());
            }
            Statement::Run(r) => {
                newstats.push(LocatedStatement::new(
                    Statement::Run(r.subst_pe(parse_state, path_searcher)),
                    *loc,
                ));
            }
            Statement::Comment => {
                // ignore
            }
            Statement::Define(name, val) => {
                log::debug!("adding {} to func_map", name);
                parse_state.func_map.insert(name.to_string(), val.clone());
            }
            Statement::EvalBlock(body) => {
                self.subst_eval_block(parse_state, path_searcher, &mut newstats, body)?;
            }
            Statement::Task(t) => {
                Self::subst_task(parse_state, path_searcher, loc, t);
            }
        }
        Ok(newstats)
    }

    fn subst_if_else_endif(
        parse_state: &mut ParseState,
        path_searcher: &impl PathSearcher,
        newstats: &mut Vec<LocatedStatement>,
        then_elif_statements: &Vec<CondThenStatements>,
        else_statements: &Vec<LocatedStatement>,
    ) -> Result<(), Error> {
        let new_then_elif_statements: ControlFlow<_> =
            then_elif_statements.iter().try_for_each(|x| {
                let e = x.cond.subst_pe(parse_state, path_searcher);
                debug!("testing {:?}", e);
                if e.verify(parse_state) {
                    debug!("condition satisfied");
                    return ControlFlow::Break(x.then_statements.subst(parse_state, path_searcher));
                } else {
                    debug!("trying alternative branches");
                    Continue(())
                }
            });
        match new_then_elif_statements {
            ControlFlow::Break(Ok(mut new_then_elif_statements)) => {
                newstats.append(&mut new_then_elif_statements);
            }
            ControlFlow::Break(Err(e)) => return Err(e),
            _ => {
                let mut else_s = else_statements.subst(parse_state, path_searcher)?;
                newstats.append(&mut else_s);
            }
        }
        Ok(())
    }

    fn subst_rule(
        parse_state: &mut ParseState,
        path_searcher: &impl PathSearcher,
        newstats: &mut Vec<LocatedStatement>,
        loc: &Loc,
        link: &Link,
    ) -> Result<(), Error> {
        let mut l = link.clone();
        while l.has_ref() {
            l = l.expand(parse_state)?; // expand all nested macro refs
        }
        let env_desc = parse_state.cur_env_desc.clone();
        newstats.push(LocatedStatement::new(
            Statement::Rule(
                l.subst_pe(parse_state, path_searcher),
                env_desc,
                parse_state.load_dirs.clone(),
            ),
            *loc,
        ));
        Ok(())
    }

    fn subst_task(
        parse_state: &mut ParseState,
        path_searcher: &impl PathSearcher,
        loc: &Loc,
        t: &TaskDetail,
    ) {
        let name = t.get_target();
        let deps = t.get_deps();
        let recipe = t.get_body();
        let search_dirs = t.get_search_dirs();
        debug!("adding task:{} with deps:{:?}", name.as_str(), &deps);
        let tup_loc = TupLoc::new(&parse_state.cur_file_desc, loc);
        let tup_dir = parse_state.get_tup_dir_desc();
        let deps = deps.subst_pe(parse_state, path_searcher);
        // each line of the recipe has the same parse state as the task
        let recipe: Vec<_> = recipe
            .iter()
            .map(|x| x.subst_pe(&mut parse_state.clone(), path_searcher))
            .collect();
        let env_desc = parse_state.cur_env_desc.clone();

        let ti = TaskInstance::new(
            &tup_dir,
            &name.as_str(),
            deps.clone(),
            recipe.clone(),
            tup_loc,
            search_dirs.clone(),
            env_desc,
        );
        parse_state.path_buffers.add_task_path(ti);
    }

    fn subst_eval_block(
        &self,
        parse_state: &mut ParseState,
        path_searcher: &impl PathSearcher,
        newstats: &mut Vec<LocatedStatement>,
        body: &Vec<PathExpr>,
    ) -> Result<(), Error> {
        debug!("evaluating block: {:?}", body);
        let body = body.subst_pe(parse_state, path_searcher);
        if body
            .split(|x| x == &PathExpr::NL || x == &PathExpr::Sp1)
            .all(|x| {
                debug!("eval block line: {:?}", x);
                matches!(x, &[PathExpr::DeGlob(_), ..])
            })
        {
            body.split(|x| x == &PathExpr::NL).fold(
                newstats,
                |acc: &mut Vec<LocatedStatement>, x: &[PathExpr]| {
                    let mut pelist = x.subst_pe(parse_state, path_searcher);
                    pelist.cleanup();
                    acc.push(LocatedStatement::new(
                        Statement::EvalBlock(pelist),
                        self.get_loc().clone(),
                    ));
                    acc
                },
            );
        } else if !body.is_empty() {
            let body_str = body.cat() + "\n";

            debug!("evaluating block: {:?}", body_str.as_str());
            let lines = parse_statements_until_eof(Span::new(body_str.as_bytes()))
                .unwrap_or_else(|e| panic!("failed to parse eval block: {:?}", e));
            if lines.len() == 1 && lines.first().unwrap() == self {
                newstats.push(self.clone())
            } else {
                debug!("lines in eval block: {:?}", lines);
                let mut stmts = lines.subst(parse_state, path_searcher)?;
                debug!("statements in eval block: {:?}", stmts);
                newstats.append(&mut stmts);
            }
        }
        Ok(())
    }

    fn add_load_dirs(
        parse_state: &mut ParseState,
        path_searcher: &impl PathSearcher,
        loc: &Loc,
        paths: &Vec<PathExpr>,
    ) -> Result<(), Error> {
        let mut paths = paths.subst_pe(parse_state, path_searcher);
        paths.cleanup();
        let dir = paths.cat();
        debug!("adding search paths:{:?}", dir);
        let dirs = dir.split(":").collect::<Vec<_>>();
        let tup_cwd = parse_state.get_tup_base_dir();
        for dir in dirs.into_iter() {
            let dirid = parse_state.path_buffers.add_path_from(&tup_cwd, dir);
            let dirid = dirid.map_err(|_| {
                Error::PathNotFound(
                    dir.to_string(),
                    TupLoc::new(&parse_state.cur_file_desc, loc),
                )
            })?;
            {
                parse_state.add_load_dir(dirid);
            }
        }
        Ok(())
    }

    fn subst_include(
        &self,
        parse_state: &mut ParseState,
        path_searcher: &impl PathSearcher,
        newstats: &mut Vec<LocatedStatement>,
        s: &Vec<PathExpr>,
    ) -> Result<(), Error> {
        debug!("Include:{:?}", s.cat());
        let s = s.subst_pe(parse_state, path_searcher);
        let scat = &s.cat();
        debug!("found in current file:{:?}", parse_state.cur_file.as_path());
        let longp = parse_state.cur_file_desc.get_parent_descriptor();
        let pscat = Path::new(scat.as_str());
        debug!("longp:{:?}, pscat:{:?}", longp, pscat);
        let fullp = longp.join(pscat).map_err(|_| {
            Error::PathNotFound(
                pscat.to_string_lossy().to_string(),
                TupLoc::new(parse_state.get_cur_file_desc(), self.get_loc()),
            )
        })?;

        debug!(
            "include path:{:?} found in {:?}",
            fullp.get_path_ref(),
            parse_state.get_cur_file()
        );
        let ps = path_searcher.discover_paths(
            parse_state.path_buffers.deref(),
            &[GlobPath::build_from(
                &parse_state.get_tup_base_dir(),
                &fullp,
            )?],
        )?;
        let p = ps.into_iter().next().ok_or_else(|| {
            Error::PathNotFound(
                pscat.to_string_lossy().to_string(),
                TupLoc::new(parse_state.get_cur_file_desc(), self.get_loc()),
            )
        })?;
        parse_state.switch_tupfile_and_process(
            p.path_descriptor_ref(),
            |parse_state| -> Result<(), Error> {
                let include_stmts =
                    get_or_insert_parsed_statements(path_searcher.get_root(), parse_state)?;
                newstats.append(&mut include_stmts.subst(parse_state, path_searcher)?);
                Ok(())
            },
        )?;
        Ok(())
    }

    fn subst_include_rules(
        parse_state: &mut ParseState,
        path_searcher: &impl PathSearcher,
        newstats: &mut Vec<LocatedStatement>,
        loc: &Loc,
    ) -> Result<(), Error> {
        let parent = parse_state.get_tup_dir_desc();
        debug!(
            "attempting to read tuprules in dir:{:?}",
            parent.get_path_ref()
        );
        let mut found = false;
        // locate tupfiles up the heirarchy from the current Tupfile folder
        for f in path_searcher.locate_tuprules(&parent, parse_state.get_path_buffers().deref()) {
            debug!("reading tuprules {:?}", f);
            parse_state.switch_tupfile_and_process(&f, |parse_state| -> Result<(), Error> {
                let include_stmts =
                    get_or_insert_parsed_statements(path_searcher.get_root(), parse_state)?;
                newstats.append(&mut include_stmts.subst(parse_state, path_searcher)?);
                found = true;
                Ok(())
            })?;
        }
        if !found {
            return Err(Error::TupRulesNotFound(TupLoc::new(
                &parse_state.cur_file_desc,
                loc,
            )));
        }
        Ok(())
    }

    fn subst_assign(
        parse_state: &mut ParseState,
        path_searcher: &impl PathSearcher,
        left: &Ident,
        right: Vec<PathExpr>,
        assignment_type: &AssignmentType,
    ) {
        let op = assignment_type.to_str();
        log::info!("assign: {:?} {} {:?}", left.name, op, right);
        /*
           With Lazy Assignment (=): The appends are added to the unevaluated value, and everything is evaluated only when the variable is expanded.
        With Eager Assignment (:=): The appends are added to the already evaluated value, and each append operation immediately affects the final value of the variable.
             */

        match assignment_type {
            AssignmentType::Immediate => {
                parse_state.assign_eager(left.as_str(), right, path_searcher);
            }
            AssignmentType::Lazy => {
                parse_state.assign_lazy(left.as_str(), right);
            }
            AssignmentType::Append => {
                parse_state.append_assign(left.as_str(), right, path_searcher);
            }
            AssignmentType::Conditional => {
                parse_state.conditional_assign(left.as_str(), right);
            }
        };
    }
}

/// Implement `subst' method for statements. As the statements are processed, this keeps
/// track of variables assigned so far and replaces variables occurrences in $(Var) or &(Var) or @(Var)
impl Subst for Vec<LocatedStatement> {
    /// `subst' accumulates variable assignments in various maps in ParseState and replaces occurrences of them in subsequent statements
    fn subst(
        &self,
        parse_state: &mut ParseState,
        path_searcher: &impl PathSearcher,
    ) -> Result<Self, Err> {
        let stats = Vec::new();
        self.iter().try_fold(stats, |mut stats, statement| {
            let newstats = statement.subst(parse_state, path_searcher)?;
            stats.extend(newstats);
            Ok(stats)
        })
    }
}

fn get_or_insert_parsed_statements(
    root: &Path,
    parse_state: &mut ParseState,
) -> Result<Vec<LocatedStatement>, Error> {
    let tup_desc = parse_state.get_cur_file_desc().clone();
    if let Some(vs) = parse_state.get_statements_from_cache(&tup_desc) {
        debug!(
            "Reusing cached statements for {:?}",
            parse_state.get_cur_file()
        );
        Ok(vs)
    } else {
        debug!("Parsing {:?}", parse_state.get_cur_file());
        let res = parse_tupfile(&root.join(parse_state.get_cur_file().as_os_str()))?;
        debug!("Got: {:?} statements", res.len());
        parse_state.add_statements_to_cache(&tup_desc, res.clone());
        Ok(res)
    }
}

/// TupParser parser for a file containing tup file syntax
/// Inputs are config vars, Tupfile\[.lua\] path and a buffer in which to store descriptors for files.
/// The parser returns  resolved rules,  outputs of rules packaged in OutputTagInfo and updated buffer objects.
#[derive(Debug, Clone)]
pub struct TupParser<Q: PathSearcher + Sized + Send + 'static> {
    path_buffers: Arc<BufferObjects>,
    path_searcher: Arc<RwLock<Q>>,
    config_vars: HashMap<String, Vec<String>>,
    statement_cache: Arc<RwLock<HashMap<TupPathDescriptor, Vec<LocatedStatement>>>>, //< cache of parsed statements for each included file
}

/// ResolvedRules represent fully resolved rules/tasks along with their inputs and outputs that the parser gathers.
#[derive(Debug, Clone, Default)]
pub struct ResolvedRules {
    resolved_links: Vec<ResolvedLink>,
    resolved_tasks: Vec<ResolvedTask>,
}

impl ResolvedRules {
    /// Empty constructor for `ResolvedRules`
    pub fn new() -> ResolvedRules {
        ResolvedRules::default()
    }
    /// Builds ResolvedRules from a vector of [ResolvedLink]s
    pub fn from(
        resolved_links: Vec<ResolvedLink>,
        resolved_tasks: Vec<ResolvedTask>,
    ) -> ResolvedRules {
        ResolvedRules {
            resolved_links,
            resolved_tasks,
        }
    }

    /// Return the number of resolved links.
    pub fn len(&self) -> usize {
        self.resolved_links.len()
    }

    /// checks if there are no links found
    pub fn is_empty(&self) -> bool {
        self.resolved_links.is_empty()
    }

    /// extend links in `resolved_rules` with those in self
    pub fn extend(&mut self, mut resolved_rules: ResolvedRules) {
        self.resolved_links
            .extend(resolved_rules.drain_resolved_links());
        self.resolved_tasks
            .extend(resolved_rules.drain_resolved_tasks());
    }
    /// add a single link
    pub fn add_link(&mut self, rlink: ResolvedLink) {
        self.resolved_links.push(rlink)
    }
    #[allow(dead_code)]
    pub(crate) fn get_resolved_link(&self, i: usize) -> &ResolvedLink {
        &self.resolved_links[i]
    }
    /// divulges secrets of all the resolved links returned by the parser,
    pub(crate) fn drain_resolved_links(&mut self) -> Drain<'_, ResolvedLink> {
        self.resolved_links.drain(..)
    }

    fn drain_resolved_tasks(&mut self) -> Drain<'_, ResolvedTask> {
        self.resolved_tasks.drain(..)
    }
    /// divulges secrets of all the resolved links returned by the parser,
    pub fn get_resolved_links(&self) -> &Vec<ResolvedLink> {
        &self.resolved_links
    }

    /// Returns a vector over slices of resolved links grouped by the tupfile that generated them
    pub fn rules_by_tup(&self) -> Vec<&'_ [ResolvedLink]> {
        let mut link_iter = self.resolved_links.as_slice().iter().peekable();
        let mut out = Vec::new();
        let mut start_index = 0;
        let mut end_index = 0;
        while let Some(x) = link_iter.next() {
            end_index += 1;
            if let Some(nx) = link_iter.peek() {
                if nx.get_tup_loc().get_tupfile_desc() != x.get_tup_loc().get_tupfile_desc() {
                    out.push(&self.resolved_links[start_index..end_index]);
                    start_index = end_index;
                }
            }
        }
        if start_index != end_index {
            out.push(&self.resolved_links[start_index..end_index]);
        }
        out
    }
    /// returns tasks grouped by tupfiles in which they were defined
    pub fn tasks_by_tup(&self) -> Vec<&'_ [ResolvedTask]> {
        let mut task_iter = self.resolved_tasks.as_slice().iter().peekable();
        let mut out = Vec::new();
        let mut start_index = 0;
        let mut end_index = 0;
        while let Some(x) = task_iter.next() {
            end_index += 1;
            if let Some(nx) = task_iter.peek() {
                if nx.get_tupfile_desc() != x.get_tupfile_desc() {
                    out.push(&self.resolved_tasks[start_index..end_index]);
                    start_index = end_index;
                }
            }
        }
        if start_index != end_index {
            out.push(&self.resolved_tasks[start_index..end_index]);
        }
        out
    }

    /// Returns a slice over resolved links that the parser found so far.
    pub fn get_rules(&self) -> &[ResolvedLink] {
        self.resolved_links.as_slice()
    }
}

/// Represents an opens  buffer that is ready to be read for all data that stored with an id during parsing.
/// such as (rules, paths, groups, bins) stored during parsing.
/// It is also available for writing some data in the parser's buffers
#[derive(Clone, Debug)]
pub struct ReadWriteBufferObjects {
    bo: Arc<BufferObjects>,
}

impl ReadWriteBufferObjects {
    /// Constructor
    pub fn new(bo: Arc<BufferObjects>) -> ReadWriteBufferObjects {
        ReadWriteBufferObjects { bo }
    }
    /// get a read only reference to buffer objects
    pub fn get(&self) -> &BufferObjects {
        self.bo.deref()
    }

    /// get a mutable reference to buffer objects
    pub fn get_mut(&self) -> &BufferObjects {
        self.bo.deref()
    }
    /// add a  path to parser's buffer and return its unique id.
    /// If it already exists in its buffers boolean returned will be false
    pub fn add_abs(&mut self, p: &Path) -> Result<PathDescriptor, Error> {
        self.get_mut().add_abs(p)
    }
    /// iterate over all the (grouppath, groupid) pairs stored in buffers during parsing

    /// Iterate over group ids
    /// Group path is of the form folder/\<group\>, Where folder is the file system path relative to root
    pub fn for_each_group<F>(&self, f: F) -> Result<(), Error>
    where
        F: FnMut(&GroupPathDescriptor) -> Result<(), Error>,
    {
        GroupBufferObject::for_each(f)
    }

    /// returns the rule corresponding to `RuleDescriptor`
    pub fn get_rule<'a>(&'a self, rd: &'a RuleDescriptor) -> &'a RuleFormulaInstance {
        let r = self.get();
        r.get_rule(rd)
    }
    /// returns task from its descriptor
    pub fn get_task<'a>(&'a self, rd: &'a TaskDescriptor) -> &'a TaskInstance {
        let r = self.get();
        r.get_task(rd)
    }
    /// Return resolved input type in the string form.
    pub fn get_input_path_str(&self, i: &InputResolvedType) -> String {
        i.get_resolved_path_desc()
            .map(|pd| self.get().get_path_str(pd))
            .unwrap_or_default()
    }
    /// Return the file path corresponding to its id
    pub fn get_path(&self, p0: &PathDescriptor) -> NormalPath {
        let r = self.get();
        r.get_path(p0).clone()
    }

    /// Return file name of the path with given descriptor
    pub fn get_name(&self, p0: &PathDescriptor) -> String {
        p0.get_file_name().to_string()
    }

    /// Return the tup file name corresponding to its descriptor
    pub fn get_tup_file_name(&self, p0: &TupPathDescriptor) -> String {
        p0.get_file_name().to_string()
    }

    /// Get the name of the task corresponding to its descriptor
    pub fn get_task_name(&self, p0: &TaskDescriptor) -> String {
        p0.get_name().to_string()
    }
    /// Return rule string from rule descriptor
    pub fn get_rule_str(&self, rd: &RuleDescriptor) -> String {
        rd.get_name()
    }

    /// Return the file path corresponding to its id
    pub fn get_parent_id(&self, pd: &PathDescriptor) -> PathDescriptor {
        let r = self.get();
        r.get_parent_id(pd)
    }

    /// Full path of the group corresponding to its descriptor
    pub fn get_group_path(&self, gd: &GroupPathDescriptor) -> NormalPath {
        let r = self.get();
        r.get_group_path(gd).get_path()
    }

    /// Name of the group from its descriptor
    pub fn get_group_name(&self, gd: &GroupPathDescriptor) -> String {
        let r = self.get();
        r.get_group_name(gd)
    }

    /// Return the folder path corresponding to  group descriptor
    pub fn get_group_parent_id(&self, gd: &GroupPathDescriptor) -> PathDescriptor {
        let r = self.get();
        r.get_group_dir(gd)
    }

    /// return the path corresponding id of the glob path
    pub fn get_glob_path(&self, gd: &GlobPathDescriptor) -> NormalPath {
        let r = self.get();
        let np = r.get_path(&gd);
        np.clone()
    }

    /// get parent to the glob path
    pub fn get_glob_parent_id(&self, gd: &GlobPathDescriptor) -> PathDescriptor {
        let r = self.get();
        r.get_parent_id(gd)
    }

    /// Return the tup folder corresponding to its id
    pub fn get_tup_parent_id(&self, td: &TupPathDescriptor) -> PathDescriptor {
        let r = self.get();
        r.get_parent_id(td)
    }

    /// Returns the tup file path corresponding to its id
    pub fn get_tup_path<'a, 'b>(&'a self, tup_pd: &'b TupPathDescriptor) -> &'b NormalPath {
        //self.get().get_path(tup_pd)
        tup_pd.get_path_ref()
    }
    /// Return tup id from its path
    pub fn add_tup_file(&self, p: &Path) -> TupPathDescriptor {
        self.get().add_tup(p)
    }

    /// Return set of environment variables
    pub fn get_envs<'a>(&'a self, e: &'a EnvList) -> HashMap<String, String> {
        e.get_key_value_pairs()
    }

    /// Return the environment variable corresponding to its id
    pub fn get_env_name(&self, e: &EnvDescriptor) -> String {
        e.get().get_key_str().to_string()
    }
    /// Return the value of the environment variable corresponding to its id
    pub fn get_env_value(&self, e: &EnvDescriptor) -> String {
        e.get().get_val_str().to_string()
    }

    /// get a reportable version of error for display
    pub fn display_str(&self, e: &Error) -> String {
        e.to_string()
    }
}

impl<Q: PathSearcher + Sized + Send> TupParser<Q> {
    /// Fallible constructor that attempts to set up a parser locating the root folder where Tupfile.ini exists.,
    /// If found, it also attempts to load config vars from
    /// tup.config files it can successfully locate in the root folder.
    pub fn try_new_from<P: AsRef<Path>>(
        cur_folder: P,
        path_searcher: Q,
    ) -> Result<TupParser<Q>, Error> {
        let (_, parent) = locate_file(cur_folder.as_ref(), "Tupfile.ini", "")
            //.or(locate_file(cur_folder.as_ref(), "Tupfile.ini", ""))
            .ok_or(RootNotFound)?;

        let root = parent.as_path();
        debug!("root folder: {:?}", root);
        let conf_vars = load_conf_vars_relative_to(root)?;
        Ok(TupParser::new_from(
            root,
            conf_vars,
            Arc::new(RwLock::new(path_searcher)),
        ))
    }

    /// return outputs gathered by this parser and the relationships to its rule, directory etc
    pub fn get_outs(&self) -> OutputHolder {
        self.get_searcher().get_outs().clone()
    }

    /// returned a reference to path searcher
    pub fn get_searcher(&self) -> RwLockReadGuard<'_, Q> {
        self.path_searcher.deref().read()
    }

    /// returned a reference to path searcher
    pub fn get_mut_searcher(&self) -> RwLockWriteGuard<'_, Q> {
        self.path_searcher.deref().write()
    }

    /// Construct at the given rootdir and using config vars
    pub fn new_from<P: AsRef<Path>>(
        root_dir: P,
        config_vars: HashMap<String, Vec<String>>,
        path_searcher: Arc<RwLock<Q>>,
    ) -> TupParser<Q> {
        TupParser {
            path_buffers: Arc::new(BufferObjects::new(root_dir)),
            path_searcher,
            config_vars,
            statement_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Fetch the parser's read/write buffer for reading and writing in id-ed data that it holds
    pub fn read_write_buffers(&self) -> ReadWriteBufferObjects {
        ReadWriteBufferObjects::new(self.path_buffers.clone())
    }

    pub(crate) fn borrow_ref(&self) -> &BufferObjects {
        self.path_buffers.deref()
    }

    pub(crate) fn with_path_buffers_do<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&BufferObjects) -> R,
    {
        let bo = self.borrow_ref();
        f(&bo)
    }

    pub(crate) fn with_path_searcher_do<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut Q) -> R,
    {
        let mut bo = self.get_mut_searcher();
        f(&mut bo)
    }
    /// `parse_tupfile` takes a tupfile or Tupfile.lua file, and gathers rules, groups, bins and file paths it finds in them.
    /// These are all referenced by their ids that are generated  on the fly.
    /// Upon success the parser returns `ResolvedRules` that holds  references to all the resolved outputs by their ids
    /// The parser currently also allows you to read its buffers (id-object pairs) and even update it based on externally saved data via `ReadBufferObjects` and `WriteBufObjects`
    /// See [ResolvedRules]
    pub fn parse_tupfile<P: AsRef<Path>>(
        &mut self,
        tup_file_path: P,
        sender: Sender<StatementsToResolve>,
    ) -> Result<(), Error> {
        let p = tup_file_path.as_ref();
        // create a parser state
        let parse_state = self.prepare_to_parse(p);
        // now we are ready to parse the tupfile or tupfile.lua
        let stmts = parse_tupfile(tup_file_path)?;
        sender
            .send(StatementsToResolve::new(stmts, parse_state))
            .map_err(|e| {
                Error::new_path_search_error(format!("Error sending statements to resolver: {}", e))
            })?; // send the statements to the resolver
        Ok(())
    }
    /// return all parsed statements along with the parse state at the end of parsing of a tupfile
    pub fn parse_tupfile_immediate<P: AsRef<Path>>(
        &mut self,
        tup_file_path: P,
    ) -> Result<StatementsToResolve, Error> {
        // add tupfile path and tup environment to the buffer

        let parse_state = self.prepare_to_parse(&tup_file_path);
        // now we ready to parse the tupfile or tupfile.lua
        let stmts = parse_tupfile(tup_file_path)?;
        Ok(StatementsToResolve::new(stmts, parse_state))
    }

    fn prepare_to_parse<P: AsRef<Path>>(&mut self, tup_file_path: P) -> ParseState {
        let (tup_desc, env_desc) = self.with_path_buffers_do(|boref| {
            let tup_desc = boref.add_tup(tup_file_path.as_ref());
            let env = init_env();
            let env_desc = env.into_iter().map(|k| boref.add_env_var(k)).collect();
            (tup_desc, env_desc)
        });

        // create a parser state
        let parse_state = ParseState::new(
            &self.config_vars,
            tup_desc,
            env_desc,
            self.statement_cache.clone(),
            self.path_buffers.clone(),
        );
        parse_state
    }
    //noinspection RsBorrowChecker
    /// wait for the next [StatementsToResolve] and process them
    pub fn receive_resolved_statements(
        &mut self,
        receiver: Receiver<StatementsToResolve>,
    ) -> Result<ResolvedRules, crate::errors::ErrorContext> {
        let resolved_rules =
            receiver
                .iter()
                .try_fold(ResolvedRules::new(), |mut resolved_rules, to_resolve| {
                    let tup_desc = to_resolve.get_tup_desc().clone();
                    let resolved_rules_ = self
                        .process_raw_statements(to_resolve)
                        .map_err(|e| crate::errors::ErrorContext::new(e, tup_desc))?;
                    resolved_rules.extend(resolved_rules_);
                    Ok(resolved_rules)
                })?;
        drop(receiver);
        Ok(resolved_rules)
    }

    /// `parse` takes a tupfile or Tupfile.lua file, and gathers rules, groups, bins and file paths it finds in them.
    /// These are all referenced by their ids that are generated  on the fly.
    /// Upon success the parser returns `ResolvedRules` that holds  references to all the resolved outputs by their ids
    /// The parser currently also allows you to read its buffers (id-object pairs) and even update it based on externally saved data via `ReadBufferObjects` and `WriteBufObjects`
    /// See [ResolvedRules]
    pub fn parse<P: AsRef<Path>>(&mut self, tup_file_path: P) -> Result<ResolvedRules, Error> {
        // add tupfile path and tup environment to the buffer
        let (tup_desc, env_desc) = self.with_path_buffers_do(|path_buffers| {
            let tup_desc = path_buffers.add_tup(tup_file_path.as_ref());
            let env = init_env();
            let env_desc: Vec<_> = env
                .into_iter()
                .map(|e| path_buffers.add_env(Cow::Owned(e)))
                .collect();
            (tup_desc, env_desc)
        });

        // create a parser state
        let parse_state = ParseState::new(
            &self.config_vars,
            tup_desc,
            env_desc,
            self.statement_cache.clone(),
            self.path_buffers.clone(),
        );
        // now we ready to parse the tupfile or tupfile.lua
        if let Some("lua") = tup_file_path.as_ref().extension().and_then(OsStr::to_str) {
            // wer are not going to  resolve group paths during the first phase of parsing.
            // both path buffers and path searcher are rc-cloned (with shared ref cells) and passed to the lua parser
            let (arts, _) = parse_script(
                parse_state,
                self.path_buffers.clone(),
                self.path_searcher.clone(),
            )?;
            Ok(arts)
        } else {
            let stmts = parse_tupfile(tup_file_path)?;
            self.process_raw_statements(StatementsToResolve::new(stmts, parse_state))
        }
    }

    fn process_raw_statements(
        &self,
        statements_to_resolve: StatementsToResolve,
    ) -> Result<ResolvedRules, Error> {
        let mut parse_state = statements_to_resolve.parse_state;
        let stmts = statements_to_resolve.statements;
        let tup_desc = parse_state.get_cur_file_desc().clone();
        let stmts: Vec<LocatedStatement> = {
            let searcher = self.get_path_searcher();
            let mut res: Vec<LocatedStatement> = stmts.subst(&mut parse_state, searcher.deref())?;
            res.expand_run(&mut parse_state, searcher.deref())?;
            Ok::<Vec<LocatedStatement>, Error>(res)
        }?;
        debug!(
            "num statements after expand run:{:?} in tupfile {:?}",
            stmts.len(),
            parse_state.get_cur_file()
        );
        stmts.resolve_paths(
            &tup_desc,
            self.get_mut_searcher().deref_mut(),
            self.borrow_ref(),
            parse_state.get_tupfiles_read(),
        )
    }

    /// Re-resolve for resolved groups that were left unresolved in the first round of parsing
    /// This step is usually run as a second pass to resolve group references across Tupfiles
    pub fn reresolve(&mut self, resolved_rules: ResolvedRules) -> Result<ResolvedRules, Error> {
        type R = Result<ResolvedRules, Error>;
        self.with_path_buffers_do(|path_buffers| -> R {
            self.with_path_searcher_do(|path_searcher| -> R {
                resolved_rules.get_resolved_links().resolve_paths(
                    &TupPathDescriptor::default(),
                    path_searcher,
                    path_buffers,
                    &vec![],
                )
            })
        })
    }
    fn get_path_searcher(&self) -> RwLockReadGuard<'_, Q> {
        self.path_searcher.deref().read()
    }
}

/// locate a file by its name relative to current tup file path by recursively going up the directory tree
/// cur_tupfile mayb be a file or a directory, if it is a directory, it is assumed to be a tupfile directory
///
pub fn locate_file<P: AsRef<Path>>(
    cur_tupfile: P,
    file_to_loc: &str,
    alt_ext: &str,
) -> Option<(PathBuf, PathBuf)> {
    let mut cwd = cur_tupfile.as_ref();
    let pb: PathBuf;
    if cwd.is_dir() || cwd.as_os_str().is_empty() {
        pb = cwd.join("Tupfile");
        cwd = &pb;
    }
    while let Some(parent) = cwd.parent() {
        let p = parent.join(file_to_loc);
        if p.is_file() {
            return Some((p, parent.to_path_buf()));
        }

        if !alt_ext.is_empty() {
            let p = p.with_extension(alt_ext);
            if p.is_file() {
                return Some((p, parent.to_path_buf()));
            }
        }
        debug!(
            "next path we are looking for {:?} in {:?}",
            file_to_loc,
            parent.parent()
        );
        cwd = parent;
    }
    None
}

/// functions for testing transformations
pub mod testing {
    use std::collections::HashMap;
    use std::path::Path;

    use crate::decode::DirSearcher;
    use crate::errors::Error;
    use crate::statements::{Cat, CatRef, CleanupPaths, LocatedStatement, PathExpr};
    use crate::transform::{get_parent, ParseState};

    /// Holds parse state variables (eager and lazily assigned)
    pub struct Vars {
        expr_map: HashMap<String, Vec<PathExpr>>,
        func_map: HashMap<String, Vec<PathExpr>>,
    }

    impl Vars {
        fn from(state: &ParseState) -> Self {
            Vars {
                expr_map: state.expr_map.clone(),
                func_map: state.func_map.clone(),
            }
        }
        /// get the variable value as a string
        pub fn get(&self, name: &str) -> Option<Vec<String>> {
            self.expr_map.get(name).and_then(|p| {
                log::debug!("get var:{}={:?}", name, p);
                let vs = p
                    .split(|x| matches!(x, PathExpr::Sp1 | PathExpr::NL))
                    .flat_map(|x| x.iter().map(|x| x.cat_ref().trim().to_string()))
                    .collect::<Vec<String>>(); // $(empty substitution depends on this)
                log::debug!("get var:{}={:?}", name, vs);
                Some(vs)
                //Some(p.into_iter().map(|x| x.cat_ref().to_string()).collect())
            })
        }
        /// get the function body as a string
        pub fn get_func(&self, name: &str) -> Option<String> {
            self.func_map.get(name).map(|x| x.cat())
        }
    }
    /// perform variable substition, resolve calls, evals, foreach etc
    pub fn subst_statements(
        filename: &Path,
        statements: Vec<LocatedStatement>,
    ) -> Result<(Vec<LocatedStatement>, Vars), Error> {
        let mut parse_state = ParseState::new_at(filename);
        let mut stmts = statements;
        let mut v = Vec::new();
        let searcher = DirSearcher::new();
        for stmt in stmts.drain(..).filter(|s| !s.is_comment()) {
            let mut vs = stmt.subst(&mut parse_state, &searcher)?;
            v.append(&mut vs);
        }
        Ok((v, Vars::from(&parse_state)))
    }

    /// perform variable substition, resolve calls, evals, foreach etc
    pub fn subst_statements_with_conf(
        filename: &Path,
        statements: Vec<LocatedStatement>,
        conf_map: HashMap<String, Vec<String>>,
    ) -> Result<(Vec<LocatedStatement>, HashMap<String, Vec<String>>), Error> {
        log::debug!("statements:{:?} in file:{:?}", statements, filename);
        let mut parse_state = ParseState::new_at(filename);
        //parse_state.set_cwd(filename).unwrap();
        parse_state.conf_map = conf_map;
        let mut stmts = statements;
        let mut v = Vec::new();
        let searcher = DirSearcher::new_at(get_parent(filename));
        for stmt in stmts.drain(..).filter(|s| !s.is_comment()) {
            let mut vs = stmt.subst(&mut parse_state, &searcher)?;
            v.append(&mut vs);
        }
        v.cleanup();
        Ok((v, parse_state.conf_map))
    }
}
