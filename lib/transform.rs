//! This module has data structures and methods to transform Statements to Statements with substitutions and expansions
use std::borrow::Cow;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::ops::{AddAssign, Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::vec::Drain;

use crossbeam::channel::{Receiver, Sender};
use log::debug;
use nom::AsBytes;
use parking_lot::MappedRwLockReadGuard;
use parking_lot::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use pathdiff::diff_paths;

use crate::buffers::{
    BufferObjects, GlobPathDescriptor, GroupPathDescriptor, MyGlob, OutputHolder, PathBuffers,
    PathDescriptor, RuleDescriptor, TupPathDescriptor,
};
use crate::decode::{
    PathSearcher, ResolvePaths, ResolvedLink, ResolvedTask, RuleFormulaInstance, TaskInstance,
    TupLoc,
};
use crate::errors::Error::RootNotFound;
use crate::errors::{Error as Err, Error};
use crate::glob::Candidate;
use crate::parser::locate_tuprules;
use crate::parser::{parse_statements_until_eof, parse_tupfile, Span};
use crate::paths::{normalize_path, NormalPath};
use crate::paths::{GlobPath, InputResolvedType};
use crate::platform::*;
use crate::scriptloader::parse_script;
use crate::statements::*;

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
    pub(crate) fn get_tup_desc(&self) -> &TupPathDescriptor {
        &self.parse_state.cur_file_desc
    }
}

/// ParseState holds maps tracking current state of variable replacements as we read a tupfile
#[derive(Debug, Clone, Default)]
pub(crate) struct ParseState {
    /// tupfile variables to be substituted
    pub(crate) expr_map: HashMap<String, Vec<String>>,
    /// tupfile reference variables to be substituted
    pub(crate) rexpr_map: HashMap<String, Vec<String>>,
    // defined functions
    pub(crate) func_map: HashMap<String, String>,
    // defered variables that will be substituted at the call site
    //pub (crate) defered_expr_map : HashMap<String, PathExpr>,
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
    /// Cache of statements from previously read Tupfiles
    pub(crate) statement_cache: Arc<RwLock<HashMap<TupPathDescriptor, Vec<LocatedStatement>>>>,
    /// Buffers to store files, groups, bins, env with its id.
    pub(crate) path_buffers: Arc<RwLock<BufferObjects>>,
}

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

/// Accessor and constructors of ParseState
impl ParseState {
    /// Initialize ParseState for var-subst-ing `cur_file'
    pub fn new(
        conf_map: &HashMap<String, Vec<String>>,
        cur_file: &Path,
        cur_file_desc: TupPathDescriptor,
        cur_env_desc: EnvDescriptor,
        statement_cache: Arc<RwLock<HashMap<TupPathDescriptor, Vec<LocatedStatement>>>>,
    ) -> Self {
        let mut def_vars = HashMap::new();
        let dir = get_parent_str(cur_file).to_string();
        let pbuffers = Arc::new(RwLock::new(BufferObjects::new(dir.as_str())));
        def_vars.insert("TUP_CWD".to_owned(), vec![dir]);

        ParseState {
            conf_map: conf_map.clone(),
            expr_map: def_vars,
            cur_file: cur_file.to_path_buf(),
            tup_base_path: cur_file.to_path_buf(),
            cur_file_desc,
            cur_env_desc,
            statement_cache: statement_cache.clone(),
            path_buffers: pbuffers,
            ..ParseState::default()
        }
    }
    pub(crate) fn get_statements_from_cache(
        &self,
        tup_desc: &TupPathDescriptor,
    ) -> Option<Vec<LocatedStatement>> {
        let x = self.statement_cache.deref().read();
        x.get(tup_desc).cloned()
    }

    pub(crate) fn replace_tup_cwd(&mut self, dir: &str) -> Option<Vec<String>> {
        let v = self.expr_map.remove("TUP_CWD");
        self.expr_map
            .insert("TUP_CWD".to_string(), vec![dir.to_string()]);
        v
    }

    pub fn with_mut_path_buffers_do<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut BufferObjects) -> R,
    {
        let mut pb = self.path_buffers.write();
        f(pb.deref_mut())
    }

    pub fn switch_tupfile_and_process(
        &mut self,
        tupfile: &Path,
        process: impl FnOnce(&mut Self) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let old_cur_file = self.get_cur_file().to_path_buf();
        self.set_cwd(tupfile)?;
        let res = process(self);
        self.set_cwd(old_cur_file.as_path())?;
        res
    }

    /// Initialize ParseState for var-subst-ing `cur_file' with no conf_map.
    /// This is useful for testing.
    #[cfg(test)]
    pub fn new_at<P: AsRef<Path>>(cur_file: P) -> Self {
        let mut def_vars = HashMap::new();
        let pbuffers = Arc::new(RwLock::new(BufferObjects::new(get_parent(
            cur_file.as_ref(),
        ))));
        let cur_file_desc = pbuffers.write().add_tup(cur_file.as_ref()).0;
        let cur_file = pbuffers.read().get_tup_path(&cur_file_desc).to_path_buf();
        let dir = get_parent_str(cur_file.as_path()).to_string().to_string();
        def_vars.insert("TUP_CWD".to_owned(), vec![dir]);

        ParseState {
            expr_map: def_vars,
            cur_file: cur_file.clone(),
            tup_base_path: cur_file.clone(),
            cur_file_desc,
            path_buffers: pbuffers,
            ..ParseState::default()
        }
    }
    /// set the current TUP_CWD in expression map in ParseState as we switch to reading an included file
    pub fn set_cwd(&mut self, tupfile: &Path) -> Result<(), Error> {
        (self.cur_file_desc, _) = self.path_buffers.write().add_tup(tupfile);
        self.cur_file = self
            .path_buffers
            .read()
            .get_tup_path(&self.cur_file_desc)
            .to_path_buf();
        let tupdir = get_parent(self.tup_base_path.as_path());
        debug!(
            "diffing:{:?} with base: {:?}",
            self.cur_file.as_path(),
            tupdir
        );
        let diff = diff_paths(self.cur_file.as_path(), tupdir.as_ref())
            .map(|x| Ok(x))
            .unwrap_or_else(|| {
                Err(Error::new_path_search_error(format!(
                    "failed diffing:{:?} with base: {:?}",
                    self.cur_file.as_path(),
                    tupdir.as_ref()
                )))
            })?;
        debug!("switching to diff:{:?}", diff);
        let parent = diff
            .parent()
            .unwrap_or_else(|| panic!("unexpected diff:{:?}", diff));
        if parent.eq(Path::new("")) {
            self.replace_tup_cwd(".");
        } else {
            let p = get_path_str(parent);
            self.replace_tup_cwd(p.to_cow_str().as_ref());
        }
        Ok(())
    }

    pub(crate) fn set_env(&mut self, ed: EnvDescriptor) {
        self.cur_env_desc = ed;
    }

    /// return the tupfile being parsed
    pub(crate) fn get_cur_file(&self) -> &Path {
        &self.cur_file
    }

    /// return the folder containing Tupfile being parsed
    pub(crate) fn get_tup_dir(&self) -> Cow<Path> {
        get_parent(self.cur_file.as_path())
    }

    /// Get folder that hosts tup file as a descriptor
    pub(crate) fn get_cur_file_desc(&self) -> &TupPathDescriptor {
        &self.cur_file_desc
    }

    fn get_env_desc(&self) -> EnvDescriptor {
        self.cur_env_desc.clone()
    }

    /// Add statements to cache.
    fn add_statements_to_cache(
        &mut self,
        tup_desc: &TupPathDescriptor,
        mut vs: Vec<LocatedStatement>,
    ) {
        let vs: Vec<_> = vs.drain(..).filter(|s| !s.is_comment()).collect();
        self.statement_cache
            .deref()
            .write()
            .entry(*tup_desc)
            .or_insert(vs);
    }
}

/// Method to expand tup `run` statement to discover new rules to add
/// run is expected to echo regular rule statements which we add to list of rules during the `subst` phase.
trait ExpandRun {
    fn expand_run(
        &self,
        parse_state: &mut ParseState,
        path_searcher: &impl PathSearcher,
        path_buffers: &mut impl PathBuffers,
        loc: &Loc,
        res: &mut Vec<LocatedStatement>,
    ) -> Result<(), Error>
    where
        Self: Sized;
}

impl ExpandRun for Statement {
    /// expand_run adds Statements returned by executing a shell command. Rules that are output from the command should be in the regular format for rules that Tup supports
    /// see docs for how the environment is picked.
    fn expand_run(
        &self,
        parse_state: &mut ParseState,
        path_searcher: &impl PathSearcher,
        path_buffers: &mut impl PathBuffers,
        loc: &Loc,
        res: &mut Vec<LocatedStatement>,
    ) -> Result<(), Error> {
        let rule_ref = TupLoc::new(&parse_state.cur_file_desc, loc);
        match self {
            Statement::Preload(v) => {
                let dir = v.cat();
                let p = Path::new(dir.as_str());
                let (dirid, _) = path_buffers.add_path_from(parse_state.get_tup_dir().as_ref(), p);
                {
                    parse_state.load_dirs.push(dirid);
                }
            }
            Statement::Run(script_args) => {
                if let Some(script) = script_args.first() {
                    let mut acnt = 0;
                    let mut cmd = if !cfg!(windows)
                        || Path::new(script.cat().as_str()).extension() == Some(OsStr::new("sh"))
                        || script.cat_ref() == "sh"
                    {
                        acnt = (script.cat_ref() == "sh").into();
                        std::process::Command::new("sh")
                    } else {
                        std::process::Command::new("cmd.exe")
                    };
                    for arg_expr in script_args.iter().skip(acnt) {
                        let arg = arg_expr.cat();
                        let arg = arg.trim();
                        if arg.contains('*') {
                            let arg_path = Path::new(arg);
                            {
                                let ref glob_path = GlobPath::new(
                                    parse_state.get_tup_dir().as_ref(),
                                    arg_path,
                                    path_buffers,
                                )?;
                                let matches = path_searcher
                                    .discover_paths(path_buffers, glob_path)
                                    .unwrap_or_else(|_| {
                                        panic!("error matching glob pattern {}", arg)
                                    });
                                debug!("expand_run num files from glob:{:?}", matches.len());
                                for ofile in matches {
                                    let p = diff_paths(
                                        path_buffers.get_path(ofile.path_descriptor()).as_path(),
                                        parse_state.get_tup_dir(),
                                    )
                                    .unwrap_or_else(|| {
                                        panic!(
                                            "Failed to diff path{:?} with base:{:?}",
                                            path_buffers
                                                .get_path(ofile.path_descriptor())
                                                .as_path(),
                                            parse_state.get_tup_dir()
                                        )
                                    });
                                    cmd.arg(
                                        p.to_string_lossy().to_string().as_str().replace('\\', "/"),
                                    );
                                }
                            }
                        } else if !arg.is_empty() {
                            cmd.arg(arg);
                        }
                    }
                    let env = path_buffers
                        .try_get_env(&parse_state.cur_env_desc)
                        .unwrap_or_else(|| {
                            panic!("unknown env var descriptor:{}", parse_state.cur_env_desc)
                        });
                    let dir = path_buffers.get_root_dir().join(parse_state.get_tup_dir());
                    if cmd.get_args().len() != 0 {
                        cmd.envs(env.getenv()).current_dir(dir.as_path());

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

                        let lstmts = parse_statements_until_eof(Span::new(contents.as_bytes()))
                            .expect("failed to parse output of tup run");
                        let mut lstmts = lstmts
                            .subst(parse_state, path_searcher)
                            .expect("subst failure in generated tup rules");
                        res.extend(lstmts.drain(..));
                    } else {
                        eprintln!("Warning tup run arguments are empty in Tupfile in dir:{:?} at pos:{:?}", dir, loc);
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }
}

impl ExpandRun for Vec<LocatedStatement> {
    /// discover more rules to add by running shell commands
    fn expand_run(
        &self,
        parse_state: &mut ParseState,
        path_searcher: &impl PathSearcher,
        path_buffers: &mut impl PathBuffers,
        _: &Loc,
        res: &mut Vec<LocatedStatement>,
    ) -> Result<(), Error>
    where
        Self: Sized,
    {
        self.iter()
            .map(|l| -> Result<(), Error> {
                let loc = l.get_loc();
                l.get_statement()
                    .expand_run(parse_state, path_searcher, path_buffers, loc, res)
            })
            .collect()
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

/// Check if a PathExpr is empty
fn is_empty(rval: &PathExpr) -> bool {
    if let PathExpr::Literal(s) = rval {
        s.len() == 0
    } else {
        false
    }
}

impl PathExpr {
    fn is_literal(&self) -> bool {
        if let PathExpr::Literal(_) = self {
            true
        } else {
            false
        }
    }
    /// substitute a single pathexpr into an array of literal pathexpr
    /// SFINAE holds

    fn subst(&self, m: &mut ParseState, path_searcher: &impl PathSearcher) -> Vec<PathExpr> {
        match self {
            PathExpr::DollarExprs(ref x) => x.subst(m, path_searcher),
            PathExpr::AtExpr(ref x) => {
                if let Some(val) = m.conf_map.get(x.as_str()) {
                    intersperse_sp1(val)
                } else if !x.contains('%') {
                    log::warn!("atexpr {} not found", x);
                    vec![PathExpr::Literal("".to_owned())]
                } else {
                    log::debug!("delay subst of atexpr {}", x);
                    vec![self.clone()]
                }
            }
            PathExpr::AmpExpr(ref x) => {
                if let Some(val) = m.rexpr_map.get(x.as_str()) {
                    intersperse_sp1(val)
                } else if !x.contains('%') {
                    log::warn!("ampexpr {} not found", x);
                    vec![PathExpr::from("".to_owned())]
                } else {
                    log::debug!("delay subst of ampexpr {}", x);
                    vec![self.clone()]
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

impl DollarExprs {
    fn subst(&self, m: &mut ParseState, path_searcher: &impl PathSearcher) -> Vec<PathExpr> {
        match self {
            DollarExprs::DollarExpr(x) => {
                if let Some(val) = m.expr_map.get(x.as_str()) {
                    let vs = intersperse_sp1(val);
                    vs
                } else if x.contains('%') {
                    log::warn!("dollarexpr {} not found", x);
                    vec![self.clone().into()]
                } else {
                    log::warn!("No substitution found for {}", x);
                    vec![PathExpr::from("".to_owned())] // postpone subst until placeholders are fixed
                }
            }
            DollarExprs::Subst(ref from, ref to, ref vs) => {
                let vs = vs.subst_pe(m, path_searcher);
                let to = to.subst_pe(m, path_searcher);
                let to = to.cat();
                let from = from
                    .iter()
                    .flat_map(|x| x.subst(m, path_searcher))
                    .collect::<Vec<PathExpr>>();
                let from = from.cat();
                let replacer = |x: &[PathExpr]| {
                    x.iter()
                        .filter_map(|x| {
                            let s = x.cat_ref();
                            if !s.is_empty() {
                                Some(PathExpr::from(s.replace(from.as_str(), to.as_str())))
                            } else {
                                None
                            }
                        })
                        .collect::<Vec<PathExpr>>()
                };
                replacer(&vs)
            }

            DollarExprs::Filter(ref filter, ref vs) => {
                let vs = vs.subst_pe(m, path_searcher);
                let filter: Vec<PathExpr> = filter.subst_pe(m, path_searcher);
                let next = |x: &[PathExpr]| -> Vec<PathExpr> {
                    let mut vs = x.to_vec();
                    vs.retain(|x| {
                        let s = x.cat_ref();
                        if !s.is_empty() {
                            for f in filter.iter() {
                                if let PathExpr::Literal(ref f) = f {
                                    if s.contains(f.as_str()) {
                                        return true;
                                    }
                                }
                            }
                        }
                        false
                    });
                    vs
                };
                next(&vs)
            }
            DollarExprs::FilterOut(ref filter, ref vs) => {
                let vs = vs.subst_pe(m, path_searcher);
                let filter: Vec<PathExpr> = filter.subst_pe(m, path_searcher);
                let next = |x: &[PathExpr]| -> Vec<PathExpr> {
                    let mut vs = x.to_vec();
                    vs.retain(|x| {
                        let s = x.cat_ref();
                        if !s.is_empty() {
                            for f in filter.iter() {
                                if let PathExpr::Literal(ref f) = f {
                                    if s.contains(f.as_str()) {
                                        return false;
                                    }
                                }
                            }
                        }
                        true
                    });
                    vs
                };
                next(&vs)
            }
            DollarExprs::ForEach(var, list, body) => {
                let mut list = list.subst_pe(m, path_searcher);
                if list.is_empty() {
                    log::warn!("Empty suffix values for {} in {:?}", var, m.get_cur_file());
                    return vec![];
                }
                //let body = body.subst_pe(m);
                let mut vs = Vec::new();
                for l in list.iter_mut() {
                    if let PathExpr::Literal(ref s) = l {
                        m.expr_map.insert(var.clone(), vec![s.clone()]);

                        let b = &mut body
                            .iter()
                            .flat_map(|x| x.subst(m, path_searcher))
                            .collect::<Vec<PathExpr>>();
                        vs.append(b);
                        vs.push(PathExpr::Sp1);
                        m.expr_map.remove(var);
                    }
                }
                while let Some(pe) = vs.iter().next_back() {
                    if matches!(pe, PathExpr::Sp1) {
                        vs.pop();
                    } else {
                        break;
                    }
                }
                vs
            }

            DollarExprs::WildCard(glob) => {
                // wild cards are not expanded in the substitution phase

                let gstr = glob.subst_pe(m, path_searcher).cat();
                let dir = m.get_tup_dir().to_path_buf();
                m.with_mut_path_buffers_do(|path_buffers_mut| {
                    let glob_path =
                        GlobPath::new(dir.as_path(), Path::new(gstr.as_str()), path_buffers_mut)
                            .unwrap();
                    let paths = path_searcher
                        .discover_paths(path_buffers_mut, &glob_path)
                        .unwrap_or_else(|e| {
                            log::warn!("Error while globbing {:?}: {}", glob_path, e);
                            vec![]
                        });
                    paths.into_iter().map(|x| PathExpr::DeGlob(x)).collect()
                })
            }
            DollarExprs::Strip(ref vs) => {
                // strip trailing and leading spaces
                let vs: Vec<_> = vs
                    .subst_pe(m, path_searcher)
                    .into_iter()
                    .rev()
                    .skip_while(|x| matches!(x, PathExpr::Sp1))
                    .collect();
                vs.into_iter()
                    .rev()
                    .skip_while(|x| matches!(x, PathExpr::Sp1))
                    .collect()
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
                let tup_dir = m.get_tup_dir().to_path_buf();
                vs.iter()
                    .filter_map(|v| {
                        let s = v.cat_ref();
                        if !s.is_empty() {
                            let p = Path::new(s.as_ref());
                            let real_path =
                                path_dedot::ParseDot::parse_dot_from(p, tup_dir.as_path())
                                    .unwrap_or_else(|x| {
                                        panic!("failed to parse dot in path: {:?} {:?}", p, x)
                                    });
                            Some(real_path.to_string_lossy().to_string().into())
                        } else {
                            None
                        }
                    })
                    .collect()
            }
            DollarExprs::BaseName(ref vs) => {
                let vs = vs.subst_pe(m, path_searcher);
                vs.iter()
                    .filter_map(|v| {
                        let s = v.cat_ref();
                        if !s.is_empty() {
                            let p = Path::new(s.as_ref());
                            let base_name = p.file_name().unwrap_or_else(|| {
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
                let vs = vs.subst_pe(m, path_searcher);
                vs.iter()
                    .filter_map(|v| {
                        let s = v.cat_ref();
                        if !s.is_empty() {
                            let p = Path::new(s.as_ref());
                            let p = path_dedot::ParseDot::parse_dot_from(p, m.get_tup_dir())
                                .unwrap_or_else(|x| {
                                    panic!("failed to parse dot in path: {:?} {:?}", p, x)
                                });
                            if p.is_dir() {
                                Some("".to_string().into())
                            } else {
                                let base_name = p.file_name().unwrap_or_else(|| {
                                    panic!("failed to get base name from path: {:?}", p)
                                });
                                Some(base_name.to_string_lossy().to_string().into())
                            }
                        } else {
                            None
                        }
                    })
                    .collect()
            }
            DollarExprs::Dir(ref vs) => {
                let vs = vs.subst_pe(m, path_searcher);
                let tup_dir = m.get_tup_dir().to_path_buf();

                let vs = vs
                    .iter()
                    .filter_map(|v| {
                        let s = v.cat_ref();
                        if !s.is_empty() {
                            let p = Path::new(s.as_ref());
                            let p = path_dedot::ParseDot::parse_dot_from(p, tup_dir.as_path())
                                .unwrap_or_else(|x| {
                                    panic!("failed to parse dot in path: {:?} {:?}", p, x)
                                });
                            if p.is_dir() {
                                Some("".to_string().into())
                            } else {
                                let base_name = p.file_name().unwrap_or_else(|| {
                                    panic!("failed to get base name from path: {:?}", p)
                                });
                                Some(base_name.to_string_lossy().to_string().into())
                            }
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
                    let s = x.to_vec().cat();
                    // find the index-th word in s
                    let mut words = s.split_whitespace();
                    let word: Vec<PathExpr> = words
                        .nth(0usize)
                        .map(|x| vec![x.to_string().into()])
                        .unwrap_or_else(|| {
                            log::warn!("failed to get first word from path: {:?}", s);
                            vec![]
                        });
                    word
                };
                next(&vs)
            }
            DollarExprs::Word(index, ref vs) => {
                let vs = vs.subst_pe(m, path_searcher);
                if index < &0 {
                    panic!("negative index in word");
                }
                let next = |x: &[PathExpr]| -> Vec<PathExpr> {
                    let s = x.to_vec().cat();
                    // find the index-th word in s
                    let mut words = s.split_whitespace();
                    let word = words.nth(*index as usize).unwrap_or_else(|| {
                        log::warn!("failed to get {}-th word from path: {:?}", index, s);
                        ""
                    });
                    if word.is_empty() {
                        vec![]
                    } else {
                        vec![PathExpr::from(word.to_string())]
                    }
                };
                next(&vs)
            }

            DollarExprs::AddPrefix(ref prefix, ref vs) => {
                let vs = vs.subst_pe(m, path_searcher);
                let prefix = prefix.subst_pe(m, path_searcher);
                let prefix: String = prefix
                    .cat()
                    .chars()
                    .take_while(|x| !x.is_whitespace())
                    .collect();
                let next = |x: &[PathExpr]| -> Vec<PathExpr> {
                    let vs = x
                        .iter()
                        .filter_map(|v| {
                            if let PathExpr::Literal(s) = v {
                                let mut prefixed = prefix.clone();
                                prefixed.push_str(s);
                                Some(PathExpr::from(prefixed))
                            } else {
                                None
                            }
                        })
                        .collect();
                    vs
                };
                next(&vs)
            }
            DollarExprs::AddSuffix(ref suffix, ref vs) => {
                let vs = vs.subst_pe(m, path_searcher);
                let sfx = suffix.subst_pe(m, path_searcher);
                let sfx: String = sfx
                    .cat()
                    .chars()
                    .take_while(|x| !x.is_whitespace())
                    .collect();
                let next = |x: &[PathExpr]| -> Vec<PathExpr> {
                    let vs = x
                        .iter()
                        .filter_map(|v| {
                            if let PathExpr::Literal(s) = v {
                                let mut s = s.clone();
                                s.push_str(sfx.as_str());
                                Some(PathExpr::from(s))
                            } else {
                                None
                            }
                        })
                        .collect();
                    vs
                };

                next(&vs)
            }
            DollarExprs::PatSubst(pat, rep, target) => {
                let pat = pat.subst_pe(m, path_searcher);
                let rep = rep.subst_pe(m, path_searcher);
                let target = target.subst_pe(m, path_searcher);
                let pat: String = pat.cat().replace('%', "*");
                let rep: String = rep.cat().replace("%", "$1");

                let glob = MyGlob::new(Candidate::new(pat.as_str())).unwrap();
                glob.re()
                    .captures_iter(target.cat().as_bytes())
                    .map(|cap| {
                        let mut s = rep.clone();
                        for i in 0..cap.len() {
                            s = s.replace(
                                &format!("${}", i + 1),
                                std::str::from_utf8(cap.get(i).unwrap().as_bytes()).unwrap_or(""),
                            )
                        }
                        PathExpr::from(s)
                    })
                    .collect()
            }
            DollarExprs::Call(ref name, args) => {
                let args: Vec<_> = args.iter().map(|x| x.subst_pe(m, path_searcher)).collect();
                let name = name.subst_pe(m, path_searcher);
                let name: String = name
                    .cat()
                    .chars()
                    .take_while(|x| !x.is_whitespace())
                    .collect();
                let body = m
                    .func_map
                    .get(&name)
                    .unwrap_or_else(|| panic!("failed to find function: {}", name));
                let mut m = m.clone();
                m.expr_map.insert("0".to_string(), vec![name]);
                for (i, arg) in args.iter().enumerate() {
                    m.expr_map.insert(format!("{}", i + 1), vec![arg.cat()]);
                }
                let (_, mut lines) = crate::parser::parse_lines(Span::new(body.as_bytes()))
                    .unwrap_or_else(|x| panic!("failed to parse function body: {:?}", x));
                lines
                    .drain(..)
                    .map(|(l, _)| l.subst_pe(&mut m, path_searcher))
                    .flatten()
                    .collect()
            }

            DollarExprs::If(cond, then_part, else_part) => {
                let cond = cond.subst_pe(m, path_searcher);
                let cond = cond.cat();
                if cond.is_empty() {
                    let else_part = else_part.subst_pe(m, path_searcher);
                    else_part
                } else {
                    let then_part = then_part.subst_pe(m, path_searcher);
                    then_part
                }
            }
        }
    }
}

/// creates [PathExpr] array separated by PathExpr::Sp1
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
    fn subst_pe(&self, m: &mut ParseState, path_searcher: &impl PathSearcher) -> Self
    where
        Self: Sized;
}

impl SubstPEs for Vec<PathExpr> {
    /// call subst on each path expr and flatten/cleanup the output.
    fn subst_pe(&self, m: &mut ParseState, path_searcher: &impl PathSearcher) -> Self {
        let mut newpe: Vec<_> = self
            .iter()
            .flat_map(|x| x.subst(m, path_searcher))
            .filter(|x| !is_empty(x))
            .collect();
        newpe.cleanup();
        newpe
    }
}

impl SubstPEs for Source {
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
        self.primary.cleanup();
        self.primary.append(&mut o.primary);

        self.secondary.cleanup();
        self.secondary.append(&mut o.secondary);

        self.group = self.group.clone().or(o.group);
        self.bin = self.bin.clone().or(o.bin);
    }
}

/// substitute only first pathexpr using ParseState
fn takefirst(
    o: &Option<PathExpr>,
    m: &mut ParseState,
    path_searcher: &impl PathSearcher,
) -> Result<Option<PathExpr>, Err> {
    if let &Some(ref pe) = o {
        Ok(pe.subst(m, path_searcher).first().cloned())
    } else {
        Ok(None)
    }
}

impl SubstPEs for Target {
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
            group: takefirst(&self.group, m, path_searcher).unwrap_or_default(),
            bin: takefirst(&self.bin, m, path_searcher).unwrap_or_default(),
        }
    }
}
impl SubstPEs for RuleFormula {
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
        let mut desc = self.rule_formula.description.clone();
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
                        if desc.is_empty() {
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
pub(crate) fn get_parent(cur_file: &Path) -> Cow<Path> {
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
        return Cow::Owned(PathBuf::from("."));
    } else {
        Cow::Borrowed(p)
    }
}

/// parent folder path as a string slice
pub fn get_parent_str(cur_file: &Path) -> Candidate {
    normalize_path(cur_file.parent().unwrap())
}

pub(crate) fn get_path_str(cur_file: &Path) -> Candidate {
    normalize_path(cur_file)
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
pub fn load_conf_vars(filename: &Path) -> Result<HashMap<String, Vec<String>>, Error> {
    let mut conf_vars = HashMap::new();
    debug!(
        "attempting loading conf vars from tup.config at {:?}",
        filename
    );
    let mut loaded = false;
    if let Some(conf_file) = Path::new(filename).parent().map(|x| x.join("tup.config")) {
        if conf_file.is_file() {
            if let Some(fstr) = conf_file.to_str() {
                debug!("loading conf vars from tup.config at {:?}", filename);
                loaded = true;
                for LocatedStatement { statement, .. } in parse_tupfile(fstr)?.iter() {
                    if let Statement::AssignExpr { left, right, .. } = statement {
                        if let Some(rest) = left.name.strip_prefix("CONFIG_") {
                            log::warn!("conf var:{} = {}", rest, right.cat());
                            conf_vars.insert(rest.to_string(), tovecstring(right.as_slice()));
                        }
                    }
                }
            }
        }
    }
    if !loaded {
        debug!(
            "no tup.config file found at folder corresponding to {:?}",
            filename
        );
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

impl SubstPEs for Link {
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

impl LocatedStatement {
    pub(crate) fn subst(
        &self,
        parse_state: &mut ParseState,
        path_searcher: &impl PathSearcher,
    ) -> Result<Vec<LocatedStatement>, Error> {
        let mut newstats = Vec::new();
        let loc = self.get_loc();
        match self.get_statement() {
            Statement::AssignExpr {
                left,
                right,
                is_append,
                is_empty_assign,
            } => {
                let &app = is_append;
                Self::update_assign(
                    parse_state,
                    path_searcher,
                    left,
                    right,
                    is_empty_assign,
                    app,
                );
            }
            Statement::AsignRefExpr {
                left,
                right,
                is_append,
                is_empty_assign,
            } => {
                let &app = is_append;
                let prefix = vec![
                    PathExpr::from(DollarExprs::DollarExpr("TUP_CWD".to_owned())),
                    PathExpr::Literal("/".to_owned()),
                ]
                .subst_pe(parse_state, path_searcher)
                .cat();
                let subst_right: Vec<String> = right
                    .split(|x| x == &PathExpr::Sp1)
                    .map(|x| {
                        prefix.clone()
                            + x.to_vec()
                                .subst_pe(parse_state, path_searcher)
                                .cat()
                                .as_str()
                    })
                    .collect();

                let curright = if app {
                    match parse_state.rexpr_map.get(left.name.as_str()) {
                        Some(prevright) => prevright.iter().cloned().chain(subst_right).collect(),
                        _ => subst_right,
                    }
                } else if *is_empty_assign {
                    match parse_state.expr_map.get(left.name.as_str()) {
                        Some(prevright) => prevright.iter().cloned().collect(),
                        _ => subst_right,
                    }
                } else {
                    subst_right
                };
                debug!(
                    "letref expr: {:?} {}= {:?}",
                    left.name,
                    if *is_empty_assign {
                        "?"
                    } else if app {
                        "+"
                    } else {
                        ""
                    },
                    curright
                );
                parse_state.rexpr_map.insert(left.name.clone(), curright);
            }

            Statement::IfElseEndIf {
                eq,
                then_statements,
                else_statements,
            } => {
                let e = EqCond {
                    lhs: eq.lhs.subst_pe(parse_state, path_searcher),
                    rhs: eq.rhs.subst_pe(parse_state, path_searcher),
                    not_cond: eq.not_cond,
                };
                debug!("testing {:?} == {:?}", e.lhs, e.rhs);
                let (ts, es) = if e.not_cond {
                    (else_statements, then_statements)
                } else {
                    (then_statements, else_statements)
                };
                if e.lhs.cat().eq(&e.rhs.cat()) {
                    newstats.append(&mut ts.subst(parse_state, path_searcher)?);
                } else {
                    newstats.append(&mut es.subst(parse_state, path_searcher)?);
                }
            }
            Statement::IfDef {
                checked_var,
                then_statements,
                else_statements,
            } => {
                let cvar = PathExpr::AtExpr(checked_var.0.name.clone());
                debug!("testing ifdef {:?}", cvar);
                if cvar.subst(parse_state, path_searcher).iter().any(is_empty) == checked_var.1 {
                    newstats.append(&mut then_statements.subst(parse_state, path_searcher)?);
                } else {
                    newstats.append(&mut else_statements.subst(parse_state, path_searcher)?);
                }
            }

            Statement::IncludeRules => {
                let parent = get_parent(parse_state.cur_file.as_path());
                debug!("attempting to read tuprules");
                let mut found = false;
                // locate tupfiles up the heirarchy from the current Tupfile folder
                for f in locate_tuprules(parent) {
                    debug!("reading tuprules {:?}", f);
                    parse_state.switch_tupfile_and_process(
                        f.as_path(),
                        |parse_state| -> Result<(), Error> {
                            //let cf = switch_to_reading(tup_desc, tup_path, m, bo);
                            let include_stmts = get_or_insert_parsed_statement(parse_state)?;
                            newstats.append(&mut include_stmts.subst(parse_state, path_searcher)?);
                            found = true;
                            Ok(())
                        },
                    )?;
                }
                if !found {
                    return Err(Error::TupRulesNotFound(TupLoc::new(
                        &parse_state.cur_file_desc,
                        loc,
                    )));
                }
            }
            Statement::Include(s) => {
                debug!("Include:{:?}", s.cat());
                let s = s.subst_pe(parse_state, path_searcher);
                let scat = &s.cat();
                let longp = get_parent(parse_state.cur_file.as_path());
                let pscat = Path::new(scat.as_str());
                let fullp = NormalPath::absolute_from(pscat, longp.as_ref());

                let p = if pscat.is_relative() {
                    fullp.as_path()
                } else {
                    pscat
                };
                debug!(
                    "cur path to include:{:?} at {:?}",
                    p,
                    parse_state.get_cur_file()
                );
                if p.is_file() {
                    parse_state.switch_tupfile_and_process(
                        p,
                        |parse_state| -> Result<(), Error> {
                            let include_stmts = get_or_insert_parsed_statement(parse_state)?;
                            newstats.append(&mut include_stmts.subst(parse_state, path_searcher)?);
                            Ok(())
                        },
                    )?;
                } else {
                    return Err(Error::PathNotFound(
                        p.to_string_lossy().to_string(),
                        TupLoc::new(parse_state.get_cur_file_desc(), self.get_loc()),
                    ));
                }
            }
            Statement::Rule(link, _) => {
                let mut l = link.clone();
                while l.has_ref() {
                    l = l.expand(parse_state)?; // expand all nested macro refs
                }
                let env_desc = parse_state.cur_env_desc.clone();
                newstats.push(LocatedStatement::new(
                    Statement::Rule(l.subst_pe(parse_state, path_searcher), env_desc),
                    *loc,
                ));
            }
            // dont subst inside a macro assignment
            // just update the rule_map
            Statement::MacroAssignment(name, link) => {
                let l = link.clone();
                parse_state.rule_map.insert(name.clone(), l);
            }
            Statement::Err(v) => {
                let v = v.subst_pe(parse_state, path_searcher);
                eprintln!("{}\n", &v.cat().as_str());
                return Err(Error::UserError(
                    v.cat().as_str().to_string(),
                    TupLoc::new(&parse_state.cur_file_desc, loc),
                ));
            }
            Statement::Preload(v) => {
                newstats.push(LocatedStatement::new(
                    Statement::Preload(v.subst_pe(parse_state, path_searcher)),
                    *loc,
                ));
            }
            Statement::Export(var) => {
                let env_desc = parse_state.get_env_desc();
                let id = parse_state
                    .with_mut_path_buffers_do(|bo| bo.add_env_var(var.clone(), &env_desc));
                parse_state.set_env(id);
            }
            Statement::Import(var, envval) => {
                if let Some(val) = envval.clone().or_else(|| std::env::var(var).ok()) {
                    parse_state
                        .expr_map
                        .entry(String::from(var.as_str()))
                        .or_default()
                        .push(val);
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
                parse_state.func_map.insert(name.to_string(), val.clone());
                //newstats.push(LocatedStatement::new(Statement::Define(name.clone(),val.clone()), loc.clone()))
            }
            Statement::Task(name, deps, recipe) => {
                debug!("adding task:{} with deps:{:?}", name.as_str(), &deps);
                let tup_loc = TupLoc::new(&parse_state.cur_file_desc, loc);
                let tup_dir = parse_state.get_tup_dir().to_path_buf();
                let deps = deps.subst_pe(parse_state, path_searcher);
                // each line of the recipe has the same parse state as the task
                let recipe: Vec<_> = recipe
                    .iter()
                    .map(|x| x.subst_pe(&mut parse_state.clone(), path_searcher))
                    .collect();
                let ti = TaskInstance::new(
                    tup_dir,
                    name.as_str(),
                    deps.clone(),
                    recipe.clone(),
                    tup_loc,
                );
                let mut bo = parse_state.path_buffers.write();
                bo.add_task_path(ti);
            }
        }
        Ok(newstats)
    }

    fn update_assign(
        parse_state: &mut ParseState,
        path_searcher: &impl PathSearcher,
        left: &Ident,
        right: &Vec<PathExpr>,
        is_empty_assign: &bool,
        app: bool,
    ) {
        let subst_right_pe: Vec<_> = right
            .iter()
            .flat_map(|x| x.subst(parse_state, path_searcher))
            //.filter_map(|x| if !matches!(x, PathExpr::Sp1) { Some(x.cat())} else { None})
            .collect();
        let subst_right: Vec<String> = subst_right_pe
            .split(|x| matches!(x, PathExpr::Sp1))
            .map(|x| x.iter().map(|x| x.cat()).collect::<Vec<String>>().join(""))
            .collect();

        let curright: Vec<String> = if app {
            match parse_state.expr_map.get(left.name.as_str()) {
                Some(prevright) => prevright.iter().cloned().chain(subst_right).collect(),
                _ => subst_right,
            }
        } else if *is_empty_assign {
            match parse_state.expr_map.get(left.name.as_str()) {
                Some(prevright) => prevright.iter().cloned().collect(),
                _ => subst_right,
            }
        } else {
            subst_right
        };
        debug!(
            "let expr: {:?} {}= {:?}",
            left.name,
            if *is_empty_assign {
                "?"
            } else if app {
                "+"
            } else {
                ""
            },
            curright
        );
        parse_state.expr_map.insert(left.name.clone(), curright);
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
        let mut stats = Vec::new();
        for statement in self.iter() {
            let newstats = statement.subst(parse_state, path_searcher)?;
            stats.extend(newstats);
        }
        Ok(stats)
    }
}

fn get_or_insert_parsed_statement(
    parse_state: &mut ParseState,
) -> Result<Vec<LocatedStatement>, Error> {
    let tup_desc = *parse_state.get_cur_file_desc();
    if let Some(vs) = parse_state.get_statements_from_cache(&tup_desc) {
        debug!(
            "Reusing cached statements for {:?}",
            parse_state.get_cur_file()
        );
        Ok(vs)
    } else {
        debug!("Parsing {:?}", parse_state.get_cur_file());
        let res = parse_tupfile(parse_state.get_cur_file())?;
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
    path_buffers: Arc<RwLock<BufferObjects>>,
    path_searcher: Arc<RwLock<Q>>,
    config_vars: HashMap<String, Vec<String>>,
    statement_cache: Arc<RwLock<HashMap<TupPathDescriptor, Vec<LocatedStatement>>>>, //< cache of parsed statements for each included file
}

/// Artifacts represent rules and their outputs that the parser gathers.
#[derive(Debug, Clone, Default)]
pub struct Artifacts {
    resolved_links: Vec<ResolvedLink>,
    resolved_tasks: Vec<ResolvedTask>,
}

impl Artifacts {
    /// Empty constructor for `Artifacts`
    pub fn new() -> Artifacts {
        Artifacts::default()
    }
    /// Builds Artifacts from a vector of [ResolvedLink]s
    pub fn from(resolved_links: Vec<ResolvedLink>, resolved_tasks: Vec<ResolvedTask>) -> Artifacts {
        Artifacts {
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

    /// extend links in `artifacts` with those in self
    pub fn extend(&mut self, mut artifacts: Artifacts) {
        self.resolved_links.extend(artifacts.drain_resolved_links());
        self.resolved_tasks.extend(artifacts.drain_resolved_tasks());
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
                if nx.get_rule_ref().get_tupfile_desc() != x.get_rule_ref().get_tupfile_desc() {
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

    /// Returns a slice over resolved links that the parser found so far.
    pub fn get_rules(&self) -> &[ResolvedLink] {
        return self.resolved_links.as_slice();
    }
}

/// Represents an opens  buffer that is ready to be read for all data that stored with an id during parsing.
/// such as (rules, paths, groups, bins) stored during parsing.
/// It is also available for writing some data in the parser's buffers
pub struct ReadWriteBufferObjects {
    bo: Arc<RwLock<BufferObjects>>,
}

impl ReadWriteBufferObjects {
    /// Constructor
    pub fn new(bo: Arc<RwLock<BufferObjects>>) -> ReadWriteBufferObjects {
        ReadWriteBufferObjects { bo }
    }
    /// get a read only reference to buffer objects
    pub fn get(&self) -> RwLockReadGuard<'_, BufferObjects> {
        self.bo.deref().read()
    }

    /// get a mutable reference to buffer objects
    pub fn get_mut(&self) -> RwLockWriteGuard<'_, BufferObjects> {
        self.bo.deref().write()
    }
    /// add a  path to parser's buffer and return its unique id.
    /// If it already exists in its buffers boolean returned will be false
    pub fn add_abs(&mut self, p: &Path) -> (PathDescriptor, bool) {
        self.get_mut().add_abs(p)
    }
    /// iterate over all the (grouppath, groupid) pairs stored in buffers during parsing
    pub fn for_each_group<F>(&self, f: F)
    where
        F: FnMut((&NormalPath, &GroupPathDescriptor)),
    {
        let r = self.get_mut();
        r.group_iter().for_each(f);
    }
    /// Iterate over group ids
    pub fn map_group_desc<F>(&self, f: F) -> Vec<(GroupPathDescriptor, i64)>
    where
        F: FnMut(&GroupPathDescriptor) -> (GroupPathDescriptor, i64),
    {
        self.bo.deref().read().get_group_descs().map(f).collect()
    }

    /// returns the rule corresponding to `RuleDescriptor`
    pub fn get_rule(&self, rd: &RuleDescriptor) -> MappedRwLockReadGuard<'_, RuleFormulaInstance> {
        let r = self.get();
        RwLockReadGuard::map(r, |x| x.get_rule(rd))
    }
    /// Return resolved input type in the string form.
    pub fn get_input_path_str(&self, i: &InputResolvedType) -> String {
        self.get().get_path_str(i.get_resolved_path_desc().unwrap())
    }
    /// Return the file path corresponding to its id
    pub fn get_path(&self, p0: &PathDescriptor) -> MappedRwLockReadGuard<'_, NormalPath> {
        let r = self.get();
        RwLockReadGuard::map(r, |x| x.get_path(p0))
    }
    /// Return the file path corresponding to its id
    pub fn get_parent_id(&self, pd: &PathDescriptor) -> Option<PathDescriptor> {
        let r = self.get();
        r.get_parent_id(pd)
    }

    /// return the path corresponding id of the glob path
    pub fn get_glob_path(&self, gd: &GlobPathDescriptor) -> PathBuf {
        let r = self.get();
        let i: usize = (*gd).into();
        let pd = PathDescriptor::new(i);
        let np = r.get_path(&pd);
        np.clone().to_path_buf()
    }

    /// Returns the tup file path corresponding to its id
    pub fn get_tup_path(&self, p0: &TupPathDescriptor) -> MappedRwLockReadGuard<'_, Path> {
        let r = self.get();
        RwLockReadGuard::map(r, |x| x.get_tup_path(p0))
    }
    /// Return tup id from its path
    pub fn get_tup_id(&self, p: &Path) -> MappedRwLockReadGuard<'_, TupPathDescriptor> {
        let r = self.get();
        RwLockReadGuard::map(r, |x| x.get_tup_id(p))
    }

    /// Return set of environment variables
    pub fn get_envs(&self, e: &EnvDescriptor) -> MappedRwLockReadGuard<'_, Env> {
        let r = self.get();
        RwLockReadGuard::map(r, |x| {
            x.try_get_env(e)
                .unwrap_or_else(|| panic!("env not found:{:?}", e))
        })
    }

    /// get a reportable version of error for display
    pub fn display_str(&self, e: &Error) -> String {
        let r = self.get();
        e.human_readable(r.deref())
    }
}

impl<Q: PathSearcher + Sized + Send> TupParser<Q> {
    /// Fallible constructor that attempts to setup a parser after looking from the current folder,
    /// a root folder where Tupfile.ini exists. If found, it also attempts to load config vars from
    /// tup.config files it can successfully locate in the root folder.
    pub fn try_new_from<P: AsRef<Path>>(
        cur_folder: P,
        path_searcher: Q,
    ) -> Result<TupParser<Q>, Error> {
        let tup_ini = locate_file(cur_folder, "Tupfile.ini", "").ok_or(RootNotFound)?;

        let root = tup_ini.parent().ok_or(RootNotFound)?;
        log::debug!("root folder: {:?}", root);
        let conf_vars = load_conf_vars(tup_ini.as_path())?;
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
            path_buffers: Arc::new(RwLock::from(BufferObjects::new(root_dir))),
            path_searcher,
            config_vars,
            statement_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Fetch the parser's read/write buffer for reading and writing in id-ed data that it holds
    pub fn read_write_buffers(&self) -> ReadWriteBufferObjects {
        ReadWriteBufferObjects::new(self.path_buffers.clone())
    }

    pub(crate) fn borrow_ref(&self) -> RwLockReadGuard<'_, BufferObjects> {
        return self.path_buffers.deref().read();
    }

    pub(crate) fn borrow_mut_ref(&self) -> RwLockWriteGuard<'_, BufferObjects> {
        return self.path_buffers.deref().write();
    }

    pub(crate) fn with_path_buffers_do<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut BufferObjects) -> R,
    {
        let mut bo = self.borrow_mut_ref();
        f(&mut bo)
    }

    pub(crate) fn with_path_searcher_do<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut Q) -> R,
    {
        let mut bo = self.get_mut_searcher();
        f(&mut bo)
    }
    /// `parse` takes a tupfile or Tupfile.lua file, and gathers rules, groups, bins and file paths it finds in them.
    /// These are all referenced by their ids that are generated  on the fly.
    /// Upon success the parser returns `Artifacts` that holds  references to all the resolved outputs by their ids
    /// The parser currently also allows you to read its buffers (id-object pairs) and even update it based on externally saved data via `ReadBufferObjects` and `WriteBufObjects`
    /// See [Artifacts]
    pub fn parse_tupfile<P: AsRef<Path>>(
        &mut self,
        tup_file_path: P,
        sender: Sender<StatementsToResolve>,
    ) -> Result<(), Error> {
        // add tupfile path and tup environment to the buffer
        let (tup_desc, env_desc) = self.with_path_buffers_do(|boref| {
            let (tup_desc, _) = boref.add_tup(tup_file_path.as_ref());
            let env = init_env();
            let (env_desc, _) = boref.add_env(Cow::Borrowed(&env));
            (tup_desc, env_desc)
        });

        // create a parser state
        let parse_state = ParseState::new(
            &self.config_vars,
            self.borrow_ref().get_tup_path(&tup_desc),
            tup_desc,
            env_desc,
            self.statement_cache.clone(),
        );
        // now we ready to parse the tupfile or tupfile.lua
        {
            let stmts = parse_tupfile(tup_file_path)?;
            sender
                .send(StatementsToResolve::new(stmts, parse_state))
                .map_err(|e| {
                    Error::new_path_search_error(format!(
                        "Error sending statements to resolver: {}",
                        e
                    ))
                })?; // send the statements to the resolver
            Ok(())
        }
    }

    /// wait for the next [StatementsToResolve] and process them
    pub fn receive_resolved_statements(
        &mut self,
        receiver: Receiver<StatementsToResolve>,
    ) -> Result<Artifacts, crate::errors::ErrorContext> {
        let mut artifacts = Artifacts::new();
        for to_resolve in receiver.iter() {
            let tup_desc = to_resolve.get_tup_desc().clone();
            let arts = self
                .process_raw_statements(to_resolve)
                .map_err(|e| crate::errors::ErrorContext::new(e, tup_desc))?;
            artifacts.extend(arts)
        }
        drop(receiver);
        Ok(artifacts)
    }

    /// `parse` takes a tupfile or Tupfile.lua file, and gathers rules, groups, bins and file paths it finds in them.
    /// These are all referenced by their ids that are generated  on the fly.
    /// Upon success the parser returns `Artifacts` that holds  references to all the resolved outputs by their ids
    /// The parser currently also allows you to read its buffers (id-object pairs) and even update it based on externally saved data via `ReadBufferObjects` and `WriteBufObjects`
    /// See [Artifacts]
    pub fn parse<P: AsRef<Path>>(&mut self, tup_file_path: P) -> Result<Artifacts, Error> {
        // add tupfile path and tup environment to the buffer
        let (tup_desc, env_desc) = self.with_path_buffers_do(|path_buffers| {
            let (tup_desc, _) = path_buffers.add_tup(tup_file_path.as_ref());
            let env = init_env();
            let (env_desc, _) = path_buffers.add_env(Cow::Borrowed(&env));
            (tup_desc, env_desc)
        });

        // create a parser state
        let parse_state = ParseState::new(
            &self.config_vars,
            self.borrow_ref().get_tup_path(&tup_desc),
            tup_desc,
            env_desc,
            self.statement_cache.clone(),
        );
        // now we ready to parse the tupfile or tupfile.lua
        if let Some("lua") = tup_file_path.as_ref().extension().and_then(OsStr::to_str) {
            // wer are not going to  resolve group paths during the first phase of parsing.
            // both path buffers and path searcher are rc-cloned (with shared ref cells) and passed to the lua parser
            parse_script(
                parse_state,
                self.path_buffers.clone(),
                self.path_searcher.clone(),
            )
        } else {
            let stmts = parse_tupfile(tup_file_path)?;
            self.process_raw_statements(StatementsToResolve::new(stmts, parse_state))
        }
    }

    fn process_raw_statements(
        &self,
        statements_to_resolve: StatementsToResolve,
    ) -> Result<Artifacts, Error> {
        let mut parse_state = statements_to_resolve.parse_state;
        let mut stmts = statements_to_resolve.statements;
        let tup_desc = *parse_state.get_cur_file_desc();
        let res =
            self.with_path_buffers_do(|bo_ref_mut| -> Result<Vec<LocatedStatement>, Error> {
                let mut res = Vec::new();
                // create a transform function that will substitute variables in the statements
                for stmt in stmts.drain(..).filter(|s| !s.is_comment()) {
                    let searcher = self.get_path_searcher();
                    let vs = stmt.subst(&mut parse_state, searcher.deref())?;
                    // create a vector generator over the statements
                    if vs
                        .iter()
                        .map(|l| l.get_statement())
                        .any(|s| matches!(s, Statement::Run(_)))
                    {
                        vs.expand_run(
                            &mut parse_state,
                            self.get_path_searcher().deref(),
                            bo_ref_mut,
                            &Loc::new(0, 0, 0),
                            &mut res,
                        )?;
                    } else {
                        res.extend(vs);
                    }
                }
                Ok(res)
            })?;
        let stmts = res;
        debug!(
            "num statements after expand run:{:?} in tupfile {:?}",
            stmts.len(),
            parse_state.get_cur_file()
        );
        stmts.resolve_paths(
            parse_state.get_cur_file(),
            self.get_mut_searcher().deref_mut(),
            self.borrow_mut_ref().deref_mut(),
            &tup_desc,
        )
    }

    /// Re-resolve for resolved groups that were left unresolved in the first round of parsing
    /// This step is usually run as a second pass to resolve group references across Tupfiles
    pub fn reresolve(&mut self, arts: Artifacts) -> Result<Artifacts, Error> {
        let pbuf = PathBuf::new();
        type R = Result<Artifacts, Error>;
        self.with_path_buffers_do(|path_buffers| -> R {
            self.with_path_searcher_do(|path_searcher| -> R {
                arts.get_resolved_links().resolve_paths(
                    pbuf.as_path(),
                    path_searcher,
                    path_buffers,
                    &TupPathDescriptor::new(0),
                )
            })
        })
    }
    fn get_path_searcher(&self) -> RwLockReadGuard<'_, Q> {
        self.path_searcher.deref().read()
    }
}

/// locate a file by its name relative to current tup file path by recursively going up the directory tree
pub fn locate_file<P: AsRef<Path>>(
    cur_tupfile: P,
    file_to_loc: &str,
    alt_ext: &str,
) -> Option<PathBuf> {
    let mut cwd = cur_tupfile.as_ref();
    let pb: PathBuf;
    if cwd.is_dir() || cwd.as_os_str().is_empty() {
        pb = cwd.join("Tupfile");
        cwd = &pb;
    }
    while let Some(parent) = cwd.parent() {
        let p = parent.join(file_to_loc);
        if p.is_file() {
            return Some(p);
        }

        if !alt_ext.is_empty() {
            let p = p.with_extension(alt_ext);
            if p.is_file() {
                return Some(p);
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
