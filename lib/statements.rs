//! This module has datastructures that capture parsed tupfile expressions
use crate::buffers::EnvList;
use std::borrow::Cow;
use std::fmt::{Display, Formatter};

use crate::buffers::PathDescriptor;
use crate::paths::MatchingPath;
use crate::transform::ParseState;

/// TaskTarget encapsulates the target of a task
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum TaskTarget {
    /// TaskTarget::Outputs(Vec<PathExpr>) represents a task target that is a list of outputs
    Outputs(Vec<PathExpr>),
    /// TaskTarget::Id(Ident) represents a task target that is an identifier
    Id(Ident),
}

impl Default for TaskTarget {
    fn default() -> Self {
        TaskTarget::Id(Ident::default())
    }
}
impl TaskTarget {
    /*
    pub(crate) fn get_outputs(&self) -> Option<&Vec<PathExpr>> {
        match self {
            TaskTarget::Outputs(o) => Some(o),
            _ => None,
        }
    }
    pub(crate) fn get_id(&self) -> Option<&Ident> {
        match self {
            TaskTarget::Id(i) => Some(i),
            _ => None,
        }
    } */
    /// create a new TaskTarget from a list of outputs
    pub(crate) fn new_outputs(o: Vec<PathExpr>) -> Self {
        TaskTarget::Outputs(o)
    }
    /// create a new TaskTarget from an identifier
    pub(crate) fn new_id(i: Ident) -> Self {
        TaskTarget::Id(i)
    }

    /// get the string representation of the TaskTarget
    pub fn as_str(&self) -> String {
        match self {
            TaskTarget::Outputs(o) => o.cat(),
            TaskTarget::Id(i) => i.as_str().to_string(),
        }
    }
}

/// PathExpr are tokens that hold some meaning in tupfiles
#[derive(PartialEq, Debug, Clone, Hash, Eq, Ord, PartialOrd)]
pub(crate) enum PathExpr {
    /// New line
    NL,
    /// a normal string
    Literal(String),
    /// spaces between paths
    Sp1,
    /// Quoted string
    Quoted(Vec<PathExpr>),
    /// Exclude patterns to avoid  passing some inputs or tracking some outputs
    ExcludePattern(String),
    /// $(EXPR)
    DollarExprs(DollarExprs),
    ///  @(EXPR)
    AtExpr(String),
    /// reference to an output available globally across Tupfiles
    Group(Vec<PathExpr>, Vec<PathExpr>),
    ///  {objs} a collector of output
    Bin(String),
    /// !macro_name reference to a macro to be expanded
    MacroRef(String),
    /// resolved glob references
    DeGlob(MatchingPath),
    /// Task Ref
    TaskRef(Ident),
}
impl Default for PathExpr {
    fn default() -> Self {
        PathExpr::Literal(String::new())
    }
}
/// level of the message to display when parsing tupfiles
#[derive(PartialEq, Debug, Clone, Copy, Eq, Hash)]
pub enum Level {
    /// Info message
    Info,
    /// Warning message
    Warning,
    /// Error message
    Error,
}

impl PathExpr {
    pub(crate) fn get_group(&self) -> Option<(&Vec<PathExpr>, &Vec<PathExpr>)> {
        match self {
            PathExpr::Group(g, g1) => Some((g, g1)),
            _ => None,
        }
    }
    pub(crate) fn is_literal(&self) -> bool {
        if let PathExpr::Literal(_) = self {
            true
        } else {
            false
        }
    }
    /// Check if a PathExpr is empty
    pub(crate) fn is_empty(&self) -> bool {
        if let PathExpr::Literal(s) = self {
            s.len() == 0
        } else {
            false
        }
    }

    pub(crate) fn is_ws(&self) -> bool {
        if let PathExpr::Literal(s) = self {
            s.trim().len() == 0
        } else {
            matches!(self, PathExpr::Sp1 | PathExpr::NL)
        }
    }
}

impl Default for Level {
    fn default() -> Self {
        Level::Info
    }
}
/// Variable tracking location of Statement (usually a rule) in a Tupfile
/// see also [TupLoc] that keeps track of file in which the location is referred
#[derive(PartialEq, Debug, Clone, Copy, Eq, Default, Hash, PartialOrd, Ord)]
pub struct Loc {
    line: u32,
    col: u32,
    span: u32,
}

impl Loc {
    /// line number of the expression
    pub fn get_line(&self) -> u32 {
        self.line
    }
    /// column number of the expression
    pub fn get_col(&self) -> u32 {
        self.col
    }
    /// length of the expression
    pub fn get_span(&self) -> u32 {
        self.span
    }
    /// create a new Loc using line, column and span
    pub fn new(line: u32, col: u32, span: u32) -> Loc {
        Loc { line, col, span }
    }
}

impl From<crate::parser::Span<'_>> for Loc {
    fn from(span: crate::parser::Span) -> Loc {
        Loc::new(
            span.location_line(),
            span.get_column() as _,
            span.fragment().len() as _,
        )
    }
}

impl From<MatchingPath> for PathExpr {
    fn from(value: MatchingPath) -> Self {
        PathExpr::DeGlob(value)
    }
}

#[derive(PartialEq, Debug, Clone, Hash, Eq, Ord, PartialOrd)]
pub(crate) enum DollarExprs {
    /// $(EXPR)
    DollarExpr(String),
    /// $(addprefix prefix, EXPR)
    /// prefix is added to each path in EXPR
    AddPrefix(Vec<PathExpr>, Vec<PathExpr>),
    /// $(addsuffix suffix, EXPR)
    /// suffix is added to each path in EXPR
    AddSuffix(Vec<PathExpr>, Vec<PathExpr>),
    /// $(subst from, to, EXPR)
    Subst(Vec<PathExpr>, Vec<PathExpr>, Vec<PathExpr>),
    /// $(patsubst pattern, replacement, EXPR) --- pattern is a wildcard pattern with %p, replacement is a string
    PatSubst(Vec<PathExpr>, Vec<PathExpr>, Vec<PathExpr>),
    // $(eval exprs)
    Eval(Vec<PathExpr>), // this is read again.
    /// $(filter pattern, EXPR)
    Filter(Vec<PathExpr>, Vec<PathExpr>),
    /// $(filter-out pattern, EXPR)
    FilterOut(Vec<PathExpr>, Vec<PathExpr>),
    /// $(foreach var, list, EXPR)
    /// var is replaced by each element in list
    ForEach(String, Vec<PathExpr>, Vec<PathExpr>),
    /// $(findstring pattern, EXPR)
    FindString(Vec<PathExpr>, Vec<PathExpr>),
    /// $(wildcard EXPR)
    WildCard(Vec<PathExpr>),
    /// $(strip EXPR)
    Strip(Vec<PathExpr>),
    /// $(notdir EXPR)
    NotDir(Vec<PathExpr>),
    /// $(dir EXPR)
    Dir(Vec<PathExpr>),
    /// $(abspath EXPR)
    AbsPath(Vec<PathExpr>),
    /// $(basename EXPR)
    BaseName(Vec<PathExpr>),
    /// $(format str, EXPR)
    Format(Box<PathExpr>, Vec<PathExpr>),
    /// $(realpath EXPR)
    RealPath(Vec<PathExpr>),
    /// $(word n, EXPR)
    Word(i32, Vec<PathExpr>),
    /// $(firstword EXPR)
    FirstWord(Vec<PathExpr>),
    /// $(if cond, then, else)
    If(Vec<PathExpr>, Vec<PathExpr>, Vec<PathExpr>),
    // $(call name, arg1, arg2, ...)
    Call(Vec<PathExpr>, Vec<Vec<PathExpr>>),
    // $(shell ..)
    Shell(Vec<PathExpr>),
    // $(grep-files content-pattern, glob-pattern, paths, ...)
    GrepFiles(Vec<PathExpr>, Vec<PathExpr>, Vec<PathExpr>),
}

/// represents the equality condition in if(n)eq (LHS,RHS)
#[derive(PartialEq, Debug, Clone)]
pub(crate) struct EqCond {
    pub lhs: Vec<PathExpr>,
    pub rhs: Vec<PathExpr>,
    pub not_cond: bool,
}

/// name of a variable in let expressions such as X=1 or
/// &X = 1
#[derive(PartialEq, Debug, Clone, Hash, Eq, Default, Ord, PartialOrd)]
pub(crate) struct Ident {
    pub name: String,
}

impl Display for Ident {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name.clone())
    }
}

impl Ident {
    /// create a new Ident from a string
    pub fn new(s: String) -> Ident {
        Ident { name: s }
    }

    pub fn as_str(&self) -> &str {
        self.name.as_str()
    }
}
/// variable being checked for defined
#[derive(PartialEq, Debug, Clone)]
pub(crate) struct CheckedVar {
    var: Ident,
    not_cond: bool,
}

impl CheckedVar {
    pub fn new(v: Ident, not_cond: bool) -> Self {
        Self { var: v, not_cond }
    }
    pub fn get_var(&self) -> &Ident {
        &self.var
    }
}
/// represents source of a link (tup rule)
#[derive(PartialEq, Debug, Clone, Default)]
pub(crate) struct Source {
    /// Primary inputs to rule that are available for %f substitution in rules and are read during rule execution
    pub primary: Vec<PathExpr>,
    /// inputs to be processed one by one as rule inputs
    pub for_each: bool,
    /// Secondary inputs that appear after pipe that are also read during rule execution
    pub secondary: Vec<PathExpr>,
}

/// represents target of a link (tup rule)
#[derive(PartialEq, Debug, Clone, Default)]
pub(crate) struct Target {
    /// Primary outputs of rule available for %o substition, and are written by the command that rule refers to
    pub primary: Vec<PathExpr>,
    /// Extra outputs of rule not available for %o substition, and are written by the command that rule refers to
    pub secondary: Vec<PathExpr>,
    ///  group that accumulates outputs of rule globbaly available for use in different tupfiles
    pub group: Option<PathExpr>, // this is Some(Group(_,_)) if not null
    ///  bin that accumulates outputs of a rule locally in a tupfile, this is Some(Bucket(_)) if not null
    pub bin: Option<PathExpr>,
}

#[derive(Debug, Clone, PartialEq, Default, Hash, Eq, Ord, PartialOrd)]
pub(crate) struct RuleDescription {
    pub(crate) flags: String,
    pub(crate) display_str: Vec<PathExpr>,
}

impl RuleDescription {
    pub(crate) fn get_flags(&self) -> &String {
        &self.flags
    }
    pub(crate) fn get_display_str(&self) -> &Vec<PathExpr> {
        &self.display_str
    }
}

impl RuleDescription {
    pub(crate) fn new(flags: String, display_str: Vec<PathExpr>) -> Self {
        RuleDescription { flags, display_str }
    }
}
/// formula for a tup rule
#[derive(PartialEq, Debug, Clone, Default, Hash, Eq, Ord, PartialOrd)]
pub(crate) struct RuleFormula {
    /// Description of a rule
    pub description: Option<RuleDescription>,
    /// Rule Formula  holds the command to be executed. It appears here in raw or subst-ed form but without % symbols decoded
    pub formula: Vec<PathExpr>,
}

impl RuleFormula {
    pub(crate) fn new(description: Option<RuleDescription>, formula: Vec<PathExpr>) -> Self {
        RuleFormula {
            description,
            formula,
        }
    }
    pub(crate) fn get_description(&self) -> Option<&RuleDescription> {
        self.description.as_ref()
    }
    pub(crate) fn get_formula(&self) -> &Vec<PathExpr> {
        &self.formula
    }
    pub(crate) fn get_flags(&self) -> &str {
        self.description
            .as_ref()
            .map(|d| d.get_flags().as_str())
            .unwrap_or_default()
    }
    pub(crate) fn get_description_str(&self) -> String {
        self.description
            .as_ref()
            .map(|d| d.display_str.cat())
            .unwrap_or_default()
    }
}
/// combined representation of a tup rule consisting of source/target and rule formula
#[derive(PartialEq, Debug, Clone, Default)]
pub(crate) struct Link {
    pub source: Source,
    pub target: Target,
    pub rule_formula: RuleFormula,
    pub pos: Loc,
}

/// Implement Display for a location useful for displaying error  s
impl Display for Loc {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "line:{}, span:{}->{}",
            self.get_line(),
            self.get_col(),
            self.get_col() + self.get_span()
        )
    }
}

/// Parsed statements and its location in a tupfile
#[derive(PartialEq, Debug, Clone)]
pub struct LocatedStatement {
    pub(crate) statement: Statement,
    pub(crate) loc: Loc,
}

impl LocatedStatement {
    pub(crate) fn new(stmt: Statement, l: Loc) -> LocatedStatement {
        LocatedStatement {
            statement: stmt,
            loc: l,
        }
    }
    pub(crate) fn get_statement(&self) -> &Statement {
        &self.statement
    }
    pub(crate) fn get_loc(&self) -> &Loc {
        &self.loc
    }
    pub(crate) fn is_comment(&self) -> bool {
        matches!(self.statement, Statement::Comment)
    }
    pub(crate) fn is_run(&self) -> bool {
        matches!(self.statement, Statement::Run(_))
    }
    pub(crate) fn is_preload(&self) -> bool {
        matches!(self.statement, Statement::Preload(_))
    }
}
/// List of env vars that are to be passed for rule execution
#[derive(PartialEq, Eq, Debug, Clone, Default, Hash, Ord, PartialOrd)]
pub struct Env {
    var: String,
    val: String,
}

impl Display for Env {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}={}", self.var, self.val)
    }
}
impl Env {
    /// create list of env vars from a map
    pub fn new(var: String) -> Self {
        Env {
            var: var.clone(),
            val: std::env::var(&var).unwrap_or_default(),
        }
    }

    /// create Env from variable (var) and its value(val)
    pub fn from(var: String, val: String) -> Self {
        Env { var, val }
    }

    /// returns String representation of the env var
    pub fn get_key(self) -> String {
        self.var
    }

    /// returns str representation of the env var
    pub fn get_key_str(&self) -> &str {
        self.var.as_str()
    }

    /// returns  env var's stored value
    pub fn get_val_str(&self) -> &str {
        self.val.as_str()
    }
}
/// [Condition] is a condition that is checked in if(n)eq statements or if(n)def statements
#[derive(PartialEq, Debug, Clone)]
pub(crate) enum Condition {
    EqCond(EqCond),
    CheckedVar(CheckedVar),
}
impl Condition {
    pub(crate) fn is_negation(&self) -> bool {
        match self {
            Condition::EqCond(eq) => eq.not_cond,
            Condition::CheckedVar(cv) => cv.not_cond,
        }
    }

    pub(crate) fn verify(&self, m: &ParseState) -> bool {
        let not_cond = self.is_negation();
        match self {
            Condition::EqCond(eq) => {
                let lhs = eq.lhs.cat();
                let rhs = eq.rhs.cat();
                (lhs == rhs) == !not_cond
            }
            Condition::CheckedVar(cv) => {
                let var = cv.get_var().as_str();
                let is_defined = m.is_var_defined(var);
                is_defined == !not_cond
            }
        }
    }
}
impl CleanupPaths for Condition {
    fn cleanup(&mut self) {
        match self {
            Condition::EqCond(eq) => {
                eq.lhs.cleanup();
                eq.rhs.cleanup();
            }
            _ => {}
        }
    }
}
#[derive(PartialEq, Debug, Clone)]
pub(crate) struct CondThenStatements {
    pub(crate) cond: Condition,
    pub(crate) then_statements: Vec<LocatedStatement>,
}

impl CleanupPaths for CondThenStatements {
    fn cleanup(&mut self) {
        self.cond.cleanup();
        self.cond.cleanup();
        self.then_statements.cleanup();
    }
}

#[derive(PartialEq, Debug, Clone, Default)]
pub(crate) struct TaskDetail {
    target: TaskTarget,
    deps: Vec<PathExpr>,
    body: Vec<Vec<PathExpr>>,
    search_dirs: Vec<PathDescriptor>,
}

impl TaskDetail {
    pub(crate) fn new(target: TaskTarget, deps: Vec<PathExpr>, body: Vec<Vec<PathExpr>>) -> Self {
        Self {
            target,
            deps,
            body,
            search_dirs: Vec::new(),
        }
    }

    pub(crate) fn get_target(&self) -> &TaskTarget {
        &self.target
    }
    pub(crate) fn get_deps(&self) -> &Vec<PathExpr> {
        &self.deps
    }
    pub(crate) fn get_body(&self) -> &Vec<Vec<PathExpr>> {
        &self.body
    }
    pub(crate) fn get_mut_body(&mut self) -> &mut Vec<Vec<PathExpr>> {
        &mut self.body
    }

    pub(crate) fn get_mut_deps(&mut self) -> &mut Vec<PathExpr> {
        &mut self.deps
    }

    pub(crate) fn get_search_dirs(&self) -> &Vec<PathDescriptor> {
        &self.search_dirs
    }
}

#[derive(PartialEq, Debug, Clone)]
pub(crate) enum AssignmentType {
    Immediate,
    Lazy,
    Append,
    Conditional,
}

impl AssignmentType {
    pub(crate) fn from_str<S: AsRef<str>>(s: S) -> Self {
        match s.as_ref() {
            ":=" => AssignmentType::Immediate,
            "=" => AssignmentType::Lazy,
            "+=" => AssignmentType::Append,
            "?=" => AssignmentType::Conditional,
            _ => panic!("Invalid assignment type"),
        }
    }
    pub(crate) fn to_str(&self) -> &str {
        match self {
            AssignmentType::Immediate => ":=",
            AssignmentType::Lazy => "=",
            AssignmentType::Append => "+=",
            AssignmentType::Conditional => "?=",
        }
    }
}
/// any of the valid statements that can appear in a tupfile
#[derive(PartialEq, Debug, Clone)]
pub(crate) enum Statement {
    AssignExpr {
        left: Ident,
        right: Vec<PathExpr>,
        assignment_type: AssignmentType,
    },
    IfElseEndIf {
        then_elif_statements: Vec<CondThenStatements>,
        // many if[n]eq (cond) or else if[n]eq(cond) statements that precede else or endif
        else_statements: Vec<LocatedStatement>, // final else block
    },
    IncludeRules,
    Include(Vec<PathExpr>),
    Rule(Link, EnvList, Vec<PathDescriptor>),
    Message(Vec<PathExpr>, Level),
    MacroRule(String, Link), /* !macro = [inputs] | [order-only inputs] |> command |> [outputs] */
    Export(String),
    Import(String, Option<String>),
    Preload(Vec<PathExpr>),
    //SearchDir(Vec<PathExpr>, Vec<PathExpr>),
    Run(Vec<PathExpr>),
    Comment,
    /// Define a multi-line variable
    /// define name { body }
    /// body is a list of statements
    Define(Ident, Vec<PathExpr>),
    Task(TaskDetail),
    EvalBlock(Vec<PathExpr>),
}

/// we could have used `Into' or 'ToString' trait
/// coherence rules are too strict in rust hence the trait below
pub(crate) trait Cat {
    fn cat(self) -> String;
}

pub(crate) trait CatRef {
    fn cat_ref(&self) -> Cow<str>;
}

pub(crate) trait CleanupPaths {
    fn cleanup(&mut self);
}

impl CleanupPaths for Vec<PathExpr> {
    fn cleanup(&mut self) {
        // first check if there are any cleanup operations to be done
        if self.is_empty() {
            return;
        }
        let mut needs_cleanup = self.iter().zip(self.iter().skip(1)).any(|(cur, next)| {
            // Merge adjacent literals, quoted strings and remove spaces, newlines that appear more than once
            match (cur, next) {
                (PathExpr::Quoted(_), PathExpr::Quoted(_)) => true,
                (PathExpr::Literal(_), PathExpr::Literal(_)) => true,
                (PathExpr::NL, PathExpr::NL) => true,
                (PathExpr::NL, PathExpr::Sp1) => true,
                (PathExpr::Sp1, PathExpr::NL) => true,
                (PathExpr::Sp1, PathExpr::Sp1) => true,
                _ => false,
            }
        });
        if !needs_cleanup {
            needs_cleanup = self.iter().find(|x| x.is_empty()) != None;
            if needs_cleanup {
                log::debug!("removing empty string in pelist");
            }
        }
        if needs_cleanup {
            let newpesall = self.iter().fold(Vec::new(), |mut acc, pe| {
                // Merge adjacent literals, quoted strings and remove spaces, newlines that appear more than once
                match pe {
                    PathExpr::Quoted(vs) => {
                        if let Some(PathExpr::Quoted(last)) = acc.last_mut() {
                            last.extend(vs.clone());
                        } else {
                            acc.push(pe.clone());
                        }
                    }
                    PathExpr::Literal(s) => {
                        if let Some(PathExpr::Literal(last)) = acc.last_mut() {
                            last.push_str(s);
                        } else if !s.is_empty() {
                            acc.push(pe.clone());
                        }
                    }
                    PathExpr::NL => {
                        if matches!(acc.last(), Some(PathExpr::NL)) {
                        } else {
                            acc.push(pe.clone());
                        }
                    }
                    PathExpr::Sp1 => {
                        if matches!(acc.last(), Some(PathExpr::Sp1) | Some(PathExpr::NL)) {
                            // acc.push(pe.clone());
                        } else {
                            acc.push(pe.clone());
                        }
                    }
                    _ => {
                        acc.push(pe.clone());
                    }
                };
                acc
            });
            *self = newpesall;
        }
    }
}
impl CleanupPaths for RuleFormula {
    fn cleanup(&mut self) {
        self.formula.cleanup();
    }
}

impl CleanupPaths for Link {
    fn cleanup(&mut self) {
        self.target.primary.cleanup();
        self.target.secondary.cleanup();
        self.source.primary.cleanup();
        self.source.secondary.cleanup();
        self.rule_formula.formula.cleanup();
    }
}

impl CleanupPaths for Statement {
    fn cleanup(&mut self) {
        match self {
            Statement::Rule(l, _, _) => {
                l.cleanup();
            }
            Statement::AssignExpr {
                left: _left, right, ..
            } => {
                right.cleanup();
            }
            Statement::IfElseEndIf {
                then_elif_statements,
                else_statements,
            } => {
                then_elif_statements
                    .iter_mut()
                    .for_each(CleanupPaths::cleanup);
                else_statements.cleanup();
            }
            Statement::Include(r) => {
                r.cleanup();
            }
            Statement::Message(r, _) => {
                r.cleanup();
            }
            Statement::MacroRule(_, link) => {
                link.cleanup();
            }
            Statement::Preload(v) => {
                v.cleanup();
            }
            Statement::Run(v) => {
                v.cleanup();
            }
            Statement::EvalBlock(v) => {
                v.cleanup();
            }
            Statement::Task(t) => {
                t.get_mut_body().iter_mut().for_each(CleanupPaths::cleanup);
                t.get_mut_deps().cleanup();
            }
            _ => {}
        }
    }
}
impl CleanupPaths for Vec<Statement> {
    fn cleanup(&mut self) {
        for f in self {
            f.cleanup();
        }
    }
}

impl CleanupPaths for Vec<LocatedStatement> {
    fn cleanup(&mut self) {
        for f in self {
            f.statement.cleanup();
        }
    }
}

impl From<String> for PathExpr {
    fn from(s: String) -> PathExpr {
        PathExpr::Literal(s)
    }
}

impl From<DollarExprs> for PathExpr {
    fn from(d: DollarExprs) -> PathExpr {
        PathExpr::DollarExprs(d)
    }
}

impl RuleFormula {
    pub(crate) fn new_from_parts(
        description: Option<RuleDescription>,
        mut formula: Vec<PathExpr>,
    ) -> RuleFormula {
        //description.cleanup();
        formula.cleanup();
        for pe in formula.iter() {
            if let PathExpr::Literal(s) = pe {
                if s.contains(" ") {
                    log::debug!("found space in formula");
                }
            }
        }
        RuleFormula::new(description, formula)
    }
}
impl Cat for &Statement {
    fn cat(self) -> String {
        match self {
            Statement::Rule(
                Link {
                    source: _,
                    target: _,
                    rule_formula: r,
                    pos: _,
                },
                ..,
            ) => r.cat(),
            Statement::EvalBlock(body) => body.cat(),
            _ => "".to_owned(),
        }
    }
}
impl Cat for &LocatedStatement {
    fn cat(self) -> String {
        self.statement.cat()
    }
}
