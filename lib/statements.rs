//! This module has datastructures that capture parsed tupfile expressions
use std::collections::{BTreeSet, HashMap};
use std::fmt::{Display, Formatter};
use std::hash::Hasher;
use std::path::Path;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Program(String);
impl Program {
    pub fn new(s: String) -> Self {
        Self(s)
    }
}
impl nom::AsBytes for Program {
    fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}


//use std::path::Path;
// rvalue typically appears on the right side of assignment statement
// in general they can be constituents of any tup expression that is not on lhs of assignment
#[derive(PartialEq, Debug, Clone, Hash, Eq)]
pub(crate) enum PathExpr {
    /// a normal string
    Literal(String),
    /// spaces between paths
    Sp1,
    /// Quoted string
    Quoted(Vec<PathExpr>),
    /// Exclude patterns to avoid  passing some inputs or tracking some outputs
    ExcludePattern(String),
    /// Include patterns to filter inputs
    IncludePattern(String),
    /// $(EXPR)
    DollarExprs(DollarExprs),
    ///  @(EXPR)
    AtExpr(String),
    /// &(Expr)
    AmpExpr(String),
    /// reference to an output available globally across Tupfiles
    Group(Vec<PathExpr>, Vec<PathExpr>),
    ///  {objs} a collector of output
    Bin(String),
    /// !macro_name reference to a macro to be expanded
    MacroRef(String),
}
/// Variable tracking location of Statement (usually a rule) in a Tupfile
/// see also [RuleRef] that keeps track of file in which the location is referred
#[derive(PartialEq, Debug, Clone, Copy, Eq, Default, Hash)]
pub(crate) struct FineLoc {
    line: u32,
    col: u32,
    span: u32,
}

impl FineLoc {
    pub fn get_line(&self) -> u32 {
        self.line
    }
    pub fn get_col(&self) -> u32 {
        self.col
    }
    pub fn get_span(&self) -> u32 {
        self.span
    }

    pub(crate) fn new(line: u32, col: u32, span: u32) -> FineLoc {
        FineLoc{ line, col, span}
    }
}



impl From<crate::parser::Span<'_>> for FineLoc {
    fn from(span: crate::parser::Span) -> FineLoc {
        FineLoc { line: span.location_line(), col: span.location_offset() as _,
            span: span.fragment().len() as u32 }
    }
}

#[derive(Clone)]
pub(crate) struct Continuation(Arc<dyn Fn(&[PathExpr]) -> Vec<PathExpr>>, FineLoc);
impl Continuation {
    pub fn new(s: crate::parser::Span) -> Continuation {
        Self { 1: s.into(), ..Default::default()}
    }

    pub fn get(&self) -> &dyn Fn(&[PathExpr]) -> Vec<PathExpr> {
        self.0.as_ref()
    }

    pub fn from(func: impl Fn(&[PathExpr]) -> Vec<PathExpr>, loc: FineLoc) -> Continuation {
       Self {0: Arc::new(func), 1:loc}
    }

    pub fn composed_from(func: impl Fn(&[PathExpr]) -> Vec<PathExpr>, outer: &Continuation) -> Continuation {
        let mut c = Self {0: Arc::new(func), 1:outer.1.clone()};
        c.compose(outer.get());
        c
    }

    pub fn compose(&mut self, func: impl Fn(&[PathExpr]) -> Vec<PathExpr>) {
        let old = self.0.clone().as_ref();
        self.0 = Arc::new(move |x| func(&*old(x)))
    }

    pub fn apply1(&self, path: &PathExpr) -> Vec<PathExpr> {
        (self.0)(std::slice::from_ref(path))
    }

    pub fn apply(&self, paths: &[PathExpr]) -> Vec<PathExpr> {
        (self.0)(paths)
    }

    pub fn get_loc(&self) -> FineLoc {
        self.1
    }
}

impl std::hash::Hash for Continuation {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.1.hash(state)
    }
}

impl Default for Continuation {
    fn default() -> Self {
        Self { 0: Arc::new(|x| x.to_vec()), 1: FineLoc::default()}
    }
}
impl PartialEq for Continuation {
    fn eq(&self, other: &Self) -> bool {
        //todo!()
        self.1 == other.1
    }
    fn ne(&self, other: &Self) -> bool {
        self.1 != other.1
    }
}
impl Eq for Continuation {

}

impl std::fmt::Debug for Continuation {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(" at line {} col {} span {}", self.1.line, self.1.col, self.1.span))
    }
}

#[derive(PartialEq, Debug, Clone, Hash, Eq)]
pub(crate) enum DollarExprs {
    /// $(EXPR)
    DollarExpr(String, Continuation),
/// $(addprefix prefix, EXPR)
    /// prefix is added to each path in EXPR
    AddPrefix(Vec<PathExpr>, Vec<PathExpr>, Continuation),
    /// $(addsuffix suffix, EXPR)
    /// suffix is added to each path in EXPR
    AddSuffix(Vec<PathExpr>, Vec<PathExpr>, Continuation),
    /// $(subst from, to, EXPR)
    Subst(Vec<PathExpr>, Vec<PathExpr>, Vec<PathExpr>, Continuation),
    /// $(patsubst pattern, replacement, EXPR) --- pattern is a wildcard pattern with %p, replacement is a string
    PatSubst(Vec<PathExpr>, Vec<PathExpr>, Vec<PathExpr>, Continuation),
    /// $(filter pattern, EXPR)
    Filter(Vec<PathExpr>, Vec<PathExpr>, Continuation),
    /// $(filter-out pattern, EXPR)
    FilterOut(Vec<PathExpr>, Vec<PathExpr>, Continuation),
    /// $(foreach var, list, EXPR)
    /// var is replaced by each element in list
    ForEach(String, Vec<PathExpr>, Vec<PathExpr>, Continuation),
    /// $(findstring pattern, EXPR)
    FindString(Vec<PathExpr>, Vec<PathExpr>, Continuation),
    /// $(wildcard EXPR)
    WildCard(Vec<PathExpr>, Continuation),
    /// $(strip EXPR)
    Strip(Vec<PathExpr>, Continuation),
    /// $(notdir EXPR)
    NotDir(Vec<PathExpr>, Continuation),
    /// $(dir EXPR)
    Dir(Vec<PathExpr>, Continuation),
    /// $(abspath EXPR)
    AbsPath(Vec<PathExpr>, Continuation),
    /// $(basename EXPR)
    BaseName(Vec<PathExpr>, Continuation),
    /// $(realpath EXPR)
    RealPath(Vec<PathExpr>, Continuation),
    /// $(word n, EXPR)
    Word(i32, Vec<PathExpr>, Continuation),
    /// $(firstword EXPR)
    FirstWord(Vec<PathExpr>, Continuation),
    /// $(if cond, then, else)
    If(Vec<PathExpr>, Vec<PathExpr>, Vec<PathExpr>, Continuation),
    // $(call name, arg1, arg2, ...)
    Call(Vec<PathExpr>, Vec<Vec<PathExpr>>, Continuation),
    // $(eval body)
    Eval(EvalBody, Continuation),
    // deferred evaluation of a list of path expressions
    Deferred(Vec<PathExpr>, Continuation),
}

#[derive(PartialEq, Debug, Clone, Hash, Eq)]
pub(crate) struct EvalBody {
    pes: Vec<PathExpr>,
    raw: Program,
}

impl AsRef<str> for Program {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

impl EvalBody {
    pub  fn new(pes: Vec<PathExpr>, raw: String) -> Self {
        Self { pes, raw: Program::new(raw)}
    }
   pub fn as_str(&self) -> &str {
        self.raw.as_ref()
    }
    pub fn get_first(&self) -> Option<&PathExpr> {
        self.pes.first()
    }
    pub fn get_body(&self) -> &Program {
        &self.raw
    }
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
#[derive(PartialEq, Debug, Clone)]
pub(crate) struct Ident {
    pub name: String,
}

impl ToString for Ident {
    fn to_string(&self) -> String {
        self.name.clone()
    }
}
/// variable being checked for defined
#[derive(PartialEq, Debug, Clone)]
pub(crate) struct CheckedVar(pub Ident, pub bool);

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
/// formula for a tup rule
#[derive(PartialEq, Debug, Clone, Default, Hash, Eq)]
pub(crate) struct RuleFormula {
    /// Description of a rule
    pub description: Vec<PathExpr>,
    /// Rule Formula  holds the command to be executed. It appears here in raw or subst-ed form but without % symbols decoded
    pub formula: Vec<PathExpr>,
}
/// combined representation of a tup rule consisting of source/target and rule formula
#[derive(PartialEq, Debug, Clone, Default)]
pub(crate) struct Link {
    pub source: Source,
    pub target: Target,
    pub rule_formula: RuleFormula,
    pub pos: (u32, usize),
}

pub type Loc = FineLoc;
/// Implement Display for a location useful for displaying error  s
impl Display for FineLoc {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "line:{},  begin:{}, end:{}", self.get_line(), self.get_col(), self.get_col() + self.get_span())
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
}
/// List of env vars that are to be passed for rule execution
#[derive(PartialEq, Eq, Debug, Clone, Default, Hash)]
pub struct Env {
    set: BTreeSet<String>,
}

impl Env {
    /// create list of env vars from a map
    pub fn new(map: HashMap<String, String>) -> Self {
        let mut bt = BTreeSet::new();
        map.into_iter().for_each(|v| {
            bt.insert(v.0);
        });
        Env { set: bt }
    }
    /// add an env var (note: we don't keep the values corresponding to keys as it is just a function call away)
    pub fn add(&mut self, k: String) -> bool {
        self.set.insert(k)
    }
    /// check if key is present in the set of env vars
    pub fn contains(&self, k: &str) -> bool {
        self.set.contains(k)
    }
    /// returns a map of env name and value pairs
    pub fn getenv(&self) -> HashMap<String, String> {
        let mut hmap = HashMap::new();
        for var in self.set.iter() {
            hmap.insert(var.to_string(), std::env::var(var).unwrap_or_default());
        }
        hmap
    }
    /// return a set of env vars
    pub fn get_keys(&self) -> &BTreeSet<String> {
        &self.set
    }
    /// returns value of env var if present
    pub fn get_env_var(&self, k: &str) -> Option<String> {
        if self.contains(k) {
            Some(std::env::var(k).unwrap_or_default())
        } else {
            None
        }
    }
}
/// ```EnvDescriptor``` is a unique id to current environment for a rule
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct EnvDescriptor(usize);
impl From<usize> for EnvDescriptor {
    fn from(i: usize) -> Self {
        Self(i)
    }
}
impl From<EnvDescriptor> for usize {
    fn from(e: EnvDescriptor) -> Self {
        e.0
    }
}
impl Default for EnvDescriptor {
    fn default() -> Self {
        Self(usize::MAX)
    }
}

impl EnvDescriptor {
    /// create EnvDescriptor from usize
    pub fn new(i: usize) -> Self {
        Self(i)
    }
    /// copy id from other
    pub fn setid(&mut self, o: &EnvDescriptor) {
        self.0 = o.0;
    }
}
impl Display for EnvDescriptor {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{0}({1})", stringify!($t), self.0)
    }
}

/// any of the valid statements that can appear in a tupfile
#[derive(PartialEq, Debug, Clone)]
pub(crate) enum Statement {
    LetExpr {
        left: Ident,
        right: Vec<PathExpr>,
        is_append: bool,
        is_empty_assign: bool,
    },
    LetRefExpr {
        left: Ident,
        right: Vec<PathExpr>,
        is_append: bool,
        is_empty_assign: bool,
    },
    IfElseEndIf {
        eq: EqCond,
        then_statements: Vec<LocatedStatement>,
        else_statements: Vec<LocatedStatement>,
    },
    IfDef {
        checked_var: CheckedVar,
        then_statements: Vec<LocatedStatement>,
        else_statements: Vec<LocatedStatement>,
    },
    IncludeRules,
    Include(Vec<PathExpr>),
    Rule(Link, EnvDescriptor),
    Err(Vec<PathExpr>),
    MacroAssignment(String, Link), /* !macro = [inputs] | [order-only inputs] |> command |> [outputs] */
    Export(String),
    Import(String, Option<String>),
    Preload(Vec<PathExpr>),
    Run(Vec<PathExpr>),
    Comment,
    GitIgnore,
    /// Define a multi-line variable
    /// define name { body }
    /// body is a list of statements
    Define(Ident, String),
    /// Evaluate a Vec of PathExpr
    DollarBlock(Vec<PathExpr>),
}

// we could have used `Into' or 'ToString' trait
// coherence rules are too strict in rust hence the trait below
pub(crate) trait Cat {
    fn cat(self) -> String;
}

pub(crate) trait CatRef {
    fn cat_ref(&self) -> &str;
}

pub(crate) trait CleanupPaths {
    fn cleanup(&mut self);
}

impl CleanupPaths for Vec<PathExpr> {
    // merges adjacent literals into one. Adjacent literals show up usually after substitution.
    fn cleanup(&mut self) {
        let mut newpes: String = String::new();
        let mut newpesall = Vec::new();
        let mut was_lit = false;
        let mut was_sp = false;
        for pe in self.iter() {
            if let PathExpr::Quoted(vs) = pe {
                let mut vs = vs.clone();
                vs.cleanup();
                newpesall.push(PathExpr::Quoted(vs));
                newpes = "".to_string();
                was_lit = false;
            } else if matches!(pe, PathExpr::Literal(_)) {
                let s = pe.cat_ref();
                newpes += s;
                was_lit = true;
            } else if was_lit {
                newpesall.push(PathExpr::Literal(newpes));
                newpes = "".to_string();
                was_lit = false;
            }
            if matches!(pe, PathExpr::Sp1) {
                was_sp = true;
            } else if was_sp {
                newpesall.push(PathExpr::Sp1);
            }
            if !matches!(
                pe,
                PathExpr::Sp1 | PathExpr::Literal(_) | PathExpr::Quoted(_)
            ) {
                newpesall.push(pe.clone());
            }
        }
        if was_lit {
            newpesall.push(PathExpr::Literal(newpes));
        }
        *self = newpesall;
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
            Statement::Rule(l, _) => {
                l.cleanup();
            }
            Statement::LetExpr {
                left: _left, right, ..
            } => {
                right.cleanup();
            }
            Statement::LetRefExpr {
                left: _left, right, ..
            } => {
                right.cleanup();
            }
            Statement::IfElseEndIf {
                eq: _,
                then_statements,
                else_statements,
            } => {
                then_statements.cleanup();
                else_statements.cleanup();
            }
            Statement::Include(r) => {
                r.cleanup();
            }
            Statement::Err(r) => {
                r.cleanup();
            }
            Statement::MacroAssignment(_, link) => {
                link.cleanup();
            }
            Statement::Preload(v) => {
                v.cleanup();
            }
            Statement::Run(v) => {
                v.cleanup();
            }
            _ => (),
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
impl Cat for &Vec<PathExpr> {
    fn cat(self) -> String {
        self.iter()
            .map(|x| x.cat_ref())
            .fold(String::new(), |x, y| x + y)
    }
}

// conversion to from string
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

impl Cat for &PathExpr {
    fn cat(self) -> String {
        match self {
            PathExpr::Literal(x) => x.clone(),
            PathExpr::Sp1 => " ".to_string(),
            PathExpr::Quoted(v) => format!("\"{}\"", v.cat()),
            PathExpr::Group(p, g) => format!("{}<{}>", p.cat(), g.cat()),
            _ => String::new(),
        }
    }
}

impl CatRef for PathExpr {
    fn cat_ref(&self) -> &str {
        match self {
            PathExpr::Literal(x) => x.as_str(),
            PathExpr::Sp1 => " ",
            _ => "",
        }
    }
}
impl Cat for &RuleFormula {
    fn cat(self) -> String {
        if self.description.is_empty() {
            self.formula.cat()
        } else {
            format!("^{}^ {}", self.description.cat(), self.formula.cat())
        }
    }
}
impl RuleFormula {
    #[allow(dead_code)]
    pub(crate) fn new(description: String, formula: String) -> RuleFormula {
        RuleFormula {
            description: vec![PathExpr::from(description)],
            formula: vec![PathExpr::from(formula)],
        }
    }
    pub(crate) fn new_from_parts(
        description: Vec<PathExpr>,
        formula: Vec<PathExpr>,
    ) -> RuleFormula {
        RuleFormula {
            description,
            formula,
        }
    }
    /// Create a RuleFormula from combined string representing both description and command
    /// in the form ^ desc^ command
    #[allow(dead_code)]
    pub(crate) fn new_from_raw(combined_formula: &str) -> RuleFormula {
        let mut sz = 0;
        let desc = if let Some(display_str) = combined_formula.strip_prefix('^') {
            if let Some(an) = display_str.find('^') {
                sz = an;
                combined_formula[1..an].to_owned()
            } else {
                String::new()
            }
        } else {
            String::new()
        };
        let formula = combined_formula[sz..].to_owned();
        RuleFormula::new(desc, formula)
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
                    pos,
                },
                _,
            ) => {
                let mut desc: String = r.description.cat();
                let formula: String = r.formula.cat();
                desc += formula.as_str();
                desc + ":" + pos.0.to_string().as_str() + "," + pos.1.to_string().as_str()
            }
            _ => "".to_owned(),
        }
    }
}
impl Cat for &LocatedStatement {
    fn cat(self) -> String {
        self.statement.cat()
    }
}
