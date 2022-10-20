use std::collections::{BTreeSet, HashMap};
use std::fmt::{Display, Formatter};

//use std::path::Path;
// rvalue typically appears on the right side of assignment statement
// in general they can be constituents of any tup expression that is not on lhs of assignment
#[derive(PartialEq, Debug, Clone)]
pub enum PathExpr {
    Literal(String), // a normal string
    Sp1,             // spaces between paths
    ExcludePattern(String),
    DollarExpr(String),                  // $(EXPR)
    AtExpr(String),                      // @(EXPR)
    AmpExpr(String),                     //&(Expr)
    Group(Vec<PathExpr>, Vec<PathExpr>), // reference to an output available globally across Tupfiles
    Bin(String),                         // {objs} a collector of output
    MacroRef(String),                    // !macro_name reference to a macro to be expanded
}

// represents the equality condition in if(n)eq (LHS,RHS)
#[derive(PartialEq, Debug, Clone)]
pub struct EqCond {
    pub lhs: Vec<PathExpr>,
    pub rhs: Vec<PathExpr>,
    pub not_cond: bool,
}

// name of a variable in let expressions such as X=1 or
// &X = 1
#[derive(PartialEq, Debug, Clone)]
pub struct Ident {
    pub name: String,
}

// variable being checked for defined
#[derive(PartialEq, Debug, Clone)]
pub struct CheckedVar(pub Ident, pub bool);

// represents source of a link (tup rule)
#[derive(PartialEq, Debug, Clone, Default)]
pub struct Source {
    pub primary: Vec<PathExpr>,
    pub for_each: bool,
    pub secondary: Vec<PathExpr>,
}

// represents target of a link (tup rule)
#[derive(PartialEq, Debug, Clone, Default)]
pub struct Target {
    pub primary: Vec<PathExpr>,
    pub secondary: Vec<PathExpr>,
    pub exclude_pattern: Option<PathExpr>,
    pub group: Option<PathExpr>, // this is Some(Group(_,_)) if not null
    pub bin: Option<PathExpr>,   // this is  Some(Bucket(_)) is not null
}
// formula for a tup rule
#[derive(PartialEq, Debug, Clone, Default)]
pub struct RuleFormula {
    pub description: Vec<PathExpr>,
    pub formula: Vec<PathExpr>,
}
// combined representation of a tup rule consisting of source/target and rule formula
#[derive(PartialEq, Debug, Clone, Default)]
pub struct Link {
    pub source: Source,
    pub target: Target,
    pub rule_formula: RuleFormula,
    pub pos: (u32, usize),
}
#[derive(PartialEq, Debug, Clone, Copy, Eq, Default)]
pub struct Loc {
    pub line: u32,
    pub offset: u32,
}
impl Display for Loc {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "line:{}, offset:{}", self.line, self.offset)
    }
}
impl Loc {
    pub fn new(line: u32, offset: u32) -> Loc {
        Loc { line, offset }
    }
    pub fn getline(&self) -> u32 {
        self.line
    }
    pub fn getoffset(&self) -> u32 {
        self.offset
    }
}

#[derive(PartialEq, Debug, Clone)]
pub struct LocatedStatement {
    pub statement: Statement,
    pub loc: Loc,
}
impl LocatedStatement {
    pub fn new(stmt: Statement, l: Loc) -> LocatedStatement {
        LocatedStatement {
            statement: stmt,
            loc: l,
        }
    }
    pub fn getstatement(&self) -> &Statement {
        &self.statement
    }

    pub fn getloc(&self) -> &Loc {
        &self.loc
    }
}
#[derive(PartialEq, Eq, Debug, Clone, Default, Hash)]
pub struct Env {
    set: BTreeSet<String>
}

 impl Env {
    pub fn new(map: HashMap<String, String>) -> Self
    {
        let mut bt = BTreeSet::new();
        map.into_iter().for_each(|v| {
            bt.insert(v.0);
        });
       Env{ set:bt}
    }
     pub fn add(&mut self, k: String) ->bool
     {
         self.set.insert(k)
     }
     pub fn contains(&self, k: &String) -> bool
     {
         self.set.contains(k)
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
impl Into<usize> for EnvDescriptor {
    fn into(self) -> usize {
        self.0
    }
}
impl Default for EnvDescriptor {
    fn default() -> Self {
        Self(usize::MAX)
    }
}

impl EnvDescriptor {
    pub fn new(i: usize) -> Self {
        Self(i)
    }
    pub fn setid(&mut self, o: &EnvDescriptor)
    {
        self.0 = o.0;
    }
}
impl Display for EnvDescriptor {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{0}({1})", stringify!($t), self.0)
    }
}

// any of the valid statements that can appear in a tupfile
#[derive(PartialEq, Debug, Clone)]
pub enum Statement {
    LetExpr {
        left: Ident,
        right: Vec<PathExpr>,
        is_append: bool,
    },
    LetRefExpr {
        left: Ident,
        right: Vec<PathExpr>,
        is_append: bool,
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
}


pub fn rule_target(statement: &LocatedStatement) -> Option<&Target> {
    if let Statement::Rule(Link { target, .. }, _) = statement.getstatement() {
        Some(target)
    } else {
        None
    }
}

pub fn rule_source(statement: &LocatedStatement) -> Option<&Source> {
    if let Statement::Rule(Link { source, .. }, _) = statement.getstatement() {
        Some(source)
    } else {
        None
    }
}

pub fn is_rule(statement: &LocatedStatement) -> bool {
    matches!(
        statement,
        LocatedStatement {
            statement: Statement::Rule(_,_),
            ..
        }
    )
}

// we could have used `Into' or 'ToString' trait
// coherence rules are too strict in rust hence the trait below
pub trait Cat {
    fn cat(self) -> String;
}

pub trait CatRef {
    fn cat_ref(&self) -> &str;
}

pub trait CleanupPaths {
    fn cleanup(&mut self);
}

impl CleanupPaths for Vec<PathExpr> {
    fn cleanup(&mut self) {
        let mut newpes: String = String::new();
        let mut newpesall = Vec::new();
        let mut was_lit = false;
        let mut was_sp = false;
        for pe in self.iter() {
            if matches!(pe, PathExpr::Literal(_)) {
                newpes += pe.cat_ref();
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
            if !matches!(pe, PathExpr::Sp1 | PathExpr::Literal(_)) {
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
                ()
            }
            Statement::LetExpr {
                left: _left, right, ..
            } => {
                right.cleanup();
                ()
            }
            Statement::LetRefExpr {
                left: _left, right, ..
            } => {
                right.cleanup();
                ()
            }
            Statement::IfElseEndIf {
                eq: _,
                then_statements,
                else_statements,
            } => {
                then_statements.cleanup();
                else_statements.cleanup();
                ()
            }
            Statement::Include(r) => {
                r.cleanup();
                ()
            }
            Statement::Err(r) => {
                r.cleanup();
                ()
            }
            Statement::MacroAssignment(_, link) => {
                link.cleanup();
                ()
            }
            Statement::Preload(v) => {
                v.cleanup();
                ()
            }
            Statement::Run(v) => {
                v.cleanup();
                ()
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
            .fold("".to_owned(), |x, y| x + y)
    }
}

// conversion to from string
impl From<String> for PathExpr {
    fn from(s: String) -> PathExpr {
        PathExpr::Literal(s)
    }
}

impl Cat for &PathExpr {
    fn cat(self) -> String {
        match self {
            PathExpr::Literal(x) => x.clone(),
            PathExpr::Sp1 => " ".to_string(),
            _ => "".to_owned(),
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

impl Cat for &Statement {
    fn cat(self) -> String {
        match self {
            Statement::Rule(Link {
                source: _,
                target: _,
                rule_formula: r,
                pos,
            }, _) => {
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
