//use std::path::Path;
// rvalue typically appears on the right side of assignment statement
// in general they can be constituents of any tup expression that is not on lhs of assignment
#[derive(PartialEq, Debug, Clone)]
pub enum PathExpr {
    Literal(String), // a normal string
    Sp1,             // spaces between paths
    ExcludePattern(String),
    DollarExpr(String),                  // this is dollar expr eg $(EXPR)
    AtExpr(String),                      // @(EXPR)
    AmpExpr(String),                     //&(Expr)
    Group(Vec<PathExpr>, Vec<PathExpr>), // reference to an output available globally
    Bucket(String),                      // {objs} a collector of output
    MacroRef(String),                    // !cc_name reference to a macro to be expanded
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
    pub description: String,
    //   pub macroref: Option<PathExpr>,
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
        then_statements: Vec<Statement>,
        else_statements: Vec<Statement>,
    },
    IfDef {
        checked_var: CheckedVar,
        then_statements: Vec<Statement>,
        else_statements: Vec<Statement>,
    },
    IncludeRules,
    Include(Vec<PathExpr>),
    Rule(Link),
    Err(Vec<PathExpr>),
    MacroAssignment(String, Link), /* !macro = [inputs] | [order-only inputs] |> command |> [outputs] */
    Export(String),
    Import(String, Option<String>),
    Preload(Vec<PathExpr>),
    Run(Vec<PathExpr>),
    Comment,
}
// we could have used `Into' or 'ToString' trait
// coherence rules are too strict in rust hence the trait below
pub trait Cat {
    fn cat(self) -> String;
}

pub trait CatRef {
    fn cat_ref(&self) -> &str;
}

pub trait StripTrailingWs {
    fn strip_trailing_ws(&mut self);
}

impl StripTrailingWs for Vec<PathExpr> {
    fn strip_trailing_ws(&mut self) {
        if let Some(PathExpr::Sp1) = self.last() {
            self.pop();
        }
    }
}
impl StripTrailingWs for RuleFormula {
    fn strip_trailing_ws(&mut self) {
        self.formula.strip_trailing_ws();
    }
}

impl StripTrailingWs for Link {
    fn strip_trailing_ws(&mut self) {
        self.target.primary.strip_trailing_ws();
        self.target.secondary.strip_trailing_ws();
        self.source.primary.strip_trailing_ws();
        self.source.secondary.strip_trailing_ws();
        self.rule_formula.formula.strip_trailing_ws();
    }
}

impl StripTrailingWs for Statement {
    fn strip_trailing_ws(&mut self) {
        match self {
            Statement::Rule(l) => {
                l.strip_trailing_ws();
                ()
            }
            Statement::LetExpr {
                left: _left, right, ..
            } => {
                right.strip_trailing_ws();
                ()
            }
            Statement::LetRefExpr {
                left: _left, right, ..
            } => {
                right.strip_trailing_ws();
                ()
            }
            Statement::IfElseEndIf {
                eq: _,
                then_statements,
                else_statements,
            } => {
                then_statements.strip_trailing_ws();
                else_statements.strip_trailing_ws();
                ()
            }
            Statement::Include(r) => {
                r.strip_trailing_ws();
                ()
            }
            Statement::Err(r) => {
                r.strip_trailing_ws();
                ()
            }
            Statement::MacroAssignment(_, link) => {
                link.strip_trailing_ws();
                ()
            }
            Statement::Preload(v) => {
                v.strip_trailing_ws();
                ()
            }
            Statement::Run(v) => {
                v.strip_trailing_ws();
                ()
            }
            _ => (),
        }
    }
}
impl StripTrailingWs for Vec<Statement> {
    fn strip_trailing_ws(&mut self) {
        for f in self {
            f.strip_trailing_ws();
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
            }) => {
                let mut desc: String = r.description.clone();
                let formula: String = r.formula.cat();
                desc += formula.as_str();
                desc + ":" + pos.0.to_string().as_str() + "," + pos.1.to_string().as_str()
            }
            _ => "".to_owned(),
        }
    }
}
