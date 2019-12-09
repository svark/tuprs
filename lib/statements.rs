// rvalue typically appears on the right side of assignment statement
// in general they can be constituents of any tup expression that is not on lhs of assignment
#[derive(PartialEq, Debug, Clone)]
pub enum RvalGeneral {
    Literal(String),         // a normal string
    DollarExpr(String),      // this is dollar expr eg $(EXPR)
    AtExpr(String),          // @(EXPR)
    AmpExpr(String),         //&(Expr)
    Group(Vec<RvalGeneral>), // reference to an output available globally
    Bucket(String),          // {objs} a collector of output
    MacroRef(String),        // !cc_name reference to a macro to be expanded
}

// represents the equality condition in if(n)eq (LHS,RHS)
#[derive(PartialEq, Debug, Clone)]
pub struct EqCond {
    pub lhs: Vec<RvalGeneral>,
    pub rhs: Vec<RvalGeneral>,
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
    pub primary: Vec<RvalGeneral>,
    pub foreach: bool,
    pub secondary: Vec<RvalGeneral>,
}

// represents target of a link (tup rule)
#[derive(PartialEq, Debug, Clone, Default)]
pub struct Target {
    pub primary: Vec<RvalGeneral>,
    pub secondary: Vec<RvalGeneral>,
    pub tag: Vec<RvalGeneral>,
}
// formula for a tup rule
#[derive(PartialEq, Debug, Clone, Default)]
pub struct RuleFormula {
    pub description: String,
    pub formula: Vec<RvalGeneral>,
}
// combined representation of a tup rule consisting of source/target and rule formula
#[derive(PartialEq, Debug, Clone, Default)]
pub struct Link {
    pub s: Source,
    pub t: Target,
    pub r: RuleFormula,
    pub pos: (u32, usize),
}
// any of the valid statements that can appear in a tupfile
#[derive(PartialEq, Debug, Clone)]
pub enum Statement {
    LetExpr {
        left: Ident,
        right: Vec<RvalGeneral>,
        is_append: bool,
    },
    LetRefExpr {
        left: Ident,
        right: Vec<RvalGeneral>,
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
    Include(Vec<RvalGeneral>),
    Rule(Link),
    Err(Vec<RvalGeneral>),
    MacroAssignment(String, Link), /* !macro = [inputs] | [order-only inputs] |> command |> [outputs] */
    Export(Vec<RvalGeneral>),
    Preload(Vec<RvalGeneral>),
    Run(Vec<RvalGeneral>),
    Comment(String),
}
// we could have used `Into' or 'ToString' trait
// coherence rules are too strict in rust hence the trait below
pub trait Cat {
    fn cat(self) -> String;
}

pub trait CatRef {
    fn cat_ref(&self) -> &str;
}

impl Cat for &Vec<RvalGeneral> {
    fn cat(self) -> String {
        self.iter()
            .map(|x| x.cat_ref())
            .fold("".to_owned(), |x, y| x + y)
    }
}

// conversion to from string
impl From<String> for RvalGeneral {
    fn from(s: String) -> RvalGeneral {
        RvalGeneral::Literal(s)
    }
}

impl Cat for &RvalGeneral {
    fn cat(self) -> String {
        match self {
            RvalGeneral::Literal(x) => x.clone(),
            _ => "".to_owned(),
        }
    }
}

impl CatRef for RvalGeneral {
    fn cat_ref(&self) -> &str {
        match self {
            RvalGeneral::Literal(x) => x.as_str(),
            _ => "",
        }
    }
}

impl Cat for Statement {
    fn cat(self) -> String {
        match self {
            Statement::Rule(Link {
                s: _,
                t: _,
                r,
                pos,
            }) => {
                let mut desc: String = r.description.into();
                let formula: String = r
                    .formula
                    .iter()
                    .map(|x| x.cat_ref())
                    .fold("".to_owned(), |x, y| x + y);
                desc += formula.as_str();
                desc + ":" +  pos.0.to_string().as_str() + "," + pos.1.to_string().as_str()
            }
            _ => "".to_owned(),
        }
    }
}
