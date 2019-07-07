use std::collections::HashMap;
use statements::*;
use parser::parse_tupfile;

pub struct SubstMap {
    pub expr_map: HashMap<String, String>,
    pub conf_map: HashMap<String, String>,
    pub rule_map: HashMap<String, Link>,
}

pub trait Subst
{
     fn subst(&self, m: &mut SubstMap) -> Self;
}

pub trait ExpandMacro
{
    fn hasref(&self) -> bool;
    fn expand(&self, m: &mut SubstMap) -> Self;
}

impl Subst for RvalGeneral {
    fn subst(&self, m: &mut SubstMap) -> Self {
        match self {
            &RvalGeneral::DollarExpr(ref x) => {
                RvalGeneral::Literal(m.expr_map
                                      .get(x.as_str())
                                      .unwrap_or(&"".to_owned())
                                      .to_string())
            }
            &RvalGeneral::AtExpr(ref x) => {
                RvalGeneral::Literal(m.conf_map
                                      .get(x.as_str())
                                      .unwrap_or(&"".to_owned())
                                      .to_string())
            }
            &RvalGeneral::Group(ref xs) => {
                RvalGeneral::Group(xs.into_iter()
                                     .map(|x| x.subst(m))
                                     .collect())
            }
            _ => self.clone(),
        }
    }
}


impl Subst for Vec<RvalGeneral> {
    fn subst(&self, m: &mut SubstMap) -> Self {
        self.iter().map(|x| x.subst(m)).collect()
    }
}
impl Subst for Source {
    fn subst(&self, m: &mut SubstMap) -> Self {
        Source {
            primary: self.primary.subst(m),
            foreach: self.foreach,
            secondary: self.secondary.subst(m),
        }
    }
}
use std::ops::AddAssign;
impl AddAssign for Source {
    fn add_assign(&mut self, other: Self) {
        let mut o = other;
        self.primary.append(&mut o.primary);
        self.secondary.append(&mut o.secondary);
        self.foreach |= o.foreach;
    }
}

impl AddAssign for Target {
    fn add_assign(&mut self, other: Self) {
        let mut o = other;
        self.primary.append(&mut o.primary);
        self.secondary.append(&mut o.secondary);
        self.tag.append(&mut o.tag);
    }
}

impl Subst for Target {
    fn subst(&self, m: &mut SubstMap) -> Self {
        Target {
            primary: self.primary.subst(m),
            secondary: self.secondary.subst(m),
            tag: self.tag.clone(),
        }
    }
}
impl Subst for RuleFormula {
    fn subst(&self, m: &mut SubstMap) -> Self {
        RuleFormula {
            description: self.description.clone(), // todo : convert to rval and subst here as well,
            formula: self.formula.subst(m),
        }
    }
}
// replace occurences of a macro ref with link data from previous assignments in namedrules
impl ExpandMacro for Link {

    fn hasref(&self) -> bool {
        for rval in self.r.formula.iter() {
            if let RvalGeneral::MacroRef(_) = *rval {
                return true;
            }
        }
        false
    }
    fn expand(&self, m: &mut SubstMap) -> Self {
        let mut source = self.s.clone();
        let mut target = self.t.clone();
        let mut desc = self.r.description.clone();
        let mut formulae = Vec::new();
        let emptylink: Link = Default::default();
        for rval in self.r.formula.iter() {
            match rval {
                &RvalGeneral::MacroRef(ref name) => {
                    let explink = m.rule_map.get(name.as_str()).unwrap_or(&emptylink);
                    source += explink.s.clone();
                    target += explink.t.clone();
                    desc += explink.r.description.as_str();
                    formulae.append(&mut explink.r.formula.clone());
                }
                _ => formulae.push(rval.clone()),
            }
        }
        Link {
            s: source,
            t: target,
            r: RuleFormula {
                description: desc,
                formula: formulae,
            },
        }
    }
}

impl Subst for Link {
    fn subst(&self, m: &mut SubstMap) -> Self {
        Link {
            s: self.s.subst(m),
            t: self.t.subst(m),
            r: self.r.subst(m),
        }
    }
}
// convert a literal to a String
fn tostr(rval: &RvalGeneral) -> String {
    match rval {
        &RvalGeneral::Literal(ref x) => x.clone(),
        _ => "".to_owned(),
    }
}
// concat string literals into a single String
fn tostr_cat(rvals: &Vec<RvalGeneral>) -> String {
    rvals.iter().map(tostr).fold("".to_owned(), |x, y| x + y.as_str())
}
// substitute variables in a sequence of statements from previous assignments
// update variable assignments into substmap as you go.
impl Subst for Vec<Statement> {
    fn subst(&self, m: &mut SubstMap) -> Vec<Statement> {
        let mut newstats = Vec::new();
        for statement in self.iter() {
            match statement {
                Statement::LetExpr{left, right, is_append} => {
                    let &app = is_append;
                    let subst_right = tostr_cat(&right.subst(m));
                    let curright = if app {
                        match m.expr_map.get(left.name.as_str()) {
                            Some(prevright) => prevright.to_string() + " " + subst_right.as_str(),
                            _ => subst_right,
                        }
                    } else {
                        subst_right
                    };
                    m.expr_map.insert(left.name.clone(), curright);
                }
                Statement::IfElseEndIf{eq, then_statements, else_statements} => {
                    let e = EqCond {
                        lhs: eq.lhs.subst(m),
                        rhs: eq.rhs.subst(m),
                        not_cond: eq.not_cond,
                    };
                    if tostr_cat(&e.lhs) == tostr_cat(&e.rhs) && !e.not_cond {
                        newstats.append(&mut then_statements.subst(m));
                    } else {
                        newstats.append(&mut else_statements.subst(m));
                    }
                }
                Statement::IncludeRules => {
                    let s = statement.clone();
                    newstats.push(s);
                }
                Statement::Include(s) => {
                    let s = s.subst(m);
                    let mut include_stmmts = parse_tupfile(tostr_cat(&s).as_str());
                    newstats.append(&mut include_stmmts.subst(m));
                }
                Statement::Rule(link) => {
                    let mut l = link.clone();
                    while l.hasref() {
                        l = l.expand(m); // expand all nested macro refs
                    }
                    newstats.push(Statement::Rule(l.subst(m)));
                }
                // dont subst inside a macro assignment
                // just update the rule_map
                Statement::MacroAssignment(name, link) => {
                    m.rule_map.insert(name.clone(), link.clone());
                }
                Statement::Err(v) => {
                    let mut v = v.subst(m);
                    eprintln!("{}\n", tostr_cat(&v).as_str());
                    break;
                }
                Statement::Preload(v) => {
                    newstats.push(Statement::Preload(v.subst(m)));
                }
                Statement::Export(ex) => {
                    newstats.push(Statement::Export(ex.subst(m)));
                }
                Statement::Run(r) => {
                    newstats.push(Statement::Export(r.subst(m)));
                }
            }
        }
        newstats
    }
}
