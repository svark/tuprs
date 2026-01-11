//! Writer for tup expressions and statements
use core::fmt::Formatter;
use std::borrow::Cow;
use std::fmt::Write;

use crate::statements::{
    Cat, CatRef, Condition, DollarExprs, Level, Link, LocatedStatement, PathExpr, RuleFormula,
    Source, Statement, Target,
};

impl Source {
    fn write_fmt<W: Write>(&self, f: &mut W) -> core::fmt::Result {
        if self.for_each {
            write!(f, "foreach ")?;
        }
        write_pathexprs(f, &self.primary)?;
        if !self.secondary.is_empty() {
            write!(f, " | ")?;
            write_pathexprs(f, &self.secondary)?;
        }
        Ok(())
    }
}

impl Target {
    fn write_fmt<W: Write>(&self, f: &mut W) -> core::fmt::Result {
        write_pathexprs(f, &self.primary)?;
        if !self.secondary.is_empty() {
            write!(f, " | ")?;
            write_pathexprs(f, &self.secondary)?;
        }
        Ok(())
    }
}

impl RuleFormula {
    fn write_fmt<W: Write>(&self, f: &mut W) -> core::fmt::Result {
        if self.description.is_some() {
            write!(f, "^{} ", self.get_flags())?;
            write_pathexprs(f, self.get_formula())?;
            write!(f, "^")?;
        }
        write_pathexprs(f, &self.formula)?;
        Ok(())
    }
}

impl Link {
    fn write_fmt<W: Write>(&self, f: &mut W) -> core::fmt::Result {
        write!(f, ":")?;
        self.source.write_fmt(f)?;
        write!(f, " |>")?;
        self.rule_formula.write_fmt(f)?;
        write!(f, " |> ")?;
        self.target.write_fmt(f)?;
        Ok(())
    }
}

pub(crate) fn write_pathexprs<W: Write>(
    writer: &mut W,
    pathexprs: &[PathExpr],
) -> core::fmt::Result {
    for pathexpr in pathexprs {
        write_pathexpr(writer, pathexpr)?;
    }
    Ok(())
}

pub(crate) fn write_pathexprs_lit<W: Write>(
    writer: &mut W,
    pathexprs: &[PathExpr],
) -> core::fmt::Result {
    for pathexpr in pathexprs
        .iter()
        .filter(|x| matches!(x, &PathExpr::Literal(_) | &PathExpr::DeGlob(_)))
    {
        write_pathexpr(writer, pathexpr)?;
    }
    Ok(())
}

pub(crate) fn write_pathexpr<W: Write>(writer: &mut W, pathexpr: &PathExpr) -> core::fmt::Result {
    match pathexpr {
        PathExpr::Literal(s) => {
            write!(writer, "{}", s)?;
        }
        PathExpr::NL => {
            write!(writer, "\n")?;
        }
        PathExpr::Sp1 => {
            write!(writer, " ")?;
        }
        PathExpr::Quoted(pe) => {
            write!(writer, "\"")?;
            write_pathexprs(writer, pe)?;
            write!(writer, "\"")?;
        }
        PathExpr::DollarExprs(d) => match d {
            DollarExprs::DollarExpr(v) => {
                write!(writer, "$({})", v)?;
            }
            DollarExprs::AddPrefix(p, a) => {
                write!(writer, "$(addprefix ")?;
                write_pathexprs(writer, p)?;
                write!(writer, ",")?;
                write_pathexprs(writer, a)?;
                write!(writer, ")")?;
            }
            DollarExprs::AddSuffix(s, a) => {
                write!(writer, "$(addsuffix ")?;
                write_pathexprs(writer, s)?;
                write!(writer, ",")?;
                write_pathexprs(writer, a)?;
                write!(writer, ")")?;
            }
            DollarExprs::Subst(p, r, text) => {
                write!(writer, "$(subst ")?;
                write_pathexprs(writer, p)?;
                write!(writer, ",")?;
                write_pathexprs(writer, r)?;
                write!(writer, ",")?;
                write_pathexprs(writer, text)?;
                write!(writer, ")")?;
            }
            DollarExprs::PatSubst(p, r, t) => {
                write!(writer, "$(patsubst ")?;
                write_pathexprs(writer, p)?;
                write!(writer, ",")?;
                write_pathexprs(writer, r)?;
                write!(writer, ",")?;
                write_pathexprs(writer, t)?;
                write!(writer, ")")?;
            }
            DollarExprs::Filter(f, t) => {
                write!(writer, "$(filter ")?;
                write_pathexprs(writer, f)?;
                write!(writer, ",")?;
                write_pathexprs(writer, t)?;
                write!(writer, ")")?;
            }
            DollarExprs::FilterOut(fo, t) => {
                write!(writer, "$(filter-out ")?;
                write_pathexprs(writer, fo)?;
                write!(writer, ",")?;
                write_pathexprs(writer, t)?;
                write!(writer, ")")?;
            }
            DollarExprs::ForEach(v, arr, body) => {
                write!(writer, "$(foreach ")?;
                write!(writer, "{},", v)?;
                write_pathexprs(writer, arr)?;
                write!(writer, ",")?;
                write_pathexprs(writer, body)?;
                write!(writer, ")")?;
            }
            DollarExprs::FindString(p, text) => {
                write!(writer, "$(findstring ")?;
                write_pathexprs(writer, p)?;
                write!(writer, ",")?;
                write_pathexprs(writer, text)?;
                write!(writer, ")")?;
            }
            DollarExprs::Format(spec, args) => {
                write!(writer, "$(formatpath ")?;
                write_pathexprs(writer, spec)?;
                write!(writer, ",")?;
                write_pathexprs(writer, args)?;
                write!(writer, ")")?;
            }
            DollarExprs::GroupName(groupname) => {
                write!(writer, "$(groupname ")?;
                write_pathexprs(writer, groupname)?;
                write!(writer, ")")?;
            }
            DollarExprs::WildCard(a) => {
                write!(writer, "$(wildcard ")?;
                write_pathexprs(writer, a)?;
                write!(writer, ")")?;
            }
            DollarExprs::Strip(s) => {
                write!(writer, "$(strip ")?;
                write_pathexprs(writer, s)?;
                write!(writer, ")")?;
            }
            DollarExprs::NotDir(nd) => {
                write!(writer, "$(notdir ")?;
                write_pathexprs(writer, nd)?;
                write!(writer, ")")?;
            }
            DollarExprs::Dir(d) => {
                write!(writer, "$(dir ")?;
                write_pathexprs(writer, d)?;
                write!(writer, ")")?;
            }
            DollarExprs::AbsPath(paths) => {
                write!(writer, "$(abspath ")?;
                write_pathexprs(writer, paths)?;
                write!(writer, ")")?;
            }
            DollarExprs::BaseName(path) => {
                write!(writer, "$(basename ")?;
                write_pathexprs(writer, path)?;
                write!(writer, ")")?;
            }
            DollarExprs::RealPath(paths) => {
                write!(writer, "$(realpath ")?;
                write_pathexprs(writer, paths)?;
                write!(writer, ")")?;
            }
            DollarExprs::Word(i, t) => {
                write!(writer, "$(word {},", i)?;
                write_pathexprs(writer, t)?;
                write!(writer, ")")?;
            }
            DollarExprs::FirstWord(t) => {
                write!(writer, "$(firstword ")?;
                write_pathexprs(writer, t)?;
                write!(writer, ")")?;
            }
            DollarExprs::If(cond, then_part, else_part) => {
                write!(writer, "$(if ")?;
                write_pathexprs(writer, cond)?;
                write!(writer, ",")?;
                write_pathexprs(writer, then_part)?;
                write!(writer, ",")?;
                write_pathexprs(writer, else_part)?;
                write!(writer, ")")?;
            }
            DollarExprs::Call(name, args) => {
                write!(writer, "$(call ")?;
                write_pathexprs(writer, name)?;
                for arg in args {
                    write!(writer, ",")?;
                    write_pathexprs(writer, arg)?;
                }
                write!(writer, ")")?;
            }
            DollarExprs::Eval(e) => {
                write!(writer, "$(eval ")?;
                write_pathexprs(writer, e)?;
                write!(writer, ")")?;
            }
            DollarExprs::Shell(script) => {
                write!(writer, "$(shell ")?;
                write_pathexprs(writer, script)?;
                write!(writer, ")")?;
            }
            DollarExprs::GrepFiles(content, glob) => {
                write!(writer, "$(grep-files ")?;
                write_pathexprs(writer, content)?;
                write!(writer, " ")?;
                write_pathexprs(writer, glob)?;
                write!(writer, " ")?;
                write!(writer, ")")?;
            }
            DollarExprs::Message(msg, level) => {
                match level {
                    Level::Info => {
                        write!(writer, "$(info ")?;
                    }
                    Level::Warning => {
                        write!(writer, "$(warning ")?;
                    }
                    Level::Error => {
                        write!(writer, "$(error ")?;
                    }
                }
                write_pathexprs(writer, msg)?;
                write!(writer, ")")?;
            }
            DollarExprs::StripPrefix(prefix, body) => {
                write!(writer, "$(stripprefix ")?;
                write_pathexprs(writer, prefix)?;
                write!(writer, ",")?;
                write_pathexprs(writer, body)?;
                write!(writer, ")")?;
            }
        },
        PathExpr::ExcludePattern(pattern) => {
            write!(writer, "^{}", pattern)?;
        }
        PathExpr::AtExpr(expr) => {
            write!(writer, "@({})", expr)?;
        }
        PathExpr::Group(p, name) => {
            write_pathexprs(writer, p)?;
            write!(writer, "<")?;
            write_pathexprs(writer, name)?;
            write!(writer, ">")?;
        }
        PathExpr::Bin(name) => {
            write!(writer, "{{{}}}", name)?;
        }
        PathExpr::MacroRef(macroref) => {
            write!(writer, "!{}", macroref)?;
        }
        PathExpr::DeGlob(mp) => {
            //let mp_par = mp.path_descriptor().get_parent_descriptor();
            write!(writer, "{}", mp.get_relative_path().to_string(),)?;
        }
        PathExpr::TaskRef(tref) => {
            write!(writer, "&task:/{}", tref.as_str())?;
        }
    }
    Ok(())
}

fn write_else_statements<W: Write>(
    writer: &mut W,
    else_statements: &[LocatedStatement],
    num_padding: usize,
) -> core::fmt::Result {
    if !else_statements.is_empty() {
        for _ in 0..num_padding {
            write!(writer, "    ")?;
        }
        write!(writer, "else\n")?;
        for stmt in else_statements {
            write!(writer, "{}", "    ".repeat(num_padding + 1))?;
            write_statement(writer, &stmt, num_padding + 1)?;
        }
    }
    for _ in 0..num_padding {
        write!(writer, "    ")?;
    }

    write!(writer, "endif\n")
}

impl Condition {
    pub fn write<W: Write>(&self, writer: &mut W) -> core::fmt::Result {
        match self {
            Condition::EqCond(eq) => {
                if self.is_negation() {
                    write!(writer, "ifneq (")?;
                } else {
                    write!(writer, "ifeq (")?;
                }

                write_pathexprs(writer, eq.lhs.as_slice())?;
                write!(writer, ",")?;
                write_pathexprs(writer, eq.rhs.as_slice())?;
                write!(writer, ")\n")
            }
            Condition::CheckedVar(cv) => {
                if self.is_negation() {
                    write!(writer, "ifndef {}\n", cv.get_var())
                } else {
                    write!(writer, "ifdef {}\n", cv.get_var())
                }
            }
        }
    }
}

pub(crate) fn write_statement<W: Write>(
    writer: &mut W,
    stmt: &LocatedStatement,
    num_padding: usize,
) -> core::fmt::Result {
    match stmt.get_statement() {
        Statement::AssignExpr {
            left,
            right,
            assignment_type,
        } => {
            let left_str = left.to_string();
            write!(writer, "{} {} ", left_str, assignment_type.to_str())?;
            write_pathexprs(writer, &right)?;
            write!(writer, "\n")
        }
        Statement::IfElseEndIf {
            then_elif_statements,
            else_statements,
        } => {
            let mut first = true;
            for stmt in then_elif_statements {
                if !first {
                    write!(writer, "{}", "    ".repeat(num_padding))?;
                    write!(writer, "else ")?;
                }
                log::debug!("writing condition:{:?}", stmt.cond);
                stmt.cond.write(writer)?;
                let then_stmts = &stmt.then_statements;
                write_statements(&then_stmts, writer, num_padding + 1)?;
                first = false;
            }
            write_else_statements(writer, &else_statements, num_padding)
        }
        Statement::Include(f) => {
            write!(writer, "include ")?;
            write_pathexprs(writer, f)?;
            write!(writer, "\n")
        }
        Statement::Message(e, level) => {
            if Level::Info.eq(level) {
                write!(writer, "$(info ")?;
            } else if Level::Warning.eq(level) {
                write!(writer, "$(warning ")?;
            } else {
                write!(writer, "$(error ")?;
            }
            log::debug!("message:{e:?}");
            write_pathexprs(writer, e)?;
            write!(writer, ")\n")
        }
        Statement::Define(d, v) => {
            write!(writer, "define ")?;
            write!(writer, "{}\n", d.name)?;
            for v in v.split(|x| matches!(x, PathExpr::NL)) {
                if !v.is_empty() {
                    for _ in 0..num_padding + 1 {
                        write!(writer, "    ")?;
                    }
                    write_pathexprs(writer, v)?;
                    write!(writer, "\n")?;
                }
            }
            for _ in 0..num_padding {
                write!(writer, "    ")?;
            }
            write!(writer, "endef\n")
        }
        Statement::Task(t) => {
            write!(writer, "definetask")?;
            write!(writer, " {} ", t.get_target().as_str())?;
            write!(writer, " : ")?;
            write_pathexprs(writer, t.get_deps())?;
            write!(writer, "\n")?;
            for cmd in t.get_body() {
                if cmd.is_empty() {
                    continue;
                }
                for _ in 0..num_padding + 1 {
                    write!(writer, "    ")?;
                }
                write_pathexprs(writer, cmd)?;
                write!(writer, "\n")?;
            }
            for _ in 0..num_padding {
                write!(writer, "    ")?;
            }
            write!(writer, "endtask\n")
        }
        Statement::EvalBlock(body) => {
            write_pathexprs(writer, body)?;
            write!(writer, "\n")
        }
        Statement::Export(var) => {
            write!(writer, "export {}\n", var)
        }
        Statement::Comment => {
            writeln!(writer, "#-")
        }
        Statement::Rule(l, _, _) => {
            l.write_fmt(writer)?;
            write!(writer, "\n")
        }
        Statement::Run(body) => {
            write!(writer, "run ")?;
            write_pathexprs(writer, body)?;
            write!(writer, "\n")
        }
        Statement::MacroRule(name, link) => {
            write!(writer, "!{} = ", name)?;
            link.write_fmt(writer)?;
            write!(writer, "\n")
        }
        Statement::Preload(paths) => {
            write!(writer, "preload ")?;
            write_pathexprs(writer, paths)?;
            write!(writer, "\n")
        }
        Statement::IncludeRules => {
            write!(writer, "includerules\n")
        }
        Statement::Import(name, alias) => {
            write!(writer, "import ")?;
            write!(writer, "{}", name)?;
            if let Some(alias) = alias {
                write!(writer, " as {}", alias)?;
            }
            write!(writer, "\n")
        }
        Statement::CachedConfig => {
            write!(writer, ".cached_config\n")
        }
    }
}
fn write_statements<W: Write>(
    then_stmts: &[LocatedStatement],
    writer: &mut W,
    num_padding: usize,
) -> core::fmt::Result {
    for stmt in then_stmts {
        write!(writer, "{}", "    ".repeat(num_padding))?;
        write_statement(writer, &stmt, num_padding)?;
    }
    Ok(())
}

impl Cat for &[PathExpr] {
    fn cat(self) -> String {
        let mut s = String::new();
        let _ = write_pathexprs(&mut s, self);
        s
    }
}

// only write literals to string
pub(crate) fn cat_literals(pelist: &[PathExpr]) -> String {
    let mut s = String::new();
    let _ = write_pathexprs_lit(&mut s, pelist);
    s
}

pub(crate) fn words_from_pelist(pelist: &[PathExpr]) -> Vec<String> {
    pelist
        .split(|x| matches!(x, PathExpr::Sp1 | PathExpr::NL))
        .map(|x| cat_literals(x))
        .collect()
}

pub(crate) fn for_each_word_in_pelist<F>(pelist: &[PathExpr], f: F)
where
    F: FnMut(String),
{
    pelist
        .split(|x| matches!(x, PathExpr::Sp1 | PathExpr::NL))
        .map(|x| cat_literals(x))
        .for_each(f);
}

impl Cat for &Vec<PathExpr> {
    fn cat(self) -> String {
        self.as_slice().cat()
    }
}

impl CatRef for PathExpr {
    fn cat_ref(&self) -> Cow<'_, str> {
        match self {
            PathExpr::Literal(x) => Cow::Borrowed(x.as_str()),
            _ => {
                let mut s = String::new();
                let _ = write_pathexpr(&mut s, self);
                Cow::Owned(s)
            }
        }
    }
}

impl CatRef for &[PathExpr] {
    fn cat_ref(&self) -> Cow<'_, str> {
        if self.is_empty() {
            Cow::Borrowed("")
        } else if self.len() == 1 {
            self.first().unwrap().cat_ref()
        } else {
            Cow::Owned(self.cat())
        }
    }
}

impl Cat for &RuleFormula {
    fn cat(self) -> String {
        let mut s = String::new();
        let _ = self.write_fmt(&mut s);
        s
    }
}

/// convert statements to strings for benchmarking
pub fn convert_to_str(statements: &Vec<LocatedStatement>) -> Vec<String> {
    let mut s = String::new();
    statements.iter().for_each(|x| {
        let _ = write_statement(&mut s, x, 0);
    });
    s.split_terminator('\n').map(|x| x.to_owned()).collect()
}

impl std::fmt::Display for PathExpr {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write_pathexpr(f, self)
    }
}

impl std::fmt::Display for LocatedStatement {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write_statement(f, self, 0)
    }
}
