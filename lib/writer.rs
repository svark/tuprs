//! Writer for tup expressions and statements
use std::borrow::Cow;
use std::io::BufWriter;
use std::io::Write;

use crate::statements::{
    Cat, CatRef, DollarExprs, Level, Link, LocatedStatement, PathExpr, RuleFormula, Source,
    Statement, Target,
};
use crate::transform;

impl Source {
    fn write_fmt<W: Write>(&self, f: &mut BufWriter<W>) {
        if self.for_each {
            write!(f, "foreach ").unwrap();
        }
        write_pathexprs(f, &self.primary);
        if self.secondary.len() > 0 {
            write!(f, " | ").unwrap();
            write_pathexprs(f, &self.secondary);
        }
    }
}

impl Target {
    fn write_fmt<W: Write>(&self, f: &mut BufWriter<W>) {
        write_pathexprs(f, &self.primary);
        if self.secondary.len() > 0 {
            write!(f, " | ").unwrap();
            write_pathexprs(f, &self.secondary);
        }
    }
}

impl RuleFormula {
    fn write_fmt<W: Write>(&self, f: &mut BufWriter<W>) {
        if self.description.len() > 0 {
            write!(f, "^").unwrap();
            write_pathexprs(f, &self.description);
            write!(f, "^").unwrap();
        }
        write_pathexprs(f, &self.formula);
    }
}

impl Link {
    fn write_fmt<W: std::io::Write>(&self, f: &mut BufWriter<W>) {
        write!(f, ":").unwrap();
        self.source.write_fmt(f);
        write!(f, " |>").unwrap();
        self.rule_formula.write_fmt(f);
        write!(f, " |> ").unwrap();
        self.target.write_fmt(f);
    }
}

pub(crate) fn write_pathexprs<T: Write>(writer: &mut BufWriter<T>, pathexprs: &[PathExpr]) {
    pathexprs.iter().for_each(|pathexpr| {
        write_pathexpr(writer, pathexpr);
    })
}

pub(crate) fn write_pathexpr<T: Write>(writer: &mut BufWriter<T>, pathexpr: &PathExpr) {
    match pathexpr {
        PathExpr::Literal(s) => {
            write!(writer, "{}", s).unwrap();
        }
        PathExpr::Sp1 => {
            write!(writer, " ").unwrap();
        }
        PathExpr::Quoted(pe) => {
            write!(writer, "\"").unwrap();
            write_pathexprs(writer, pe);
            write!(writer, "\"").unwrap();
        }
        PathExpr::DollarExprs(d) => match d {
            DollarExprs::DollarExpr(v) => {
                write!(writer, "$({})", v).unwrap();
            }
            DollarExprs::AddPrefix(p, a) => {
                write!(writer, "$(addprefix ").unwrap();
                write_pathexprs(writer, p);
                write!(writer, ", ").unwrap();
                write_pathexprs(writer, a);
                write!(writer, ")").unwrap();
            }
            DollarExprs::AddSuffix(s, a) => {
                write!(writer, "$(addsuffix ").unwrap();
                write_pathexprs(writer, s);
                write!(writer, ", ").unwrap();
                write_pathexprs(writer, a);
                write!(writer, ")").unwrap();
            }
            DollarExprs::Subst(p, r, text) => {
                write!(writer, "$(subst ").unwrap();
                write_pathexprs(writer, p);
                write!(writer, ", ").unwrap();
                write_pathexprs(writer, r);
                write!(writer, ", ").unwrap();
                write_pathexprs(writer, text);
                write!(writer, ")").unwrap();
            }
            DollarExprs::PatSubst(p, r, t) => {
                write!(writer, "$(patsubst ").unwrap();
                write_pathexprs(writer, p);
                write!(writer, ", ").unwrap();
                write_pathexprs(writer, r);
                write!(writer, ", ").unwrap();
                write_pathexprs(writer, t);
                write!(writer, ")").unwrap();
            }
            DollarExprs::Filter(f, t) => {
                write!(writer, "$(filter ").unwrap();
                write_pathexprs(writer, f);
                write!(writer, ", ").unwrap();
                write_pathexprs(writer, t);
                write!(writer, ")").unwrap();
            }
            DollarExprs::FilterOut(fo, t) => {
                write!(writer, "$(filter-out ").unwrap();
                write_pathexprs(writer, fo);
                write!(writer, ", ").unwrap();
                write_pathexprs(writer, t);
                write!(writer, ")").unwrap();
            }
            DollarExprs::ForEach(v, arr, body) => {
                write!(writer, "$(foreach ").unwrap();
                write!(writer, "{}, ", v).unwrap();
                write_pathexprs(writer, arr);
                write!(writer, ", ").unwrap();
                write_pathexprs(writer, body);
                write!(writer, ")").unwrap();
            }
            DollarExprs::FindString(p, text) => {
                write!(writer, "$(findstring ").unwrap();
                write_pathexprs(writer, p);
                write!(writer, ", ").unwrap();
                write_pathexprs(writer, text);
                write!(writer, ")").unwrap();
            }
            DollarExprs::WildCard(a) => {
                write!(writer, "$(wildcard ").unwrap();
                write_pathexprs(writer, a);
                write!(writer, ")").unwrap();
            }
            DollarExprs::Strip(s) => {
                write!(writer, "$(strip ").unwrap();
                write_pathexprs(writer, s);
                write!(writer, ")").unwrap();
            }
            DollarExprs::NotDir(nd) => {
                write!(writer, "$(notdir ").unwrap();
                write_pathexprs(writer, nd);
                write!(writer, ")").unwrap();
            }
            DollarExprs::Dir(d) => {
                write!(writer, "$(dir ").unwrap();
                write_pathexprs(writer, d);
                write!(writer, ")").unwrap();
            }
            DollarExprs::AbsPath(paths) => {
                write!(writer, "$(abspath ").unwrap();
                write_pathexprs(writer, paths);
                write!(writer, ")").unwrap();
            }
            DollarExprs::BaseName(path) => {
                write!(writer, "$(basename ").unwrap();
                write_pathexprs(writer, path);
                write!(writer, ")").unwrap();
            }
            DollarExprs::RealPath(paths) => {
                write!(writer, "$(realpath ").unwrap();
                write_pathexprs(writer, paths);
                write!(writer, ")").unwrap();
            }
            DollarExprs::Word(i, t) => {
                write!(writer, "$(word {}, ", i).unwrap();
                write_pathexprs(writer, t);
                write!(writer, ")").unwrap();
            }
            DollarExprs::FirstWord(t) => {
                write!(writer, "$(firstword ").unwrap();
                write_pathexprs(writer, t);
                write!(writer, ")").unwrap();
            }
            DollarExprs::If(cond, then_part, else_part) => {
                write!(writer, "$(if ").unwrap();
                write_pathexprs(writer, cond);
                write!(writer, ", ").unwrap();
                write_pathexprs(writer, then_part);
                write!(writer, ", ").unwrap();
                write_pathexprs(writer, else_part);
                write!(writer, ")").unwrap();
            }
            DollarExprs::Call(name, args) => {
                write!(writer, "$(call ").unwrap();
                write_pathexprs(writer, name);
                write!(writer, ", ").unwrap();
                for arg in args {
                    write_pathexprs(writer, arg);
                    write!(writer, ", ").unwrap();
                }
                write!(writer, ")").unwrap();
            }
            DollarExprs::Eval(e) => {
                write!(writer, "$(eval ").unwrap();
                write_pathexprs(writer, e);
                write!(writer, ")").unwrap();
            }
            DollarExprs::Shell(script) => {
                write!(writer, "$(shell ").unwrap();
                write_pathexprs(writer, script);
                write!(writer, ")").unwrap();
            }
        },
        PathExpr::ExcludePattern(pattern) => {
            write!(writer, "^{}", pattern).unwrap();
        }
        PathExpr::AtExpr(expr) => {
            write!(writer, "@({})", expr).unwrap();
        }
        PathExpr::AmpExpr(expr) => {
            write!(writer, "&({})", expr).unwrap();
        }
        PathExpr::Group(p, name) => {
            write_pathexprs(writer, p);
            write!(writer, "<").unwrap();
            write_pathexprs(writer, name);
            write!(writer, ">").unwrap();
        }
        PathExpr::Bin(name) => {
            write!(writer, "{{{}}}", name).unwrap();
        }
        PathExpr::MacroRef(macroref) => {
            write!(writer, "!{}", macroref).unwrap();
        }
        PathExpr::DeGlob(mp) => {
            let mp = transform::get_path_with_fsep(mp.get_path());
            write!(writer, "{}", mp.to_cow_str()).unwrap();
        }
        PathExpr::TaskRef(tref) => {
            write!(writer, "&task:/{}", tref.as_str()).unwrap();
        }
    }
}

pub(crate) fn write_statement<T: std::io::Write>(
    writer: &mut BufWriter<T>,
    stmt: &LocatedStatement,
) {
    match stmt.get_statement() {
        Statement::AssignExpr {
            left,
            right,
            is_append,
            is_empty_assign,
        } => {
            let left_str = left.to_string();
            if *is_append {
                write!(writer, "{} += ", left_str).unwrap();
            } else if *is_empty_assign {
                write!(writer, "{} ?= ", left_str).unwrap();
            } else {
                write!(writer, "{} = ", left_str).unwrap();
            }
            write_pathexprs(writer, &right);
            write!(writer, "\n").unwrap();
        }
        Statement::IfElseEndIf {
            then_elif_statements,
            else_statements,
        } => {
            for stmt in then_elif_statements {
                if stmt.eq.not_cond {
                    write!(writer, "ifneq ").unwrap();
                } else {
                    write!(writer, "ifeq ").unwrap();
                }
                write_pathexprs(writer, &stmt.eq.lhs);
                write!(writer, ", ").unwrap();
                write_pathexprs(writer, &stmt.eq.rhs);
                write!(writer, "\n").unwrap();
                for stmt in &stmt.then_statements {
                    write!(writer, "    ").unwrap();
                    write_statement(writer, &stmt);
                }
            }
            if !else_statements.is_empty() {
                write!(writer, "else\n").unwrap();
                for stmt in else_statements {
                    write!(writer, "    ").unwrap();
                    write_statement(writer, &stmt);
                }
            }
            write!(writer, "endif\n").unwrap();
        }
        Statement::IfDef {
            checked_var_then_statements,
            else_statements,
        } => {
            for stmt in checked_var_then_statements {
                let ifclause = if stmt.checked_var.is_not_cond() {
                    "ifndef"
                } else {
                    "ifdef"
                };
                write!(writer, "{} {}\n", ifclause, stmt.checked_var.get_var()).unwrap();
                for stmt in &stmt.then_statements {
                    write!(writer, "    ").unwrap();
                    write_statement(writer, &stmt);
                }
            }
            if !else_statements.is_empty() {
                write!(writer, "else\n").unwrap();
                for stmt in else_statements {
                    write!(writer, "    ").unwrap();
                    write_statement(writer, &stmt);
                }
            }
            write!(writer, "endif\n").unwrap();
        }
        Statement::Include(f) => {
            write!(writer, "include ").unwrap();
            write_pathexprs(writer, f);
            write!(writer, "\n").unwrap();
        }
        Statement::Message(pe, e) => {
            if e.eq(&Level::Info) {
                write!(writer, "$(info ").unwrap();
            } else if e.eq(&Level::Warning) {
                write!(writer, "$(warning ").unwrap();
            } else if e.eq(&Level::Error) {
                write!(writer, "$(error ").unwrap();
            }
            write_pathexprs(writer, pe);
            write!(writer, ")\n").unwrap();
        }
        Statement::SearchPaths(paths) => {
            write!(writer, "preload ").unwrap();
            write_pathexprs(writer, paths);
            write!(writer, "\n").unwrap();
        }
        Statement::Define(d, v) => {
            write!(writer, "define ").unwrap();
            write!(writer, "{}\n", d.name).unwrap();
            write!(writer, "{}\n", v).unwrap();
            write!(writer, "endef\n").unwrap();
        }
        Statement::Task(t) => {
            write!(writer, "definetask").unwrap();
            write!(writer, " {} ", t.get_target().name).unwrap();
            write!(writer, " : ").unwrap();
            write_pathexprs(writer, t.get_deps());
            write!(writer, "\n").unwrap();
            for cmd in t.get_body() {
                write!(writer, "\t").unwrap();
                write_pathexprs(writer, cmd);
                write!(writer, "\n").unwrap();
            }
            write!(writer, "endef\n").unwrap();
        }
        Statement::EvalBlock(body) => {
            write_pathexprs(writer, body);
            write!(writer, "\n").unwrap();
        }
        Statement::Export(var) => {
            write!(writer, "export {}\n", var).unwrap();
        }
        Statement::Comment => {
            writeln!(writer, "#-").unwrap();
        }
        Statement::Rule(l, _, _) => {
            l.write_fmt(writer);
            write!(writer, "\n").unwrap();
        }
        Statement::Run(body) => {
            write!(writer, "run ").unwrap();
            write_pathexprs(writer, body);
            write!(writer, "\n").unwrap();
        }
        Statement::AsignRefExpr {
            left,
            right,
            is_append,
            is_empty_assign,
        } => {
            write!(writer, "&{}", left.name).unwrap();
            if *is_append {
                write!(writer, " += ").unwrap();
            } else if *is_empty_assign {
                write!(writer, " ?= ").unwrap();
            } else {
                write!(writer, " = ").unwrap();
            }
            write_pathexprs(writer, &right);
            write!(writer, "\n").unwrap();
        }
        Statement::MacroRule(name, link) => {
            write!(writer, "!{} = ", name).unwrap();
            link.write_fmt(writer);
            write!(writer, "\n").unwrap();
        }
        Statement::Preload(paths) => {
            write!(writer, "preload ").unwrap();
            write_pathexprs(writer, paths);
            write!(writer, "\n").unwrap();
        }
        Statement::IncludeRules => {
            write!(writer, "includerules\n").unwrap();
        }
        Statement::Import(name, alias) => {
            write!(writer, "import ").unwrap();
            write!(writer, "{}", name).unwrap();
            if let Some(alias) = alias {
                write!(writer, " as {}", alias).unwrap();
            }
            write!(writer, "\n").unwrap();
        }
    }
}

impl Cat for &[PathExpr] {
    fn cat(self) -> String {
        let mut s: Vec<u8> = Vec::new();
        write_pathexprs(&mut BufWriter::new(&mut s), self);
        std::str::from_utf8(&s).unwrap().to_string()
    }
}

impl Cat for &Vec<PathExpr> {
    fn cat(self) -> String {
        self.as_slice().cat()
    }
}

impl CatRef for PathExpr {
    fn cat_ref(&self) -> Cow<str> {
        match self {
            PathExpr::Literal(x) => Cow::Borrowed(x.as_str()),
            _ => {
                let mut s: Vec<u8> = Vec::new();
                write_pathexpr(&mut BufWriter::new(&mut s), self);
                Cow::Owned(std::str::from_utf8(&s).unwrap().to_string())
            }
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

/// convert statements to strings for benchmarking
pub fn convert_to_str(statements: &Vec<LocatedStatement>) -> Vec<String> {
    let mut o: Vec<u8> = Vec::new();
    let mut buffered_writer = BufWriter::new(&mut o);
    statements.iter().for_each(|x| {
        write_statement(&mut buffered_writer, x);
    });
    std::str::from_utf8(buffered_writer.buffer())
        .unwrap()
        .split_terminator('\n')
        .map(|x| x.to_owned())
        .collect()
}
