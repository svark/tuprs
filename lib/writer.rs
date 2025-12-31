//! Writer for tup expressions and statements
use std::borrow::Cow;
use std::io::BufWriter;
use std::io::Write;

use crate::statements::{
    Cat, CatRef, Condition, DollarExprs, Level, Link, LocatedStatement, PathExpr, RuleFormula,
    Source, Statement, Target,
};

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
        if self.description.is_some() {
            write!(f, "^{} ", self.get_flags()).unwrap();
            write_pathexprs(f, self.get_formula());
            write!(f, "^").unwrap();
        }
        write_pathexprs(f, &self.formula);
    }
}

impl Link {
    fn write_fmt<W: Write>(&self, f: &mut BufWriter<W>) {
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

pub(crate) fn write_pathexprs_lit<T: Write>(writer: &mut BufWriter<T>, pathexprs: &[PathExpr]) {
    pathexprs
        .iter()
        .filter(|x| matches!(x, &PathExpr::Literal(_) | &PathExpr::DeGlob(_)))
        .for_each(|pathexpr| {
            write_pathexpr(writer, pathexpr);
        })
}

pub(crate) fn write_pathexpr<T: Write>(writer: &mut BufWriter<T>, pathexpr: &PathExpr) {
    match pathexpr {
        PathExpr::Literal(s) => {
            write!(writer, "{}", s).unwrap();
        }
        PathExpr::NL => {
            write!(writer, "\n").unwrap();
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
                write!(writer, ",").unwrap();
                write_pathexprs(writer, a);
                write!(writer, ")").unwrap();
            }
            DollarExprs::AddSuffix(s, a) => {
                write!(writer, "$(addsuffix ").unwrap();
                write_pathexprs(writer, s);
                write!(writer, ",").unwrap();
                write_pathexprs(writer, a);
                write!(writer, ")").unwrap();
            }
            DollarExprs::Subst(p, r, text) => {
                write!(writer, "$(subst ").unwrap();
                write_pathexprs(writer, p);
                write!(writer, ",").unwrap();
                write_pathexprs(writer, r);
                write!(writer, ",").unwrap();
                write_pathexprs(writer, text);
                write!(writer, ")").unwrap();
            }
            DollarExprs::PatSubst(p, r, t) => {
                write!(writer, "$(patsubst ").unwrap();
                write_pathexprs(writer, p);
                write!(writer, ",").unwrap();
                write_pathexprs(writer, r);
                write!(writer, ",").unwrap();
                write_pathexprs(writer, t);
                write!(writer, ")").unwrap();
            }
            DollarExprs::Filter(f, t) => {
                write!(writer, "$(filter ").unwrap();
                write_pathexprs(writer, f);
                write!(writer, ",").unwrap();
                write_pathexprs(writer, t);
                write!(writer, ")").unwrap();
            }
            DollarExprs::FilterOut(fo, t) => {
                write!(writer, "$(filter-out ").unwrap();
                write_pathexprs(writer, fo);
                write!(writer, ",").unwrap();
                write_pathexprs(writer, t);
                write!(writer, ")").unwrap();
            }
            DollarExprs::ForEach(v, arr, body) => {
                write!(writer, "$(foreach ").unwrap();
                write!(writer, "{},", v).unwrap();
                write_pathexprs(writer, arr);
                write!(writer, ",").unwrap();
                write_pathexprs(writer, body);
                write!(writer, ")").unwrap();
            }
            DollarExprs::FindString(p, text) => {
                write!(writer, "$(findstring ").unwrap();
                write_pathexprs(writer, p);
                write!(writer, ",").unwrap();
                write_pathexprs(writer, text);
                write!(writer, ")").unwrap();
            }
            DollarExprs::Format(spec, args) => {
                write!(writer, "$(formatpath ").unwrap();
                write_pathexprs(writer, spec);
                write!(writer, ",").unwrap();
                write_pathexprs(writer, args);
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
                write!(writer, "$(word {},", i).unwrap();
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
                write!(writer, ",").unwrap();
                write_pathexprs(writer, then_part);
                write!(writer, ",").unwrap();
                write_pathexprs(writer, else_part);
                write!(writer, ")").unwrap();
            }
            DollarExprs::Call(name, args) => {
                write!(writer, "$(call ").unwrap();
                write_pathexprs(writer, name);
                for arg in args {
                    write!(writer, ",").unwrap();
                    write_pathexprs(writer, arg);
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
            DollarExprs::GrepFiles(content, glob) => {
                write!(writer, "$(grep-files ").unwrap();
                write_pathexprs(writer, content);
                write!(writer, " ").unwrap();
                write_pathexprs(writer, glob);
                write!(writer, " ").unwrap();
                write!(writer, ")").unwrap();
            }
            DollarExprs::Message(msg, level) => {
                match level {
                    Level::Info => {
                        write!(writer, "$(info ").unwrap();
                    }
                    Level::Warning => {
                        write!(writer, "$(warning ").unwrap();
                    }
                    Level::Error => {
                        write!(writer, "$(error ").unwrap();
                    }
                }
                write_pathexprs(writer, msg);
                write!(writer, ")").unwrap();
            }
            DollarExprs::StripPrefix(prefix, body) => {
                write!(writer, "$(stripprefix ").unwrap();
                write_pathexprs(writer, prefix);
                write!(writer, ",").unwrap();
                write_pathexprs(writer, body);
                write!(writer, ")").unwrap();
            }
        },
        PathExpr::ExcludePattern(pattern) => {
            write!(writer, "^{}", pattern).unwrap();
        }
        PathExpr::AtExpr(expr) => {
            write!(writer, "@({})", expr).unwrap();
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
            //let mp_par = mp.path_descriptor().get_parent_descriptor();
            write!(writer, "{}", mp.get_relative_path().to_string(),).unwrap();
        }
        PathExpr::TaskRef(tref) => {
            write!(writer, "&task:/{}", tref.as_str()).unwrap();
        }
    }
}

fn write_else_statements<T: Write>(
    writer: &mut BufWriter<T>,
    else_statements: &[LocatedStatement],
    num_padding: usize,
) {
    if !else_statements.is_empty() {
        for _ in 0..num_padding {
            write!(writer, "    ").unwrap();
        }
        write!(writer, "else\n").unwrap();
        for stmt in else_statements {
            write!(writer, "{}", "    ".repeat(num_padding + 1)).unwrap();
            write_statement(writer, &stmt, num_padding + 1);
        }
    }
    for _ in 0..num_padding {
        write!(writer, "    ").unwrap();
    }

    write!(writer, "endif\n").unwrap();
}

impl Condition {
    pub fn write<T: Write>(&self, buf_writer: &mut BufWriter<T>) {
        match self {
            Condition::EqCond(eq) => {
                if self.is_negation() {
                    buf_writer.write_all(b"ifneq (").unwrap();
                } else {
                    buf_writer.write_all(b"ifeq (").unwrap();
                }

                write_pathexprs(buf_writer, eq.lhs.as_slice());
                buf_writer.write_all(b",").unwrap();
                write_pathexprs(buf_writer, eq.rhs.as_slice());
                buf_writer.write_all(b")\n").unwrap();
            }
            Condition::CheckedVar(cv) => {
                if self.is_negation() {
                    write!(buf_writer, "ifndef {}\n", cv.get_var()).unwrap();
                } else {
                    write!(buf_writer, "ifdef {}\n", cv.get_var()).unwrap();
                }
            }
        }
    }
}

pub(crate) fn write_statement<T: Write>(
    writer: &mut BufWriter<T>,
    stmt: &LocatedStatement,
    num_padding: usize,
) {
    match stmt.get_statement() {
        Statement::AssignExpr {
            left,
            right,
            assignment_type,
        } => {
            let left_str = left.to_string();
            write!(writer, "{} {} ", left_str, assignment_type.to_str()).unwrap();
            write_pathexprs(writer, &right);
            write!(writer, "\n").unwrap();
        }
        Statement::IfElseEndIf {
            then_elif_statements,
            else_statements,
        } => {
            let mut first = true;
            for stmt in then_elif_statements {
                if !first {
                    write!(writer, "{}", "    ".repeat(num_padding)).unwrap();
                    write!(writer, "else ").unwrap();
                }
                log::debug!("writing condition:{:?}", stmt.cond);
                stmt.cond.write(writer);
                let then_stmts = &stmt.then_statements;
                write_statements(&then_stmts, writer, num_padding + 1);
                first = false;
            }
            write_else_statements(writer, &else_statements, num_padding);
        }
        Statement::Include(f) => {
            write!(writer, "include ").unwrap();
            write_pathexprs(writer, f);
            write!(writer, "\n").unwrap();
        }
        Statement::Message(e, level) => {
            if Level::Info.eq(level) {
                write!(writer, "$(info ").unwrap();
            } else if Level::Warning.eq(level) {
                write!(writer, "$(warning ").unwrap();
            } else {
                write!(writer, "$(error ").unwrap();
            }
            log::debug!("message:{e:?}");
            write_pathexprs(writer, e);
            write!(writer, ")\n").unwrap();
        }
        Statement::Define(d, v) => {
            write!(writer, "define ").unwrap();
            write!(writer, "{}\n", d.name).unwrap();
            v.split(|x| matches!(x, PathExpr::NL)).for_each(|v| {
                if v.cat().is_empty() {
                } else {
                    for _ in 0..num_padding + 1 {
                        write!(writer, "    ").unwrap();
                    }
                    write_pathexprs(writer, v);
                    write!(writer, "\n").unwrap();
                }
            });
            for _ in 0..num_padding {
                write!(writer, "    ").unwrap();
            }
            write!(writer, "endef\n").unwrap();
        }
        Statement::Task(t) => {
            write!(writer, "definetask").unwrap();
            write!(writer, " {} ", t.get_target().as_str()).unwrap();
            write!(writer, " : ").unwrap();
            write_pathexprs(writer, t.get_deps());
            write!(writer, "\n").unwrap();
            for cmd in t.get_body() {
                if cmd.is_empty() {
                    continue;
                }
                for _ in 0..num_padding + 1 {
                    write!(writer, "    ").unwrap();
                }
                write_pathexprs(writer, cmd);
                write!(writer, "\n").unwrap();
            }
            for _ in 0..num_padding {
                write!(writer, "    ").unwrap();
            }
            write!(writer, "endtask\n").unwrap();
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
        Statement::CachedConfig => {
            write!(writer, ".cached_config\n").unwrap();
        }
    }
}
fn write_statements<T: Write>(
    then_stmts: &[LocatedStatement],
    writer: &mut BufWriter<T>,
    num_padding: usize,
) {
    for stmt in then_stmts {
        write!(writer, "{}", "    ".repeat(num_padding)).unwrap();
        write_statement(writer, &stmt, num_padding);
    }
}

impl Cat for &[PathExpr] {
    fn cat(self) -> String {
        let mut s: Vec<u8> = Vec::new();
        write_pathexprs(&mut BufWriter::new(&mut s), self);
        std::str::from_utf8(&s).unwrap().to_string()
    }
}

// only write literals to string
pub(crate) fn cat_literals(pelist: &[PathExpr]) -> String {
    let mut s: Vec<u8> = Vec::new();
    write_pathexprs_lit(&mut BufWriter::new(&mut s), pelist);
    std::str::from_utf8(&s).unwrap().to_string()
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
                let mut s: Vec<u8> = Vec::new();
                write_pathexpr(&mut BufWriter::new(&mut s), self);
                Cow::Owned(std::str::from_utf8(&s).unwrap().to_string())
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
        let buf: Vec<u8> = Vec::new();
        let mut writer = BufWriter::new(buf);
        self.write_fmt(&mut writer);
        std::str::from_utf8(writer.buffer()).unwrap().to_string()
    }
}

/// convert statements to strings for benchmarking
pub fn convert_to_str(statements: &Vec<LocatedStatement>) -> Vec<String> {
    let mut o: Vec<u8> = Vec::new();
    let mut buffered_writer = BufWriter::new(&mut o);
    statements.iter().for_each(|x| {
        write_statement(&mut buffered_writer, x, 0);
    });
    std::str::from_utf8(buffered_writer.buffer())
        .unwrap()
        .split_terminator('\n')
        .map(|x| x.to_owned())
        .collect()
}
