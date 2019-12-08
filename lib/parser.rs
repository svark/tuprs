// promote a string into a tup variable
use nom::character::complete::{line_ending, multispace0, multispace1, not_line_ending, space1};
use nom::combinator::{complete, cut, map, map_res, not, opt, peek};
use nom::error::{context, ErrorKind};
use nom::multi::{many0, many_till};
use nom::sequence::{delimited, preceded};
use nom::AsBytes;
use nom::Err;
use nom::IResult;
use nom::{
    branch::alt,
    bytes::complete::{is_not, tag, take, take_until, take_while},
    character::complete::{char, one_of},
};
use nom_locate::{position, LocatedSpan};
use statements::*;
type Span<'a> = LocatedSpan<&'a [u8]>;
fn to_lval(name: String) -> Ident {
    Ident { name: name }
}
fn from_utf8(s: Span) -> Result<String, std::str::Utf8Error> {
    std::str::from_utf8(s.as_bytes()).map(|x| x.to_owned())
}

// convert byte str to RvalGeneral::Literal
fn from_str(res: Span) -> Result<RvalGeneral, std::str::Utf8Error> {
    from_utf8(res).map(|s| RvalGeneral::Literal(s))
}
// check if char is part of an identifier (lhs of var assignment)
fn is_ident(c: u8) -> bool {
    nom::character::is_alphanumeric(c) || c == b'_'
}

fn is_ident_perc(c: u8) -> bool {
    nom::character::is_alphanumeric(c) || c == b'_' || c == b'%'
}

fn ws1(input: Span) -> IResult<Span, Span> {
    alt((
        preceded(tag("\\"), line_ending),
        multispace1,
        map(peek(one_of("<{")), |_| Span::new(b"".as_ref())),
    ))(input)
}

// read a space or blackslash newline continuation
fn sp1(input: Span) -> IResult<Span, Span> {
    alt((complete(preceded(tag("\\"), line_ending)), space1))(input)
}

// parse rvalue wrapped inside dollar or at
fn parse_rvalue_raw(input: Span) -> IResult<Span, String> {
    let (s, _) = alt((tag("$("), tag("@("), tag("&(")))(input)?;
    let (s, r) = take_while(is_ident_perc)(s)?;
    let (s, _) = tag(")")(s)?;
    let raw = std::str::from_utf8(r.as_bytes()).unwrap();
    Ok((s, raw.to_owned()))
}

// read a ! followed by macro name
fn parse_rvalue_raw_excl(i: Span) -> IResult<Span, String> {
    let (s, _) = opt(sp1)(i)?;
    let (s, _) = tag("!")(s)?;
    let (s, r) = take_while(is_ident)(s)?;
    let raw = std::str::from_utf8(r.as_bytes()).unwrap();
    Ok((s, raw.to_owned()))
}

// read a curly brace and the identifier inside it
fn parse_rvalue_raw_bucket(i: Span) -> IResult<Span, String> {
    let (s, _) = tag("{")(i)?;
    let (s, r) = take_while(is_ident)(s)?;
    let (s, _) = tag("}")(s)?;
    let raw = std::str::from_utf8(r.as_bytes()).unwrap();
    Ok((s, raw.to_owned()))
}

// read '<' and the list of rvals inside it until '>'
fn parse_rvalue_raw_angle(i: Span) -> IResult<Span, Vec<RvalGeneral>> {
    let (s, _) = context("group", tag("<"))(i)?;
    let (r, v) = parse_rvalgeneral_list_long(s, ">")?;
    Ok((r, v.0))
}
// parse rvalue at expression eg $(H) for config vars
fn parse_rvalue_at(i: Span) -> IResult<Span, RvalGeneral> {
    context(
        "config(@) expression",
        cut(map(parse_rvalue_raw, |rv| {
            RvalGeneral::AtExpr(rv.to_owned())
        })),
    )(i)
}
// parse rvalue dollar expression eg $(H)
fn parse_rvalue_dollar(i: Span) -> IResult<Span, RvalGeneral> {
    context(
        "dollar expression",
        cut(map(parse_rvalue_raw, |s| {
            RvalGeneral::DollarExpr(s.to_owned())
        })),
    )(i)
}

// parse rvalue dollar expression eg $(H)
fn parse_rvalue_amp(i: Span) -> IResult<Span, RvalGeneral> {
    context(
        "ampersand expression",
        cut(map(parse_rvalue_raw, |rv| {
            RvalGeneral::AmpExpr(rv.to_owned())
        })),
    )(i)
}

fn parse_rvalue_exclamation(i: Span) -> IResult<Span, RvalGeneral> {
    context(
        "macro",
        cut(map(parse_rvalue_raw_excl, |rv| {
            RvalGeneral::MacroRef(rv.to_owned())
        })),
    )(i)
}

fn parse_rvalue_angle(i: Span) -> IResult<Span, RvalGeneral> {
    context(
        "group",
        cut(map(parse_rvalue_raw_angle, |rv| RvalGeneral::Group(rv))),
    )(i)
}

// parse to a bucket name: {objs}
fn parse_rvalue_bucket(i: Span) -> IResult<Span, RvalGeneral> {
    context(
        "bin",
        cut(map(parse_rvalue_raw_bucket, |rv| RvalGeneral::Bucket(rv))),
    )(i)
}

// parse to any of the special expressions (dollar, at, angle, bucket)
pub fn parse_rvalue(i: Span) -> IResult<Span, RvalGeneral> {
    let (s, r) = peek(take(1 as usize))(i)?;
    match r.as_bytes() {
        b"$" => parse_rvalue_dollar(s),
        b"@" => parse_rvalue_at(s),
        b"&" => parse_rvalue_amp(s),
        b"<" => parse_rvalue_angle(s),
        b"{" => parse_rvalue_bucket(s),
        b"!" => parse_rvalue_exclamation(s),
        _ => Err(Err::Error(error_position!(i, ErrorKind::Eof))),
    }
}

// eat up the (dollar or at) that dont parse to (dollar or at) expression
fn parse_delim<'a>(i: Span<'a>) -> nom::IResult<Span<'a>, Span<'a>> {
    let (s, _) = peek(one_of("$@!<#&"))(i)?;
    let (s, _) = not(parse_rvalue)(s)?;
    let (s, r) = take(1 as usize)(s)?;
    Ok((s, r))
}

// read  a rvalue until delimiter
// in addition, \\\n , $,@, ! also pause the parsing
fn parse_greedy<'a, 'b>(input: Span<'a>, delim: &'b str) -> nom::IResult<Span<'a>, Span<'a>> {
    let mut s = String::from("\\\n$@{<!#&");
    s.push_str(delim);
    alt((
        map(preceded(tag("\\"), line_ending), |_| default_inp()),
        parse_delim,
        is_not(s.clone().as_str()),
        // take(1 as usize) // not sure why we need to clone there, compiler errors otherwise
    ))(input)
}
// parse either (dollar|at|curly|angle|exclamation) expression or a general rvalue delimited by delimb
fn parse_rvalgeneral<'a, 'b>(s: Span<'a>, delim: &'b str) -> nom::IResult<Span<'a>, RvalGeneral> {
    alt((
        complete(preceded(opt(sp1), parse_rvalue)),
        complete(map_res(|i| parse_greedy(i, delim), from_str)),
    ))(s)
}

// repeatedly invoke the rvalue parser until eof or delim is encountered
fn parse_rvalgeneral_list_long<'a, 'b>(
    input: Span<'a>,
    delim: &'b str,
) -> nom::IResult<Span<'a>, (Vec<RvalGeneral>, Span<'a>)> {
    many_till(|i| parse_rvalgeneral(i, delim), tag(delim))(input)
}
//  wrapper over the previous parser that handles empty inputs and stops at newline;
fn parse_rvalgeneral_list(input: Span) -> IResult<Span, (Vec<RvalGeneral>, Span)> {
    alt((
        // complete(map(eof, |_| (Vec::new(), Span::new(b"".as_ref())))),
        complete(map(
            delimited(multispace0, line_ending, multispace0),
            |_| (Vec::new(), Span::new(b"".as_ref())),
        )),
        complete(|i| parse_rvalgeneral_list_long(i, "\n")),
    ))(input)
}

fn parse_rvalgeneral_list_sp(input: Span) -> nom::IResult<Span, (Vec<RvalGeneral>, Span)> {
    many_till(
        |i| parse_rvalgeneral(i, " \t\r\n{<"), // avoid reading tags , newlines, spaces
        ws1,
    )(input)
}

// wrapper over the previous that handles empty inputs and stops at newline
fn parse_rvalgeneral_list_until_space(input: Span) -> IResult<Span, (Vec<RvalGeneral>, Span)> {
    alt((
        complete(map(peek(one_of("\r\n{<")), |_| {
            (Vec::new(), Span::new(b"".as_ref()))
        })),
        complete(parse_rvalgeneral_list_sp),
    ))(input)
}

// parse a lvalue ref to a ident
fn parse_lvalue_ref(input: Span) -> IResult<Span, Ident> {
    let (s, _) = char('&')(input)?;
    parse_lvalue(s)
}
// parse a lvalue to a ident
fn parse_lvalue(input: Span) -> IResult<Span, Ident> {
    map(map_res(take_while(is_ident), from_utf8), to_lval)(input)
}

// parse include expression
fn parse_include(i: Span) -> IResult<Span, Statement> {
    let (s, _) = multispace0(i)?;
    let (s, _) = tag("include")(s)?;
    let (s, _) = sp1(s)?;
    let (s, r) = context("include statement", cut(parse_rvalgeneral_list))(s)?;
    Ok((s, Statement::Include(r.0)))
}
// parse error expression
fn parse_error(i: Span) -> IResult<Span, Statement> {
    let (s, _) = multispace0(i)?;
    let (s, _) = tag("error")(s)?;
    let (s, _) = sp1(s)?;
    let (s, r) = context("error expression", cut(parse_rvalgeneral_list))(s)?;
    Ok((s, Statement::Err(r.0)))
}

// parse export expression
fn parse_export(i: Span) -> IResult<Span, Statement> {
    let (s, _) = multispace0(i)?;
    let (s, _) = tag("export")(s)?;
    let (s, _) = sp1(s)?;
    let (s, r) = context("export expression", cut(parse_rvalgeneral_list))(s)?;
    Ok((s, Statement::Export(r.0)))
}

// parse preload expression
fn parse_preload(i: Span) -> IResult<Span, Statement> {
    let (s, _) = multispace0(i)?;
    let (s, _) = tag("preload")(s)?;
    let (s, _) = sp1(s)?;
    let (s, r) = context("preload expression", cut(parse_rvalgeneral_list))(s)?;
    Ok((s, Statement::Preload(r.0)))
}

// parse the run expresssion
fn parse_run(i: Span) -> IResult<Span, Statement> {
    let (s, _) = multispace0(i)?;
    let (s, _) = tag("run")(s)?;
    let (s, _) = sp1(s)?;
    let (s, r) = context("run expression", cut(parse_rvalgeneral_list))(s)?;
    Ok((s, Statement::Run(r.0)))
}
// parse include_rules expresssion
fn parse_include_rules(i: Span) -> IResult<Span, Statement> {
    let (s, _) = multispace0(i)?;
    let (s, _) = tag("include_rules")(s)?;
    let (s, _) = context("include_rules", cut(multispace0))(s)?;
    Ok((s, Statement::IncludeRules))
}

// parse comment expresssion
fn parse_comment(i: Span) -> IResult<Span, Statement> {
    let (s, _) = multispace0(i)?;
    let (s, _) = tag("#")(s)?;
    let (s, r) = context("comment", cut(map_res(not_line_ending, from_utf8)))(s)?;
    Ok((s, Statement::Comment(r.to_owned())))
}

// parse an assignment expression
fn parse_let_expr(i: Span) -> IResult<Span, Statement> {
    let (s, _) = multispace0(i)?;
    let (s, l) = parse_lvalue(s)?;
    let (s, _) = opt(sp1)(s)?;
    let (s, op) = alt((complete(tag("=")), complete(tag(":=")), complete(tag("+="))))(s)?;
    let (s, _) = opt(sp1)(s)?;
    let (s, r) = complete(parse_rvalgeneral_list)(s)?;
    Ok((
        s,
        Statement::LetExpr {
            left: l,
            right: r.0,
            is_append: (op.as_bytes() == b"+="),
        },
    ))
}

// parse an assignment expression
fn parse_letref_expr(i: Span) -> IResult<Span, Statement> {
    let (s, _) = multispace0(i)?;
    let (s, l) = parse_lvalue_ref(s)?;
    let (s, _) = opt(sp1)(s)?;
    let (s, op) = alt((complete(tag("=")), complete(tag(":=")), complete(tag("+="))))(s)?;
    let (s, _) = opt(sp1)(s)?;
    let (s, r) = complete(parse_rvalgeneral_list)(s)?;
    Ok((
        s,
        Statement::LetRefExpr {
            left: l,
            right: r.0,
            is_append: (op.as_bytes() == b"+="),
        },
    ))
}
// parse description insude a rule (between ^^)
fn parse_rule_description(i: Span) -> IResult<Span, String> {
    let (s, _) = multispace0(i)?;
    let (s, _) = tag("^")(s)?;
    let (s, r) = context("rule description", cut(map_res(take_until("^"), from_utf8)))(s)?;
    let (s, _) = tag("^")(s)?;
    let (s, _) = multispace0(s)?;
    Ok((s, String::from(r)))
}
// parse the insides of a rule, which includes a description and rule formula
fn parse_rule_gut(i: Span) -> IResult<Span, RuleFormula> {
    let (s, desc) = opt(parse_rule_description)(i)?;
    let (s, formula) = parse_rvalgeneral_list_long(s, "|")?;
    Ok((
        s,
        RuleFormula {
            description: desc.unwrap_or(String::from("")),
            formula: formula.0,
        },
    ))
}

// convert the inputs to a rule to 'Source' struct
fn from_input(primary: Vec<RvalGeneral>, foreach: bool, secondary: Vec<RvalGeneral>) -> Source {
    Source {
        primary: primary,
        foreach: foreach,
        secondary: secondary,
    }
}
// convert the output to a rule to 'Target' struct
fn from_output(
    primary: Vec<RvalGeneral>,
    secondary: Vec<RvalGeneral>,
    tag: Vec<RvalGeneral>,
) -> Target {
    Target {
        primary: primary,
        secondary: secondary,
        tag: tag,
    }
}

fn default_inp<'a>() -> Span<'a> {
    Span::new(b"")
}
// parse a rule expression
// : [foreach] [inputs] [ | order-only inputs] |> command |> [outputs] [ | extra outputs] [<group>] [{bin}]
fn parse_secondary_inp(i: Span) -> IResult<Span, (Vec<RvalGeneral>, Span)> {
    let (s, _) = tag("|")(i)?;
    let (s, _) = opt(sp1)(s)?;
    parse_rvalgeneral_list_long(s, "|")
}
pub fn parse_rule(i: Span) -> IResult<Span, Statement> {
    let (s, _) = multispace0(i)?;
    let (s, _) = tag(":")(s)?;
    let (s, pos) = position(s)?;
    let (s, _) = opt(sp1)(s)?;
    let (s, for_each) = opt(tag("foreach"))(s)?;
    let (s, _) = opt(sp1)(s)?;
    let (s, input) = context(
        "rule input",
        cut(opt(|i| parse_rvalgeneral_list_long(i, "|"))),
    )(s)?;
    let (s, _) = opt(sp1)(s)?;
    let (s, secondary_input) = context("rule secondary input", cut(opt(parse_secondary_inp)))(s)?;
    let (s, _) = tag(">")(s)?;
    let (s, _) = opt(sp1)(s)?;
    let (s, rule_formula) = context("rule formula", cut(parse_rule_gut))(s)?;
    let (s, _) = tag(">")(s)?;
    let (s, _) = opt(sp1)(s)?;
    let (s, secondary_output) = opt(|i| parse_rvalgeneral_list_long(i, "|"))(s)?;
    let (s, output) = context(
        "rule output",
        opt(complete(parse_rvalgeneral_list_until_space)),
    )(s)?;
    let (s, _) = opt(sp1)(s)?;
    let (s, tags) = context("rule tags", cut(opt(parse_rvalgeneral_list)))(s)?;
    Ok((
        s,
        Statement::Rule(Link {
            s: from_input(
                input.map(|(x, _)| x).unwrap_or(Vec::new()),
                for_each.is_some(),
                secondary_input.unwrap_or((Vec::new(), default_inp())).0,
            ),
            t: from_output(
                output.unwrap_or((Vec::new(), default_inp())).0,
                secondary_output.unwrap_or((Vec::new(), default_inp())).0,
                tags.unwrap_or((Vec::new(), default_inp())).0,
            ),
            r: rule_formula,
            pos: (pos.line, pos.get_column()),
        }),
    ))
}

// parse a macro assignment which is more or less same as parsing a rule expression
// !macro = [inputs] | [order-only inputs] |> command |> [outputs]
pub fn parse_macroassignment(i: Span) -> IResult<Span, Statement> {
    let (s, _) = multispace0(i)?;
    let (s, _) = tag("!")(s)?;
    let (s, macroname) = take_while(is_ident)(s)?;
    let (s, pos) = position(s)?;
    let (s, _) = opt(sp1)(s)?;
    let (s, _) = tag("=")(s)?;
    let (s, _) = opt(sp1)(s)?;
    let (s, for_each) = opt(tag("foreach"))(s)?;
    let (s, _) = opt(sp1)(s)?;
    let (s, input) = context(
        "rule input",
        cut(opt(|i| parse_rvalgeneral_list_long(i, "|"))),
    )(s)?;
    let (s, _) = opt(sp1)(s)?;
    let (s, secondary_input) = context("rule secondary input", cut(opt(parse_secondary_inp)))(s)?;
    let (s, _) = tag(">")(s)?;
    let (s, _) = opt(sp1)(s)?;
    let (s, rule_formula) = context("rule formula", cut(parse_rule_gut))(s)?;
    let (s, _) = tag(">")(s)?;
    let (s, _) = opt(sp1)(s)?;
    let (s, secondary_output) = opt(|i| parse_rvalgeneral_list_long(i, "|"))(s)?;
    let (s, output) = context(
        "rule output",
        opt(complete(parse_rvalgeneral_list_until_space)),
    )(s)?;
    let (s, _) = opt(sp1)(s)?;
    Ok((
        s,
        Statement::MacroAssignment(
            from_utf8(macroname).unwrap_or("".to_owned()),
            Link {
                s: from_input(
                    input.map(|(x, _)| x).unwrap_or(Vec::new()),
                    for_each.is_some(),
                    secondary_input.unwrap_or((Vec::new(), default_inp())).0,
                ),
                t: from_output(
                    output.unwrap_or((Vec::new(), default_inp())).0,
                    secondary_output.unwrap_or((Vec::new(), default_inp())).0,
                    Vec::new(),
                ),
                r: rule_formula,
                pos: (pos.line, pos.get_column()),
            },
        ),
    ))
}

// parse any of the different types of statements in a tupfile
pub fn parse_statement(i: Span) -> IResult<Span, Statement> {
    alt((
        complete(parse_include),
        complete(parse_include_rules),
        complete(parse_letref_expr),
        complete(parse_let_expr),
        complete(parse_rule),
        complete(parse_ifelseendif),
        complete(parse_ifdef),
        complete(parse_macroassignment),
        complete(parse_error),
        complete(parse_export),
        complete(parse_run),
        complete(parse_preload),
        complete(parse_comment),
    ))(i)
}

// parse until the start of else block
fn parse_statements_until_else(i: Span) -> IResult<Span, (Vec<Statement>, Span)> {
    many_till(parse_statement, delimited(opt(ws1), tag("else"), opt(ws1)))(i)
}

// parse until endif statement
fn parse_statements_until_endif(i: Span) -> IResult<Span, (Vec<Statement>, Span)> {
    many_till(parse_statement, delimited(opt(ws1), tag("endif"), opt(ws1)))(i)
}

// parse statements till end of file
pub fn parse_statements_until_eof(i: Span) -> IResult<Span, Vec<Statement>> {
    many0(parse_statement)(i)
}

// parse equality condition (only the condition, not the statements that follow if)
pub fn parse_eq(i: Span) -> IResult<Span, EqCond> {
    let (s, _) = opt(ws1)(i)?;
    let (s, not_cond) = alt((map(tag("ifeq"), |_| false), map(tag("ifneq"), |_| true)))(s)?;
    let (s, _) = opt(ws1)(s)?;
    let (s, _) = char('(')(s)?;
    let (s, e1) = parse_rvalgeneral_list_long(s, ",")?;
    let (s, e2) = parse_rvalgeneral_list_long(s, ")")?;
    Ok((
        s,
        EqCond {
            lhs: e1.0,
            rhs: e2.0,
            not_cond: not_cond,
        },
    ))
}

pub fn parse_checked_var(i: Span) -> IResult<Span, CheckedVar> {
    let (s, _) = opt(ws1)(i)?;
    let (s, negate) = alt((map(tag("ifdef"), |_| false), map(tag("ifndef"), |_| true)))(s)?;
    let (s, _) = opt(ws1)(s)?;
    let (s, var) = parse_lvalue(s)?;
    let (s, _) = opt(ws1)(s)?;
    Ok((s, CheckedVar(var, negate)))
}

pub fn parse_ifelseendif_inner(i: Span, eqcond: EqCond) -> IResult<Span, Statement> {
    let (s, then_else_s) = opt(parse_statements_until_else)(i)?;
    let (s, then_endif_s) = parse_statements_until_endif(s)?;
    if let Some(then_s) = then_else_s {
        Ok((
            s,
            Statement::IfElseEndIf {
                eq: eqcond,
                then_statements: then_s.0,
                else_statements: then_endif_s.0,
            },
        ))
    } else {
        Ok((
            s,
            Statement::IfElseEndIf {
                eq: eqcond,
                then_statements: then_endif_s.0,
                else_statements: Vec::new(),
            },
        ))
    }
}
// parse if else endif block along with condition
pub fn parse_ifelseendif(i: Span) -> IResult<Span, Statement> {
    let (s, eqcond) = parse_eq(i)?;
    let (s, _) = opt(ws1)(s)?;
    context(
        "if else block",
        cut(move |s| parse_ifelseendif_inner(s, eqcond.clone())),
    )(s)
}

pub fn parse_ifdef_inner(i: Span, cvar: CheckedVar) -> IResult<Span, Statement> {
    let (s, then_else_s) = opt(parse_statements_until_else)(i)?;
    let (s, then_endif_s) = parse_statements_until_endif(s)?;
    if let Some(then_s) = then_else_s {
        Ok((
            s,
            Statement::IfDef {
                checked_var: cvar,
                then_statements: then_s.0,
                else_statements: then_endif_s.0,
            },
        ))
    } else {
        Ok((
            s,
            Statement::IfDef {
                checked_var: cvar,
                then_statements: then_endif_s.0,
                else_statements: Vec::new(),
            },
        ))
    }
}
// parse if else endif block
pub fn parse_ifdef(i: Span) -> IResult<Span, Statement> {
    let (s, cvar) = parse_checked_var(i)?;
    let (s, _) = opt(ws1)(s)?;
    context(
        "ifdef block",
        cut(move |s| parse_ifdef_inner(s, cvar.clone())),
    )(s)
}

// parse statements in a tupfile
pub fn parse_tupfile(filename: &str) -> Vec<Statement> {
    use std::fs::File;
    use std::io::prelude::*;
    let mut file = File::open(filename).expect("no such file");
    let mut contents = String::new();
    if file.read_to_string(&mut contents).ok().is_some() {
        if let Some(v) = parse_statements_until_eof(Span::new(contents.as_bytes())).ok() {
            (v.1)
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    }
}
use std::path::{Path, PathBuf};
pub(crate) fn locate_file(cur_tupfile: &Path, file_to_loc: &str) -> Option<PathBuf> {
    let mut cwd = cur_tupfile;
    while let Some(parent) = cwd.parent() {
        let p = parent.join(file_to_loc);
        if p.is_file() {
            return Some(p);
        }
        cwd = parent;
    }
    None
}

pub(crate) fn locate_tuprules(cur_tupfile: &Path) -> Option<PathBuf> {
    locate_file(cur_tupfile, "Tuprules.tup")
}

pub fn parse_config(filename: &str) -> Vec<Statement> {
    use std::fs::File;
    use std::io::prelude::*;
    let mut file = File::open(filename).expect("no such file");
    let mut contents = String::new();
    if file.read_to_string(&mut contents).ok().is_some() {
        if let Some(v) = parse_statements_until_eof(Span::new(contents.as_bytes())).ok() {
            (v.1)
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    }
}
