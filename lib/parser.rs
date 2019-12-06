// promote a string into a tup variable
use nom::character::complete::{multispace0, multispace1, space1, line_ending, not_line_ending};
use nom::combinator::{complete, cut, map, map_res, not, opt, peek};
use nom::error::{context, ErrorKind};
use nom::multi::{many0, many_till};
use nom::sequence::{delimited, preceded};
use nom::Err;
use nom::IResult;
use nom::{
    branch::alt,
    bytes::complete::{is_not, tag, take, take_until, take_while},
    character::complete::{char, one_of},
};
use statements::*;

fn to_lval(s: &str) -> Ident {
    Ident { name: s.to_owned() }
}
// convert byte str to RvalGeneral::Literal
fn from_str(res: &[u8]) -> Result<RvalGeneral, std::str::Utf8Error> {
    std::str::from_utf8(res).map(|s| RvalGeneral::Literal(s.to_owned()))
}
// check if char is part of an identifier (lhs of var assignment)
fn is_ident(c: u8) -> bool {
    nom::character::is_alphanumeric(c) || c == b'_'
}

fn is_ident_perc(c: u8) -> bool {
    nom::character::is_alphanumeric(c) || c == b'_' || c == b'%'
}

fn ws1<'a>(input: &'a [u8]) -> IResult<&'a [u8], &'a [u8]> {
    alt((
        preceded(tag("\\"), line_ending),
        multispace1,
        map(peek(one_of("<{")), |_| b"".as_ref()),
    ))(input)
}

// read a space or blackslash newline continuation
fn sp1<'a>(input: &'a [u8]) -> IResult<&'a [u8], &'a [u8]> {
    alt((complete(preceded(tag("\\"), line_ending)), space1))(input)
}

// parse rvalue wrapped inside dollar or at
fn parse_rvalue_raw<'a>(input: &'a [u8]) -> IResult<&'a [u8], &'a [u8]> {
    delimited(
        alt((tag("$("), tag("@("), tag("&("))),
        take_while(is_ident_perc),
        tag(")"),
    )(input)
}

// read a ! followed by macro name
fn parse_rvalue_raw_excl<'a>(i: &'a [u8]) -> IResult<&'a [u8], &'a [u8]> {
    let (s, _) = opt(sp1)(i)?;
    let (s, _) = tag("!")(s)?;
    take_while(is_ident)(s)
}

// read a curly brace and the identifier inside it
fn parse_rvalue_raw_bucket<'a>(i: &'a [u8]) -> IResult<&'a [u8], &'a [u8]> {
    delimited(tag("{"), take_while(is_ident), tag("}"))(i)
}

// read '<' and the list of rvals inside it until '>'
fn parse_rvalue_raw_angle<'a>(i: &'a [u8]) -> IResult<&'a [u8], Vec<RvalGeneral>> {
    let (s, _) = context("group", tag("<"))(i)?;
    let (r, v) = parse_rvalgeneral_list_long(s, ">")?;
    Ok((r, v.0))
}
// parse rvalue at expression eg $(H) for config vars
fn parse_rvalue_at<'a>(i: &'a [u8]) -> IResult<&'a [u8], RvalGeneral> {
    context(
        "config(@) expression",
        cut(map(map_res(parse_rvalue_raw, std::str::from_utf8), |rv| {
            RvalGeneral::AtExpr(rv.to_owned())
        })),
    )(i)
}
// parse rvalue dollar expression eg $(H)
fn parse_rvalue_dollar<'a>(i: &'a [u8]) -> IResult<&'a [u8], RvalGeneral> {
    context(
        "dollar expression",
        cut(map(map_res(parse_rvalue_raw, std::str::from_utf8), |s| {
            RvalGeneral::DollarExpr(s.to_owned())
        })),
    )(i)
}

// parse rvalue dollar expression eg $(H)
fn parse_rvalue_amp<'a>(i: &'a [u8]) -> IResult<&'a [u8], RvalGeneral> {
    context(
        "ampersand expression",
        cut(map(map_res(parse_rvalue_raw, std::str::from_utf8), |rv| {
            RvalGeneral::AmpExpr(rv.to_owned())
        })),
    )(i)
}

fn parse_rvalue_exclamation<'a>(i: &'a [u8]) -> IResult<&'a [u8], RvalGeneral> {
    context(
        "macro",
        cut(map(
            map_res(parse_rvalue_raw_excl, std::str::from_utf8),
            |rv| RvalGeneral::MacroRef(rv.to_owned()),
        )),
    )(i)
}

fn parse_rvalue_angle<'a>(i: &'a [u8]) -> IResult<&'a [u8], RvalGeneral> {
    context(
        "group",
        cut(map(parse_rvalue_raw_angle, |rv| {
            RvalGeneral::Group(rv.to_owned())
        })),
    )(i)
}

// parse to a bucket name: {objs}
fn parse_rvalue_bucket<'a>(i: &'a [u8]) -> IResult<&'a [u8], RvalGeneral> {
    context(
        "bin",
        cut(map(
            map_res(parse_rvalue_raw_bucket, std::str::from_utf8),
            |rv| RvalGeneral::Bucket(rv.to_owned()),
        )),
    )(i)
}

// parse to any of the special expressions (dollar, at, angle, bucket)
named!(parse_rvalue<&[u8], RvalGeneral>,
       switch!(peek!(take!(1)),
           b"$" => call!(parse_rvalue_dollar) |
               b"@" => call!(parse_rvalue_at) |
               b"&" => call!(parse_rvalue_amp) |
               b"<" => call!(parse_rvalue_angle) |
               b"{" => call!(parse_rvalue_bucket) |
               b"!" => call!(parse_rvalue_exclamation)
       )
);

// eat up the (dollar or at) that dont parse to (dollar or at) expression
fn parse_delim<'a>(i: &'a [u8]) -> nom::IResult<&'a [u8], &'a [u8]> {
    let _ = peek(one_of("$@!<#&"))(i)?;
    let _ = not(parse_rvalue);
    take(1 as usize)(i)
}

// read  a rvalue until delimiter
// in addition, \\\n , $,@, ! also pause the parsing
fn parse_greedy<'a, 'b>(input: &'a [u8], delim: &'b str) -> nom::IResult<&'a [u8], &'a [u8]> {
    let mut s = String::from("\\\n$@{<!#&");
    s.push_str(delim);
    alt((
        map( preceded(tag("\\"), line_ending), |_| b"".as_ref()),
        parse_delim,
        is_not(s.clone().as_str()), // not sure why we need to clone there, compiler errors otherwise
    ))(input)
}
// parse either (dollar|at|curly|angle|exclamation) expression or a general rvalue delimited by delimb
fn parse_rvalgeneral<'a, 'b>(s: &'a [u8], delim: &'b str) -> nom::IResult<&'a [u8], RvalGeneral> {
    alt((
        complete(preceded(opt(sp1), parse_rvalue)),
        complete(map_res(|i| parse_greedy(i, delim), from_str)),
    ))(s)
}

fn eof<'a>(i: &'a [u8]) -> IResult<&'a [u8], &'a [u8]> {
    if i.len() == 0 {
        Ok((i, i))
    } else {
        Err(Err::Error(error_position!(i, ErrorKind::Eof)))
    }
}
// repeatedly invoke the rvalue parser until eof or delim is encountered
fn parse_rvalgeneral_list_long<'a, 'b>(
    input: &'a [u8],
    delim: &'b str,
) -> nom::IResult<&'a [u8], (Vec<RvalGeneral>, &'a [u8])> {
    many_till(
        |i| parse_rvalgeneral(i, delim),
        tag(delim),
    )(input)
}
//  wrapper over the previous parser that handles empty inputs and stops at newline;
fn parse_rvalgeneral_list(input: &[u8]) -> IResult<&[u8], (Vec<RvalGeneral>, &[u8])> {
    alt((
        complete(map(eof, |_| (Vec::new(), b"".as_ref()))),
        complete(map(delimited(multispace0, line_ending, multispace0), |_| {
            (Vec::new(), b"".as_ref())
        })),
        complete(|i| parse_rvalgeneral_list_long(i, "\n")),
    ))(input)
}

fn parse_rvalgeneral_list_sp<'a>(
    input: &'a [u8],
) -> nom::IResult<&'a [u8], (Vec<RvalGeneral>, &'a [u8])> {
    many_till(
        |i| parse_rvalgeneral(i, " \t\r\n{<"), // avoid reading tags , newlines, spaces
        ws1,
    )(input)
}

// wrapper over the previous that handles empty inputs and stops at newline
fn parse_rvalgeneral_list_until_space(input: &[u8]) -> IResult<&[u8], (Vec<RvalGeneral>, &[u8])> {
    alt((
        complete(map(eof, |_| (Vec::new(), b"".as_ref()))),
        complete(map(peek(one_of("\r\n{<")), |_| (Vec::new(), b"".as_ref()))),
        complete(parse_rvalgeneral_list_sp),
    ))(input)
}

// parse a lvalue ref to a ident
fn parse_lvalue_ref(input: &[u8]) -> IResult<&[u8], Ident> {
    let (s, _) = char('&')(input)?;
    parse_lvalue(s)
}
// parse a lvalue to a ident
fn parse_lvalue(input: &[u8]) -> IResult<&[u8], Ident> {
    map(map_res(take_while(is_ident), std::str::from_utf8), to_lval)(input)
}

// parse include expression
fn parse_include(i: &[u8]) -> IResult<&[u8], Statement> {
    let (s, _) = multispace0(i)?;
    let (s, _) = tag("include")(s)?;
    let (s, _) = sp1(s)?;
    let (s, r) = context("include statement", cut(parse_rvalgeneral_list))(s)?;
    Ok((s, Statement::Include(r.0)))
}
// parse error expression
fn parse_error(i: &[u8]) -> IResult<&[u8], Statement> {
    let (s, _) = multispace0(i)?;
    let (s, _) = tag("error")(s)?;
    let (s, _) = sp1(s)?;
    let (s, r) = context("error expression", cut(parse_rvalgeneral_list))(s)?;
    Ok((s, Statement::Err(r.0)))
}

// parse export expression
fn parse_export(i: &[u8]) -> IResult<&[u8], Statement> {
    let (s, _) = multispace0(i)?;
    let (s, _) = tag("export")(s)?;
    let (s, _) = sp1(s)?;
    let (s, r) = context("export expression", cut(parse_rvalgeneral_list))(s)?;
    Ok((s, Statement::Export(r.0)))
}

// parse preload expression
fn parse_preload(i: &[u8]) -> IResult<&[u8], Statement> {
    let (s, _) = multispace0(i)?;
    let (s, _) = tag("preload")(s)?;
    let (s, _) = sp1(s)?;
    let (s, r) = context("preload expression", cut(parse_rvalgeneral_list))(s)?;
    Ok((s, Statement::Preload(r.0)))
}

// parse the run expresssion
fn parse_run(i: &[u8]) -> IResult<&[u8], Statement> {
    let (s, _) = multispace0(i)?;
    let (s, _) = tag("run")(s)?;
    let (s, _) = sp1(s)?;
    let (s, r) = context("run expression", cut(parse_rvalgeneral_list))(s)?;
    Ok((s, Statement::Run(r.0)))
}
// parse include_rules expresssion
fn parse_include_rules(i: &[u8]) -> IResult<&[u8], Statement> {
    let (s, _) = multispace0(i)?;
    let (s, _) = tag("include_rules")(s)?;
    let (s, _) = context("include_rules", cut(multispace0))(s)?;
    Ok((s, Statement::IncludeRules))
}

// parse comment expresssion
fn parse_comment(i: &[u8]) -> IResult<&[u8], Statement> {
    let (s, _) = multispace0(i)?;
    let (s, _) = tag("#")(s)?;
    let (s, r) = context(
        "comment",
        cut(map_res(not_line_ending,  std::str::from_utf8)),
    )(s)?;
    Ok((s, Statement::Comment(r.to_owned())))
}

// parse an assignment expression
fn parse_let_expr(i: &[u8]) -> IResult<&[u8], Statement> {
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
            is_append: (op == b"+="),
        },
    ))
}

// parse an assignment expression
fn parse_letref_expr(i: &[u8]) -> IResult<&[u8], Statement> {
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
            is_append: (op == b"+="),
        },
    ))
}
// parse description insude a rule (between ^^)
fn parse_rule_description(i: &[u8]) -> IResult<&[u8], String> {
    let (s, _) = multispace0(i)?;
    let (s, _) = tag("^")(s)?;
    let (s, r) = context("rule description", cut(map_res(take_until("^"), std::str::from_utf8)))(s)?;
    let (s, _) = tag("^")(s)?;
    let (s, _) = multispace0(s)?;
    Ok((s, String::from(r)))
}
// parse the insides of a rule, which includes a description and rule formula
fn parse_rule_gut(i: &[u8]) -> IResult<&[u8], RuleFormula> {
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

// parse a rule expression
// : [foreach] [inputs] [ | order-only inputs] |> command |> [outputs] [ | extra outputs] [<group>] [{bin}]
fn parse_secondary_inp(i: &[u8]) -> IResult<&[u8], (Vec<RvalGeneral>, &[u8])> {
    let (s, _) = tag("|")(i)?;
    let (s, _) = opt(sp1)(s)?;
    parse_rvalgeneral_list_long(s, "|")
}
pub fn parse_rule(i: &[u8]) -> IResult<&[u8], Statement> {
    let (s, _) = multispace0(i)?;
    let (s, _) = tag(":")(s)?;
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
                secondary_input.unwrap_or((Vec::new(), b"")).0,
            ),
            t: from_output(
                output.unwrap_or((Vec::new(), b"")).0,
                secondary_output.unwrap_or((Vec::new(), b"")).0,
                tags.unwrap_or((Vec::new(), b"")).0,
            ),
            r: rule_formula,
        }),
    ))
}

// parse a macro assignment which is more or less same as parsing a rule expression
// !macro = [inputs] | [order-only inputs] |> command |> [outputs]
pub fn parse_macroassignment(i: &[u8]) -> IResult<&[u8], Statement> {
    let (s, _) = multispace0(i)?;
    let (s, _) = tag("!")(s)?;
    let (s, macroname) = take_while(is_ident)(s)?;
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
            std::str::from_utf8(macroname).unwrap_or("").to_owned(),
            Link {
                s: from_input(
                    input.map(|(x, _)| x).unwrap_or(Vec::new()),
                    for_each.is_some(),
                    secondary_input.unwrap_or((Vec::new(), b"")).0,
                ),
                t: from_output(
                    output.unwrap_or((Vec::new(), b"")).0,
                    secondary_output.unwrap_or((Vec::new(), b"")).0,
                    Vec::new(),
                ),
                r: rule_formula,
            },
        ),
    ))
}

// parse any of the different types of statements in a tupfile
pub fn parse_statement(i: &[u8]) -> IResult<&[u8], Statement> {
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
fn parse_statements_until_else(i: &[u8]) -> IResult<&[u8], (Vec<Statement>, &[u8])> {
    many_till(parse_statement, delimited(opt(ws1), tag("else"), opt(ws1)))(i)
}

// parse until endif statement
fn parse_statements_until_endif(i: &[u8]) -> IResult<&[u8], (Vec<Statement>, &[u8])> {
    many_till(parse_statement, delimited(opt(ws1), tag("endif"), opt(ws1)))(i)
}

// parse statements till end of file
pub fn parse_statements_until_eof(i: &[u8]) -> IResult<&[u8], Vec<Statement>> {
    many0(parse_statement)(i)
}

// parse equality condition (only the condition, not the statements that follow if)
pub fn parse_eq(i: &[u8]) -> IResult<&[u8], EqCond> {
    let (s, _) = opt(ws1)(i)?;
    let (s, not_cond) = alt((map(tag("ifeq"), |_| false), map(tag("ifneq"), |_| true)))(s)?;
    let (s, _) = opt(ws1)(s)?;
    let (s, _) = char('(')(s)?;
    let (s, _) = opt(ws1)(s)?;
    let (s, e1) = parse_rvalgeneral_list_long(s, ",")?;
    let (s, _) = opt(ws1)(s)?;
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

pub fn parse_checked_var(i: &[u8]) -> IResult<&[u8], CheckedVar> {
    let (s, _) = opt(ws1)(i)?;
    let (s, negate) = alt((map(tag("ifdef"), |_| false), map(tag("ifndef"), |_| true)))(s)?;
    let (s, _) = opt(ws1)(s)?;
    let (s, var) = parse_lvalue(s)?;
    let (s, _) = opt(ws1)(s)?;
    Ok((s, CheckedVar(var, negate)))
}

pub fn parse_ifelseendif_inner(i: &[u8], eqcond: EqCond) -> IResult<&[u8], Statement> {
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
pub fn parse_ifelseendif(i: &[u8]) -> IResult<&[u8], Statement> {
    let (s, eqcond) = parse_eq(i)?;
    let (s, _) = opt(ws1)(s)?;
    context("if else block", cut(move |s| parse_ifelseendif_inner(s,eqcond.clone())))(s)
}

pub fn parse_ifdef_inner(i:&[u8], cvar: CheckedVar) -> IResult<&[u8], Statement>
{
    let (s,then_else_s) = opt(parse_statements_until_else)(i)?;
    let (s, then_endif_s) = parse_statements_until_endif(s)?;
    if let Some(then_s) = then_else_s {
        Ok((
            s,
            Statement::IfDef { checked_var : cvar,
                               then_statements: then_s.0,
                               else_statements: then_endif_s.0,
            }
        ))
    }else {
        Ok((
            s,
            Statement::IfDef{
                checked_var : cvar,
                then_statements:  then_endif_s.0,
                else_statements: Vec::new()
            }
        ))
    }
}
// parse if else endif block
pub fn parse_ifdef(i:&[u8]) -> IResult< &[u8], Statement>
{
    let (s,cvar) = parse_checked_var(i)?;
    let (s,_) = opt(ws1)(s)?;
    context("ifdef block", cut(move |s| parse_ifdef_inner(s, cvar.clone())))(s)
}


// parse statements in a tupfile
pub fn parse_tupfile(filename: &str) -> Vec<Statement> {
    use std::fs::File;
    use std::io::prelude::*;
    let mut file = File::open(filename).expect("no such file");
    let mut contents = String::new();
    if file.read_to_string(&mut contents).ok().is_some() {
        if let Some(v) = parse_statements_until_eof(contents.as_bytes()).ok() {
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
        if let Some(v) = parse_statements_until_eof(contents.as_bytes()).ok() {
            (v.1)
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    }
}
