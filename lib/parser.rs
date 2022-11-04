//! Module that uses nom to parse a Tupfile into vector of ```Statement'''
use nom::character::complete::{line_ending, multispace0, multispace1, space1};
use nom::combinator::{complete, cut, map, map_res, opt, peek, value};
use nom::error::{context, ErrorKind};
use nom::multi::{many0, many1, many_till};
use nom::sequence::{delimited, preceded};
use nom::AsBytes;

use nom::bytes::complete::{is_a, is_not};
use nom::Err;
use nom::IResult;
use nom::{
    branch::alt,
    bytes::complete::{tag, take, take_until, take_while},
    character::complete::{char, one_of},
};
use nom_locate::{position, LocatedSpan};
use statements::*;
use std::path::{Path, PathBuf};

/// Span is an alias for LocatedSpan
pub(crate) type Span<'a> = LocatedSpan<&'a [u8]>;
fn to_lval(name: String) -> Ident {
    Ident { name }
}
fn from_utf8(s: Span) -> Result<String, std::str::Utf8Error> {
    std::str::from_utf8(s.as_bytes()).map(|x| x.to_owned())
}
impl Loc {
    /// construct a Loc from a span
    pub fn from_span(span: &Span) -> Loc {
        Loc::new(span.location_line(), span.get_column() as u32)
    }
}
lazy_static! {
    static ref BRKTOKSINNER: &'static str = "\\\n$&";
    static ref BRKTOKS: &'static str = "\\\n$@&";
    static ref BRKTOKSWS: &'static str = "\\\n$@& ";
    static ref BRKTOKSIO: &'static str = "\\\n $@&^<{";
    static ref BRKTAGSNOWS: &'static str = "<|{^";
    static ref BRKTAGS: &'static str = " <|{^";
}

/// convert byte str to PathExpr
fn from_str(res: Span) -> Result<PathExpr, std::str::Utf8Error> {
    from_utf8(res).map(|s| s.into())
}
/// check if char is part of an identifier (lhs of var assignment)
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
fn manynewlineesc(input: Span) -> IResult<Span, Span> {
    let (s, _) = many1(preceded(tag("\\"), line_ending))(input)?;
    Ok((s, default_inp()))
}
// read a space or blackslash newline continuation
fn sp1(input: Span) -> IResult<Span, Span> {
    alt((complete(manynewlineesc), space1))(input)
}
// checks for presence of a group expression that begins with some path.`
fn parse_pathexpr_raw_angle(input: Span) -> IResult<Span, Span> {
    //let i = input.clone();
    preceded(is_not(*BRKTAGS), tag("<"))(input)
}

// parse expession wrapped inside dollar or at
fn parse_pathexpr_ref_raw(input: Span) -> IResult<Span, String> {
    let (s, _) = alt((tag("$("), tag("@("), tag("&(")))(input)?;
    let (s, r) = take_while(is_ident_perc)(s)?;
    let (s, _) = tag(")")(s)?;
    let raw = std::str::from_utf8(r.as_bytes()).unwrap();
    Ok((s, raw.to_owned()))
}

// read a ! followed by macro name
fn parse_pathexpr_raw_macroref(i: Span) -> IResult<Span, String> {
    let (s, _) = opt(sp1)(i)?;
    let (s, _) = tag("!")(s)?;
    let (s, r) = take_while(is_ident)(s)?;
    let raw = std::str::from_utf8(r.as_bytes()).unwrap();
    Ok((s, raw.to_owned()))
}

// read a curly brace and the identifier inside it
fn parse_pathexpr_raw_bin(i: Span) -> IResult<Span, String> {
    let (s, _) = tag("{")(i)?;
    let (s, r) = take_while(is_ident)(s)?;
    let (s, _) = tag("}")(s)?;
    let raw = std::str::from_utf8(r.as_bytes()).unwrap();
    Ok((s, raw.to_owned()))
}
fn parse_pathexpr_hat(i: Span) -> IResult<Span, String> {
    let (s, _) = tag("^")(i)?;
    let (s, r) = is_not(" \t\n\r")(s)?;
    let raw = std::str::from_utf8(r.as_bytes()).unwrap();
    Ok((s, raw.to_owned()))
}

// read '<' and the list of rvals inside it until '>'
fn parse_pathexpr_angle(i: Span) -> nom::IResult<Span, (Vec<PathExpr>, Vec<PathExpr>)> {
    //let input = i.clone();
    let (s, v0) = many_till(|i| parse_pathexpr_no_ws(i, " \t\r\n<{", *BRKTOKS), tag("<"))(i)?;
    //let (s, _) = tag("<")(s)?;
    let (s, v) = many_till(
        |i| parse_pathexpr_no_ws(i, ">", *BRKTOKS), // avoid reading tags , newlines, spaces
        tag(">"),
    )(s)?;
    //let v0 = v0.map(|x| x.0);
    Ok((s, (v0.0, v.0)))
}
// parse rvalue at expression eg $(H) for config vars
fn parse_pathexpr_at(i: Span) -> IResult<Span, PathExpr> {
    context(
        "config(@) expression",
        cut(map(parse_pathexpr_ref_raw, |rv| {
            PathExpr::AtExpr(rv.to_owned())
        })),
    )(i)
}
// parse rvalue dollar expression eg $(H)
fn parse_pathexpr_dollar(i: Span) -> IResult<Span, PathExpr> {
    context(
        "dollar expression",
        cut(map(parse_pathexpr_ref_raw, |s| {
            PathExpr::DollarExpr(s.to_owned())
        })),
    )(i)
}

// parse rvalue dollar expression eg $(H)
fn parse_pathexpr_amp(i: Span) -> IResult<Span, PathExpr> {
    context(
        "ampersand expression",
        cut(map(parse_pathexpr_ref_raw, |rv| {
            PathExpr::AmpExpr(rv.to_owned())
        })),
    )(i)
}

fn parse_pathexpr_macroref(i: Span) -> IResult<Span, PathExpr> {
    context(
        "reference to macro",
        map(parse_pathexpr_raw_macroref, |rv| {
            PathExpr::MacroRef(rv.to_owned())
        }),
    )(i)
}
fn parse_pathexpr_exclude_pattern(i: Span) -> IResult<Span, PathExpr> {
    context(
        "exclude pattern",
        map(parse_pathexpr_hat, |rv| PathExpr::ExcludePattern(rv)),
    )(i)
}

fn parse_pathexpr_group(i: Span) -> IResult<Span, PathExpr> {
    context(
        "group",
        map(parse_pathexpr_angle, |rv| PathExpr::Group(rv.0, rv.1)),
    )(i)
}

// parse to a bucket name: {objs}
fn parse_pathexpr_bin(i: Span) -> IResult<Span, PathExpr> {
    context("bin", map(parse_pathexpr_raw_bin, |rv| PathExpr::Bin(rv)))(i)
}

fn parse_escaped(i: Span) -> IResult<Span, PathExpr> {
    let (_, r) = peek(take(2 as usize))(i)?;
    match r.as_bytes() {
        b"\\\r" => {
            let (_, r) = peek(take(3 as usize))(i)?;
            if r.as_bytes() == b"\\\r\n" {
                let (s, _) = take(3 as usize)(i)?; //consumes \n after \r as well
                Ok((s, ("".to_string()).into()))
            } else {
                Err(Err::Error(error_position!(i, ErrorKind::Eof))) //FIXME: what errorkind should we return?
            }
        }
        b"\\\n" => {
            let (s, _) = take(2 as usize)(i)?;
            Ok((s, ("".to_string()).into()))
        }
        b"\\$" | b"\\@" | b"\\&" | b"\\{" | b"\\<" | b"\\^" | b"\\|" => {
            let (s, _) = take(2 as usize)(i)?;
            let pe = from_str(r).map_err(|_| Err::Error(error_position!(i, ErrorKind::Escaped)))?;
            Ok((s, pe))
        }
        _ => Err(Err::Error(error_position!(i, ErrorKind::Eof))), //FIXME: what errorkind should we return?
    }
}
fn test_pathexpr_ref(i: Span) -> bool {
    let res = || -> IResult<Span, bool> {
        let (_, r) = (peek(take(1 as usize))(i))?;
        let ismatch = match r.as_bytes() {
            b"$" => true,
            b"@" => true,
            b"&" => true,
            _ => false,
        };
        Ok((i, ismatch))
    };
    return res().map(|x| x.1).unwrap_or(false);
}

/// parse basic special expressions (dollar, at, ampersand)
fn parse_pathexprbasic(i: Span) -> IResult<Span, PathExpr> {
    let (s, r) = peek(take(2 as usize))(i)?;
    match r.as_bytes() {
        b"$(" => parse_pathexpr_dollar(s),
        b"@(" => parse_pathexpr_at(s),
        b"&(" => parse_pathexpr_amp(s),
        _ => Err(Err::Error(error_position!(i, ErrorKind::Eof))), //fixme: what errorkind should we return?
    }
}

/// process whitespace
fn parse_ws(i: Span) -> IResult<Span, PathExpr> {
    let (s, _) = is_a(" \t")(i)?;
    Ok((s, PathExpr::Sp1))
}

/// eat up the (dollar or at) that dont parse to (dollar or at) expression
fn parse_delim(i: Span) -> nom::IResult<Span, Span> {
    if !test_pathexpr_ref(i) {
        return Err(Err::Error(error_position!(i, ErrorKind::Escaped)));
    }
    let (s, r) = take(1 as usize)(i)?;
    Ok((s, r))
}

/// eats up \\n
/// consume dollar's etc that where left out during previous parsing
/// consume a literal that is not a pathexpr token
fn parse_misc_bits<'a, 'b>(
    input: Span<'a>,
    delim: &'b str,
    pathexpr_toks: &'static str,
) -> nom::IResult<Span<'a>, Span<'a>> {
    let islit = |ref i| !delim.as_bytes().contains(i) && !pathexpr_toks.as_bytes().contains(i);
    alt((complete(parse_delim), complete(take_while(islit))))(input)
}
/// parse either (dollar|at|) expression or a general rvalue delimited by delim
/// pathexpr_toks are the tokens that identify a tup-expression such as $expr, &expr, {bin} or <grp>
pub(crate) fn parse_pathexpr_ws<'a, 'b>(
    s: Span<'a>,
    delim: &'b str,
    pathexpr_toks: &'static str,
) -> nom::IResult<Span<'a>, PathExpr> {
    alt((
        complete(parse_ws),
        complete(parse_escaped),
        complete(parse_pathexprbasic),
        complete(map_res(
            |i| parse_misc_bits(i, delim, pathexpr_toks),
            from_str,
        )),
    ))(s)
}
fn parse_pathexpr_no_ws<'a, 'b>(
    s: Span<'a>,
    delim: &'b str,
    pathexpr_toks: &'static str,
) -> nom::IResult<Span<'a>, PathExpr> {
    alt((
        complete(parse_escaped),
        complete(parse_pathexprbasic),
        complete(map_res(
            |i| parse_misc_bits(i, delim, pathexpr_toks),
            from_str,
        )),
    ))(s)
}

// repeatedly invoke the rvalue parser until eof or delim is encountered
fn parse_pelist_till_delim_with_ws<'a, 'b>(
    input: Span<'a>,
    delim: &'b str,
    pathexpr_delims: &'static str,
) -> nom::IResult<Span<'a>, (Vec<PathExpr>, Span<'a>)> {
    many_till(
        |i| parse_pathexpr_ws(i, delim, pathexpr_delims),
        is_a(delim),
    )(input)
}
// repeatedly invoke the rvalue parser until eof or delim is encountered
fn parse_pelist_till_delim_no_ws<'a, 'b>(
    input: Span<'a>,
    delim: &'b str,
    pathexpr_delims: &'static str,
) -> nom::IResult<Span<'a>, (Vec<PathExpr>, Span<'a>)> {
    many_till(
        |i| parse_pathexpr_no_ws(i, delim, pathexpr_delims),
        is_a(delim),
    )(input)
}

//  wrapper over the previous parser that handles empty inputs and stops at newline;
fn parse_pelist_till_line_end_with_ws(input: Span) -> IResult<Span, (Vec<PathExpr>, Span)> {
    alt((
        complete(map(
            delimited(multispace0, line_ending, multispace0),
            |_| (Vec::new(), Span::new(b"".as_ref())),
        )),
        complete(|i| parse_pelist_till_delim_with_ws(i, "\r\n", *BRKTOKSWS)),
    ))(input)
}

// read all pathexpr separated by whitespaces, pausing at BRKTOKS
fn parse_pathexpr_list_until_ws_plus(input: Span) -> nom::IResult<Span, (Vec<PathExpr>, Span)> {
    many_till(|i| parse_pathexpr_no_ws(i, " \t\r\n", *BRKTOKS), ws1)(input)
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

impl From<(Statement, Span<'_>)> for LocatedStatement {
    fn from((stmt, i): (Statement, Span<'_>)) -> Self {
        LocatedStatement::new(stmt, Loc::from_span(&i))
    }
}

// parse include expression
fn parse_include(i: Span) -> IResult<Span, LocatedStatement> {
    let (s, _) = multispace0(i)?;
    let (s, _) = tag("include")(s)?;
    let (s, _) = sp1(s)?;
    let (s, r) = context("include statement", cut(parse_pathexpr_list_until_ws_plus))(s)?;
    let (s, _) = multispace0(s)?;
    //let (s, _) = line_ending(s)?;
    Ok((s, (Statement::Include(r.0), i).into()))
}
// parse error expression
fn parse_error(i: Span) -> IResult<Span, LocatedStatement> {
    let (s, _) = multispace0(i)?;
    let (s, _) = tag("error")(s)?;
    let (s, _) = sp1(s)?;
    let (s, r) = context("error expression", cut(parse_pelist_till_line_end_with_ws))(s)?;
    Ok((s, (Statement::Err(r.0), i).into()))
}

// parse export expression
// export VARIABLE
fn parse_export(i: Span) -> IResult<Span, LocatedStatement> {
    let (s, _) = multispace0(i)?;
    let (s, _) = tag("export")(s)?;
    let (s, _) = sp1(s)?;
    let (s, r) = context("export expression", cut(take_while(is_ident)))(s)?;
    let (s, _) = multispace0(s)?;
    let (s, _) = line_ending(s)?;
    let raw = std::str::from_utf8(r.as_bytes()).unwrap();
    Ok((s, (Statement::Export(raw.to_owned()), i).into()))
}

// import VARIABLE[=default]
//   The import directive sets a variable inside the Tupfile that has the value of the environment variable.
// If the environment variable is unset, the default value is used instead if provided.
// This introduces a dependency from the environment variable to the Tupfile,
// so that if the environment variable changes, the Tupfile is re-parsed. For example:
//
// import CC=gcc
// : foreach *.c |> $(CC) -c %f -o %o |> %B.o
// Unlike 'export', the import command does not pass the variables to the sub-process's environment.
// In the previous example, the CC environment variable is therefore not set in the subprocess, unless 'export CC' was also in the Tupfile.
fn parse_import(i: Span) -> IResult<Span, LocatedStatement> {
    let (s, _) = multispace0(i)?;
    let (s, _) = tag("import")(s)?;
    let (s, _) = sp1(s)?;
    let (s, r) = context("import expression", cut(take_while(is_ident)))(s)?;
    let raw = std::str::from_utf8(r.as_bytes()).unwrap();
    let (s, def) = opt(preceded(
        tag("="),
        preceded(multispace0, cut(take_while(is_ident))),
    ))(s)?;
    let (s, _) = multispace0(s)?;
    let (s, _) = line_ending(s)?;

    let default_raw = def.and_then(|x| from_utf8(x).ok());
    Ok((
        s,
        (Statement::Import(raw.to_owned(), default_raw), i).into(),
    ))
}

// parse preload expression
// preload directory
fn parse_preload(i: Span) -> IResult<Span, LocatedStatement> {
    let (s, _) = multispace0(i)?;
    let (s, _) = tag("preload")(s)?;
    let (s, _) = sp1(s)?;
    // preload a single directory
    let (s, r) = context("preload expression", cut(parse_pathexpr_list_until_ws_plus))(s)?;

    let (s, _) = multispace0(s)?;
    let (s, _) = line_ending(s)?;
    Ok((s, (Statement::Preload(r.0), i).into()))
}

// parse the run expresssion
// run ./script args
// reading other directories requires preload
// run ./build.sh *.c src/*.c
fn parse_run(i: Span) -> IResult<Span, LocatedStatement> {
    let (s, _) = multispace0(i)?;
    let (s, _) = tag("run")(s)?;
    let (s, _) = sp1(s)?;
    // run  script paths
    let (s, r) = context("run expression", cut(parse_pelist_till_line_end_with_ws))(s)?;
    Ok((s, (Statement::Run(r.0), i).into()))
}
// parse include_rules expresssion
fn parse_include_rules(i: Span) -> IResult<Span, LocatedStatement> {
    let (s, _) = multispace0(i)?;
    let (s, _) = tag("include_rules")(s)?;
    let (s, _) = context("include_rules", multispace0)(s)?;
    let (s, _) = line_ending(s)?;
    Ok((s, (Statement::IncludeRules, i).into()))
}

// parse comment expresssion
fn parse_comment(i: Span) -> IResult<Span, LocatedStatement> {
    let (s, _) = multispace0(i)?;
    let (s, _) = tag("#")(s)?;
    let (s, _) = is_not("\n\r")(s)?;
    let (s, _) = line_ending(s)?;
    Ok((s, (Statement::Comment, i).into()))
}

// parse an assignment expression
fn parse_let_expr(i: Span) -> IResult<Span, LocatedStatement> {
    let (s, _) = multispace0(i)?;
    let (s, l) = parse_lvalue(s)?;
    let (s, _) = opt(sp1)(s)?;
    let (s, op) = alt((complete(tag("=")), complete(tag(":=")), complete(tag("+="))))(s)?;
    let (s, _) = opt(sp1)(s)?;
    let (s, r) = complete(parse_pelist_till_line_end_with_ws)(s)?;
    Ok((
        s,
        (
            Statement::LetExpr {
                left: l,
                right: r.0,
                is_append: (op.as_bytes() == b"+="),
            },
            i,
        )
            .into(),
    ))
}

// parse an assignment expression
fn parse_letref_expr(i: Span) -> IResult<Span, LocatedStatement> {
    let (s, _) = multispace0(i)?;
    let (s, l) = parse_lvalue_ref(s)?;
    let (s, _) = opt(sp1)(s)?;
    let (s, op) = alt((complete(tag("=")), complete(tag(":=")), complete(tag("+="))))(s)?;
    let (s, _) = opt(sp1)(s)?;
    let (s, r) = complete(parse_pelist_till_line_end_with_ws)(s)?;
    Ok((
        s,
        (
            Statement::LetRefExpr {
                left: l,
                right: r.0,
                is_append: (op.as_bytes() == b"+="),
            },
            i,
        )
            .into(),
    ))
}
// parse description insude a rule (between ^^)
fn parse_rule_flags_or_description(i: Span) -> IResult<Span, String> {
    let (s, _) = multispace0(i)?;
    let (s, _) = tag("^")(s)?;
    let (s, r) = cut(map_res(take_until("^"), from_utf8))(s)?;
    let (s, _) = tag("^")(s)?;
    let (s, _) = multispace0(s)?;
    Ok((s, String::from(r)))
}

// parse the insides of a rule, which includes a description and rule formula
pub(crate) fn parse_rule_gut(i: Span) -> IResult<Span, RuleFormula> {
    let (s, desc) = opt(context(
        "parsing rule flags/descriptions",
        parse_rule_flags_or_description,
    ))(i)?;
    let (s, me) = opt(parse_pathexpr_macroref)(s)?;
    let (s, formula) = parse_pelist_till_delim_with_ws(s, "|", *BRKTOKSWS)?;
    Ok((
        s,
        RuleFormula {
            description: desc.iter().map(|x| (x.clone()).into()).collect(),
            //macroref : me,
            formula: me.into_iter().chain(formula.0.into_iter()).collect(),
        },
    ))
}

// convert the inputs to a rule to 'Source' struct
fn from_input(primary: Vec<PathExpr>, for_each: bool, secondary: Vec<PathExpr>) -> Source {
    Source {
        primary,
        for_each,
        secondary,
    }
}
// convert the output to a rule to 'Target' struct
fn from_output(
    primary: Vec<PathExpr>,
    secondary: Vec<PathExpr>,
    exclude: Option<PathExpr>,
    group: Option<PathExpr>,
    bin: Option<PathExpr>,
) -> Target {
    Target {
        primary,
        secondary,
        exclude_pattern: exclude,
        group,
        bin,
    }
}

fn default_inp<'a>() -> Span<'a> {
    Span::new(b"")
}
/// parse rule inputs including groups and bin and exclude patterns
pub(crate) fn parse_rule_inp(i: Span) -> IResult<Span, (Vec<PathExpr>, Span)> {
    let (s, _) = opt(sp1)(i)?;
    let pe = |i| parse_pathexpr_ws(i, "|", *BRKTOKSIO);
    many_till(
        alt((
            complete(parse_pathexpr_exclude_pattern),
            complete(parse_pathexpr_group),
            complete(parse_pathexpr_bin),
            complete(pe),
        )),
        preceded(multispace0, tag("|")),
    )(s)
}
/// parse secondary input in a rule expression
pub(crate) fn parse_secondary_inp(i: Span) -> IResult<Span, (Vec<PathExpr>, Span)> {
    //context("read secondary inputs",  preceded( tag("|"),
    let (s, _) = opt(sp1)(i)?;
    //let (s, _) = tag("|")(s)?;
    let pe = |i| parse_pathexpr_ws(i, "|", *BRKTOKSIO);
    many_till(
        alt((
            complete(parse_pathexpr_group),
            complete(parse_pathexpr_bin),
            complete(pe),
        )),
        preceded(multispace0, tag("|")),
    )(s)
}

fn parse_output_delim(i: Span) -> IResult<Span, Span> {
    alt((
        complete(line_ending),
        complete(map(peek(one_of(*BRKTAGSNOWS)), |_| i)),
        complete(peek(parse_pathexpr_raw_angle)),
    ))(i)
}

fn parse_primary_output1(i: Span) -> IResult<Span, Vec<PathExpr>> {
    let (s, _) = tag("|")(i)?;
    let pe = |i| parse_pathexpr_ws(i, "\r\n", *BRKTOKSIO);
    let (s, v0) = many_till(pe, parse_output_delim)(s)?;
    Ok((s, v0.0))
}

fn parse_primary_output0(i: Span) -> IResult<Span, (Vec<PathExpr>, bool)> {
    let (s, _) = opt(sp1)(i)?;
    let pe = |i| parse_pathexpr_ws(i, "|<{^\r\n", *BRKTOKSIO);
    let (s, v0) = many_till(pe, parse_output_delim)(s)?;
    //eprintln!("{}", v0.1.as_bytes().first().unwrap_or(&b' ').as_char());
    let has_more = v0.1.as_bytes().first().map(|&c| c == b'|').unwrap_or(false);
    Ok((s, (v0.0, has_more)))
}

/// parse a rule expression of the form
/// : \[foreach\] \[inputs\] \[ \| order-only inputs\] \|\> command \|\> \[outputs\] \[ | extra outputs\] \[exclusions\] \[<group>\] \[{bin}\]
pub(crate) fn parse_rule(i: Span) -> IResult<Span, LocatedStatement> {
    let (s, _) = multispace0(i)?;
    let (s, _) = tag(":")(s)?;
    let (s, pos) = position(s)?;
    let (s, _) = opt(sp1)(s)?;
    let (s, for_each) = opt(tag("foreach"))(s)?;
    let (s, input) = context("rule input", cut(opt(parse_rule_inp)))(s)?;
    let (s, _) = opt(sp1)(s)?;
    let (s, c) = peek(take(1 as usize))(s)?;
    let (s, secondary_input) = if c.as_bytes().first().cloned() != Some(b'>') {
        let (s, _) = opt(sp1)(s)?;
        let (s, secondary_input) = context("secondary inputs", opt(parse_secondary_inp))(s)?;
        (s, secondary_input)
    } else {
        (s, None)
    };
    let (s, _) = tag(">")(s)?;
    let (s, _) = opt(sp1)(s)?;
    let (s, rule_formula) = context("rule formula", cut(parse_rule_gut))(s)?;
    let (s, _) = tag(">")(s)?;
    let (s, _) = opt(sp1)(s)?;
    // read until "|" or lineending
    let (s, output0) = context("rule output", opt(parse_primary_output0))(s)?;
    let has_more = output0
        .as_ref()
        .map_or(false, |(_, has_more)| has_more.clone());
    let (s, output1) = if has_more {
        context("rule output", cut(parse_primary_output1))(s)?
    } else {
        (s, vec![])
    };

    let (output, secondary_output) = if has_more {
        (output1, output0.unwrap_or((Vec::new(), false)).0)
    } else {
        (output0.unwrap_or((Vec::new(), false)).0, Vec::new())
    };
    let (s, exclude_patterns) = opt(parse_pathexpr_exclude_pattern)(s)?;
    // let secondary_output = if hassecondary { output1.unwrap_or(Vec::new())} else { Vec::new() };
    let (s, _) = opt(sp1)(s)?;
    let (s, v1) = opt(parse_pathexpr_group)(s)?;
    let (s, _) = opt(sp1)(s)?;
    let (s, v2) = opt(parse_pathexpr_bin)(s)?;
    let (s, _) = multispace0(s)?;
    let _curs = s.clone();
    //let (s, _) = line_ending(s)?;
    Ok((
        s,
        (
            Statement::Rule(
                Link {
                    source: from_input(
                        input.map(|(x, _)| x).unwrap_or(Vec::new()),
                        for_each.is_some(),
                        secondary_input.unwrap_or((Vec::new(), default_inp())).0,
                    ),
                    target: from_output(output, secondary_output, exclude_patterns, v1, v2),
                    rule_formula,
                    pos: (pos.location_line(), pos.get_column()),
                },
                EnvDescriptor::default(),
            ),
            i,
        )
            .into(),
    ))
}

// parse a macro assignment which is more or less same as parsing a rule expression
// !macro = [inputs] | [order-only inputs] |> command |> [outputs]
pub(crate) fn parse_macroassignment(i: Span) -> IResult<Span, LocatedStatement> {
    let (s, _) = multispace0(i)?;
    let (s, _) = tag("!")(s)?;
    let (s, macroname) = take_while(is_ident)(s)?;
    let (s, pos) = position(s)?;
    let (s, _) = opt(sp1)(s)?;
    let (s, _) = tag("=")(s)?;
    let (s, _) = opt(sp1)(s)?;
    let (s, for_each) = opt(tag("foreach"))(s)?;
    let (s, _) = opt(sp1)(s)?;
    let (s, input) = opt(context("rule input", cut(parse_rule_inp)))(s)?;
    let (s, c) = peek(take(1 as usize))(s)?;
    let (s, secondary_input) = if c.as_bytes().first().cloned() != Some(b'>') {
        let (s, _) = opt(sp1)(s)?;
        let (s, secondary_input) =
            opt(context("rule secondary input", cut(parse_secondary_inp)))(s)?;
        (s, secondary_input)
    } else {
        (s, None)
    };
    let (s, _) = tag(">")(s)?;
    let (s, _) = opt(sp1)(s)?;
    let (s, rule_formula) = context("rule formula", cut(parse_rule_gut))(s)?;
    let (s, _) = tag(">")(s)?;
    let (s, output0) = context("rule output", opt(parse_primary_output0))(s)?;
    let has_more = output0
        .as_ref()
        .map_or(false, |(_, has_more)| has_more.clone());
    let (s, output1) = if has_more {
        context("rule output", opt(parse_primary_output1))(s)?
    } else {
        (s, None)
    };

    let (output, secondary_output) = if has_more {
        (output0.unwrap().0, output1.unwrap_or(Vec::new()))
    } else {
        (output1.unwrap_or(Vec::new()), Vec::new())
    };
    /*    let output = if has_secondary { output0.unwrap() } else { output1.unwrap_or(Vec::new())};
        let secondary_output = if has_secondary { output1.unwrap_or(Vec::new())} else { Vec::new() };
    */

    Ok((
        s,
        (
            Statement::MacroAssignment(
                from_utf8(macroname).unwrap_or("".to_owned()),
                Link {
                    source: from_input(
                        input.map(|(x, _)| x).unwrap_or(Vec::new()),
                        for_each.is_some(),
                        secondary_input.unwrap_or((Vec::new(), default_inp())).0,
                    ),
                    target: from_output(output, secondary_output, None, None, None),
                    rule_formula,
                    pos: (pos.location_line(), pos.get_column()),
                },
            ),
            i,
        )
            .into(),
    ))
}

// parse any of the different types of statements in a tupfile
pub(crate) fn parse_statement(i: Span) -> IResult<Span, LocatedStatement> {
    alt((
        complete(parse_comment),
        complete(parse_include),
        complete(parse_include_rules),
        complete(parse_letref_expr),
        complete(parse_let_expr),
        complete(parse_rule),
        complete(parse_if_else_endif),
        complete(parse_ifdef_endif),
        complete(parse_macroassignment),
        complete(parse_error),
        complete(parse_export),
        complete(parse_run),
        complete(parse_preload),
        complete(parse_import),
    ))(i)
}

/// parse until the start of else block
fn parse_statements_until_else(i: Span) -> IResult<Span, (Vec<LocatedStatement>, Span)> {
    many_till(parse_statement, delimited(opt(ws1), tag("else"), opt(ws1)))(i)
}

/// parse until endif statement
fn parse_statements_until_endif(i: Span) -> IResult<Span, (Vec<LocatedStatement>, Span)> {
    many_till(parse_statement, delimited(opt(ws1), tag("endif"), opt(ws1)))(i)
}

/// parse statements till end of file
pub(crate) fn parse_statements_until_eof(
    i: Span,
) -> Result<Vec<LocatedStatement>, crate::errors::Error> {
    many0(parse_statement)(i).map(|v| v.1).map_err(|e| match e {
        Err::Incomplete(_) => {
            crate::errors::Error::ParseError("Incomplete data found".to_string(), Loc::new(0, 0))
        }
        Err::Error(e) => crate::errors::Error::ParseError(
            format!("Parse Error {:?}", e.code),
            Loc::from_span(&e.input),
        ),
        Err::Failure(e) => crate::errors::Error::ParseError(
            format!("Parse Failure {:?}", e.code),
            Loc::from_span(&e.input),
        ),
    })
}

// parse equality condition (only the condition, not the statements that follow if)
pub(crate) fn parse_eq(i: Span) -> IResult<Span, EqCond> {
    let (s, _) = opt(ws1)(i)?;
    let (s, not_cond) = alt((
        complete(value(false, tag("ifeq"))),
        complete(value(true, tag("ifneq"))),
    ))(s)?;
    let (s, _) = opt(ws1)(s)?;
    let (s, _) = char('(')(s)?;
    let (s, e1) = parse_pelist_till_delim_no_ws(s, ",", *BRKTOKS)?;
    let (s, _) = opt(sp1)(s)?;
    let (s, e2) = parse_pelist_till_delim_no_ws(s, ")", *BRKTOKS)?;
    Ok((
        s,
        EqCond {
            lhs: e1.0,
            rhs: e2.0,
            not_cond,
        },
    ))
}

pub(crate) fn parse_checked_var(i: Span) -> IResult<Span, CheckedVar> {
    let (s, _) = opt(ws1)(i)?;
    let (s, negate) = alt((map(tag("ifdef "), |_| false), map(tag("ifndef "), |_| true)))(s)?;
    let (s, _) = opt(ws1)(s)?;
    let (s, var) = parse_lvalue(s)?;
    let (s, _) = opt(ws1)(s)?;
    Ok((s, CheckedVar(var, negate)))
}
// parse contents inside if else endif bocks(without condition)
pub(crate) fn parse_ifelseendif_inner(i: Span, eqcond: EqCond) -> IResult<Span, LocatedStatement> {
    let (s, then_else_s) = opt(parse_statements_until_else)(i)?;
    let (s, then_endif_s) = parse_statements_until_endif(s)?;
    if let Some(then_s) = then_else_s {
        Ok((
            s,
            (
                Statement::IfElseEndIf {
                    eq: eqcond,
                    then_statements: then_s.0,
                    else_statements: then_endif_s.0,
                },
                i,
            )
                .into(),
        ))
    } else {
        Ok((
            s,
            (
                Statement::IfElseEndIf {
                    eq: eqcond,
                    then_statements: then_endif_s.0,
                    else_statements: Vec::new(),
                },
                i,
            )
                .into(),
        ))
    }
}

// parse if else endif block along with condition
pub(crate) fn parse_if_else_endif(i: Span) -> IResult<Span, LocatedStatement> {
    let (s, eqcond) = parse_eq(i)?;
    let (s, _) = opt(ws1)(s)?;
    context(
        "if else block",
        cut(move |s| parse_ifelseendif_inner(s, eqcond.clone())),
    )(s)
}

// parse inside a ifdef block
pub(crate) fn parse_ifdef_inner(i: Span, cvar: CheckedVar) -> IResult<Span, LocatedStatement> {
    let (s, then_else_s) = opt(parse_statements_until_else)(i)?;
    let (s, then_endif_s) = parse_statements_until_endif(s)?;
    if let Some(then_s) = then_else_s {
        Ok((
            s,
            (
                Statement::IfDef {
                    checked_var: cvar,
                    then_statements: then_s.0,
                    else_statements: then_endif_s.0,
                },
                i,
            )
                .into(),
        ))
    } else {
        Ok((
            s,
            (
                Statement::IfDef {
                    checked_var: cvar,
                    then_statements: then_endif_s.0,
                    else_statements: Vec::new(),
                },
                i,
            )
                .into(),
        ))
    }
}
/// parse if else endif block
pub(crate) fn parse_ifdef_endif(i: Span) -> IResult<Span, LocatedStatement> {
    let (s, cvar) = parse_checked_var(i)?;
    let (s, _) = opt(ws1)(s)?;
    context(
        "ifdef block",
        cut(move |s| parse_ifdef_inner(s, cvar.clone())),
    )(s)
}

/// parse statements in a tupfile
pub(crate) fn parse_tupfile<P: AsRef<Path>>(
    filename: P,
) -> Result<Vec<LocatedStatement>, crate::errors::Error> {
    use errors::Error as Err;
    use std::fs::File;
    use std::io::prelude::*;
    let mut file = File::open(filename).map_err(|e| Err::IoError(e, Loc::new(0, 0)))?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)
        .map_err(|e| Err::IoError(e, Loc::new(0, 0)))?;
    //contents.retain( |e| *e != b'\r');
    parse_statements_until_eof(Span::new(contents.as_bytes()))
}

/// locate a file by its name relative to current tup file path by recursively going up the directory tree
pub fn locate_file(cur_tupfile: &Path, file_to_loc: &str) -> Option<PathBuf> {
    let mut cwd = cur_tupfile;
    let pb: PathBuf;
    if cur_tupfile.is_dir() {
        pb = cur_tupfile.join("Tupfile");
        cwd = &pb;
    }
    while let Some(parent) = cwd.parent() {
        let p = parent.join(file_to_loc);
        if p.is_file() {
            return Some(p);
        }
        cwd = parent;
    }
    None
}

/// locate TupRules.tup\[.lua\] walking up the directory tree
pub(crate) fn locate_tuprules(cur_tupfile: &Path) -> Option<PathBuf> {
    locate_file(cur_tupfile, "Tuprules.tup").or(locate_file(cur_tupfile, "Tuprules.lua"))
}
