use crate::nom::Parser;
use nom::AsChar;
/// This module handles tokenizing and parsing of statements in a tupfile using nom
use std::collections::VecDeque;
use std::path::Path;

use combinator::eof;
use log::log_enabled;
use nom::bytes::complete::{is_a, is_not};
use nom::character::complete;
use nom::character::complete::{anychar, line_ending, multispace0, space0, space1};
use nom::character::complete::{multispace1, newline, not_line_ending};
use nom::combinator::{complete, cut, opt, peek, value};
use nom::error::{context, ErrorKind};
use nom::multi::{many0, many1, many_till};
use nom::number::Endianness;
use nom::sequence::{delimited, preceded, terminated};
use nom::Err;
use nom::IResult as nomIResult;
use nom::{
    branch::alt,
    bytes::complete::{tag, take, take_while},
    character::complete::one_of,
    combinator,
};
use nom::{AsBytes, Offset};
use nom_language::error::{VerboseError, VerboseErrorKind};
use nom_locate::LocatedSpan;

use crate::statements::Level;
use crate::statements::*;
use tuppaths::descs::PathDescriptor;

type IResult<I, O, E = VerboseError<I>> = nomIResult<I, O, E>;

/// Span is an alias for LocatedSpan
pub(crate) type Span<'a> = LocatedSpan<&'a [u8]>;
pub(crate) struct InputRange<'a> {
    i: Span<'a>,
    offset: usize,
}

impl<'a> InputRange<'a> {
    fn new(i: Span<'a>, offset: usize) -> Self {
        InputRange { i, offset }
    }
    pub(crate) fn location_line(&self) -> u32 {
        self.i.location_line()
    }
    pub(crate) fn get_column(&self) -> usize {
        self.i.get_column()
    }
    pub(crate) fn get_offset(&self) -> usize {
        self.offset
    }
    pub(crate) fn fragment_len(&self) -> usize {
        self.i.fragment()[..self.get_offset()].len()
    }
}

fn span(i: Span, offset: usize) -> InputRange {
    InputRange::new(i, offset)
}

const END_KEYWORDS: [&str; 4] = ["else", "endif", "endef", "endtask"];
fn from_utf8(s: Span) -> Result<String, std::str::Utf8Error> {
    std::str::from_utf8(s.as_bytes()).map(|x| x.to_owned())
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum EndClause {
    Else,
    Endif,
    //EndDef
}

static BRKTOKS: &'static str = "\\\n$@";
static BRKTOKSQ: &'static str = "\\\n$@\"";
static BRKTOKSWS: &'static str = "\\\n$@ ";
static BRKTOKSIO: &'static str = "\\\n $@^<{";
static BRKTAGSNOWS: &'static str = "<|{";
static BRKTAGS: &'static str = " <|{^";

/// convert byte str to PathExpr
fn from_str(res: Span) -> Result<PathExpr, std::str::Utf8Error> {
    from_utf8(res).map(PathExpr::from)
}
/// check if char is part of an identifier (lhs of var assignment)
fn is_ident(c: u8) -> bool {
    AsChar::is_alphanum(c)
        || c == b'_'
        || c == b'-'
        || c == b'.'
        || c == b'%'
        || c == b'+'
        || c == b'/'
        || c == b'\\'
        || c == b'?'
}

fn is_ident_perc(c: u8) -> bool {
    is_ident(c)
}

fn manynewlineesc(input: Span) -> IResult<Span, Span> {
    let (s, _) = many1(preceded(tag("\\"), line_ending)).parse(input)?;
    Ok((s, default_inp()))
}
/// read a space or blackslash newline continuation
fn sp1(input: Span) -> IResult<Span, Span> {
    alt((complete(manynewlineesc), space1)).parse(input)
}

/// ignore until line ending
fn ws0_line_ending(i: Span) -> IResult<Span, ()> {
    if i.is_empty() {
        return Err(Err::Error(error_position!(i, ErrorKind::Eof)));
    }
    let (s, _) = space0(i)?;
    if s.is_empty() {
        return Ok((s, ()));
    }
    let (s, _) = alt((line_ending, tag("\r"))).parse(s)?;
    Ok((s, ()))
}
// checks for presence of a group expression that begins with some path.`
fn parse_pathexpr_raw_angle(input: Span) -> IResult<Span, Span> {
    //let i = input.clone();
    preceded(is_not(BRKTAGS), tag("<")).parse(input)
}

// parse expession wrapped inside dollar or at
fn close_bracket(s: char) -> char {
    match s {
        '<' => '>',
        '{' => '}',
        '(' => ')',
        '[' => ']',
        _ => s,
    }
}

fn parse_pathexpr_ref_raw(schar: char, input: Span) -> IResult<Span, String> {
    let (s, _) = alt((tag("$"), tag("@"))).parse(input)?;
    let (s, _) = complete::char(schar).parse(s)?;
    let (s, r) = context("dollar expression name", cut(take_while(is_ident_perc))).parse(s)?;
    let (s, _) = complete::char(close_bracket(schar)).parse(s)?;
    let raw = std::str::from_utf8(r.as_bytes()).expect("failed to decode name as utf8");
    log::debug!("parsed $({})", raw);
    Ok((s, raw.to_owned()))
}

/// parses dollar expressions that replace a string with another (pattern and its replacement appears after a colon)
fn parse_pathexpr_patsubst_alt(
    input: Span,
) -> IResult<Span, (String, Vec<PathExpr>, Vec<PathExpr>)> {
    let (s, _) = alt((tag("$("), tag("@("))).parse(input)?;
    let (s, r) = take_while(is_ident_perc).parse(s)?;
    let (s, _) = tag(":").parse(s)?;
    let (s, (pattern, _)) = context(
        "pattern ",
        cut(|s| parse_pelist_till_delim_with_ws(s, "=", &BRKTOKSWS)),
    )
    .parse(s)?;
    let (s, (replacement, _)) = context(
        "replacement ",
        cut(|s| parse_pelist_till_delim_with_ws(s, ")", &BRKTOKSWS)),
    )
    .parse(s)?;
    let raw = std::str::from_utf8(r.as_bytes()).unwrap();
    log::debug!("parsed $({}:{:?}={:?})", raw, pattern, replacement);
    Ok((s, (raw.to_owned(), pattern, replacement)))
}

// read a ! followed by macro name
fn parse_pathexpr_raw_macroref(i: Span) -> IResult<Span, String> {
    let (s, _) = opt(sp1).parse(i)?;
    let (s, _) = tag("!").parse(s)?;
    let (s, r) = take_while(is_ident).parse(s)?;
    let raw = std::str::from_utf8(r.as_bytes()).unwrap();
    log::debug!("parsed macro ref: {:?}", raw);
    Ok((s, raw.to_owned()))
}

// read a curly brace and the identifier inside it
fn parse_pathexpr_raw_bin(i: Span) -> IResult<Span, String> {
    let (s, _) = tag("{").parse(i)?;
    let (s, r) = take_while(is_ident).parse(s)?;
    let (s, _) = tag("}").parse(s)?;
    let raw = std::str::from_utf8(r.as_bytes()).unwrap();
    Ok((s, raw.to_owned()))
}
// parse the beginning of an exclude pattern (starts with ^)
fn parse_pathexpr_hat(i: Span) -> IResult<Span, String> {
    let (s, _) = tag("^").parse(i)?;
    let (s, r) = is_not(" \t\n\r").parse(s)?;
    let raw = std::str::from_utf8(r.as_bytes()).unwrap();
    Ok((s, raw.to_owned()))
}

// read '<' and the list of rvals inside it until '>'
fn parse_pathexpr_angle(i: Span) -> IResult<Span, (Vec<PathExpr>, Vec<PathExpr>)> {
    //let input = i.clone();
    let (s, v0) =
        many_till(|i| parse_pathexpr_no_ws(i, " \t\r\n<{", &BRKTOKS), tag("<")).parse(i)?;
    //let (s, _) = tag("<").parse(s)?;
    let (s, v) = many_till(
        |i| parse_pathexpr_no_ws(i, ">", &BRKTOKS), // avoid reading tags , newlines, spaces
        tag(">"),
    )
    .parse(s)?;
    //let v0 = v0.map(|x| x.0);
    Ok((s, (v0.0, v.0)))
}

// parse rvalue at expression eg $(H) for config vars
fn parse_pathexpr_at(i: Span) -> IResult<Span, PathExpr> {
    context(
        "config(@) expression",
        alt((
            complete((|i| parse_pathexpr_ref_raw('(', i)).map(PathExpr::AtExpr)),
            complete((|i| parse_pathexpr_ref_raw('{', i)).map(PathExpr::AtExpr)),
        )),
    )
    .parse(i)
}

fn parse_pathexpr_taskref(i: Span) -> IResult<Span, PathExpr> {
    context(
        "task reference",
        delimited(tag("&task{"), parse_ident, tag("}")).map(PathExpr::TaskRef),
    )
    .parse(i)
}

// parse rvalue dollar expression eg $(H)
pub(crate) fn parse_pathexpr_dollar(i: Span) -> IResult<Span, PathExpr> {
    let (_, peekchars) = peek(take(3usize)).parse(i)?;
    let parse_pathexpr_fallback = alt((
        complete(
            parse_pathexpr_patsubst_alt.map(|(sym, pattern, replacement)| {
                PathExpr::from(DollarExprs::PatSubst(
                    pattern,
                    replacement,
                    vec![PathExpr::from(DollarExprs::DollarExpr(sym))],
                ))
            }),
        ),
        complete(
            (|i| parse_pathexpr_ref_raw('(', i))
                .map(|x| PathExpr::from(DollarExprs::DollarExpr(x))),
        ),
    ));
    match peekchars.as_bytes() {
        b"$(a" | b"$(b" => context(
            "dollar expression (class 1)",
            // select among parsers that process dollar exprs with first char 'a' or 'b'
            alt((
                complete(parse_pathexpr_addprefix),
                complete(parse_pathexpr_addsuffix),
                complete(parse_pathexpr_abspath),
                complete(parse_pathexpr_basename),
                complete(parse_pathexpr_fallback),
            )),
        )
        .parse(i),
        b"$(c" | b"$(d" | b"$(e" => context(
            "dollar expression (class 2)",
            // select among parsers that process dollar exprs with first char 'c', 'd' or 'e'
            alt((
                complete(parse_pathexpr_call),
                complete(parse_pathexpr_dir),
                complete(parse_pathexpr_eval),
                complete(parse_pathexpr_message), // for $(error..
                complete(parse_pathexpr_fallback),
            )),
        )
        .parse(i),
        b"$(f" | b"$(g" => context(
            "dollar expression (class 3)",
            // select among parsers that process dollar exprs with first char 'f'
            alt((
                complete(parse_pathexpr_filter),
                complete(parse_pathexpr_filter_out),
                complete(parse_pathexpr_format),
                complete(parse_pathexpr_findstring),
                complete(parse_pathexpr_foreach),
                complete(parse_pathexpr_firstword),
                complete(parse_pathexpr_grep_files),
                complete(parse_pathexpr_groupname),
                complete(parse_pathexpr_fallback),
            )),
        )
        .parse(i),
        b"$(i" | b"$(n" | b"$(p" | b"$(r" => context(
            "dollar expression (class 4)",
            // select among parsers that process dollar exprs with first char 'i'... 'r'
            alt((
                complete(parse_pathexpr_if),
                complete(parse_pathexpr_notdir),
                complete(parse_pathexpr_patsubst),
                complete(parse_pathexpr_realpath),
                complete(parse_pathexpr_message), // for $(info..
                complete(parse_pathexpr_fallback),
            )),
        )
        .parse(i),

        b"$(s" | b"$(w" => context(
            "dollar expression (class 5)",
            //  select among parsers that process dollar exprs with first char 's'... 'w'
            alt((
                complete(parse_pathexpr_strip),
                complete(parse_pathexpr_subst),
                complete(parse_pathexpr_shell),
                complete(parse_pathexpr_stripprefix),
                complete(parse_pathexpr_word),
                complete(parse_pathexpr_wildcard),
                complete(parse_pathexpr_message), // for $(warning.. or $(warn..
                complete(parse_pathexpr_fallback),
            )),
        )
        .parse(i),
        _ => context("dollar expression general", parse_pathexpr_fallback).parse(i),
    }
}

// parse rvalue dollar expression with curlies eg ${H}
fn parse_pathexpr_dollar_curl(i: Span) -> IResult<Span, PathExpr> {
    context("Expression with curls", |i| parse_pathexpr_ref_raw('{', i))
        .map(|x| PathExpr::from(DollarExprs::DollarExpr(x)))
        .parse(i)
}

// parse a references to a macro
fn parse_pathexpr_macroref(i: Span) -> IResult<Span, PathExpr> {
    context(
        "reference to macro",
        parse_pathexpr_raw_macroref.map(PathExpr::MacroRef),
    )
    .parse(i)
}

// parse an exclude pattern
fn parse_pathexpr_exclude_pattern(i: Span) -> IResult<Span, PathExpr> {
    context(
        "exclude pattern",
        parse_pathexpr_hat.map(PathExpr::ExcludePattern),
    )
    .parse(i)
}

// parse a group path/<group>
fn parse_pathexpr_group(i: Span) -> IResult<Span, PathExpr> {
    context(
        "Group",
        parse_pathexpr_angle.map(|rv| PathExpr::Group(rv.0, rv.1)),
    )
    .parse(i)
}

// parse to a bucket name: {objs}
fn parse_pathexpr_bin(i: Span) -> IResult<Span, PathExpr> {
    context("Bin", parse_pathexpr_raw_bin.map(PathExpr::Bin)).parse(i)
}

// there isn't much escaping in tupfiles,(similar to makefile),
// only $ and newline are escaped
// if you have problems use variables to escape special characters that
// clash with break_toks and end_toks.
fn parse_escaped<'a, 'b>(i: Span<'a>, end_tok: &'b str) -> IResult<Span<'a>, PathExpr> {
    let (_, r) = peek(take(2_usize)).parse(i)?;
    match r.as_bytes() {
        b"\\\r" => {
            let (_, r) = peek(take(3_usize)).parse(i)?;
            if r.as_bytes() == b"\\\r\n" {
                let (s, _) = take(3_usize).parse(i)?; //consumes \n after \r as well
                Ok((s, Default::default()))
            } else {
                Err(Err::Error(error_position!(i, ErrorKind::Eof))) //FIXME: what errorkind should we return?
            }
        }
        b"\\\n" => {
            let (s, _) = take(2_usize).parse(i)?;
            Ok((s, Default::default()))
        }
        [b'\\', c] if !end_tok.contains(*c as char) => {
            let (s, r) = take(2_usize).parse(i)?;
            let pe = from_str(r).map_err(|_| Err::Error(error_position!(i, ErrorKind::Escaped)))?;
            Ok((s, pe))
        }
        [b'\\', c] if end_tok.contains(*c as char) => {
            let (s, r) = take(1_usize).parse(i)?;
            let pe = from_str(r).map_err(|_| Err::Error(error_position!(i, ErrorKind::Escaped)))?;
            Ok((s, pe))
        }
        _ => Err(Err::Error(error_position!(i, ErrorKind::Eof))), //FIXME: what errorkind should we return?
    }
}
fn test_pathexpr_ref(i: Span) -> bool {
    let res = || -> IResult<Span, bool> {
        let (_, r) = peek(take(1_usize)).parse(i)?;
        let ismatch = matches!(r.as_bytes(), b"$" | b"@");
        Ok((i, ismatch))
    };
    res().map(|x| x.1).unwrap_or(false)
}

/// parse basic special expressions (dollar, at, ampersand)
fn parse_pathexprbasic(i: Span) -> IResult<Span, PathExpr> {
    let (s, r) = peek(take(2_usize)).parse(i)?;
    match r.as_bytes() {
        b"$(" => parse_pathexpr_dollar(s),
        b"@(" => parse_pathexpr_at(s),
        b"${" => parse_pathexpr_dollar_curl(s),
        _ => Err(Err::Error(error_position!(i, ErrorKind::Eof))),
    }
}

/// parse $(addsuffix suffix, list)
fn parse_pathexpr_addsuffix(i: Span) -> IResult<Span, PathExpr> {
    let (s, _) = tag("$(addsuffix").parse(i)?;
    let (s, _) = parse_ws(s)?;
    let (s, (suffix, _)) = parse_pelist_till_delim_with_ws(s, ",", &BRKTOKSWS)?;
    let (s, _) = opt(parse_ws).parse(s)?;
    let (s, (list, _)) = parse_pelist_till_delim_with_ws(s, ")", &BRKTOKSWS)?;
    let (s, _) = opt(parse_ws).parse(s)?;
    log::debug!("parsed add suffix: {:?} {:?}", suffix, list);
    Ok((s, PathExpr::from(DollarExprs::AddSuffix(suffix, list))))
}

/// parse $(addprefix prefix, list)
fn parse_pathexpr_addprefix(i: Span) -> IResult<Span, PathExpr> {
    let (s, _) = tag("$(addprefix").parse(i)?;
    let (s, _) = parse_ws(s)?;
    let (s, (prefix, _)) = cut(|s| parse_pelist_till_delim_with_ws(s, ",", &BRKTOKSWS)).parse(s)?;
    let (s, _) = opt(parse_ws).parse(s)?;
    let (s, (list, _)) = cut(|s| parse_pelist_till_delim_with_ws(s, ")", &BRKTOKSWS)).parse(s)?;
    let (s, _) = opt(parse_ws).parse(s)?;
    log::debug!("parsed add prefix: {:?} {:?}", prefix, list);
    Ok((s, PathExpr::from(DollarExprs::AddPrefix(prefix, list))))
}

/// parse $(subst from,to,text)
/// $(subst from,to,text) is a function that replaces all occurrences of from with to in text.
fn parse_pathexpr_subst(i: Span) -> IResult<Span, PathExpr> {
    let (s, _) = tag("$(subst").parse(i)?;
    let (s, _) = parse_ws(s)?;
    let (s, (from, _)) = cut(|s| parse_pelist_till_delim_with_ws(s, ",", &BRKTOKSWS)).parse(s)?;
    let (s, _) = opt(parse_ws).parse(s)?;
    let (s, (to, _)) = cut(|s| parse_pelist_till_delim_with_ws(s, ",", &BRKTOKSWS)).parse(s)?;
    let (s, _) = opt(parse_ws).parse(s)?;
    let (s, (text, _)) = cut(|s| parse_pelist_till_delim_with_ws(s, ")", &BRKTOKSWS)).parse(s)?;
    let (s, _) = opt(parse_ws).parse(s)?;
    log::debug!(
        "parsed subst: from : {:?} to:{:?} on text:{:?}",
        from,
        to,
        text
    );
    Ok((s, PathExpr::from(DollarExprs::Subst(from, to, text))))
}

/// $(patsubst from,to,text) is a function that replaces all occurrences of from with to in text.
fn parse_pathexpr_patsubst(i: Span) -> IResult<Span, PathExpr> {
    let (s, _) = tag("$(patsubst").parse(i)?;
    let (s, _) = parse_ws(s)?;
    let (s, (from, _)) = cut(|s| parse_pelist_till_delim_with_ws(s, ",", &BRKTOKSWS)).parse(s)?;
    let (s, _) = opt(parse_ws).parse(s)?;
    let (s, (to, _)) = cut(|s| parse_pelist_till_delim_with_ws(s, ",", &BRKTOKSWS)).parse(s)?;
    let (s, _) = opt(parse_ws).parse(s)?;
    let (s, (text, _)) = cut(|s| parse_pelist_till_delim_with_ws(s, ")", &BRKTOKSWS)).parse(s)?;
    let (s, _) = opt(parse_ws).parse(s)?;
    log::debug!(
        "parsed patsubst: from : {:?} to:{:?} on text:{:?}",
        from,
        to,
        text
    );
    Ok((s, PathExpr::from(DollarExprs::PatSubst(from, to, text))))
}

/// parse $(finstring find, in)
/// $(findstring find, in) is a function that searches for find in and returns `find` if it is found, otherwise it returns the empty string.
fn parse_pathexpr_findstring(i: Span) -> IResult<Span, PathExpr> {
    let (s, _) = tag("$(findstring").parse(i)?;
    let (s, _) = parse_ws(s)?;
    let (s, (find, _)) = parse_pelist_till_delim_with_ws(s, ",", &BRKTOKSWS)?;
    let (s, _) = opt(parse_ws).parse(s)?;
    let (s, (in_, _)) = parse_pelist_till_delim_with_ws(s, ")", &BRKTOKSWS)?;
    let (s, _) = opt(parse_ws).parse(s)?;
    log::debug!("parsed findstring: {:?} {:?}", find, in_);
    Ok((s, PathExpr::from(DollarExprs::FindString(find, in_))))
}

/// parse $(foreach var,list,text)
/// $(foreach var,list,text) is a function that expands text once for each word in list, replacing each occurrence of var with the current word.
fn parse_pathexpr_foreach(i: Span) -> IResult<Span, PathExpr> {
    let (s, _) = tag("$(foreach").parse(i)?;
    let (s, _) = parse_ws(s)?;
    let (s, r) = take_while(is_ident).parse(s)?;
    let var = std::str::from_utf8(r.as_bytes()).unwrap().to_string();
    let (s, _) = opt(parse_ws).parse(s)?;
    let (s, _) = tag(",").parse(s)?;
    let (s, (list, _)) = parse_pelist_till_delim_with_ws(s, ",", &BRKTOKSIO)?;
    let (s, _) = opt(parse_ws).parse(s)?;
    log::debug!(
        "next few chars: {:?}",
        std::str::from_utf8(&s.as_bytes()[..10]).unwrap()
    );
    let (s, (text, _)) = parse_pelist_till_delim_with_ws(s, ")", &BRKTOKSWS)?;
    let (s, _) = opt(parse_ws).parse(s)?;
    log::debug!("parsed foreach: {:?} {:?}", list, text);
    Ok((s, PathExpr::from(DollarExprs::ForEach(var, list, text))))
}

/// parse $(filter pattern...,text)
/// $(filter pattern...,text) is a function that returns the words in text that match at least one of the given patterns.
fn parse_pathexpr_filter(i: Span) -> IResult<Span, PathExpr> {
    let (s, _) = tag("$(filter").parse(i)?;
    let (s, _) = parse_ws(s)?;
    let (s, (patterns, _)) = parse_pelist_till_delim_with_ws(s, ",", &BRKTOKSWS)?;
    let (s, _) = opt(parse_ws).parse(s)?;
    let (s, (text, _)) = parse_pelist_till_delim_with_ws(s, ")", &BRKTOKSWS)?;
    let (s, _) = opt(parse_ws).parse(s)?;
    log::debug!("parsed filter: {:?} {:?}", patterns, text);
    Ok((s, PathExpr::from(DollarExprs::Filter(patterns, text))))
}

// parse $(filter-out pattern...,text)
/// $(filter-out pattern...,text) is a function that returns the words in text that do not match any of the given patterns.
fn parse_pathexpr_filter_out(i: Span) -> IResult<Span, PathExpr> {
    let (s, _) = tag("$(filter-out").parse(i)?;
    let (s, _) = parse_ws(s)?;
    let (s, (patterns, _)) = parse_pelist_till_delim_with_ws(s, ",", &BRKTOKSWS)?;
    let (s, _) = opt(parse_ws).parse(s)?;
    let (s, (text, _)) = parse_pelist_till_delim_with_ws(s, ")", &BRKTOKSWS)?;
    let (s, _) = opt(parse_ws).parse(s)?;
    log::debug!("parsed filter-out: {:?} {:?}", patterns, text);
    Ok((s, PathExpr::from(DollarExprs::FilterOut(patterns, text))))
}

/// parse $(shell command)
fn parse_pathexpr_shell(i: Span) -> IResult<Span, PathExpr> {
    let (s, _) = tag("$(shell").parse(i)?;
    let (s, _) = parse_ws(s)?;
    let (s, (cmd, _)) = parse_pelist_till_delim_with_ws(s, ")", &BRKTOKSQ)?;
    let (s, _) = opt(parse_ws).parse(s)?;
    log::debug!("parsed shell: {:?}", cmd);
    Ok((s, PathExpr::DollarExprs(DollarExprs::Shell(cmd))))
}

fn be_32(s: Span) -> IResult<Span, i32> {
    nom::number::complete::i32(Endianness::Big).parse(s)
}

/// parse $(word n,text)
/// $(word n,text) is a function that returns the nth word of text.
fn parse_pathexpr_word(i: Span) -> IResult<Span, PathExpr> {
    let (s, _) = tag("$(word").parse(i)?;
    let (s, _) = parse_ws(s)?;
    let (s, n) = be_32(s)?;
    let (s, _) = opt(parse_ws).parse(s)?;
    let (s, (text, _)) = parse_pelist_till_delim_with_ws(s, ")", &BRKTOKSWS)?;
    let (s, _) = opt(parse_ws).parse(s)?;
    log::debug!("parsed word at {n} on {:?}", text);
    Ok((s, PathExpr::from(DollarExprs::Word(n, text))))
}

/// parse $(call variable, param...)
fn parse_pathexpr_call(i: Span) -> IResult<Span, PathExpr> {
    let (s, _) = tag("$(call").parse(i)?;
    let (s, _) = parse_ws(s)?;
    let (s, (var, mut end)) = parse_pelist_till_delim_with_ws(s, ",)", &BRKTOKSWS)?;
    let mut params = Vec::new();
    log::debug!("parsed call var: {:?}", var);
    let mut rest = s;
    while end == ',' {
        let (s, _) = opt(parse_ws).parse(rest)?;
        let (s, (p, e)) = parse_pelist_till_delim_with_ws(s, ",)", &BRKTOKSWS)?;
        log::debug!("parsed call param: {:?}", p);
        params.push(p);
        end = e;
        rest = s;
    }
    log::debug!("parsed call var {:?} with params: {:?}", var, params);
    Ok((rest, PathExpr::from(DollarExprs::Call(var, params))))
}

/// parse wild card $(wildcard pattern...)
/// $(wildcard pattern...) is a function that returns the names of all files that match one of the given patterns.
fn parse_pathexpr_wildcard(i: Span) -> IResult<Span, PathExpr> {
    let (s, _) = tag("$(wildcard").parse(i)?;
    let (s, _) = parse_ws(s)?;
    let (s, (pattern, _)) = parse_pelist_till_delim_with_ws(s, ")", &BRKTOKSWS)?;
    let (s, _) = opt(parse_ws).parse(s)?;
    log::debug!("parsed wildcard: {:?}", pattern);
    Ok((s, PathExpr::from(DollarExprs::WildCard(pattern))))
}

/// parse $(firstword names...)
/// $(firstword names...) is a function that returns the first word of names.
fn parse_pathexpr_firstword(i: Span) -> IResult<Span, PathExpr> {
    let (s, _) = tag("$(firstword").parse(i)?;
    let (s, _) = parse_ws(s)?;
    let (s, (pattern, _)) = parse_pelist_till_delim_with_ws(s, ")", &BRKTOKSWS)?;
    let (s, _) = opt(parse_ws).parse(s)?;
    log::debug!("parsed firstword: {:?}", pattern);
    Ok((s, PathExpr::from(DollarExprs::FirstWord(pattern))))
}

/// parse eval expression $(eval body)
fn parse_pathexpr_eval(i: Span) -> IResult<Span, PathExpr> {
    let (s, _) = tag("$(eval").parse(i)?;
    let (s, _) = parse_ws(s)?;
    let (s, (exps, _)) = cut(context("parsing body of eval block", |s| {
        parse_pelist_till_delim_with_ws(s, ")", &BRKTOKSWS)
    }))
    .parse(s)?;
    let (s, _) = opt(parse_ws).parse(s)?;
    let (s, _) = opt(tag(";")).parse(s)?;
    log::debug!("parsed eval: {:?}", exps);
    Ok((s, PathExpr::DollarExprs(DollarExprs::Eval(exps))))
}
/// parse message expression $(error/info/warn/warning body)
fn parse_pathexpr_message(i: Span) -> IResult<Span, PathExpr> {
    let (s, level) = alt((
        complete(value(Level::Warning, tag("$(warning"))),
        complete(value(Level::Warning, tag("$(warn"))),
        complete(value(Level::Info, tag("$(info"))),
        complete(value(Level::Error, tag("$(error"))),
    ))
    .parse(i)?;
    let (s, _) = parse_ws(s)?;
    let (s, (exps, _)) = cut(context("parsing body of message", |s| {
        parse_pelist_till_delim_with_ws(s, ")", &BRKTOKSWS)
    }))
    .parse(s)?;
    let (s, _) = opt(parse_ws).parse(s)?;
    let (s, _) = opt(tag(";")).parse(s)?;
    log::debug!("parsed message: {:?} at level {:?}", exps, level);
    Ok((s, PathExpr::DollarExprs(DollarExprs::Message(exps, level))))
}

/// parse $(dir names...)
/// $(dir names...) is a function that returns the directory-part of each file name in names.
fn parse_pathexpr_dir(i: Span) -> IResult<Span, PathExpr> {
    let (s, _) = tag("$(dir").parse(i)?;
    let (s, _) = parse_ws(s)?;
    let (s, (pattern, _)) = parse_pelist_till_delim_with_ws(s, ")", &BRKTOKSWS)?;
    let (s, _) = opt(parse_ws).parse(s)?;
    log::debug!("parsed dir: {:?}", pattern);
    Ok((s, PathExpr::from(DollarExprs::Dir(pattern))))
}

/// parse $(notdir names...)
/// $(nodir names...) is a function that returns the non-directory-part of each file name in names.
fn parse_pathexpr_notdir(i: Span) -> IResult<Span, PathExpr> {
    let (s, _) = tag("$(notdir").parse(i)?;
    let (s, _) = parse_ws(s)?;
    let (s, (pattern, _)) = parse_pelist_till_delim_with_ws(s, ")", &BRKTOKSWS)?;
    let (s, _) = opt(parse_ws).parse(s)?;
    log::debug!("parsed notdir: {:?}", pattern);
    Ok((s, PathExpr::from(DollarExprs::NotDir(pattern))))
}

/// parse $(abspath names...)
/// $(abspath names...) is a function that returns the absolute file names of the given file names.
fn parse_pathexpr_abspath(i: Span) -> IResult<Span, PathExpr> {
    let (s, _) = tag("$(abspath").parse(i)?;
    let (s, _) = parse_ws(s)?;
    let (s, (pattern, _)) = parse_pelist_till_delim_with_ws(s, ")", &BRKTOKSWS)?;
    let (s, _) = opt(parse_ws).parse(s)?;
    log::debug!("parsed abspath: {:?}", pattern);
    Ok((s, PathExpr::from(DollarExprs::AbsPath(pattern))))
}

// parse $(grep-files pattern, glob, paths)
/// $(grep-files pattern, glob, paths) is a function that returns the files in paths that match the given pattern.
fn parse_pathexpr_grep_files(i: Span) -> IResult<Span, PathExpr> {
    let (s, _) = tag("$(grep-files").parse(i)?;
    let (s, _) = parse_ws(s)?;
    let (s, _) = many0(delimited(tag("-"), anychar, sp1)).parse(s)?;
    let (s, pattern) = cut(context("parsing grep pattern", parse_quote)).parse(s)?;
    let (s, _) = opt(parse_ws).parse(s)?;
    let (s, (glob, _end)) = cut(context("parsing file globs", |s| {
        parse_pelist_till_delim_with_ws(s, ")", &BRKTOKSWS)
    }))
    .parse(s)?;
    let (s, _) = opt(parse_ws).parse(s)?;
    //let (s, bytes) = take_until(")").parse(s)?;

    let (s, _) = opt(parse_ws).parse(s)?;
    log::debug!("parsed grep-files: pattern: {:?} glob: {:?}", pattern, glob);
    Ok((
        s,
        PathExpr::from(DollarExprs::GrepFiles(vec![pattern], glob)),
    ))
}

/// parse $(if condition, then-part\[,else-part\])
/// $(if condition, then-part\[,else-part\]) is a function that evaluates condition as the contents of a make variable would be evaluated as a conditional
/// (see Syntax of Conditionals). If condition is true, then-part is evaluated and becomes the result of the function.
/// Otherwise, else-part is evaluated and becomes the result of the function. If else-part is omitted, it is treated as an empty string.
fn parse_pathexpr_if(i: Span) -> IResult<Span, PathExpr> {
    let (s, _) = tag("$(if").parse(i)?;
    let (s, _) = parse_ws(s)?;
    let (s, (condition, _)) = parse_pelist_till_delim_with_ws(s, ",", &BRKTOKSWS)?;
    let (s, (then_part, endchar)) = parse_pelist_till_delim_with_ws(s, ",)", &BRKTOKSWS)?;
    if endchar == ')' {
        return Ok((
            s,
            PathExpr::from(DollarExprs::If(condition, then_part, Vec::new())),
        ));
    }
    let (s, (else_part, _)) = parse_pelist_till_delim_with_ws(s, ")", &BRKTOKSWS)?;
    let (s, _) = opt(parse_ws).parse(s)?;
    log::debug!("parsed if: {:?} {:?} {:?}", condition, then_part, else_part);
    Ok((
        s,
        PathExpr::from(DollarExprs::If(condition, then_part, else_part)),
    ))
}

/// parse $(stripprefix prefix, body)
/// $(stripprefix prefix, body) is a function that removes the prefix from the beginning of body.
/// If body does not start with prefix, the result is body.
fn parse_pathexpr_stripprefix(i: Span) -> IResult<Span, PathExpr> {
    let (s, _) = tag("$(stripprefix").parse(i)?;
    let (s, _) = parse_ws(s)?;
    let (s, (prefix, _)) = parse_pelist_till_delim_with_ws(s, ",", &BRKTOKSWS)?;
    let (s, _) = opt(parse_ws).parse(s)?;
    let (s, (body, _)) = parse_pelist_till_delim_with_ws(s, ")", &BRKTOKSWS)?;
    let (s, _) = opt(parse_ws).parse(s)?;
    log::debug!("parsed stripprefix: {:?} {:?}", prefix, body);
    Ok((s, PathExpr::from(DollarExprs::StripPrefix(prefix, body))))
}

/// parse $(formatpath quoted_str, ...)
/// $(formatpath quoted_str...) is a function that returns the string str with the format specifiers replaced by the corresponding arguments for each word in the list.
fn parse_pathexpr_format(i: Span) -> IResult<Span, PathExpr> {
    let (s, _) = tag("$(formatpath ").parse(i)?;
    let (s, _) = opt(parse_ws).parse(s)?;
    let (s, (format_spec, _e)) = cut(context("parsing format specifier ", |s| {
        parse_pelist_till_delim_with_ws(s, ",", &BRKTOKSWS)
    }))
    .parse(s)?;
    let (s, (pattern, _)) = cut(context("parsing body of format ", |s| {
        parse_pelist_till_delim_with_ws(s, ")", &BRKTOKSWS)
    }))
    .parse(s)?;
    log::debug!("parsed formatpath: {:?} {:?}", format_spec, pattern);
    Ok((s, PathExpr::from(DollarExprs::Format(format_spec, pattern))))
}

fn parse_pathexpr_groupname(i: Span) -> IResult<Span, PathExpr> {
    let (s, _) = tag("$(groupname").parse(i)?;
    let (s, _) = parse_ws(s)?;
    let (s, (groupname, _)) = parse_pelist_till_delim_with_ws(s, ")", &BRKTOKSWS)?;
    let (s, _) = opt(parse_ws).parse(s)?;
    Ok((s, PathExpr::from(DollarExprs::GroupName(groupname))))
}
/// parse $(realpath names...)
/// $(realpath names...) is a function that returns the canonical absolute names of the given file names.
fn parse_pathexpr_realpath(i: Span) -> IResult<Span, PathExpr> {
    let (s, _) = tag("$(realpath").parse(i)?;
    let (s, _) = parse_ws(s)?;
    let (s, (pattern, _)) = parse_pelist_till_delim_with_ws(s, ")", &BRKTOKSWS)?;
    let (s, _) = opt(parse_ws).parse(s)?;
    Ok((s, PathExpr::from(DollarExprs::RealPath(pattern))))
}

/// parse $(basename names...)
/// $(basename names...) is a function that returns the non-directory-part of each file name without extension in names.
fn parse_pathexpr_basename(i: Span) -> IResult<Span, PathExpr> {
    let (s, _) = tag("$(basename").parse(i)?;
    let (s, _) = parse_ws(s)?;
    let (s, (pattern, _)) = parse_pelist_till_delim_with_ws(s, ")", &BRKTOKSWS)?;
    let (s, _) = opt(parse_ws).parse(s)?;
    Ok((s, PathExpr::from(DollarExprs::BaseName(pattern))))
}

/// parse $(strip names...)
/// $(strip names...) is a function that returns the non-directory-part of each file name without extension in names.
fn parse_pathexpr_strip(i: Span) -> IResult<Span, PathExpr> {
    let (s, _) = tag("$(strip").parse(i)?;
    let (s, _) = parse_ws(s)?;
    let (s, (pattern, _)) = parse_pelist_till_delim_with_ws(s, ")", &BRKTOKSWS)?;
    let (s, _) = opt(parse_ws).parse(s)?;
    Ok((s, PathExpr::from(DollarExprs::Strip(pattern))))
}
/// process whitespace
fn parse_ws(i: Span) -> IResult<Span, PathExpr> {
    let (s, _) = is_a(" \t").parse(i)?;
    Ok((s, PathExpr::Sp1))
}

fn parse_quote(i: Span) -> IResult<Span, PathExpr> {
    let (s, _) = tag("\"").parse(i)?;
    let parse_inner = |s| parse_pelist_till_delim_no_ws(s, "\"", &BRKTOKSQ);
    let (s, (inner, _)) = parse_inner(s)?;
    log::debug!("read quoted pathexpr: {:?}", inner);
    Ok((s, PathExpr::Quoted(inner)))
}

/// eat up the (dollar or at) that don't parse to (dollar or at) expression
fn parse_delim(i: Span) -> IResult<Span, Span> {
    if !test_pathexpr_ref(i) {
        return Err(Err::Error(error_position!(i, ErrorKind::Escaped)));
    }
    let (s, r) = take(1_usize).parse(i)?;
    Ok((s, r))
}

/// eats up \\n
/// consume dollar's etc. that where left out during previous parsing
/// consume a literal that is not a pathexpr token
fn parse_misc_bits<'a, 'b>(input: Span<'a>, end_toks: &'b str) -> IResult<Span<'a>, Span<'a>> {
    let islit = |ref i| !end_toks.as_bytes().contains(i);
    alt((complete(parse_delim), complete(take_while(islit)))).parse(input)
}
/// parse either (dollar|at|) expression or a general rvalue delimited by delim
/// break_toks are the tokens that pause and restart the parser to create a new pathexpr
pub(crate) fn parse_pathexpr_ws<'a>(
    s: Span<'a>,
    end_tok: &'static str,
    break_toks: &'static str,
) -> IResult<Span<'a>, PathExpr> {
    let from_str_1 = |i: Span| -> Result<PathExpr, std::str::Utf8Error> {
        let pe: PathExpr = from_str(i)?;
        log::debug!("parsed misc pathexpr: {:?}", pe);
        Ok(pe)
    };
    let all_end_toks = format!("{}{}", end_tok, break_toks);
    let res = alt((
        complete(|i| parse_escaped(i, all_end_toks.as_str())),
        complete(parse_quote),
        complete(parse_ws),
        complete(parse_pathexprbasic),
        complete(parse_pathexpr_taskref),
        complete((|i| parse_misc_bits(i, all_end_toks.as_str())).map_res(from_str_1)),
    ))
    .parse(s);
    res
}

/// break_toks are the tokens that pause and restart the parser to create a new pathexpr
fn parse_pathexpr_no_ws<'a>(
    s: Span<'a>,
    end_tok: &'static str,
    break_toks: &'static str,
) -> IResult<Span<'a>, PathExpr> {
    let all_end_toks = format!("{}{}", end_tok, break_toks);
    let res = alt((
        complete(|i| parse_escaped(i, all_end_toks.as_str())),
        complete(parse_pathexprbasic),
        complete((|i| parse_misc_bits(i, all_end_toks.as_str())).map_res(from_str)),
    ))
    .parse(s);
    res
}

pub(crate) fn reparse_literal_as_input(e: &str) -> Result<Vec<PathExpr>, ()> {
    let pe_list = parse_rule_inp(Span::new(e.as_bytes()), "")
        .map(|(_, (r, _))| r)
        .map_err(|_| ())?;
    Ok(pe_list)
}
// repeatedly invoke the rvalue parser until eof or end_tok is encountered
// parser pauses to create new pathexpr when break_tok is encountered
fn parse_pelist_till_delim_with_ws<'a>(
    input: Span<'a>,
    end_tok: &'static str,
    break_toks: &'static str,
) -> IResult<Span<'a>, (Vec<PathExpr>, char)> {
    many_till(
        |i| parse_pathexpr_ws(i, end_tok, break_toks),
        alt((value('\0' as char, eof), one_of(end_tok))),
    )
    .parse(input)
}
fn parse_pelist_till_delim_or_com_with_ws<'a>(
    input: Span<'a>,
    end_tok: &'static str,
    break_toks: &'static str,
) -> IResult<Span<'a>, (Vec<PathExpr>, char)> {
    many_till(
        |i| parse_pathexpr_ws(i, end_tok, break_toks),
        alt((
            value('\0' as char, eof),
            one_of(end_tok),
            value('\0' as char, parse_ignored_comment),
        )),
    )
    .parse(input)
}

// repeatedly invoke the rvalue parser until eof or delim is encountered
// parser pauses to create new pathexpr when break_tok is encountered
fn parse_pelist_till_delim_no_ws<'a>(
    input: Span<'a>,
    end_tok: &'static str,
    break_tok: &'static str,
) -> IResult<Span<'a>, (Vec<PathExpr>, char)> {
    many_till(
        |i| parse_pathexpr_no_ws(i, end_tok, break_tok),
        alt((value('\0' as char, eof), one_of(end_tok))),
    )
    .parse(input)
}

//  wrapper over the previous parser that handles empty inputs and stops at newline;
pub(crate) fn parse_pelist_till_line_end_with_ws(
    input: Span,
) -> IResult<Span, (Vec<PathExpr>, char)> {
    alt((
        complete(ws0_line_ending.map(|_| (Vec::new(), '\0'))), // trailing ws before line ends are ignored
        complete(|i| parse_pelist_till_delim_with_ws(i, "\r\n", &BRKTOKSWS)),
    ))
    .parse(input)
}

pub(crate) fn parse_pelist_till_line_end_or_comment_with_ws(
    input: Span,
) -> IResult<Span, (Vec<PathExpr>, char)> {
    alt((
        complete(ws0_line_ending.map(|_| (Vec::new(), '\0'))), // trailing ws before line ends are ignored
        complete(|i| parse_pelist_till_delim_or_com_with_ws(i, "\r\n", &BRKTOKSWS)),
    ))
    .parse(input)
}

// read all pathexpr separated by whitespaces, pausing at BRKTOKS
fn parse_pathexpr_list_until_ws_plus(input: Span) -> IResult<Span, (Vec<PathExpr>, Span)> {
    many_till(
        |i| parse_pathexpr_no_ws(i, " \t\r\n", &BRKTOKS),
        multispace1,
    )
    .parse(input)
}

// parse a lvalue to an ident
fn parse_ident(input: Span) -> IResult<Span, Ident> {
    take_while(is_ident)
        .map_res(from_utf8)
        .map(Ident::new)
        .parse(input)
}

impl From<(Statement, InputRange<'_>)> for LocatedStatement {
    fn from((stmt, i): (Statement, InputRange<'_>)) -> Self {
        LocatedStatement::new(stmt, i.into())
    }
}

// parse include expression
fn parse_include(i: Span) -> IResult<Span, LocatedStatement> {
    let s = i;
    let (s, _) = tag("include").parse(s)?;
    let (s, _) = sp1(s)?;
    let (s, r) = context("include statement", cut(parse_pathexpr_list_until_ws_plus)).parse(s)?;
    let offset = i.offset(&s);
    let (s, _) = multispace0(s)?;
    log::debug!("parsed include: {:?} ", r.0);
    let x = span(i, offset);
    Ok((s, (Statement::Include(r.0), x).into()))
}

// parse error expression
fn parse_message(i: Span) -> IResult<Span, LocatedStatement> {
    let s = i;
    let (s, level) = alt((
        value(Level::Error, tag("$(error")),
        value(Level::Warning, tag("$(warning")),
        value(Level::Warning, tag("$(warn")),
        value(Level::Info, tag("$(info")),
    ))
    .parse(s)?;

    let (s, _) = sp1(s)?;

    let (s, r) = context(
        "Message expression",
        cut(|i| parse_pelist_till_delim_with_ws(i, ")", &BRKTOKSWS)),
    )
    .parse(s)?;
    let offset = i.offset(&s);
    Ok((s, (Statement::Message(r.0, level), span(i, offset)).into()))
}

// parse export expression
// export VARIABLE
fn parse_export(i: Span) -> IResult<Span, LocatedStatement> {
    let s = i;
    let (s, _) = tag("export").parse(s)?;
    let (s, _) = sp1(s)?;
    let (s, r) = context("export expression", cut(take_while(is_ident))).parse(s)?;
    let offset = i.offset(&s);
    let (s, _) = multispace0(s)?;
    let raw = std::str::from_utf8(r.as_bytes()).unwrap();
    Ok((
        s,
        (Statement::Export(raw.to_owned()), span(i, offset)).into(),
    ))
}

// import VARIABLE[=default]
//   The import directive sets a variable inside the Tupfile that has the value of the environment variable.
// If the environment variable is unset, the default value is used instead if provided.
// This introduces a dependency from the environment variable to the Tupfile,
// so that if the environment variable changes, the Tupfile is reparsed. For example:
//
// import CC=gcc
// : foreach *.c |> $(CC) -c %f -o %o |> %B.o
// Unlike 'export', the import command does not pass the variables to the sub-process's environment.
// In the previous example, the CC environment variable is therefore not set in the subprocess, unless 'export CC' was also in the Tupfile.
fn parse_import(i: Span) -> IResult<Span, LocatedStatement> {
    let s = i;
    let (s, _) = tag("import").parse(s)?;
    let (s, _) = sp1(s)?;
    let (s, r) = context("import expression", cut(take_while(is_ident))).parse(s)?;
    let raw = std::str::from_utf8(r.as_bytes()).unwrap();
    let (s, def) = opt(preceded(
        tag("="),
        preceded(multispace0, cut(take_while(is_ident))),
    ))
    .parse(s)?;
    let offset = i.offset(&s);
    let (s, _) = multispace0(s)?;
    let default_raw = def.and_then(|x| from_utf8(x).ok());
    Ok((
        s,
        (
            Statement::Import(raw.to_owned(), default_raw),
            span(i, offset),
        )
            .into(),
    ))
}

// parse source search dir
// vpath %.cxx ../srcs
/*fn parse_search_dir(i: Span) -> IResult<Span, LocatedStatement > {
    let s = i;
    let (s, _) = tag("vpath").parse(s)?;
    let (s, _) = sp1(s)?;
    let (s, pattern) = parse_pelist_till_delim_no_ws(s, " ", &BRKTOKSWS)?;
    let (s, _) = sp1(s)?;
    let (s, _) = tag(":").parse(s)?;
    let (s, _) = sp1(s)?;

    let (s, r) = context("search source path", cut(parse_pelist_till_line_end_with_ws)).parse(s)?;
    let offset = i.offset(&s);
    let (s, _) = multispace0(s)?;
    Ok((s, (Statement::SearchDir(pattern.0, r.0), span(i, offset)).into()))
}*/

// parse preload expression
// preload directory
fn parse_preload(i: Span) -> IResult<Span, LocatedStatement> {
    let s = i;
    let (s, _) = tag("preload").parse(s)?;
    let (s, _) = sp1(s)?;
    // preload a single directory
    let (s, r) = context(
        "preload expression",
        cut(parse_pelist_till_line_end_with_ws),
    )
    .parse(s)?;
    log::debug!("parsed preload: {:?} ", r.0);
    let offset = i.offset(&s);
    let (s, _) = multispace0(s)?;
    Ok((s, (Statement::Preload(r.0), span(i, offset)).into()))
}

// parse the run expresssion
// run ./script args
// reading other directories requires preload
// run ./build.sh *.c src/*.c
fn parse_run(i: Span) -> IResult<Span, LocatedStatement> {
    let s = i;
    let (s, _) = tag("run").parse(s)?;
    let (s, _) = sp1(s)?;
    // run  script paths
    let (s, r) = context("run expression", cut(parse_pelist_till_line_end_with_ws)).parse(s)?;
    let offset = i.offset(&s);
    let (s, _) = multispace0(s)?;
    log::debug!("parsed run: {:?} ", r.0);
    Ok((s, (Statement::Run(r.0), span(i, offset)).into()))
}
// parse include_rules expresssion
fn parse_include_rules(i: Span) -> IResult<Span, LocatedStatement> {
    let s = i;
    let (s, _) = tag("include_rules").parse(s)?;
    let (s, _) = complete(ws0_line_ending).parse(s)?;
    let offset = i.offset(&s);
    let (s, _) = multispace0(s)?;
    log::debug!("parsed include_rules");
    Ok((s, (Statement::IncludeRules, span(i, offset)).into()))
}

/// parse comment expresssion
fn parse_comment(i: Span) -> IResult<Span, LocatedStatement> {
    let s = i;
    let (s, _) = tag("#").parse(s)?;
    let (s, _) = opt(is_not("\n\r")).parse(s)?;
    let offset = i.offset(&s);
    let (s, _) = line_ending(s)?;
    Ok((s, (Statement::Comment, span(i, offset)).into()))
}
fn parse_ignored_comment(i: Span) -> IResult<Span, ()> {
    let s = i;
    if s.is_empty() {
        return Err(Err::Error(error_position!(i, ErrorKind::Eof)));
    }

    let (s, _) = opt(sp1).parse(s)?;
    let (s, _) = tag("#").parse(s)?;
    let (s, _str) = is_not("\n\r").parse(s)?;
    let (s, _) = line_ending(s)?;
    Ok((s, ()))
}

/// Parse targets by name or by output
fn parse_task_target(i: Span) -> IResult<Span, TaskTarget> {
    type Error<'a> = nom::error::Error<Span<'a>>;
    let (s, targets) = alt((
        terminated(parse_ident, preceded(space0, tag(":")))
            .map_res(|x| Ok::<TaskTarget, Error>(TaskTarget::new_id(x))),
        terminated(
            |i| parse_pelist_till_delim_no_ws(i, ":", &BRKTOKS),
            preceded(space0, tag(":")),
        )
        .map_res(|x| Ok::<TaskTarget, Error>(TaskTarget::new_outputs(x.0))),
    ))
    .parse(i)?;
    Ok((s, targets))
}
/// task(name) : dep1 dep2.
///       commands.
/// dep1 dep2 could be outputs, group, bin or another task
fn parse_task_statement(i: Span) -> IResult<Span, LocatedStatement> {
    let s = i;
    let (s, _) = tag("definetask").parse(s)?;
    let (s, _) = opt(sp1).parse(s)?;
    let (s, name) = context("Parsing task name/outputs", cut(parse_task_target)).parse(s)?;
    log::debug!("parsed task name: {:?}", name);
    let (s, _) = opt(sp1).parse(s)?;
    let (s, deps) = opt(parse_pelist_till_line_end_with_ws).parse(s)?;
    if log_enabled!(log::Level::Debug) {
        //    let nextfew_chars = std::str::from_utf8(&s.fragment()[..10]).unwrap();
        //   log::warn!("remaining: {:?}", nextfew_chars);
    }
    let deps = deps.map(|x| x.0).unwrap_or_default();

    let read_lines = |s| {
        let (s, line) =
            context("task expression", cut(parse_pelist_till_line_end_with_ws)).parse(s)?;
        Ok((s, line.0))
    };
    // take until enddef or endef occurs
    let (s, (body, _)) = context(
        "task expression",
        cut(many_till(read_lines, preceded(space0, tag("endtask")))),
    )
    .parse(s)?;
    let offset = i.offset(&s);
    let (s, _) = multispace0(s)?;
    Ok((
        s,
        (
            Statement::Task(TaskDetail::new(name, deps, body)),
            span(i, offset),
        )
            .into(),
    ))
}

/// parse an assignment expression
fn parse_assignment_expr(i: Span) -> IResult<Span, LocatedStatement> {
    let s = i;
    // parse the left side of the assignment
    let (s, left) = parse_ident(s)?;
    let (s, _) = opt(sp1).parse(s)?;
    let (s, op) = alt((tag(":="), tag("?="), tag("+="), tag("="))).parse(s)?;
    log::debug!("parsing assignment expression with lhs {:?}", left.name);
    log::debug!("op:{:?}", std::str::from_utf8(op.fragment()).unwrap_or(""));
    let (s, _) = opt(sp1).parse(s)?;
    let (s, r) = complete(parse_pelist_till_line_end_or_comment_with_ws).parse(s)?;
    log::debug!("and rhs: {:?}", r);
    let right = r.0;
    let offset = i.offset(&s);
    Ok((
        s,
        (
            Statement::AssignExpr {
                left,
                right,
                assignment_type: AssignmentType::from_str(from_utf8(op).unwrap_or_default()),
            },
            span(i, offset),
        )
            .into(),
    ))
}

// parse a cached_config statement which helps save current file parsed and substed to a new file
fn parse_cached_config_statement(i: Span) -> IResult<Span, LocatedStatement> {
    let s = i;
    let (s, _) = tag(".cached_config").parse(s)?;
    let (s, _) = complete(ws0_line_ending).parse(s)?;
    let (s, _) = multispace0(s)?;
    log::debug!("parsed cached config");
    let offset = i.offset(&s);
    Ok((s, (Statement::CachedConfig, span(i, offset)).into()))
}

/// parse alternative make-like rule blocks:
/// define_rule <targets> [<group>] : <deps> \n
///   <rule_definition_here> \n
/// endef
fn parse_define_rule_block(i: Span, for_each: bool) -> IResult<Span, LocatedStatement> {
    let s0 = i;
    // keyword
    let (s, _) = if for_each {
        tag("define_foreach_rule").parse(i)?
    } else {
        tag("define_rule").parse(i)?
    };
    let (s, _) = sp1(s)?;

    // Parse primary outputs until ':' or until we hit a group '<'
    let (s, (primary_out, brk)) = parse_pelist_till_delim_with_ws(s, ":", &BRKTOKSIO)?;
    // If we broke due to '<', parse group and then the ':'
    let (s, group) = if brk == '<' {
        let (s, g) = parse_pathexpr_group(s)?;
        let (s, _) = tag(":").parse(s)?;
        (s, Some(g))
    } else {
        (s, None)
    };

    // deps until end of line
    let (s, (mut deps, _)) = parse_pelist_till_line_end_with_ws(s)?;

    // Cleanup outputs/deps and strip a leading 'foreach' from outputs for foreach variant
    let mut primary_out = primary_out;
    primary_out.cleanup();
    deps.cleanup();
    if for_each {
        if let Some(PathExpr::Literal(s0)) = primary_out.first() {
            if s0 == "foreach" {
                primary_out.remove(0);
                if let Some(PathExpr::Sp1) = primary_out.first() {
                    primary_out.remove(0);
                }
            }
        }
    }
    // body until endef
    let (s, (mut body_lines, _)) = context(
        "define rule body",
        cut(many_till(
            parse_pelist_till_line_end_with_ws.map(|r| r.0),
            preceded(space0, tag("endef")),
        )),
    )
    .parse(s)?;

    // Cleanup and join body lines with NL separators, flattening into single Vec<PathExpr>
    body_lines.iter_mut().for_each(CleanupPaths::cleanup);
    let mut formula: Vec<PathExpr> = Vec::new();
    let mut first = true;
    for mut line in body_lines.into_iter() {
        // skip empty/whitespace-only lines
        if line.is_empty() || !line.iter().any(|t| !t.is_ws()) {
            continue;
        }
        if !first {
            formula.push(PathExpr::NL);
        }
        first = false;
        formula.append(&mut line);
    }

    // Build rule
    let link = Link {
        source: from_input(deps, for_each, Vec::new()),
        target: from_output(primary_out, Vec::new(), group, None),
        rule_formula: RuleFormula::new_from_parts(None, formula),
        ..Default::default()
    };
    let offset = s0.offset(&s);
    let (s, _) = multispace0(s)?;
    Ok((
        s,
        (
            Statement::Rule(link, crate::buffers::EnvList::default(), Vec::new()),
            span(s0, offset),
        )
            .into(),
    ))
}

fn parse_define_rule(i: Span) -> IResult<Span, LocatedStatement> {
    parse_define_rule_block(i, false)
}

fn parse_define_foreach_rule(i: Span) -> IResult<Span, LocatedStatement> {
    parse_define_rule_block(i, true)
}
/// parse a define statement and its body until enddef occurs
fn parse_pathexpr_define(i: Span) -> IResult<Span, LocatedStatement> {
    let s = i;
    let (s, _) = tag("define").parse(s)?;
    let (s, _) = sp1(s)?;
    log::debug!("parsing define expression");
    let (s, ident) = context("define expression", cut(parse_ident)).parse(s)?;
    log::debug!("with name: {:?}", ident);
    let (s, _) = multispace0(s)?;

    // take until enddef occurs
    let (s, (mut body, _)) = context(
        "define expression",
        cut(many_till(
            parse_pelist_till_line_end_with_ws.map(|r| r.0),
            preceded(space0, tag("endef")),
        )),
    )
    .parse(s)?;

    body.iter_mut().for_each(CleanupPaths::cleanup);
    log::debug!("with body: {:?}", body);
    let body: Vec<_> = body
        .drain(..)
        .filter(|x| !x.is_empty() && x.iter().filter(|x| !x.is_ws()).count() != 0)
        .collect();
    let mut body = body.join(&PathExpr::NL);
    body.push(PathExpr::NL);
    //log::debug!("with body: {:?}", body);
    let offset = i.offset(&s);
    let (s, _) = multispace0(s)?;
    Ok((s, (Statement::Define(ident, body), span(i, offset)).into()))
}

// eval block statements are parsed in the initial phase as regular pathexprs.
// These will be parsed again in the second phase
// during substitution as regular statements that can be evaluated.
// examples are $(foreach... and $(if... and $(eval ..)
// even raw pathexprs are parsed as eval blocks. Later is useful as return values of functions.
// See test case in Tupfile2
fn parse_eval_block(i: Span) -> IResult<Span, LocatedStatement> {
    // there is no standard way to determine we are parsing an eval block. Any string of tokens can be an eval block.
    let s = i;

    log::debug!(
        "attempting to parse input as eval block: {:?}",
        from_utf8(s)
    );
    let (s, (body, _)) = complete(parse_pelist_till_line_end_with_ws).parse(s)?;
    log::debug!("parsed eval block: {:?}", body);
    if body.is_empty() {
        return Err(Err::Error(error_position!(s, ErrorKind::Escaped)));
    }
    if let PathExpr::Literal(v) = body.first().unwrap() {
        for keyword in END_KEYWORDS {
            if v.as_str().eq(keyword) {
                return Err(Err::Error(error_position!(s, ErrorKind::Escaped)));
            }
        }
    }
    let offset = i.offset(&s);
    let (s, _) = multispace0(s)?;
    Ok((s, (Statement::EvalBlock(body), span(i, offset)).into()))
}

// parse an assignment expression
// parse description insude a rule (between ^^)
fn parse_rule_flags_or_description(i: Span) -> IResult<Span, RuleDescription> {
    let s = i;
    let (s, _) = tag("^").parse(s)?;
    let (s, c) = alt((
        value(vec![' '], complete::char(' ')),
        many1(one_of("bcjot1")),
    ))
    .parse(s)?;

    let rule_flags: String = c.iter().skip_while(|c| c.is_whitespace()).collect();
    let (s, (r, _)) = cut(context("parsing rule description", |s| {
        parse_pelist_till_delim_with_ws(s, "^", &BRKTOKSIO)
    }))
    .parse(s)?;
    let (s, _) = multispace0(s)?;
    Ok((s, RuleDescription::new(rule_flags, r)))
}

// parse the insides of a rule, which includes a description and rule formula
pub(crate) fn parse_rule_gut(i: Span) -> IResult<Span, RuleFormula> {
    let (s, desc) = opt(context(
        "parsing rule flags/descriptions",
        parse_rule_flags_or_description,
    ))
    .parse(i)?;
    let (s, me) = opt(parse_pathexpr_macroref).parse(s)?;
    let (s, formula) = parse_pelist_till_delim_with_ws(s, "|", &BRKTOKSWS)?;
    Ok((
        s,
        RuleFormula {
            description: desc,
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
    group: Option<PathExpr>,
    bin: Option<PathExpr>,
) -> Target {
    Target {
        primary,
        secondary,
        //exclude_pattern: exclude,
        group,
        bin,
    }
}

fn default_inp<'a>() -> Span<'a> {
    Span::new(b"")
}
/// parse rule inputs including groups and bin and exclude patterns
pub(crate) fn parse_rule_inp<'a, 'b: 'static>(
    i: Span<'a>,
    end_tok: &'b str,
) -> IResult<Span<'a>, (Vec<PathExpr>, Span<'a>)> {
    let (s, _) = opt(sp1).parse(i)?;
    let pe = |i| parse_pathexpr_ws(i, end_tok, &BRKTOKSIO);
    let end = |i| {
        if end_tok.eq("") {
            eof(i)
        } else {
            tag(end_tok).parse(i)
        }
    };
    many_till(
        alt((
            complete(parse_pathexpr_exclude_pattern),
            complete(parse_pathexpr_group),
            complete(parse_pathexpr_bin),
            complete(pe),
        )),
        preceded(multispace0, end),
    )
    .parse(s)
}
/// parse secondary input in a rule expression
pub(crate) fn parse_secondary_inp(i: Span) -> IResult<Span, (Vec<PathExpr>, Span)> {
    //context("read secondary inputs",  preceded( tag("|"),
    let (s, _) = opt(sp1).parse(i)?;
    //let (s, _) = tag("|").parse(s)?;
    let pe = |i| parse_pathexpr_ws(i, "|", &BRKTOKSIO);
    many_till(
        alt((
            complete(parse_pathexpr_group),
            complete(parse_pathexpr_bin),
            complete(pe),
        )),
        preceded(multispace0, tag("|")),
    )
    .parse(s)
}

fn parse_output_delim(i: Span) -> IResult<Span, Span> {
    alt((
        complete(peek(line_ending)),
        complete(peek(one_of(BRKTAGSNOWS)).map(|_| i)),
        complete(peek(parse_pathexpr_raw_angle)),
    ))
    .parse(i)
}

fn parse_primary_output1(i: Span) -> IResult<Span, Vec<PathExpr>> {
    let (s, _) = tag("|").parse(i)?;
    let pe = |i| parse_pathexpr_ws(i, "<{^\r\n", &BRKTOKSIO);
    let (s, v0) = many_till(
        alt((complete(parse_pathexpr_exclude_pattern), complete(pe))),
        parse_output_delim,
    )
    .parse(s)?;
    Ok((s, v0.0))
}

fn parse_primary_output0(i: Span) -> IResult<Span, (Vec<PathExpr>, bool)> {
    let (s, _) = opt(sp1).parse(i)?;
    let pe = |i| parse_pathexpr_ws(i, "|<{^\r\n", &BRKTOKSIO);
    let (s, v0) = many_till(
        alt((complete(parse_pathexpr_exclude_pattern), complete(pe))),
        parse_output_delim,
    )
    .parse(s)?;
    //eprintln!("{}", v0.1.as_bytes().first().unwrap_or(&b' ').as_char());
    let has_more = v0.1.as_bytes().first().map(|&c| c == b'|').unwrap_or(false);
    Ok((s, (v0.0, has_more)))
}

/// parse a rule expression of the form
/// : \[foreach\] \[inputs\] \[ \| order-only inputs\] \|\> command \|\> \[outputs\] \[ | extra outputs\] \[exclusions\] \[<group>\] \[{bin}\]
pub(crate) fn parse_rule(i: Span) -> IResult<Span, LocatedStatement> {
    let s = i;
    let (s, _) = tag(":").parse(s)?;
    log::debug!("parsing rule expression at line:{}", i.location_line());
    let (s, _) = opt(sp1).parse(s)?;
    let (s, for_each) = opt(tag("foreach")).parse(s)?;
    let (s, input) = context("rule input", cut(opt(|i| parse_rule_inp(i, "|")))).parse(s)?;
    let (s, _) = opt(sp1).parse(s)?;
    let (s, c) = peek(take(1_usize)).parse(s)?;
    let (s, secondary_input) = if c.as_bytes().first().cloned() != Some(b'>') {
        let (s, _) = opt(sp1).parse(s)?;
        let (s, secondary_input) =
            context("secondary inputs", opt(parse_secondary_inp)).parse(s)?;
        (s, secondary_input)
    } else {
        (s, None)
    };
    let (s, _) = tag(">").parse(s)?;
    let (s, _) = opt(sp1).parse(s)?;
    let (s, rule_formula) = context("rule formula", cut(parse_rule_gut)).parse(s)?;
    let (s, _) = tag(">").parse(s)?;
    let (s, _) = opt(sp1).parse(s)?;
    // read until "|" or lineending
    let (s, output0) = context("rule output maybe primary", opt(parse_primary_output0)).parse(s)?;
    let has_more = output0.as_ref().map_or(false, |(_, has_more)| *has_more);
    let (s, output1) = if has_more {
        context("rule output", cut(parse_primary_output1)).parse(s)?
    } else {
        (s, vec![])
    };

    let (output, secondary_output) = if has_more {
        (output0.unwrap_or((Vec::new(), false)).0, output1)
    } else {
        (output0.unwrap_or((Vec::new(), false)).0, Vec::new())
    };
    //let (s, exclude_patterns) = opt(parse_pathexpr_exclude_pattern).parse(s)?;
    // let secondary_output = if hassecondary { output1.unwrap_or(Vec::new())} else { Vec::new() };
    let (s, _) = opt(sp1).parse(s)?;
    let (s, v1) = opt(parse_pathexpr_group).parse(s)?;
    let (s, _) = opt(sp1).parse(s)?;
    let (s, v2) = opt(parse_pathexpr_bin).parse(s)?;
    let offset = i.offset(&s);
    let (s, _) = multispace0(s)?;
    //let (s, _) = line_ending(s)?;
    Ok((
        s,
        (
            Statement::Rule(
                Link {
                    source: from_input(
                        input.map(|(x, _)| x).unwrap_or_default(),
                        for_each.is_some(),
                        secondary_input
                            .unwrap_or_else(|| (Vec::new(), default_inp()))
                            .0,
                    ),
                    target: from_output(output, secondary_output, v1, v2),
                    rule_formula,
                    ..Default::default()
                },
                crate::buffers::EnvList::default(),
                Vec::new(),
            ),
            span(i, offset),
        )
            .into(),
    ))
}

// parse a macro assignment which is more or less same as parsing a rule expression
// !macro = [inputs] | [order-only inputs] |> command |> [outputs]
pub(crate) fn parse_macroassignment(i: Span) -> IResult<Span, LocatedStatement> {
    let s = i;
    let (s, _) = tag("!").parse(s)?;
    let (s, macroname) = take_while(is_ident).parse(s)?;
    let (s, _) = opt(sp1).parse(s)?;
    let (s, _) = tag("=").parse(s)?;
    let (s, _) = opt(sp1).parse(s)?;
    log::debug!("reading macro: {:?}", from_utf8(macroname).unwrap());
    if macroname.eq(&Span::new(b"EXEC")) {
        log::error!("macro name EXEC is reserved");
    }
    let (s, for_each) = opt(tag("foreach")).parse(s)?;
    let (s, _) = opt(sp1).parse(s)?;
    let (s, input) = opt(context("rule input", cut(|i| parse_rule_inp(i, "|")))).parse(s)?;
    let (s, c) = peek(take(1_usize)).parse(s)?;
    let (s, secondary_input) = if c.as_bytes().first().cloned() != Some(b'>') {
        let (s, _) = opt(sp1).parse(s)?;
        let (s, secondary_input) =
            opt(context("rule secondary input", cut(parse_secondary_inp))).parse(s)?;
        (s, secondary_input)
    } else {
        (s, None)
    };
    let (s, _) = tag(">").parse(s)?;
    let (s, _) = opt(sp1).parse(s)?;
    let (s, rule_formula) = context("rule formula", cut(parse_rule_gut)).parse(s)?;
    let (s, _) = tag(">").parse(s)?;
    let (s, output0) = context("rule output", opt(parse_primary_output0)).parse(s)?;
    let has_more = output0.as_ref().map_or(false, |(_, has_more)| *has_more);
    let (s, output1) = if has_more {
        context("rule output", cut(parse_primary_output1)).parse(s)?
    } else {
        (s, vec![])
    };

    let (output, secondary_output) = if has_more {
        (output1, output0.unwrap_or((Vec::new(), false)).0)
    } else {
        (output0.unwrap_or((Vec::new(), false)).0, Vec::new())
    };
    let (s, _) = opt(sp1).parse(s)?;
    let (s, group) = opt(parse_pathexpr_group).parse(s)?;
    let (s, _) = opt(sp1).parse(s)?;
    let (s, bin) = opt(parse_pathexpr_bin).parse(s)?;
    let macroname_str = from_utf8(macroname).unwrap_or_default();
    log::debug!("built macro:{}", macroname_str);
    let offset = i.offset(&s);
    let (s, _) = multispace0(s)?;
    Ok((
        s,
        (
            Statement::MacroRule(
                macroname_str,
                Link {
                    source: from_input(
                        input.map(|(x, _)| x).unwrap_or_default(),
                        for_each.is_some(),
                        secondary_input
                            .unwrap_or_else(|| (Vec::new(), default_inp()))
                            .0,
                    ),
                    target: from_output(output, secondary_output, group, bin),
                    rule_formula,
                    ..Default::default()
                },
            ),
            span(i, offset),
        )
            .into(),
    ))
}

// parse any of the different types of statements in a tupfile
pub(crate) fn parse_statement(i: Span) -> IResult<Span, LocatedStatement> {
    let (s, _) = multispace0(i)?;
    if s.is_empty() {
        return Err(Err::Error(error_position!(s, ErrorKind::Eof)));
    }
    log_line(s)?;
    alt((
        complete(parse_comment),
        complete(parse_include),
        complete(parse_include_rules),
        complete(parse_define_foreach_rule),
        complete(parse_define_rule),
        complete(parse_assignment_expr),
        complete(parse_message),
        complete(parse_rule),
        complete(parse_if_else_endif),
        complete(parse_macroassignment),
        complete(parse_export),
        complete(parse_run),
        complete(parse_preload),
        //complete(parse_search_dir),
        complete(parse_import),
        complete(parse_pathexpr_define),
        complete(parse_task_statement),
        complete(parse_cached_config_statement),
        complete(parse_eval_block),
    ))
    .parse(s)
}

fn log_line(s: Span) -> IResult<Span, ()> {
    if log_enabled!(log::Level::Debug) {
        let (s, c) = opt(peek(many_till(not_line_ending, alt((line_ending, eof))))).parse(s)?;
        if let Some(c) = c {
            let l =
                c.0.iter()
                    .cloned()
                    .map(|c| from_utf8(c).unwrap())
                    .collect::<Vec<_>>();
            log::debug!("line: {:?}", l.join(" "));
        }
        Ok((s, ()))
    } else {
        Ok((s, ()))
    }
}

/// parse until the start of else block
fn parse_statements_until_else_or_endif(
    i: Span,
) -> IResult<Span, (Vec<LocatedStatement>, EndClause)> {
    let matches_endif = preceded(multispace0, tag("endif"));
    let matches_else = preceded(multispace0, tag("else"));
    let g = alt((
        value(EndClause::Else, matches_else),
        value(EndClause::Endif, matches_endif),
    ));
    many_till(parse_statement, g).parse(i)
}

/// parse until endif statement
fn parse_statements_until_endif(i: Span) -> IResult<Span, (Vec<LocatedStatement>, EndClause)> {
    let g = value(
        EndClause::Endif,
        delimited(
            multispace0,
            tag("endif"),
            alt((ws0_line_ending, parse_ignored_comment)),
        ),
    );
    many_till(parse_statement, g).parse(i)
}

/// Converts nom error into a readable string
pub fn convert_error(input: Span, e: VerboseError<Span>) -> String {
    use std::fmt::Write;

    let mut result = String::new();

    for (i, (substring, kind)) in e.errors.iter().enumerate() {
        let offset = input.offset(substring);

        if input.is_empty() {
            match kind {
                VerboseErrorKind::Char(c) => {
                    write!(&mut result, "{}: expected '{}', got empty input\n\n", i, c)
                }
                VerboseErrorKind::Context(s) => {
                    write!(&mut result, "{}: in {}, got empty input\n\n", i, s)
                }
                VerboseErrorKind::Nom(e) => {
                    write!(&mut result, "{}: in {:?}, got empty input\n\n", i, e)
                }
            }
        } else {
            let prefix = &input.as_bytes()[..offset];

            let rest = &input.as_bytes()[offset..];
            // Count the number of newlines in the first `offset` bytes of input
            let line_number = prefix.iter().filter(|&&b| b == b'\n').count() + 1;

            // Find the line that includes the subslice:
            // Find the *last* newline before the substring starts
            let line_begin = prefix
                .iter()
                .rev()
                .position(|&b| b == b'\n')
                .map(|pos| offset - pos)
                .unwrap_or(0);

            let line_end = rest
                .as_bytes()
                .iter()
                .position(|&b| b == b'\n')
                .map(|pos| offset + pos)
                .unwrap_or(input.fragment().len());

            // Find the full line after that newline
            let line = std::str::from_utf8(&input[line_begin..line_end]).unwrap();
            let line = line.trim_end();

            let substring_str = std::str::from_utf8(substring).unwrap();
            // The (1-indexed) column number is the offset of our substring into that line
            let column_number = line.offset(substring_str) + 1;

            match kind {
                VerboseErrorKind::Char(c) => {
                    if let Some(actual) = substring_str.chars().next() {
                        write!(
                            &mut result,
                            "{i}: at line {line_number}:\n\
               {line}\n\
               {caret:>column$}\n\
               expected '{expected}', found {actual}\n\n",
                            i = i,
                            line_number = line_number,
                            line = line,
                            caret = '^',
                            column = column_number,
                            expected = c,
                            actual = actual,
                        )
                    } else {
                        write!(
                            &mut result,
                            "{i}: at line {line_number}:\n\
               {line}\n\
               {caret:>column$}\n\
               expected '{expected}', got end of input\n\n",
                            i = i,
                            line_number = line_number,
                            line = line,
                            caret = '^',
                            column = column_number,
                            expected = c,
                        )
                    }
                }
                VerboseErrorKind::Context(s) => write!(
                    &mut result,
                    "{i}: at line {line_number}, in {context}:\n\
             {line}\n\
             {caret:>column$}\n\n",
                    i = i,
                    line_number = line_number,
                    context = s,
                    line = line,
                    caret = '^',
                    column = column_number,
                ),
                VerboseErrorKind::Nom(e) => write!(
                    &mut result,
                    "{i}: at line {line_number}, in {nom_err:?}:\n\
             {line}\n\
             {caret:>column$}\n\n",
                    i = i,
                    line_number = line_number,
                    nom_err = e,
                    line = line,
                    caret = '^',
                    column = column_number,
                ),
            }
        }
        // Because `write!` to a `String` is infallible, this `unwrap` is fine.
        .unwrap();
    }

    result
}

/// parse statements till end of file
pub(crate) fn parse_statements_until_eof(
    i: Span,
) -> Result<Vec<LocatedStatement>, crate::errors::Error> {
    many0(parse_statement)
        .parse(i)
        .map(|v| v.1)
        .map_err(|e| match e {
            Err::Incomplete(_) => crate::errors::Error::ParseError(
                "Incomplete data found".to_string(),
                Loc::default(),
            ),
            Err::Error(e) | Err::Failure(e) => {
                let err_message = convert_error(i, e.clone());
                let loc = e
                    .errors
                    .first()
                    .map(|x| x.0)
                    .map(|s: Span| Loc::from(InputRange::new(s, 0)))
                    .unwrap();
                crate::errors::Error::ParseError(err_message, loc)
            }
        })
}

// parse equality condition (only the condition, not the statements that follow if)
pub(crate) fn parse_eq(i: Span) -> IResult<Span, EqCond> {
    let s = i;
    let (s, not_cond) = alt((
        complete(value(false, tag("ifeq"))),
        complete(value(true, tag("ifneq"))),
    ))
    .parse(s)?;
    let (s, (e1, e2)) = context("parsing eq condition", cut(complete(parse_eq_inner))).parse(s)?;
    log::debug!(
        "parsed eq condition: {:?} {}= {:?}",
        e1,
        if not_cond { "!" } else { "" },
        e2
    );

    Ok((
        s,
        EqCond {
            lhs: e1,
            rhs: e2,
            not_cond,
        },
    ))
}

fn parse_eq_inner(s: Span) -> IResult<Span, (Vec<PathExpr>, Vec<PathExpr>)> {
    let (s, _) = opt(sp1).parse(s)?;
    let (s, _) = complete::char('(').parse(s)?;
    let (s, (e1, _)) = parse_pelist_till_delim_no_ws(s, ",", &BRKTOKS)?;
    let (s, _) = opt(sp1).parse(s)?;
    let (s, (e2, _)) = parse_pelist_till_delim_no_ws(s, ")", &BRKTOKS)?;
    let (s, _) = many0(newline).parse(s)?;
    Ok((s, (e1, e2)))
}

pub(crate) fn parse_checked_var(i: Span) -> IResult<Span, CheckedVar> {
    let s = i;
    let (s, negate) = alt((value(false, tag("ifdef")), value(true, tag("ifndef")))).parse(s)?;

    let c = if negate { "n" } else { "" };
    log::debug!("parsing if{}def", c);
    let (s, _) = opt(sp1).parse(s)?;
    let (s, var) = cut(complete(parse_ident)).parse(s)?;
    let (s, _) = opt(sp1).parse(s)?;
    log::debug!("parsed if{}def var: {:?}", c, var);
    Ok((s, CheckedVar::new(var, negate)))
}

pub(crate) fn parse_condition(i: Span) -> IResult<Span, Condition> {
    alt((
        parse_checked_var.map(Condition::CheckedVar),
        parse_eq.map(Condition::EqCond),
    ))
    .parse(i)
}
/// parse contents inside if else endif bocks(without condition)
pub(crate) fn parse_ifelseendif_inner(i: Span, cond: Condition) -> IResult<Span, LocatedStatement> {
    let (s, then_else_s) = parse_statements_until_else_or_endif(i)?;
    let (s, _) = opt(parse_ignored_comment).parse(s)?;
    let mut cvar_then_statements = vec![CondThenStatements {
        cond: cond.clone(),
        then_statements: then_else_s.0,
    }];

    let mut else_endif_s = Vec::new();
    let mut rest = s;
    let mut end_clause = then_else_s.1;
    if end_clause == EndClause::Endif {
        log::debug!("endif reached at line:{}", rest.location_line());
    }
    while end_clause == EndClause::Else {
        // at this point if else block can continue to add more conditional blocks or finish with endif
        if let (s, Some(inner_condition)) = opt(preceded(sp1, parse_condition)).parse(rest)? {
            log::debug!("parsing else if block");
            let (s, _) = opt(sp1).parse(s)?;
            let (s, cond_then_s) = parse_statements_until_else_or_endif(s)?;
            end_clause = cond_then_s.1;
            let cond_then_statements_inner = CondThenStatements {
                cond: inner_condition,
                then_statements: cond_then_s.0,
            };
            log::debug!("parsed else if block: {:?}", cond_then_statements_inner);
            cvar_then_statements.push(cond_then_statements_inner);
            rest = s;
        } else {
            log::debug!(
                "parsing else block until endif at line:{}",
                rest.location_line()
            );
            let (s, _) = opt(sp1).parse(rest)?;
            let (s, else_s) = parse_statements_until_endif(s)?;
            rest = s;
            log::debug!(
                "parsed else block: {:?} at line:{}, for condition {:?}",
                else_s,
                s.location_line(),
                cond
            );
            else_endif_s = else_s.0;
            break;
        }
    }

    log::debug!("parsed if else endif block at line:{}", s.location_line());
    let s = rest;
    let offset = i.offset(&s);
    Ok((
        s,
        (
            Statement::IfElseEndIf {
                then_elif_statements: cvar_then_statements,
                else_statements: else_endif_s,
            },
            span(i, offset),
        )
            .into(),
    ))
}

/// parse if else endif block along with condition
pub(crate) fn parse_if_else_endif(i: Span) -> IResult<Span, LocatedStatement> {
    let (s, cond) = parse_condition(i)?;
    log::debug!("parsed condition: {:?} at line:{}", cond, i.location_line());
    let (s, _) = opt(sp1).parse(s)?;
    context(
        "if else block",
        cut(move |s| parse_ifelseendif_inner(s, cond.clone())),
    )
    .parse(s)
}

/// parse statements in a tupfile
pub(crate) fn parse_tupfile<P: AsRef<Path>>(
    filename: P,
) -> Result<Vec<LocatedStatement>, crate::errors::Error> {
    use crate::errors::Error as Err;
    use std::fs::File;
    use std::io::prelude::*;
    let filename = filename.as_ref();
    let filename_str = filename.to_str().unwrap();
    log::info!("parsing tupfile: {}", filename_str);
    let mut file = File::open(filename)
        .map_err(|e| Err::IoError(e, filename_str.to_string(), Loc::default()))?;
    let mut contents = Vec::new();
    let _res = file
        .read_to_end(&mut contents)
        .inspect_err(|e| log::error!("error reading file: {:?}", e))
        .map_err(|e| Err::IoError(e, filename_str.to_string(), Loc::default()))?;
    if contents.last() != Some(&b'\n') {
        contents.push(b'\n');
    }
    parse_statements_until_eof(Span::new(contents.as_bytes())).map_err(|e| {
        crate::errors::Error::with_context(
            e,
            format!("Parsing :{}", filename.to_string_lossy().to_string()),
        )
    })
}

/// locate TupRules.tup\[.lua\] walking up the directory tree
pub(crate) fn locate_tuprules_from(cur_tupfile: PathDescriptor) -> Vec<PathDescriptor> {
    let mut v = VecDeque::new();

    log::debug!("locating tuprules for {:?}", cur_tupfile.as_ref());

    for anc in cur_tupfile
        .ancestors()
        .skip(1) // dont include self
        .chain(std::iter::once(PathDescriptor::default()))
    // add the root path '.'
    {
        log::debug!("try:{:?}", anc);
        let rulestup = anc.get_path_ref().as_path().join("TupRules.tup");
        if rulestup.is_file() {
            let tupr = anc.join_leaf("Tuprules.tup");
            v.push_front(tupr.clone());
        } else {
            let rulestup = rulestup.with_extension("lua");
            if rulestup.is_file() {
                let tupr = anc.join_leaf("Tuprules.lua");
                v.push_front(tupr.clone());
            }
        }
    }
    v.drain(..).collect()
}

/// module only for testing purposes
pub mod testing {
    /// parse all statements in this tupfile, used currently only for testing
    pub fn parse_tupfile<P: AsRef<std::path::Path>>(
        filename: P,
    ) -> Result<Vec<crate::statements::LocatedStatement>, crate::errors::Error> {
        crate::parser::parse_tupfile(filename)
    }
}
