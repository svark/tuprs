use std::cmp::Ordering;
/// This module handles tokenizing and parsing of statements in a tupfile using nom
use std::collections::VecDeque;
use std::path::{Path, PathBuf};

use nom::bytes::complete::{is_a, is_not};
use nom::character::complete::digit1;
use nom::character::complete::{line_ending, multispace0, multispace1, space0, space1};
use nom::combinator::{complete, cut, map, map_res, opt, peek, value};
use nom::error::{context, ErrorKind};
use nom::multi::{many0, many1, many_till};
use nom::sequence::{delimited, preceded};
use nom::Err;
use nom::IResult;
use nom::{
    branch::alt,
    bytes::complete::{tag, take, take_until, take_while},
    character::complete::{char, one_of},
};
use nom::{AsBytes, Offset, Slice};
use nom_locate::LocatedSpan;

use crate::statements::*;
use crate::transform;

/// Span is an alias for LocatedSpan
pub(crate) type Span<'a> = LocatedSpan<&'a [u8]>;

fn from_utf8(s: Span) -> Result<String, std::str::Utf8Error> {
    std::str::from_utf8(s.as_bytes()).map(|x| x.to_owned())
}
lazy_static! {
    static ref BRKTOKSINNER: &'static str = "\\\n$&";
    static ref BRKTOKS: &'static str = "\\\n$@&";
    static ref BRKTOKSQ: &'static str = "\\\n$@&\"";
    static ref BRKTOKSWS: &'static str = "\\\n$@& ";
    static ref BRKTOKSIO: &'static str = "\\\n $@&^<{";
    static ref BRKTAGSNOWS: &'static str = "<|{";
    static ref BRKTAGS: &'static str = " <|{^";
}

/// convert byte str to PathExpr
fn from_str(res: Span) -> Result<PathExpr, std::str::Utf8Error> {
    from_utf8(res).map(|s| s.into())
}
/// check if char is part of an identifier (lhs of var assignment)
fn is_ident(c: u8) -> bool {
    nom::character::is_alphanumeric(c) || c == b'_' || c == b'-' || c == b'.'
}

fn is_ident_perc(c: u8) -> bool {
    nom::character::is_alphanumeric(c) || c == b'_' || c == b'-' || c == b'.' || c == b'%'
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
/// read a space or blackslash newline continuation
fn sp1(input: Span) -> IResult<Span, Span> {
    alt((complete(manynewlineesc), space1))(input)
}

/// ignore until line ending
fn ws0_line_ending(i: Span) -> IResult<Span, ()> {
    let (s, _) = opt(many0(space0))(i)?;
    let (s, _) = line_ending(s)?;
    Ok((s, ()))
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
fn parse_pathexpr_ref_raw_curl(input: Span) -> IResult<Span, String> {
    let (s, _) = alt((tag("${"), tag("@{"), tag("&{")))(input)?;
    let (s, r) = take_while(is_ident_perc)(s)?;
    let (s, _) = tag("}")(s)?;
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
// parse the beginning of an exclude pattern (starts with ^)
fn parse_pathexpr_hat(i: Span) -> IResult<Span, String> {
    let (s, _) = tag("^")(i)?;
    let (s, r) = is_not(" \t\n\r")(s)?;
    let raw = std::str::from_utf8(r.as_bytes()).unwrap();
    Ok((s, raw.to_owned()))
}

// read '<' and the list of rvals inside it until '>'
fn parse_pathexpr_angle(i: Span) -> IResult<Span, (Vec<PathExpr>, Vec<PathExpr>)> {
    //let input = i.clone();
    let (s, v0) = many_till(|i| parse_pathexpr_no_ws(i, " \t\r\n<{", &BRKTOKS), tag("<"))(i)?;
    //let (s, _) = tag("<")(s)?;
    let (s, v) = many_till(
        |i| parse_pathexpr_no_ws(i, ">", &BRKTOKS), // avoid reading tags , newlines, spaces
        tag(">"),
    )(s)?;
    //let v0 = v0.map(|x| x.0);
    Ok((s, (v0.0, v.0)))
}

// parse rvalue at expression eg $(H) for config vars
fn parse_pathexpr_at(i: Span) -> IResult<Span, PathExpr> {
    context(
        "config(@) expression",
        alt((
            complete(map(parse_pathexpr_ref_raw, PathExpr::AtExpr)),
            complete(map(parse_pathexpr_ref_raw_curl, PathExpr::AtExpr)),
        )),
    )(i)
}

fn parse_pathexpr_taskref(i: Span) -> IResult<Span, PathExpr> {
    context(
        "task reference",
        map(
            delimited(tag("&task{"), parse_lvalue, tag("}")),
            PathExpr::TaskRef,
        ),
    )(i)
}

// parse rvalue dollar expression eg $(H)
pub(crate) fn parse_pathexpr_dollar(i: Span) -> IResult<Span, PathExpr> {
    let (_, peekchars) = peek(take(3usize))(i)?;
    let parse_pathexpr_fallback = |i| {
        map(parse_pathexpr_ref_raw, |x| {
            PathExpr::from(DollarExprs::DollarExpr(x))
        })(i)
    };
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
        )(i),
        b"$(c" | b"$(d" | b"$(e" => context(
            "dollar expression (class 2)",
            // select among parsers that process dollar exprs with first char 'c', 'd' or 'e'
            alt((
                complete(parse_pathexpr_call),
                complete(parse_pathexpr_dir),
                complete(parse_pathexpr_eval),
                complete(parse_pathexpr_fallback),
            )),
        )(i),
        b"$(f" => context(
            "dollar expression (class 3)",
            // select among parsers that process dollar exprs with first char 'f'
            alt((
                complete(parse_pathexpr_filter),
                complete(parse_pathexpr_filter_out),
                complete(parse_pathexpr_findstring),
                complete(parse_pathexpr_foreach),
                complete(parse_pathexpr_firstword),
                complete(parse_pathexpr_fallback),
            )),
        )(i),
        b"$(i" | b"$(n" | b"$(p" | b"$(r" => context(
            "dollar expression (class 4)",
            // select among parsers that process dollar exprs with first char 'i'... 'r'
            alt((
                complete(parse_pathexpr_if),
                complete(parse_pathexpr_nodir),
                complete(parse_pathexpr_patsubst),
                complete(parse_pathexpr_realpath),
                complete(parse_pathexpr_fallback),
            )),
        )(i),

        b"$(s" | b"$(w" => context(
            "dollar expression (class 5)",
            //  select among parsers that process dollar exprs with first char 's'... 'w'
            alt((
                complete(parse_pathexpr_strip),
                complete(parse_pathexpr_subst),
                complete(parse_pathexpr_shell),
                complete(parse_pathexpr_word),
                complete(parse_pathexpr_wildcard),
                complete(parse_pathexpr_fallback),
            )),
        )(i),
        _ => context("dollar expression general", parse_pathexpr_fallback)(i),
    }
}

// parse rvalue dollar expression with curlies eg ${H}
fn parse_pathexpr_dollar_curl(i: Span) -> IResult<Span, PathExpr> {
    context(
        "dollar expression with curlies",
        alt((complete(map(parse_pathexpr_ref_raw_curl, |x| {
            PathExpr::from(DollarExprs::DollarExpr(x))
        })),)),
    )(i)
}

// parse rvalue ampersand expression eg &(H)
fn parse_pathexpr_amp(i: Span) -> IResult<Span, PathExpr> {
    context(
        "ampersand expression",
        cut(map(parse_pathexpr_ref_raw, PathExpr::AmpExpr)),
    )(i)
}

// parse a references to a macro
fn parse_pathexpr_macroref(i: Span) -> IResult<Span, PathExpr> {
    context(
        "reference to macro",
        map(parse_pathexpr_raw_macroref, PathExpr::MacroRef),
    )(i)
}

// parse an exclude pattern
fn parse_pathexpr_exclude_pattern(i: Span) -> IResult<Span, PathExpr> {
    context(
        "exclude pattern",
        map(parse_pathexpr_hat, PathExpr::ExcludePattern),
    )(i)
}

// parse a group path/<group>
fn parse_pathexpr_group(i: Span) -> IResult<Span, PathExpr> {
    context(
        "group",
        map(parse_pathexpr_angle, |rv| PathExpr::Group(rv.0, rv.1)),
    )(i)
}

// parse to a bucket name: {objs}
fn parse_pathexpr_bin(i: Span) -> IResult<Span, PathExpr> {
    context("bin", map(parse_pathexpr_raw_bin, PathExpr::Bin))(i)
}

fn parse_escaped(i: Span) -> IResult<Span, PathExpr> {
    let (_, r) = peek(take(2_usize))(i)?;
    match r.as_bytes() {
        b"\\\r" => {
            let (_, r) = peek(take(3_usize))(i)?;
            if r.as_bytes() == b"\\\r\n" {
                let (s, _) = take(3_usize)(i)?; //consumes \n after \r as well
                Ok((s, ("".to_string()).into()))
            } else {
                Err(Err::Error(error_position!(i, ErrorKind::Eof))) //FIXME: what errorkind should we return?
            }
        }
        b"\\\n" => {
            let (s, _) = take(2_usize)(i)?;
            Ok((s, ("".to_string()).into()))
        }

        b"$$" | b"\\$" | b"\\@" | b"\\&" | b"\\{" | b"\\}" | b"\\<" | b"\\>" | b"\\^" | b"\\|" => {
            let (s, _) = take(1_usize)(i)?;
            let (s, r) = take(1_usize)(s)?;
            let pe = from_str(r).map_err(|_| Err::Error(error_position!(i, ErrorKind::Escaped)))?;
            Ok((s, pe))
        }
        [b'\\', ..] => {
            let (s, r) = take(2_usize)(i)?;
            let pe = from_str(r).map_err(|_| Err::Error(error_position!(i, ErrorKind::Escaped)))?;
            Ok((s, pe))
        }
        _ => Err(Err::Error(error_position!(i, ErrorKind::Eof))), //FIXME: what errorkind should we return?
    }
}
fn test_pathexpr_ref(i: Span) -> bool {
    let res = || -> IResult<Span, bool> {
        let (_, r) = (peek(take(1_usize))(i))?;
        let ismatch = matches!(r.as_bytes(), b"$" | b"@" | b"&");
        Ok((i, ismatch))
    };
    res().map(|x| x.1).unwrap_or(false)
}

/// parse basic special expressions (dollar, at, ampersand)
fn parse_pathexprbasic(i: Span) -> IResult<Span, PathExpr> {
    let (s, r) = peek(take(2_usize))(i)?;
    match r.as_bytes() {
        b"$(" => parse_pathexpr_dollar(s),
        b"@(" => parse_pathexpr_at(s),
        b"&(" => parse_pathexpr_amp(s),
        b"${" => parse_pathexpr_dollar_curl(s),
        _ => Err(Err::Error(error_position!(i, ErrorKind::Eof))),
    }
}

/// parse $(addsuffix suffix, list)
fn parse_pathexpr_addsuffix(i: Span) -> IResult<Span, PathExpr> {
    let (s, _) = tag("$(addsuffix")(i)?;
    let (s, _) = parse_ws(s)?;
    let (s, (suffix, _)) = parse_pelist_till_delim_no_ws(s, " \t,", &BRKTOKS)?;
    let (s, _) = opt(parse_ws)(s)?;
    let (s, (list, _)) = parse_pelist_till_delim_with_ws(s, ")", &BRKTOKS)?;
    let (s, _) = opt(parse_ws)(s)?;
    log::debug!("parsed add suffix: {:?} {:?}", suffix, list);
    // log::debug!("rest:{:?}", from_utf8(s).unwrap().as_str());
    Ok((s, PathExpr::from(DollarExprs::AddSuffix(suffix, list))))
}

/// parse $(addprefix prefix, list)
fn parse_pathexpr_addprefix(i: Span) -> IResult<Span, PathExpr> {
    let (s, _) = tag("$(addprefix")(i)?;
    let (s, _) = parse_ws(s)?;
    let (s, (prefix, _)) = cut(|s| parse_pelist_till_delim_no_ws(s, " \t,", &BRKTOKS))(s)?;
    let (s, _) = opt(parse_ws)(s)?;
    let (s, (list, _)) = cut(|s| parse_pelist_till_delim_with_ws(s, ")", &BRKTOKS))(s)?;
    let (s, _) = opt(parse_ws)(s)?;
    log::debug!("parsed add prefix: {:?} {:?}", prefix, list);
    //  log::debug!("rest:{:?}", from_utf8(s).unwrap().as_str());
    Ok((s, PathExpr::from(DollarExprs::AddPrefix(prefix, list))))
}

/// parse $(subst from,to,text)
/// $(subst from,to,text) is a function that replaces all occurrences of from with to in text.
fn parse_pathexpr_subst(i: Span) -> IResult<Span, PathExpr> {
    let (s, _) = tag("$(subst")(i)?;
    let (s, _) = parse_ws(s)?;
    let (s, (from, _)) = cut(|s| parse_pelist_till_delim_with_ws(s, ",", &BRKTOKS))(s)?;
    let (s, _) = opt(parse_ws)(s)?;
    let (s, (to, _)) = cut(|s| parse_pelist_till_delim_with_ws(s, ",", &BRKTOKS))(s)?;
    let (s, _) = opt(parse_ws)(s)?;
    let (s, (text, _)) = cut(|s| parse_pelist_till_delim_with_ws(s, ")", &BRKTOKS))(s)?;
    let (s, _) = opt(parse_ws)(s)?;
    Ok((s, PathExpr::from(DollarExprs::Subst(from, to, text))))
}

/// $(patsubst from,to,text) is a function that replaces all occurrences of from with to in text.
fn parse_pathexpr_patsubst(i: Span) -> IResult<Span, PathExpr> {
    let (s, _) = tag("$(patsubst")(i)?;
    let (s, _) = parse_ws(s)?;
    let (s, (from, _)) = cut(|s| parse_pelist_till_delim_with_ws(s, ",", &BRKTOKS))(s)?;
    let (s, _) = opt(parse_ws)(s)?;
    let (s, (to, _)) = cut(|s| parse_pelist_till_delim_with_ws(s, ",", &BRKTOKS))(s)?;
    let (s, _) = opt(parse_ws)(s)?;
    let (s, (text, _)) = cut(|s| parse_pelist_till_delim_with_ws(s, ")", &BRKTOKS))(s)?;
    let (s, _) = opt(parse_ws)(s)?;
    Ok((s, PathExpr::from(DollarExprs::PatSubst(from, to, text))))
}

/// parse $(finstring find, in)
/// $(findstring find, in) is a function that searches for find in in and returns `find` if it is found, otherwise it returns the empty string.
fn parse_pathexpr_findstring(i: Span) -> IResult<Span, PathExpr> {
    let (s, _) = tag("$(findstring")(i)?;
    let (s, _) = parse_ws(s)?;
    let (s, (find, _)) = parse_pelist_till_delim_no_ws(s, " \t,", &BRKTOKS)?;
    let (s, _) = opt(parse_ws)(s)?;
    let (s, (in_, _)) = parse_pelist_till_delim_with_ws(s, ")", &BRKTOKS)?;
    let (s, _) = opt(parse_ws)(s)?;
    Ok((s, PathExpr::from(DollarExprs::FindString(find, in_))))
}

/// parse $(foreach var,list,text)
/// $(foreach var,list,text) is a function that expands text once for each word in list, replacing each occurrence of var with the current word.
fn parse_pathexpr_foreach(i: Span) -> IResult<Span, PathExpr> {
    let (s, _) = tag("$(foreach")(i)?;
    let (s, _) = parse_ws(s)?;
    let (s, r) = take_while(is_ident)(s)?;
    let var = std::str::from_utf8(r.as_bytes()).unwrap().to_string();
    let (s, _) = opt(parse_ws)(s)?;
    let (s, _) = tag(",")(s)?;
    let (s, (list, _)) = parse_pelist_till_delim_with_ws(s, ",", &BRKTOKSIO)?;
    let (s, _) = opt(parse_ws)(s)?;
    let (s, (text, _)) = parse_pelist_till_delim_with_ws(s, ")", &BRKTOKS)?;
    let (s, _) = opt(parse_ws)(s)?;
    Ok((s, PathExpr::from(DollarExprs::ForEach(var, list, text))))
}

/// parse $(filter pattern...,text)
/// $(filter pattern...,text) is a function that returns the words in text that match at least one of the given patterns.
fn parse_pathexpr_filter(i: Span) -> IResult<Span, PathExpr> {
    let (s, _) = tag("$(filter")(i)?;
    let (s, _) = parse_ws(s)?;
    let (s, (patterns, _)) = parse_pelist_till_delim_with_ws(s, ",", &BRKTOKS)?;
    let (s, _) = opt(parse_ws)(s)?;
    let (s, (text, _)) = parse_pelist_till_delim_with_ws(s, ")", &BRKTOKS)?;
    let (s, _) = opt(parse_ws)(s)?;
    Ok((s, PathExpr::from(DollarExprs::Filter(patterns, text))))
}

// parse $(filter-out pattern...,text)
/// $(filter-out pattern...,text) is a function that returns the words in text that do not match any of the given patterns.
fn parse_pathexpr_filter_out(i: Span) -> IResult<Span, PathExpr> {
    let (s, _) = tag("$(filter-out")(i)?;
    let (s, _) = parse_ws(s)?;
    let (s, (patterns, _)) = parse_pelist_till_delim_with_ws(s, ",", &BRKTOKS)?;
    let (s, _) = opt(parse_ws)(s)?;
    let (s, (text, _)) = parse_pelist_till_delim_with_ws(s, ")", &BRKTOKS)?;
    let (s, _) = opt(parse_ws)(s)?;
    Ok((s, PathExpr::from(DollarExprs::FilterOut(patterns, text))))
}

/// parse $(shell command)
fn parse_pathexpr_shell(i: Span) -> IResult<Span, PathExpr> {
    let (s, _) = tag("$(shell")(i)?;
    let (s, _) = parse_ws(s)?;
    let (s, (cmd, _)) = parse_pelist_till_delim_with_ws(s, ")", &BRKTOKS)?;
    let (s, _) = opt(parse_ws)(s)?;
    Ok((s, PathExpr::DollarExprs(DollarExprs::Shell(cmd))))
}

fn be_32(s: Span) -> IResult<Span, i32> {
    let read_i32 = |i| String::from_utf8_lossy(i).parse::<i32>().unwrap();
    let x = map(digit1, |i: Span| read_i32(i.fragment()))(s);
    x
}
/// parse $(word n,text)
/// $(word n,text) is a function that returns the nth word of text.
fn parse_pathexpr_word(i: Span) -> IResult<Span, PathExpr> {
    let (s, _) = tag("$(word")(i)?;
    let (s, _) = parse_ws(s)?;
    let (s, n) = be_32(s)?;
    let (s, _) = opt(parse_ws)(s)?;
    let (s, (text, _)) = parse_pelist_till_delim_with_ws(s, ")", &BRKTOKS)?;
    let (s, _) = opt(parse_ws)(s)?;
    Ok((s, PathExpr::from(DollarExprs::Word(n, text))))
}

/// parse $(call variable, param...)
fn parse_pathexpr_call(i: Span) -> IResult<Span, PathExpr> {
    let (s, _) = tag("$(call")(i)?;
    let (s, _) = parse_ws(s)?;
    let (s, (var, mut end)) = parse_pelist_till_delim_with_ws(s, ",)", &BRKTOKS)?;
    let mut params = Vec::new();
    log::debug!("parsed call var: {:?}", var);
    let mut rest = s;
    while end == ',' {
        let (s, _) = opt(parse_ws)(rest)?;
        let (s, (p, e)) = parse_pelist_till_delim_with_ws(s, ",)", &BRKTOKS)?;
        log::debug!("parsed call param: {:?}", p);
        params.push(p);
        end = e;
        rest = s;
    }
    Ok((rest, PathExpr::from(DollarExprs::Call(var, params))))
}

/// parse wild card $(wildcard pattern...)
/// $(wildcard pattern...) is a function that returns the names of all files that match one of the given patterns.
fn parse_pathexpr_wildcard(i: Span) -> IResult<Span, PathExpr> {
    let (s, _) = tag("$(wildcard")(i)?;
    let (s, _) = parse_ws(s)?;
    let (s, (pattern, _)) = parse_pelist_till_delim_with_ws(s, ")", &BRKTOKS)?;
    let (s, _) = opt(parse_ws)(s)?;
    Ok((s, PathExpr::from(DollarExprs::WildCard(pattern))))
}

/// parse $(firstword names...)
/// $(firstword names...) is a function that returns the first word of names.
fn parse_pathexpr_firstword(i: Span) -> IResult<Span, PathExpr> {
    let (s, _) = tag("$(firstword")(i)?;
    let (s, _) = parse_ws(s)?;
    let (s, (pattern, _)) = parse_pelist_till_delim_with_ws(s, ")", &BRKTOKS)?;
    let (s, _) = opt(parse_ws)(s)?;
    Ok((s, PathExpr::from(DollarExprs::FirstWord(pattern))))
}

/// parse eval expression $(eval body)
fn parse_pathexpr_eval(i: Span) -> IResult<Span, PathExpr> {
    let (s, _) = tag("$(eval")(i)?;
    let (s, _) = parse_ws(s)?;
    let (s, (exps, _)) = parse_pelist_till_delim_with_ws(s, ")", &BRKTOKS)?;
    let (s, _) = opt(parse_ws)(s)?;
    Ok((s, PathExpr::DollarExprs(DollarExprs::Eval(exps))))
}

/// parse $(dir names...)
/// $(dir names...) is a function that returns the directory-part of each file name in names.
fn parse_pathexpr_dir(i: Span) -> IResult<Span, PathExpr> {
    let (s, _) = tag("$(dir")(i)?;
    let (s, _) = parse_ws(s)?;
    let (s, (pattern, _)) = parse_pelist_till_delim_with_ws(s, ")", &BRKTOKS)?;
    let (s, _) = opt(parse_ws)(s)?;
    Ok((s, PathExpr::from(DollarExprs::Dir(pattern))))
}

/// parse $(nodir names...)
/// $(nodir names...) is a function that returns the non-directory-part of each file name in names.
fn parse_pathexpr_nodir(i: Span) -> IResult<Span, PathExpr> {
    let (s, _) = tag("$(nodir")(i)?;
    let (s, _) = parse_ws(s)?;
    let (s, (pattern, _)) = parse_pelist_till_delim_with_ws(s, ")", &BRKTOKS)?;
    let (s, _) = opt(parse_ws)(s)?;
    Ok((s, PathExpr::from(DollarExprs::NotDir(pattern))))
}

/// parse $(abspath names...)
/// $(abspath names...) is a function that returns the absolute file names of the given file names.
fn parse_pathexpr_abspath(i: Span) -> IResult<Span, PathExpr> {
    let (s, _) = tag("$(abspath")(i)?;
    let (s, _) = parse_ws(s)?;
    let (s, (pattern, _)) = parse_pelist_till_delim_with_ws(s, ")", &BRKTOKS)?;
    let (s, _) = opt(parse_ws)(s)?;
    Ok((s, PathExpr::from(DollarExprs::AbsPath(pattern))))
}

/// parse $(if condition, then-part\[,else-part\])
/// $(if condition, then-part\[,else-part\]) is a function that evaluates condition as the contents of a make variable would be evaluated as a conditional
/// (see Syntax of Conditionals). If condition is true, then-part is evaluated and becomes the result of the function.
/// Otherwise, else-part is evaluated and becomes the result of the function. If else-part is omitted, it is treated as an empty string.
fn parse_pathexpr_if(i: Span) -> IResult<Span, PathExpr> {
    let (s, _) = tag("$(if")(i)?;
    let (s, _) = parse_ws(s)?;
    let (s, (condition, _)) = parse_pelist_till_delim_with_ws(s, ",", &BRKTOKS)?;
    let (s, (then_part, _)) = parse_pelist_till_delim_with_ws(s, ",)", &BRKTOKS)?;
    let (s, o) = opt(tag(","))(s)?;
    if o == None {
        return Ok((
            s,
            PathExpr::from(DollarExprs::If(condition, then_part, Vec::new())),
        ));
    }
    let (s, (else_part, _)) = parse_pelist_till_delim_with_ws(s, ")", &BRKTOKS)?;
    let (s, _) = opt(parse_ws)(s)?;
    Ok((
        s,
        PathExpr::from(DollarExprs::If(condition, then_part, else_part)),
    ))
}

/// parse $(realpath names...)
/// $(realpath names...) is a function that returns the canonical absolute names of the given file names.
fn parse_pathexpr_realpath(i: Span) -> IResult<Span, PathExpr> {
    let (s, _) = tag("$(realpath")(i)?;
    let (s, _) = parse_ws(s)?;
    let (s, (pattern, _)) = parse_pelist_till_delim_with_ws(s, ")", &BRKTOKS)?;
    let (s, _) = opt(parse_ws)(s)?;
    Ok((s, PathExpr::from(DollarExprs::RealPath(pattern))))
}

/// parse $(basename names...)
/// $(basename names...) is a function that returns the non-directory-part of each file name without extension in names.
fn parse_pathexpr_basename(i: Span) -> IResult<Span, PathExpr> {
    let (s, _) = tag("$(basename")(i)?;
    let (s, _) = parse_ws(s)?;
    let (s, (pattern, _)) = parse_pelist_till_delim_with_ws(s, ")", &BRKTOKS)?;
    let (s, _) = opt(parse_ws)(s)?;
    Ok((s, PathExpr::from(DollarExprs::BaseName(pattern))))
}

/// parse $(strip names...)
/// $(strip names...) is a function that returns the non-directory-part of each file name without extension in names.
fn parse_pathexpr_strip(i: Span) -> IResult<Span, PathExpr> {
    let (s, _) = tag("$(strip")(i)?;
    let (s, _) = parse_ws(s)?;
    let (s, (pattern, _)) = parse_pelist_till_delim_with_ws(s, ")", &BRKTOKS)?;
    let (s, _) = opt(parse_ws)(s)?;
    Ok((s, PathExpr::from(DollarExprs::Strip(pattern))))
}
/// process whitespace
fn parse_ws(i: Span) -> IResult<Span, PathExpr> {
    let (s, _) = is_a(" \t")(i)?;
    Ok((s, PathExpr::Sp1))
}

fn parse_quote(i: Span) -> IResult<Span, PathExpr> {
    let (s, _) = tag("\"")(i)?;
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
    let (s, r) = take(1_usize)(i)?;
    Ok((s, r))
}

/// eats up \\n
/// consume dollar's etc that where left out during previous parsing
/// consume a literal that is not a pathexpr token
fn parse_misc_bits<'a, 'b>(
    input: Span<'a>,
    end_tok: &'b str,
    break_toks: &'static str,
) -> IResult<Span<'a>, Span<'a>> {
    let islit = |ref i| !end_tok.as_bytes().contains(i) && !break_toks.as_bytes().contains(i);
    alt((complete(parse_delim), complete(take_while(islit))))(input)
}
/// parse either (dollar|at|) expression or a general rvalue delimited by delim
/// break_toks are the tokens that pause and restart the parser to create a new pathexpr
pub(crate) fn parse_pathexpr_ws<'a, 'b>(
    s: Span<'a>,
    end_tok: &'b str,
    break_toks: &'static str,
) -> IResult<Span<'a>, PathExpr> {
    alt((
        complete(parse_escaped),
        complete(parse_quote),
        complete(parse_ws),
        complete(parse_pathexprbasic),
        complete(parse_pathexpr_taskref),
        complete(map_res(
            |i| parse_misc_bits(i, end_tok, break_toks),
            from_str,
        )),
    ))(s)
}

/// break_toks are the tokens that pause and restart the parser to create a new pathexpr
fn parse_pathexpr_no_ws<'a, 'b>(
    s: Span<'a>,
    end_tok: &'b str,
    break_toks: &'static str,
) -> IResult<Span<'a>, PathExpr> {
    alt((
        complete(parse_escaped),
        complete(parse_pathexprbasic),
        complete(map_res(
            |i| parse_misc_bits(i, end_tok, break_toks),
            from_str,
        )),
    ))(s)
}

// repeatedly invoke the rvalue parser until eof or end_tok is encountered
// parser pauses to create new pathexpr when break_tok is encountered
fn parse_pelist_till_delim_with_ws<'a, 'b>(
    input: Span<'a>,
    end_tok: &'b str,
    break_toks: &'static str,
) -> IResult<Span<'a>, (Vec<PathExpr>, char)> {
    many_till(
        |i| parse_pathexpr_ws(i, end_tok, break_toks),
        one_of(end_tok),
    )(input)
}
// repeatedly invoke the rvalue parser until eof or delim is encountered
// parser pauses to create new pathexpr when break_tok is encountered
fn parse_pelist_till_delim_no_ws<'a, 'b>(
    input: Span<'a>,
    end_tok: &'b str,
    break_tok: &'static str,
) -> IResult<Span<'a>, (Vec<PathExpr>, char)> {
    many_till(
        |i| parse_pathexpr_no_ws(i, end_tok, break_tok),
        one_of(end_tok),
    )(input)
}

//  wrapper over the previous parser that handles empty inputs and stops at newline;
fn parse_pelist_till_line_end_with_ws(input: Span) -> IResult<Span, (Vec<PathExpr>, char)> {
    alt((
        complete(map(ws0_line_ending, |_| (Vec::new(), '\0'))),
        complete(|i| parse_pelist_till_delim_with_ws(i, "\r\n", &BRKTOKSWS)),
    ))(input)
}

// read all pathexpr separated by whitespaces, pausing at BRKTOKS
fn parse_pathexpr_list_until_ws_plus(input: Span) -> IResult<Span, (Vec<PathExpr>, Span)> {
    many_till(|i| parse_pathexpr_no_ws(i, " \t\r\n", &BRKTOKS), ws1)(input)
}

pub(crate) fn parse_lines(input: Span) -> IResult<Span, Vec<(Vec<PathExpr>, char)>> {
    many0(complete(parse_pelist_till_line_end_with_ws))(input)
}

// parse a lvalue ref to a ident
fn parse_lvalue_ref(input: Span) -> IResult<Span, Ident> {
    let (s, _) = char('&')(input)?;
    parse_lvalue(s)
}
// parse a lvalue to a ident
fn parse_lvalue(input: Span) -> IResult<Span, Ident> {
    map(map_res(take_while(is_ident), from_utf8), Ident::new)(input)
}

impl From<(Statement, Span<'_>)> for LocatedStatement {
    fn from((stmt, i): (Statement, Span<'_>)) -> Self {
        LocatedStatement::new(stmt, i.into())
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
    let offset = i.offset(&s);
    Ok((s, (Statement::Include(r.0), i.slice(..offset)).into()))
}
// parse error expression
fn parse_message(i: Span) -> IResult<Span, LocatedStatement> {
    let (s, _) = multispace0(i)?;
    let string_to_enum = |i, s: &[u8]| -> IResult<Span, Level> {
        match &s[..6] {
            b"$(erro" => Ok((i, Level::Error)),
            b"$(warn" => Ok((i, Level::Warning)),
            b"$(info" => Ok((i, Level::Info)),
            _ => Err(Err::Error(error_position!(i, ErrorKind::Escaped))),
        }
    };
    let curs = s.clone();
    let (s, op) = alt((
        complete(tag("$(error")),
        complete(tag("$(warn")),
        complete(tag("$(info")),
    ))(s)?;
    let (_, level) = string_to_enum(curs, op.as_bytes()).unwrap();
    let (s, _) = sp1(s)?;
    let (s, r) = context(
        "message expression",
        cut(|i| parse_pelist_till_delim_with_ws(i, ")", &BRKTOKSWS)),
    )(s)?;
    let offset = i.offset(&s);
    Ok((
        s,
        (Statement::Message(r.0, level), i.slice(..offset)).into(),
    ))
}

// parse export expression
// export VARIABLE
fn parse_export(i: Span) -> IResult<Span, LocatedStatement> {
    let (s, _) = multispace0(i)?;
    let (s, _) = tag("export")(s)?;
    let (s, _) = sp1(s)?;
    let (s, r) = context("export expression", cut(take_while(is_ident)))(s)?;
    let (s, _) = multispace0(s)?;
    let raw = std::str::from_utf8(r.as_bytes()).unwrap();
    let offset = i.offset(&s);
    Ok((
        s,
        (Statement::Export(raw.to_owned()), i.slice(..offset)).into(),
    ))
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
    let offset = i.offset(&s);
    let default_raw = def.and_then(|x| from_utf8(x).ok());
    Ok((
        s,
        (
            Statement::Import(raw.to_owned(), default_raw),
            i.slice(..offset),
        )
            .into(),
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
    let offset = i.offset(&s);
    Ok((s, (Statement::Preload(r.0), i.slice(..offset)).into()))
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
    let (s, _) = multispace0(s)?;
    let offset = i.offset(&s);
    Ok((s, (Statement::Run(r.0), i.slice(..offset)).into()))
}
// parse include_rules expresssion
fn parse_include_rules(i: Span) -> IResult<Span, LocatedStatement> {
    let (s, _) = multispace0(i)?;
    let (s, _) = tag("include_rules")(s)?;
    let (s, _) = complete(ws0_line_ending)(s)?;
    let offset = i.offset(&s);
    Ok((s, (Statement::IncludeRules, i.slice(..offset)).into()))
}

// parse comment expresssion
fn parse_comment(i: Span) -> IResult<Span, LocatedStatement> {
    let (s, _) = multispace0(i)?;
    let (s, _) = tag("#")(s)?;
    let (s, _) = opt(is_not("\n\r"))(s)?;
    let (s, _) = line_ending(s)?;
    Ok((s, (Statement::Comment, i).into()))
}

/// task(name) : dep1 dep2..
///       commands..
/// dep1 dep2 could be outputs, group, bin or another task
fn parse_task_statement(i: Span) -> IResult<Span, LocatedStatement> {
    let (s, _) = multispace0(i)?;
    let (s, _) = tag("task")(s)?;
    let (s, _) = opt(sp1)(s)?;
    let (s, name) = context(
        "task name",
        cut(delimited(tag("{"), parse_lvalue, tag("}"))),
    )(s)?;
    let (s, _) = opt(sp1)(s)?;
    let (s, _) = tag(":")(s)?;
    let (s, _) = opt(sp1)(s)?;
    let (s, deps) = opt(parse_pelist_till_line_end_with_ws)(s)?;
    log::warn!("remaining: {:?}", s);
    let deps = deps.map(|x| x.0).unwrap_or_default();

    let read_lines = |s| {
        let (s, line) = context("task expression", cut(parse_pelist_till_line_end_with_ws))(s)?;
        Ok((s, line.0))
    };
    // take until enddef or endef occurs
    let (s, (body, _)) = context(
        "task expression",
        cut(many_till(read_lines, tag("endtask"))),
    )(s)?;
    let offset = i.offset(&s);
    Ok((
        s,
        (Statement::Task(name, deps, body, vec![]), i.slice(..offset)).into(),
    ))
}

/// parse an assignment expression
fn parse_assignment_expr(i: Span) -> IResult<Span, LocatedStatement> {
    let (s, _) = multispace0(i)?;
    // parse the left side of the assignment
    let (s, left) = parse_lvalue(s)?;
    let (s, _) = opt(sp1)(s)?;
    let (s, op) = alt((
        complete(tag("=")),
        complete(tag(":=")),
        complete(tag("?=")),
        complete(tag("+=")),
    ))(s)?;
    let (s, _) = opt(sp1)(s)?;
    let (s, r) = complete(parse_pelist_till_line_end_with_ws)(s)?;
    let right = r.0;
    let offset = i.offset(&s);
    Ok((
        s,
        (
            Statement::AssignExpr {
                left,
                right,
                is_append: (op.as_bytes() == b"+="),
                is_empty_assign: (op.as_bytes() == b"?="),
            },
            i.slice(..offset),
        )
            .into(),
    ))
}

/// parse a define statement and its body until enddef occurs
fn parse_define_expr(i: Span) -> IResult<Span, LocatedStatement> {
    let (s, _) = multispace0(i)?;
    let (s, _) = tag("define")(s)?;
    let (s, _) = sp1(s)?;
    log::debug!("parsing define expression");
    let (s, ident) = context("define expression", cut(parse_lvalue))(s)?;
    log::debug!("with name: {:?}", ident);
    let (s, _) = multispace0(s)?;

    // take until enddef occurs
    let (s, body) = context(
        "define expression",
        cut(map_res(take_until("enddef"), from_utf8)),
    )(s)?;
    let (s, _) = multispace0(s)?;
    let (s, _) = tag("enddef")(s)?;
    let offset = i.offset(&s);
    Ok((
        s,
        (Statement::Define(ident, body), i.slice(..offset)).into(),
    ))
}
// eval block statements are parsed in the initial phase as regular pathexprs.
// These will be parsed again in the second phase
// during substitution as regular statements that can be evaluated
fn parse_eval_block(i: Span) -> IResult<Span, LocatedStatement> {
    let (s, _) = multispace0(i)?;
    //peek to check if the next token is  $(eval or $(foreach or (call..
    let (s, _) = peek(alt((tag("$(eval"), tag("$(foreach"), tag("$(call"))))(s)?;
    let (s, (body, _)) = complete(parse_pelist_till_line_end_with_ws)(s)?;
    log::debug!("parsed eval block: {:?}", body);
    let offset = i.offset(&s);
    Ok((s, (Statement::EvalBlock(body), i.slice(..offset)).into()))
}

// parse an assignment expression
fn parse_ref_assignment_expr(i: Span) -> IResult<Span, LocatedStatement> {
    let (s, _) = multispace0(i)?;
    let (s, l) = context("lhs", parse_lvalue_ref)(s)?;
    let (s, _) = opt(sp1)(s)?;
    let (s, op) = alt((
        complete(tag("=")),
        complete(tag(":=")),
        complete(tag("?=")),
        complete(tag("+=")),
    ))(s)?;
    let (s, _) = opt(sp1)(s)?;
    log::debug!("parsing assignment expression with lhs  {:?} {:?}", l, op);
    let (s, r) = context("rhs", cut(complete(parse_pelist_till_line_end_with_ws)))(s)?;
    log::debug!("and rhs: {:?}", r);
    let offset = i.offset(&s);
    Ok((
        s,
        (
            Statement::AsignRefExpr {
                left: l,
                right: r.0,
                is_append: (op.as_bytes() == b"+="),
                is_empty_assign: (op.as_bytes() == b"?="),
            },
            i.slice(..offset),
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
    Ok((s, r))
}

// parse the insides of a rule, which includes a description and rule formula
pub(crate) fn parse_rule_gut(i: Span) -> IResult<Span, RuleFormula> {
    let (s, desc) = opt(context(
        "parsing rule flags/descriptions",
        parse_rule_flags_or_description,
    ))(i)?;
    let (s, me) = opt(parse_pathexpr_macroref)(s)?;
    let (s, formula) = parse_pelist_till_delim_with_ws(s, "|", &BRKTOKSWS)?;
    Ok((
        s,
        RuleFormula {
            description: desc.into_iter().map(PathExpr::from).collect(),
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
pub(crate) fn parse_rule_inp(i: Span) -> IResult<Span, (Vec<PathExpr>, Span)> {
    let (s, _) = opt(sp1)(i)?;
    let pe = |i| parse_pathexpr_ws(i, "|", &BRKTOKSIO);
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
    let pe = |i| parse_pathexpr_ws(i, "|", &BRKTOKSIO);
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
    let pe = |i| parse_pathexpr_ws(i, "<{^\r\n", &BRKTOKSIO);
    let (s, v0) = many_till(
        alt((complete(parse_pathexpr_exclude_pattern), complete(pe))),
        parse_output_delim,
    )(s)?;
    Ok((s, v0.0))
}

fn parse_primary_output0(i: Span) -> IResult<Span, (Vec<PathExpr>, bool)> {
    let (s, _) = opt(sp1)(i)?;
    let pe = |i| parse_pathexpr_ws(i, "|<{^\r\n", &BRKTOKSIO);
    let (s, v0) = many_till(
        alt((complete(parse_pathexpr_exclude_pattern), complete(pe))),
        parse_output_delim,
    )(s)?;
    //eprintln!("{}", v0.1.as_bytes().first().unwrap_or(&b' ').as_char());
    let has_more = v0.1.as_bytes().first().map(|&c| c == b'|').unwrap_or(false);
    Ok((s, (v0.0, has_more)))
}

/// parse a rule expression of the form
/// : \[foreach\] \[inputs\] \[ \| order-only inputs\] \|\> command \|\> \[outputs\] \[ | extra outputs\] \[exclusions\] \[<group>\] \[{bin}\]
pub(crate) fn parse_rule(i: Span) -> IResult<Span, LocatedStatement> {
    log::debug!("parsing rule expression at line:{}", i.location_line());

    let (s, _) = multispace0(i)?;
    let (s, _) = tag(":")(s)?;
    let (s, _) = opt(sp1)(s)?;
    let (s, for_each) = opt(tag("foreach"))(s)?;
    let (s, input) = context("rule input", cut(opt(parse_rule_inp)))(s)?;
    let (s, _) = opt(sp1)(s)?;
    let (s, c) = peek(take(1_usize))(s)?;
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
    let (s, output0) = context("rule output maybe primary", opt(parse_primary_output0))(s)?;
    let has_more = output0.as_ref().map_or(false, |(_, has_more)| *has_more);
    let (s, output1) = if has_more {
        context("rule output", cut(parse_primary_output1))(s)?
    } else {
        (s, vec![])
    };

    let (output, secondary_output) = if has_more {
        (output0.unwrap_or((Vec::new(), false)).0, output1)
    } else {
        (output0.unwrap_or((Vec::new(), false)).0, Vec::new())
    };
    //let (s, exclude_patterns) = opt(parse_pathexpr_exclude_pattern)(s)?;
    // let secondary_output = if hassecondary { output1.unwrap_or(Vec::new())} else { Vec::new() };
    let (s, _) = opt(sp1)(s)?;
    let (s, v1) = opt(parse_pathexpr_group)(s)?;
    let (s, _) = opt(sp1)(s)?;
    let (s, v2) = opt(parse_pathexpr_bin)(s)?;
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
                    pos: Loc::from(i.slice(..offset)),
                },
                EnvDescriptor::default(),
                Vec::new(),
            ),
            i.slice(..offset),
        )
            .into(),
    ))
}

pub(crate) fn parse_searchpaths(i: Span) -> IResult<Span, LocatedStatement> {
    let (s, _) = multispace0(i)?;
    let (s, _) = alt((complete(tag("searchpaths")), complete(tag("vpath"))))(s)?;
    let (s, _) = sp1(s)?;
    let (s, r) = context(
        "searchpaths expression",
        cut(parse_pelist_till_line_end_with_ws),
    )(s)?;
    let offset = i.offset(&s);
    Ok((s, (Statement::SearchPaths(r.0), i.slice(..offset)).into()))
}

// parse a macro assignment which is more or less same as parsing a rule expression
// !macro = [inputs] | [order-only inputs] |> command |> [outputs]
pub(crate) fn parse_macroassignment(i: Span) -> IResult<Span, LocatedStatement> {
    let (s, _) = multispace0(i)?;
    let (s, _) = tag("!")(s)?;
    let (s, macroname) = take_while(is_ident)(s)?;
    let (s, _) = opt(sp1)(s)?;
    let (s, _) = tag("=")(s)?;
    let (s, _) = opt(sp1)(s)?;
    let (s, for_each) = opt(tag("foreach"))(s)?;
    let (s, _) = opt(sp1)(s)?;
    let (s, input) = opt(context("rule input", cut(parse_rule_inp)))(s)?;
    let (s, c) = peek(take(1_usize))(s)?;
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
    let has_more = output0.as_ref().map_or(false, |(_, has_more)| *has_more);
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
    let macroname_str = from_utf8(macroname).unwrap_or_default();
    log::debug!("built macro:{}", macroname_str);
    let offset = i.offset(&s);
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
                    target: from_output(output, secondary_output, None, None),
                    rule_formula,
                    pos: Loc::from(i.slice(..offset)),
                },
            ),
            i.slice(..offset),
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
        complete(parse_ref_assignment_expr),
        complete(parse_assignment_expr),
        complete(parse_rule),
        complete(parse_if_else_endif),
        complete(parse_ifdef_endif),
        complete(parse_macroassignment),
        complete(parse_message),
        complete(parse_export),
        complete(parse_run),
        complete(parse_preload),
        complete(parse_import),
        complete(parse_define_expr),
        complete(parse_task_statement),
        complete(parse_searchpaths),
        complete(parse_eval_block),
    ))(i)
}

/// parse until the start of else block
fn parse_statements_until_else_or_endif(i: Span) -> IResult<Span, (Vec<LocatedStatement>, &str)> {
    let g = map(alt((tag("else"), tag("endif"))), |i: Span| {
        if i.fragment().slice(..4).cmp(&b"else".as_bytes()) == Ordering::Equal {
            "else"
        } else {
            "endif"
        }
    });
    many_till(parse_statement, g)(i)
}

/// parse until endif statement
fn parse_statements_until_endif(i: Span) -> IResult<Span, (Vec<LocatedStatement>, &str)> {
    let g = map(tag("endif"), |_| "endif");
    many_till(parse_statement, g)(i)
}

/// parse statements till end of file
pub(crate) fn parse_statements_until_eof(
    i: Span,
) -> Result<Vec<LocatedStatement>, crate::errors::Error> {
    many0(parse_statement)(i).map(|v| v.1).map_err(|e| match e {
        Err::Incomplete(_) => {
            crate::errors::Error::ParseError("Incomplete data found".to_string(), Loc::default())
        }
        Err::Error(e) => crate::errors::Error::ParseError(
            format!("Parse Error {:?}", e.code),
            Loc::from(e.input),
        ),
        Err::Failure(e) => crate::errors::Error::ParseError(
            format!("Parse Failure {:?}", e.code),
            Loc::from(e.input),
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
    let (s, (e1, _)) = parse_pelist_till_delim_no_ws(s, ",", &BRKTOKS)?;
    let (s, _) = opt(sp1)(s)?;
    let (s, (e2, _)) = parse_pelist_till_delim_no_ws(s, ")", &BRKTOKS)?;
    Ok((
        s,
        EqCond {
            lhs: e1,
            rhs: e2,
            not_cond,
        },
    ))
}

pub(crate) fn parse_checked_var(i: Span) -> IResult<Span, CheckedVar> {
    let (s, _) = opt(ws1)(i)?;
    let (s, negate) = alt((map(tag("ifdef "), |_| false), map(tag("ifndef "), |_| true)))(s)?;
    log::debug!("parsing if{}def", if negate { "n" } else { "" });
    let (s, _) = opt(ws1)(s)?;
    let (s, var) = cut(complete(parse_lvalue))(s)?;
    let (s, _) = opt(ws1)(s)?;
    Ok((s, CheckedVar(var, negate)))
}

// parse contents inside if else endif bocks(without condition)
pub(crate) fn parse_ifelseendif_inner(i: Span, eqcond: EqCond) -> IResult<Span, LocatedStatement> {
    let (s, then_else_s) = parse_statements_until_else_or_endif(i)?;
    let mut cvar_then_statements = vec![CondThenStatements {
        eq: eqcond,
        then_statements: then_else_s.0,
    }];

    let mut else_endif_s = Vec::new();
    let mut rest = s;
    let mut end_clause = then_else_s.1;
    while end_clause == "else" {
        // at this point if else block can continue to add more conditional blocks or finish with endif
        if let (s, Some(cvarinner)) = opt(preceded(ws1, parse_eq))(rest)? {
            let (s, _) = opt(ws1)(s)?;
            let (s, cond_then_s) = parse_statements_until_else_or_endif(s)?;
            end_clause = cond_then_s.1;
            let cond_then_statements_inner = CondThenStatements {
                eq: cvarinner,
                then_statements: cond_then_s.0,
            };
            cvar_then_statements.push(cond_then_statements_inner);
            rest = s;
        } else {
            let (s, _) = opt(ws1)(rest)?;
            let (s, else_s) = parse_statements_until_endif(s)?;
            rest = s;
            else_endif_s = else_s.0;
            break;
        }
    }

    let s = rest;
    let offset = i.offset(&s);
    Ok((
        s,
        (
            Statement::IfElseEndIf {
                then_elif_statements: cvar_then_statements,
                else_statements: else_endif_s,
            },
            i.slice(..offset),
        )
            .into(),
    ))
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
    let (s, then_else_s) = parse_statements_until_else_or_endif(i)?;
    let mut cvar_then_statements = vec![CheckedVarThenStatements {
        checked_var: cvar,
        then_statements: then_else_s.0,
    }];

    let mut else_endif_s = Vec::new();
    let mut rest = s;
    let mut end_clause = then_else_s.1;
    while end_clause == "else" {
        // at this point if else block can continue to add more conditional blocks or finish with endif
        if let (s, Some(cvarinner)) = opt(preceded(ws1, parse_checked_var))(rest)? {
            let (s, _) = opt(ws1)(s)?;
            let (s, cond_then_s) = parse_statements_until_else_or_endif(s)?;
            end_clause = cond_then_s.1;
            let cvar_then_statements_inner = CheckedVarThenStatements {
                checked_var: cvarinner,
                then_statements: cond_then_s.0,
            };
            cvar_then_statements.push(cvar_then_statements_inner);
            rest = s;
        } else {
            let (s, _) = opt(ws1)(rest)?;
            let (s, else_statements) = parse_statements_until_endif(s)?;
            rest = s;
            else_endif_s = else_statements.0;
            break;
        }
    }

    let s = rest;
    let offset = i.offset(&s);
    Ok((
        s,
        (
            Statement::IfDef {
                checked_var_then_statements: cvar_then_statements,
                else_statements: else_endif_s,
            },
            i.slice(..offset),
        )
            .into(),
    ))
}

/// parse if else endif block
pub(crate) fn parse_ifdef_endif(i: Span) -> IResult<Span, LocatedStatement> {
    let (s, cvar) = parse_checked_var(i)?;
    let (s, _) = opt(ws1)(s)?;
    let ctx = if cvar.1 {
        "parsing ifndef block"
    } else {
        "parsing ifdef block"
    };
    context(ctx, cut(move |s| parse_ifdef_inner(s, cvar.clone())))(s)
}

/// parse statements in a tupfile
pub(crate) fn parse_tupfile<P: AsRef<Path>>(
    filename: P,
) -> Result<Vec<LocatedStatement>, crate::errors::Error> {
    use crate::errors::Error as Err;
    use std::fs::File;
    use std::io::prelude::*;
    let mut file = File::open(filename).map_err(|e| Err::IoError(e, Loc::default()))?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)
        .map_err(|e| Err::IoError(e, Loc::default()))?;
    //contents.retain( |e| *e != b'\r');
    parse_statements_until_eof(Span::new(contents.as_bytes()))
}

/// locate TupRules.tup\[.lua\] walking up the directory tree
pub(crate) fn locate_tuprules<P: AsRef<Path>>(cur_tupfile: P) -> VecDeque<PathBuf> {
    let mut v = VecDeque::new();

    log::debug!("locating tuprules for {:?}", cur_tupfile.as_ref());
    let mut tupr = cur_tupfile.as_ref();
    while let Some(p) = transform::locate_file(tupr, "Tuprules.tup", "lua") {
        v.push_front(p);
        tupr = v.front().and_then(|p| p.parent()).unwrap();
        if tupr.as_os_str().is_empty() || tupr.as_os_str().eq(".") {
            break;
        }
        tupr = tupr.parent().unwrap();
        log::debug!("try:{:?}", tupr);
    }
    v
}

/// module only for testing purposes
pub mod testing {
    /// parse all statements in this tupfile, used currently only for testing
    pub fn parse_tupfile<P: AsRef<std::path::Path>>(
        filename: P,
    ) -> Result<Vec<crate::statements::LocatedStatement>, crate::errors::Error> {
        return crate::parser::parse_tupfile(filename);
    }
}
