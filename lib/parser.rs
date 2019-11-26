// promote a string into a tup variable
use statements::*;
use nom::character::complete::{multispace0, multispace1, space1};

fn to_lval(s: &str) -> Ident {
    Ident { name: s.to_owned() }
}
// convert byte str to RvalGeneral::Literal
fn from_str(res: &[u8]) -> Result<RvalGeneral, std::str::Utf8Error> {
    match std::str::from_utf8(res) {
        Ok(s) => Ok(RvalGeneral::Literal(s.to_owned())),
        Err(e) => Err(e),
    }
}
// check if char is part of an identifier (lhs of var assignment)
fn is_ident(c: u8) -> bool {
    nom::character::is_alphanumeric(c) || c == b'_'
}

fn is_ident_perc(c: u8) -> bool {
    nom::character::is_alphanumeric(c) || c == b'_' || c == b'%'
}

named!(ws1, alt!(
    complete!(tag!("\\\n"))|
    multispace1 |
    value!(b"".as_ref(), peek!(one_of!("<{")))
));
named!(sp1, alt!(
    complete!(tag!("\\\n"))|
    space1
));



// parse rvalue wrapped inside dollar or at
named!(
    parse_rvalue_raw,
    delimited!(
        alt!(tag!("$(") | tag!("@(") | tag!("&(")),
        take_while!(is_ident_perc),
        tag!(")")
    )
);

// parse a macro ref starting with a exclamation mark
named!(
    parse_rvalue_raw_excl,
    do_parse!( opt!(sp1) >> tag!("!") >> v: take_while!(is_ident) >> (v))
);

// parse an inline comment
named!(
    parse_rvalue_raw_comment,
    do_parse!(opt!(sp1) >> tag!("#") >> v: take_until!("\n") >> (v))
);
// read a curly brace and the identifier inside it
named!(
    parse_rvalue_raw_bucket,
    delimited!(tag!("{"), take_while!(is_ident), tag!("}"))
);

// read '<' and the list of rvals inside it until '>'
named!(parse_rvalue_raw_angle<&[u8], Vec<RvalGeneral>>,
       do_parse!(
           tag!("<") >>
           v : call!(parse_rvalgeneral_list_long, ">") >>
           (v.0))
);

// parse rvalue at expression eg @(V)
named!(parse_rvalue_at<&[u8], RvalGeneral>,
   do_parse!(
       rv : map_res!(parse_rvalue_raw, std::str::from_utf8) >>
       (RvalGeneral::AtExpr(rv.to_owned()))
   )
);

// parse rvalue dollar expression eg $(H)
named!(parse_rvalue_dollar<&[u8], RvalGeneral>,
   do_parse!(
       rv : map_res!(parse_rvalue_raw, std::str::from_utf8) >>
       (RvalGeneral::DollarExpr(rv.to_owned()))
   )
);

// parse rvalue dollar expression eg $(H)
named!(parse_rvalue_amp<&[u8], RvalGeneral>,
       do_parse!(
           rv : map_res!(parse_rvalue_raw, std::str::from_utf8) >>
               (RvalGeneral::AmpExpr(rv.to_owned()))
       )
);

// parse rvalue macro ref eg !CC
named!(parse_rvalue_exclamation<&[u8], RvalGeneral>,
       do_parse!(
           rv : map_res!(parse_rvalue_raw_excl, std::str::from_utf8) >>
               (RvalGeneral::MacroRef(rv.to_owned()))
       )
);

// parse to a group <group>
named!(parse_rvalue_angle<&[u8], RvalGeneral>,
       do_parse!(
           rv : parse_rvalue_raw_angle >>
               (RvalGeneral::Group(rv))
       )
);
// parse to a bucket name: {objs}
named!(parse_rvalue_bucket<&[u8], RvalGeneral>,
       do_parse!(
           rv : map_res!(parse_rvalue_raw_bucket, std::str::from_utf8) >>
               (RvalGeneral::Bucket(rv.to_owned()))
       )
);

// parse trailing comments (#--)
named!(parse_rvalue_comment<&[u8], RvalGeneral>,
       do_parse!(
           rv : map_res!(parse_rvalue_raw_comment, std::str::from_utf8) >>
               (RvalGeneral::InlineComment(rv.to_owned()))
       )
);
// parse to any of the special expressions (dollar, at, angle, bucket)
named!(parse_rvalue<&[u8], RvalGeneral>,
       switch!(peek!(take!(1)),
           b"$" => call!(parse_rvalue_dollar) |
               b"@" => call!(parse_rvalue_at) |
               b"&" => call!(parse_rvalue_amp) |
               b"<" => call!(parse_rvalue_angle) |
               b"{" => call!(parse_rvalue_bucket) |
               b"!" => call!(parse_rvalue_exclamation) |
               b"#" => call!(parse_rvalue_comment)
       )
);

// eat up the (dollar or at) that dont parse to (dollar or at) expression
named!(chompdollar,
    do_parse!(peek!(one_of!("$@!<#&")) >> not!(parse_rvalue) >> r: take!(1) >> (r))
);

// read  a rvalue until delimiter
// in addition, \\\n , $,@, ! also pause the parsing
fn parse_greedy<'a, 'b>(
    input: &'a [u8],
    delim: &'b str,
) -> nom::IResult<&'a [u8], &'a [u8] > {
    let mut s = String::from("\\\n$@{<!#&");
    s.push_str(delim);
    alt!(input,
        value!(b"".as_ref(), complete!(tag!("\\\n")))
            | chompdollar
            | is_not!(s.as_str()) )
}
// parse either (dollar|at|curly|angle|exclamation) expression or a general rvalue delimited by delim
fn parse_rvalgeneral<'a, 'b>(
    s: &'a [u8],
    delim: &'b str,
) -> nom::IResult<&'a [u8], RvalGeneral> {
    alt!(
        s,
        complete!(preceded!(opt!(sp1), parse_rvalue)) |
        complete!(map_res!(call!(parse_greedy, delim), from_str))
    )
}
// repeatedly invoke the rvalue parser until eof or delim is encountered
fn parse_rvalgeneral_list_long<'a, 'b>(
    input: &'a [u8],
    delim: &'b str,
) -> nom::IResult<&'a [u8], (Vec<RvalGeneral>, &'a [u8]) > {
    many_till!(
        input,
        call!(parse_rvalgeneral, delim),
        alt!(tag!(delim) | eof!())
    )
}

named!(parse_rvalgeneral_list_sp<&[u8], (Vec<RvalGeneral>, &[u8])>,
    many_till!(
        call!(parse_rvalgeneral, " \t\r\n{<"), // avoid reading tags , newlines, spaces
        alt!(eof!() | ws1 )
    )
);

//  wrapper over the previous parser that handles empty inputs and stops at newline
named!(parse_rvalgeneral_list<&[u8], (Vec<RvalGeneral>, &[u8]) >,
       alt!( complete!(value!((Vec::new(), b"".as_ref()), eof!() )) |
             complete!(value!((Vec::new(), b"".as_ref()), delimited!(multispace0, tag!("\n"), multispace0) )) |
             complete!(call!(parse_rvalgeneral_list_long, "\n")) )
);

named!(parse_rvalgeneral_list_until_space<&[u8], (Vec<RvalGeneral>, &[u8]) >,
       alt!( complete!(value!((Vec::new(), b"".as_ref()), eof!() )) |
                       complete!(value!((Vec::new(), b"".as_ref()), peek!(one_of!("\n{<")) )) |
                      complete!(call!(parse_rvalgeneral_list_sp) ))
);


// parse a lvalue to a string
named!(parse_lvalue_ref<&[u8], Ident>,
       do_parse!(
           char!('&') >>
               l : call!(parse_lvalue) >>
               (l)
       )
);

named!(parse_lvalue<&[u8], Ident>,
       do_parse!(
           l : map_res!(take_while!(is_ident), std::str::from_utf8)>> (to_lval(l))
       )
);

// parse include expression
named!(parse_include<&[u8], Statement>,
       do_parse!( multispace0 >>
                  tag!("include") >> sp1 >> s: call!(parse_rvalgeneral_list) >>
                 (Statement::Include(s.0))
        )
);

// parse error expression
named!(parse_error<&[u8], Statement>,
       do_parse!(multispace0 >>
                 tag!("error") >> opt!(sp1) >> sp1 >>  s: call!(parse_rvalgeneral_list) >>
                 (Statement::Err(s.0))
       )
);

// parse export expression
named!(parse_export<&[u8], Statement>,
       do_parse!( multispace0 >> tag!("export") >> sp1 >> s: call!(parse_rvalgeneral_list) >>
                 (Statement::Export(s.0))
       )
);

// parse preload expression
named!(parse_preload<&[u8], Statement>,
       do_parse!(multispace0 >>  tag!("preload") >> sp1 >>  s: call!(parse_rvalgeneral_list) >>
                 (Statement::Preload(s.0))
       )
);
// parse the run expresssion
named!(parse_run<&[u8], Statement>,
       do_parse!(multispace0 >>  tag!("run")  >> sp1 >>  s: call!(parse_rvalgeneral_list) >>
                 (Statement::Run(s.0))
       )
);

// parse include_rules expresssion
named!(parse_include_rules<&[u8], Statement>,
       do_parse!(multispace0 >>  tag!("include_rules")
                 >> _s: map_res!(take_until!("\n"), std::str::from_utf8) >>
                 (Statement::IncludeRules)
       )
);

// parse comment expresssion
named!(parse_comment<&[u8], Statement>,
       do_parse!(multispace0 >>  tag!("#")  >>
                 s: map_res!(take_until!("\n"), std::str::from_utf8) >>
                 (Statement::Comment(s.to_owned()))
       )
);

// parse an assignment expression
named!(parse_let_expr<&[u8], Statement>,
       do_parse!( multispace0 >>
                  l : parse_lvalue >> opt!(sp1) >>
                  op : alt!( complete!(tag!("=")) |
                             complete!(tag!(":=")) |
                             complete!(tag!("+="))  ) >>
                  opt!(sp1) >>
                  r :  complete!(parse_rvalgeneral_list)  >>
                  (Statement::LetExpr{ left:l, right: r.0,
                                       is_append: (op == b"+=") }) )
);

// parse an assignment expression
named!(parse_letref_expr<&[u8], Statement>,
       do_parse!( multispace0 >>
                  l : parse_lvalue_ref >> opt!(sp1) >>
                  op : alt!( complete!(tag!("="))
                                 | complete!(tag!(":="))
                             | complete!(tag!("+="))  ) >>
                  opt!(sp1) >>
                  r :  complete!(parse_rvalgeneral_list)  >>
                  (Statement::LetRefExpr{ left:l, right:r.0,
                                       is_append: (op == b"+=") }) )
);

// parse the insides of a rule, which includes a description and rule formula
named!(parse_rule_gut<&[u8], RuleFormula>,
       do_parse!(
           description :
           opt!(do_parse!( multispace0 >>
                           tag!("^") >>
                           r: map_res!(take_until!("^"), std::str::from_utf8) >>
                           tag!("^") >> multispace0 >> (String::from(r)) ) )  >>
               formula : call!(parse_rvalgeneral_list_long, "|") >>
               (RuleFormula { description : description.unwrap_or(String::from("")), formula : formula.0}) )
);

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
named!(parse_rule<&[u8], Statement>,
      do_parse!( multispace0 >> tag!(":") >> multispace0 >>
                 for_each: opt!(tag!("foreach")) >> opt!(sp1)  >>
                 input : call!(parse_rvalgeneral_list_long, "|") >> opt!(sp1) >>
                 secondary_input : opt!( do_parse!( tag!("|") >> opt!(sp1) >>  r : call!(parse_rvalgeneral_list_long, "|") >> (r)) ) >>
                 tag!(">") >> opt!(sp1) >>
                 rule_formula : parse_rule_gut >>
                 tag!(">")  >> opt!(sp1) >>
                 secondary_output : opt!( call!(parse_rvalgeneral_list_long, "|") ) >> opt!(sp1) >>
                 output : opt!(complete!(call!(parse_rvalgeneral_list_until_space))) >> opt!(sp1) >>
                 tags :  opt!(call!(parse_rvalgeneral_list)) >>
                 (Statement::Rule(Link {
                     s : from_input(input.0, for_each.is_some(),
                                    secondary_input.unwrap_or((Vec::new(), b"")).0),
                     t : from_output(output.unwrap_or((Vec::new(), b"")).0,
                                     secondary_output.unwrap_or((Vec::new(), b"")).0,
                                     tags.unwrap_or((Vec::new(), b"")).0),
                     r : rule_formula
                     }
                 )) )
);

// parse a macro assignment which is more or less same as parsing a rule expression
// !macro = [inputs] | [order-only inputs] |> command |> [outputs]
named!(pub parse_macroassignment<&[u8], Statement>,
       do_parse!( multispace0 >> tag!("!") >>
                  macroname : take_while!(is_ident) >> opt!(sp1) >> tag!("=") >> opt!(sp1)>>
                  for_each: opt!(tag!("foreach")) >> opt!(sp1)  >>
                  input : call!(parse_rvalgeneral_list_long, "|") >> opt!(sp1) >>
                  secondary_input : opt!( do_parse!(tag!("|") >>  r : call!(parse_rvalgeneral_list_long, "|") >> (r)) ) >>
                  tag!(">") >> opt!(sp1) >>
                  rule_formula : parse_rule_gut >>
                  tag!(">") >> opt!(sp1) >>
                  secondary_output : opt!( complete!(do_parse!( r: call!(parse_rvalgeneral_list_long, "|") >> (r)) )) >>
                  output : opt!(call!(parse_rvalgeneral_list_until_space)) >> opt!(sp1) >>
                  (Statement::MacroAssignment(std::str::from_utf8(macroname).unwrap_or("").to_owned(), Link {
                      s : from_input(input.0, for_each.is_some(),
                                     secondary_input.unwrap_or((Vec::new(), b"")).0),
                      t : from_output(output.unwrap_or((Vec::new(), b"")).0,
                                      secondary_output.unwrap_or((Vec::new(), b"")).0,
                                      Vec::new()
                                      ),
                      r : rule_formula
                  }
                 )))
);

// parse any of the different types of statements in a tupfile
named!(pub parse_statement<&[u8], Statement>,
       alt!( complete!(parse_include) |
             complete!(parse_include_rules) |
             complete!(parse_letref_expr) |
             complete!(parse_let_expr) |
             complete!(parse_rule) |
             complete!(parse_ifelseendif) |
             complete!(parse_ifdef) |
             complete!(parse_macroassignment) |
             complete!(parse_error) |
             complete!(parse_export) |
             complete!(parse_run) |
             complete!(parse_preload) |
             complete!(parse_comment)
       )
);

// parse until the start of else block
named!(parse_statements_until_else<&[u8], (Vec<Statement>, &[u8])>,
       many_till!(parse_statement,
                  delimited!( opt!(ws1),
                  tag!("else"), opt!(ws1)) )
);

// parse until endif statement
named!(parse_statements_until_endif<&[u8], (Vec<Statement>, &[u8])>,
       many_till!(parse_statement,
                  delimited!(opt!(ws1),
                  tag!("endif"), opt!(ws1)) )
);
// parse statements till end of file
named!(pub parse_statements_until_eof<&[u8], Vec<Statement>>,
       many0!(parse_statement)
);

// parse equality condition (only the condition, not the statements that follow if)
named!(pub parse_eq<&[u8], EqCond>,
       do_parse!( opt!(ws1) >>
                   not_cond : alt!(tag!("ifeq") => { |_|  false } |
                                   tag!("ifneq") => { |_|  true } )  >>
                   opt!(ws1) >>
                   char!('(') >> opt!(ws1) >>
                   e1:  call!(parse_rvalgeneral_list_long, ",") >> opt!(ws1) >>
                   e2 : call!(parse_rvalgeneral_list_long, ")") >> opt!(ws1) >>
                   (EqCond{lhs: e1.0, rhs: e2.0, not_cond: not_cond})
       )
);

named!(parse_checked_var<&[u8], CheckedVar>,
       do_parse!( opt!(ws1) >>
                  negate : alt!(tag!("ifdef") => {|_| false} |
                                tag!("ifndef") => { |_| true } ) >>
                  opt!(ws1) >>
                  var : parse_lvalue >> opt!(ws1) >>
                  (CheckedVar(var, negate))
                  )
);

// parse if else endif block
named!(pub parse_ifelseendif<&[u8], Statement>,
       do_parse!( eqcond : call!(parse_eq) >>
                  opt!(ws1) >>
                  then_s : alt!(
                      complete!(do_parse!( t0 : parse_statements_until_else >>
                                  e : parse_statements_until_endif >> ((t0.0, e.0)) )) |
                      complete!(do_parse!( t : parse_statements_until_endif >>  (t.0, vec![])) )) >>
                  (Statement::IfElseEndIf{ eq : eqcond,
                                           then_statements: then_s.0 , else_statements :then_s.1
                  }) )
);

// parse if else endif block
named!(pub parse_ifdef<&[u8], Statement>,
       do_parse!(cvar: call!(parse_checked_var) >> opt!(ws1) >>
                  then_s : alt!(
                      complete!(do_parse!( t0 : parse_statements_until_else >>
                                 e : parse_statements_until_endif >> ((t0.0, e.0)) )) |
                      complete!(do_parse!( t : parse_statements_until_endif >>  (t.0, vec![])) )) >>
                  (Statement::IfDef{ checked_var : cvar,
                                     then_statements: then_s.0 , else_statements :then_s.1
                  }) )
);

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
