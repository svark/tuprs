#[macro_use]
extern crate nom;

named!(till_comma, take_till!(|ch| ch == b','));
named!(till_endbrace, take_until!(")\n"));

// rvalue is something that can appear on the right side of assignment statement
#[derive(Debug)]
enum RvalGeneral {
    Prefix(String), // a normal string
    DollarExpr(String), // this is dollar expr eg $(EXPR)
    AtExpr(String), // @(EXPR)
    Group(Vec<RvalGeneral>),
    Bucket(String),
}

#[derive(Debug)]
struct EqCond {
    lhs: Vec<RvalGeneral>,
    rhs: Vec<RvalGeneral>,
    not_cond : bool
}

#[derive(Debug)]
struct Ident {
    name: String,
}

fn to_lval(s: &str) -> Ident {
    Ident { name: s.to_owned() }
}

#[derive(Debug)]
struct Source {
    primary: Vec<RvalGeneral>,
    foreach: bool,
    secondary: Vec<RvalGeneral>,
}

#[derive(Debug)]
struct Target {
    primary: Vec<RvalGeneral>,
    secondary: Vec<RvalGeneral>,
    tag: Vec<RvalGeneral>,
}

#[derive(Debug)]
struct RuleFormula {
    description: String,
    formula: Vec<RvalGeneral>,
}


#[derive(Debug)]
enum Statement {
    LetExpr {
        left: Ident,
        right: Vec<RvalGeneral>,
        is_append: bool,
    },
    IfElseEndIf {
        eq: EqCond,
        then_statements: Vec<Statement>,
        else_statements: Vec<Statement>,
    },
    IncludeRules,
    Include(String),
    Link {
        s: Source,
        t: Target,
        r: RuleFormula,
    },
}

// convert byte str to RvalGeneral::Prefix
fn from_str(res: &[u8]) -> Result<RvalGeneral, std::str::Utf8Error> {
    match std::str::from_utf8(res) {
        Ok(s) => Ok(RvalGeneral::Prefix(s.to_owned())),
        Err(e) => Err(e),
    }
}

fn is_ident(c: u8) -> bool {
    nom::is_alphanumeric(c) || c == b'_'
}
// parse rvalue wrapped inside dollar or at
named!(parse_rvalue_raw,
       delimited!(alt!(tag!("$(") | tag!("@(")),
                  take_while!(is_ident),
                  tag!(")")));

named!(parse_rvalue_raw_bucket,
       delimited!(ws!(tag!("{")), take_while!(is_ident), tag!("}")));

named!(parse_rvalue_raw_angle<&[u8], Vec<RvalGeneral>>,
       do_parse!(tag!("<") >>
                 v: apply!(parse_rvalgeneral_list_long, ">") >>
                 tag!(">") >> (v.0))
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
named!(parse_rvalue_angle<&[u8], RvalGeneral>,
       do_parse!(
           rv : parse_rvalue_raw_angle >>
               (RvalGeneral::Group(rv))
       )
);
named!(parse_rvalue_bucket<&[u8], RvalGeneral>,
       do_parse!(
           rv : map_res!(parse_rvalue_raw_bucket, std::str::from_utf8) >>
               (RvalGeneral::Bucket(rv.to_owned()))
       )
);

named!(parse_rvalue<&[u8], RvalGeneral>,
       switch!(peek!(take!(1)),
           b"$" => call!(parse_rvalue_dollar) |
               b"@" => call!(parse_rvalue_at) |
               b"<" => call!(parse_rvalue_angle) |
               b"{" => call!(parse_rvalue_bucket)
       )
);

// eat up the dollar or at that dont parse to dollar expression or at expression
named!(chompdollar,
       do_parse!( peek!(one_of!("$@")) >> not!(parse_rvalue_raw) >> r : take!(1)  >> (r)));
// read  a rvalue until delimiter
// in addition, \\\n , $ and @ also pause the parsing
fn parse_greedy<'a, 'b>(input: &'a [u8],
                        delim: &'b str)
                        -> Result<(&'a [u8], &'a [u8]), nom::Err<&'a [u8]>> {
    let mut s = String::from("\\\n$@{<");
    s.push_str(delim);
    alt!(input,
         value!(b"".as_ref(), complete!(tag!("\\\n"))) | chompdollar |
         alt_complete!(take_until_either!(s.as_str()) | eof!()))
}
// parse either (dollar|at) expression or a general rvalue delimited by delim
fn parse_rvalgeneral<'a, 'b>(s: &'a [u8],
                             delim: &'b str)
                             -> Result<(&'a [u8], RvalGeneral), nom::Err<&'a [u8]>> {
    alt_complete!(s,
                  parse_rvalue | map_res!(apply!(parse_greedy, delim), from_str))
}
// repeatedly invoke the rvalue parser until eof or delim is encountered
fn parse_rvalgeneral_list_long<'a, 'b>
    (input: &'a [u8],
     delim: &'b str)
     -> Result<(&'a [u8], (Vec<RvalGeneral>, &'a [u8])), nom::Err<&'a [u8]>> {
    many_till!(input,
               apply!(parse_rvalgeneral, delim),
               alt!(tag!(delim) | eof!()))
}
// specialization of previos one delimited by eol
named!(parse_rvalgeneral_list<&[u8], (Vec<RvalGeneral>, &[u8]) >,
       apply!(parse_rvalgeneral_list_long, "\n") );

// parse a lvalue to a string
named!(parse_lvalue<&[u8], Ident>,
        do_parse!(  l : map_res!(take_while!(is_ident), std::str::from_utf8)>> (to_lval(l)) )
);

named!(parse_include<&[u8], Statement>,
       do_parse!(ws!(tag!("include")) >> s: map_res!(take_until!("\n"), std::str::from_utf8) >>
                 (Statement::Include(String::from(s)))
        )
);

named!(parse_include_rules<&[u8], Statement>,
       do_parse!(ws!(tag!("include_rules")) >> _s: map_res!(take_until!("\n"), std::str::from_utf8) >>
                 (Statement::IncludeRules)
       )
);

// parse an assignment expr
named!(parse_let_expr<&[u8], Statement>,
       do_parse!( l : ws!(parse_lvalue) >>
                  op : ws!(alt_complete!( tag!("=") | tag!(":=") | tag!("+=")  )) >>
                  r :  complete!(parse_rvalgeneral_list)  >>
                  (Statement::LetExpr{ left:l, right:r.0,
                               is_append: (op == b"+=") }) )
);

named!(parse_rule_gut<&[u8], RuleFormula>,
       do_parse!(
           description :
           ws!(opt!(do_parse!( tag!("^") >>
                               r: map_res!(take_until!("^"), std::str::from_utf8) >>
                               tag!("^") >> (String::from(r)) ) ) ) >>
               formula : apply!(parse_rvalgeneral_list_long, "|") >>
               (RuleFormula { description : description.unwrap_or(String::from("")), formula : formula.0}) )
);

fn from_input(primary: Vec<RvalGeneral>, foreach: bool, secondary: Vec<RvalGeneral>) -> Source {
    Source {
        primary: primary,
        foreach: foreach,
        secondary: secondary,
    }
}

fn from_output(primary: Vec<RvalGeneral>,
               secondary: Vec<RvalGeneral>,
               tag: Vec<RvalGeneral>)
               -> Target {
    Target {
        primary: primary,
        secondary: secondary,
        tag: tag,
    }
}
named!(parse_rule<&[u8], Statement>,
      do_parse!( ws!(tag!(":")) >>
                 for_each: opt!(ws!(tag!("foreach"))) >>
                 input : apply!(parse_rvalgeneral_list_long, "|") >>
                 secondary_input : opt!( do_parse!(tag!("|") >>  r : apply!(parse_rvalgeneral_list_long, "|") >> (r)) ) >>
                 tag!(">") >>
                 rule_formula : parse_rule_gut >>
                 ws!(tag!(">")) >>
                 secondary_output : opt!( do_parse!( r: apply!(parse_rvalgeneral_list_long, "|") >> (r)) ) >>
                 output : apply!(parse_rvalgeneral_list_long, "\n") >>
              //   opt!(eat_separator!(" \t")) >>
                 outputtag : opt!(parse_rvalgeneral_list) >>
                 (Statement::Link {
                     s : from_input(input.0, for_each.is_some(),
                                    secondary_input.unwrap_or((Vec::new(), b"")).0),
                     t : from_output(output.0, secondary_output.unwrap_or((Vec::new(), b"")).0, outputtag.unwrap_or((Vec::new(), b"")).0),
                     r : rule_formula
                     }
                 ))
);

named!(parse_statement<&[u8], Statement>,
       alt_complete!( parse_include |
                      parse_include_rules |
                      parse_let_expr |
                      parse_rule |
                      parse_ifelseendif
       )
);

named!(parse_statements_until_else<&[u8], (Vec<Statement>, &[u8])>,
       many_till!(parse_statement, tag!("else"))
);

named!(parse_statements_until_endif<&[u8], (Vec<Statement>, &[u8])>,
       many_till!(parse_statement, tag!("endif"))
);


// parse equality condition (only the condition, not the statements that follow if)
named!(parse_eq<&[u8], EqCond>,
       do_parse!(  not_cond : alt!(ws!(tag_s!("ifeq")) => { |_|  false } |
                                   ws!(tag_s!("ifneq")) => { |_|  true } )  >>
                   char!('(') >>
                   e1:  apply!(parse_rvalgeneral_list_long, ",") >>
                   e2 : apply!(parse_rvalgeneral_list_long, ")") >>
                   (EqCond{lhs: e1.0, rhs: e2.0, not_cond: not_cond})
       )
);

named!(parse_ifelseendif<&[u8], Statement>,
       do_parse!( eqcond : call!(parse_eq) >>
                  eat_separator!(" \t\n") >>
                  then_s : alt_complete!(do_parse!( t0 : parse_statements_until_else  >>  e : parse_statements_until_endif >> ((t0.0, e.0)) ) |
                                         do_parse!( t : parse_statements_until_endif >>  (t.0, vec![])) ) >>
                  (Statement::IfElseEndIf{ eq : eqcond,
                                           then_statements: then_s.0 , else_statements :then_s.1
                  }) )
);
fn main() {
    let res1 = parse_eq(b" ifeq($(HW_DEBUG),20)\nvar x=y");
    println!("res1: {:?}", res1);
    let res2 = parse_rvalue(b"$(HW_DEBUG)x");
    println!("{:?}\n", res2);
    let res3 = parse_rvalgeneral(b"help help$(HW_DEBUG)\n", "");
    let inp = b"geko $(help)\\\ngeko geko\\\ngg@(H),$(V) \n";
    let res4 = do_parse!(&inp,
                         r : apply!(parse_rvalgeneral_list_long, ",") >> (r));

    println!("r3: {:?}", res3);
    println!("r40{:?}", res4);
    let res4 = std::str::from_utf8(parse_greedy(b"a,$(h)_", ",").unwrap().1);

    println!("r4:{:?}", res4);
    let inp = b" SOURCES_  += sdsd$(HW_ROOTDIR).cxx \n".as_ref();
    let res41 = do_parse!(inp,
                          map_res!(ws!(take_while!(is_ident)), std::str::from_utf8)>>
                          alt_complete!(tag!("=") | tag!("+=")) >>
                          v : apply!(parse_rvalgeneral_list_long , "\n") >> (v) );
    println!("41: {:?}", res41);
    let res5 = parse_let_expr(b"SOURCES += $(HW_ROOTDIR)/*.cxx  \n");
    println!("{:?}", res5);
    let res6 = parse_rule(b": {objs} |> cl %i /Fout:%f |> command.pch |   %B.o {obj}\n");
    match res6 {
        Ok(something) => println!("{:?}", something),
        Err(nom::Err::Error(nom::Context::Code(x,_y))) => println!("{:?}", std::str::from_utf8(x).to_owned() ),
        _ => println!("unknown")
    }
    let res7 = parse_ifelseendif(b"ifeq($(HW_DEBUG),20)\nx=ysds\nelse\nx+=eere\nendif\n");
    match res7 {
        Ok(something) => println!("{:?}", something),
        Err(nom::Err::Error(nom::Context::Code(x,_y))) => println!("{:?}", std::str::from_utf8(x).to_owned()),
        _ => println!("unknown")
    }
}
