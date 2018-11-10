#[macro_use]
extern crate nom;

named!(till_comma, take_till!(|ch| ch == b','));
named!(till_endbrace, take_until!(")\n"));


#[derive(Debug)]
enum RvalGeneral {
    Prefix(String),
    DollarExpr(String),
    AtExpr(String),
}
#[derive(Debug)]
struct IfEq {
    lhs: Vec<RvalGeneral>,
    rhs: Vec<RvalGeneral>,
}

fn from_str(res: &[u8]) -> Result<RvalGeneral, std::str::Utf8Error> {
    match std::str::from_utf8(res) {
        Ok(s) => Ok(RvalGeneral::Prefix(s.to_owned())),
        Err(e) => Err(e),
    }
}
fn is_ident(c: u8) -> bool {
    nom::is_alphanumeric(c) || c == b'_'
}


named!(parse_rvalue_raw,
       delimited!(alt!(tag!("$(") | tag!("@(")), take_while!(is_ident), tag!(")")));
named!(parse_rvalue_at<&[u8], RvalGeneral>,
   do_parse!(
       rv : map_res!(parse_rvalue_raw, std::str::from_utf8) >>
       (RvalGeneral::AtExpr(rv.to_owned()))
   )
);
named!(parse_rvalue_dollar<&[u8], RvalGeneral>,
   do_parse!(
       rv : map_res!(parse_rvalue_raw, std::str::from_utf8) >>
       (RvalGeneral::DollarExpr(rv.to_owned()))
   )
);
named!(parse_rvalue<&[u8], RvalGeneral>,
       switch!(peek!(take!(1)),
           b"$" => call!(parse_rvalue_dollar) |
           b"@" => call!(parse_rvalue_at)
       )
);

named!(chompdollar,
       do_parse!( peek!(one_of!("$@")) >> not!(parse_rvalue_raw) >> r : take!(1)  >> (r)));

fn parse_greedy<'a, 'b>(input: &'a [u8],
                        delim: &'b str)
                        -> Result<(&'a [u8], &'a [u8]), nom::Err<&'a [u8]>> {
    let mut s = String::from("\\\n$@");
    s.push_str(delim);
    alt!(input,
         value!(b"".as_ref(), complete!(tag!("\\\n"))) | chompdollar |
         alt_complete!(take_until_either!(s.as_str()) | eof!()))
}

fn parse_rvalgeneral<'a, 'b>(s: &'a [u8],
                             delim: &'b str)
                             -> Result<(&'a [u8], RvalGeneral), nom::Err<&'a [u8]>> {
    alt_complete!(s,
                  parse_rvalue | map_res!(apply!(parse_greedy, delim), from_str))
}

fn parse_rvalgeneral_list_long<'a, 'b>
    (input: &'a [u8],
     delim: &'b str)
     -> Result<(&'a [u8], (Vec<RvalGeneral>, &'a [u8])), nom::Err<&'a [u8]>> {
    many_till!(input,
               apply!(parse_rvalgeneral, delim),
               alt!(tag!(delim) | eof!())  )
}

#[derive(Debug)]
struct Ident {
    name: String,
}

fn to_lval(s: &str) -> Ident {
    Ident { name: s.to_owned() }
}

named!(parse_rvalgeneral_list<&[u8], (Vec<RvalGeneral>, &[u8]) >,
       apply!(parse_rvalgeneral_list_long, "\n") );

named!(parse_lvalue<&[u8], Ident>,
        do_parse!(  l : map_res!(take_while!(is_ident), std::str::from_utf8)>> (to_lval(l)) )
       );

#[derive(Debug)]
struct Assignment {
    left: Ident,
    right: Vec<RvalGeneral>,
    is_append: bool,
}


named!(parse_let_expr<&[u8], Assignment>,
       do_parse!( l : ws!(parse_lvalue) >>
                  op : ws!(alt_complete!( tag!("=") | tag!("+=")  )) >>
                  r :  complete!(parse_rvalgeneral_list)  >>
                  (Assignment{ left:l, right:r.0,
                               is_append: (op == b"+=") }) )
);

fn parse_it(s: &[u8]) {
    let res2 = do_parse!(s,
         ws!(tag_s!("ifeq")) >>
         char!('(') >>
         e1:  apply!(parse_rvalgeneral_list_long, ",") >>
         e2 : apply!(parse_rvalgeneral_list_long, ")") >>
          (IfEq{lhs: e1.0, rhs: e2.0})
         );
    println!("statement {:?}", res2);
}

fn main() {
    parse_it(b" ifeq($(HW_DEBUG),20)\nvar x=y");
    let res2 = parse_rvalue(b"$(HW_DEBUG)x");
    println!("{:?}\n",  res2);
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

}
