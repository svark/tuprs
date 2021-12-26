#[macro_use]
extern crate nom;
#[macro_use]
extern crate lazy_static;
extern crate capturing_glob as glob;
extern crate nom_locate;
extern crate regex;

pub mod decode;
pub mod parser;
mod platform;
pub mod statements;
pub mod transform;
//#[macro_use]
//extern crate thiserror;

#[test]
fn test_op() {
    use std::fs::File;
    use std::io::Write;
    use statements::StripTrailingWs;
    use statements::PathExpr::Sp1;
    {
        let mut file = File::create("tupdata0.txt").expect("cannot open file");
        let stmts = b"DEBUG =1\n\
                      ifdef CVAR\n\
                      PRVSRCS=impl/*.cxx\n\
                      endif\n\
                  SRCS=*.cxx $(PRVSRCS)\n\
                  #comment\n\
                  SRCS +=*.cpp\n\
                  !CC = |> cl %f /Fout:%o |> \n";
        file.write_all(stmts).expect("write failed");
        let stmts1 = b"include tupdata0.txt\n\
                       ifeq ($(DEBUG),1) \n \
                       :foreach $(SRCS)  ../<grp> ../<grp2> |> \
                  !CC %<grp> %<grp2> |> command.pch | ^exclude_pattern.* {objs}\
                  \n &v := src/main.rs\n\
                  :&(v) |> type %f > file.txt |> \\\nfile.txt |\n\
                  : |> type &(v) |> \n\
                  else\n  x+=eere #append\nendif\n";
        let mut file = File::create("tupdata1.txt").expect("cannot open file");
        file.write_all(stmts1).expect("write failed");

        let mut file = File::create("tup.config").expect("cannot open file");
        let stmts2 = b"CONFIG_PLATFORM=win64\nCONFIG_CVAR=1\n";
        file.write_all(stmts2).expect("write failed to config file");
    }
    {
        let stmts = parser::parse_tupfile("tupdata1.txt");
        use statements::PathExpr::{Bucket, Literal, Group, ExcludePattern};
        use statements::{Link, RuleFormula, Source, Statement, Target};
        use transform::*;

        use std::path::Path;
        let tuppath = Path::new("./tupdata1.txt");
        let mut map = SubstMap {
            conf_map: load_conf_vars(tuppath),
            ..SubstMap::default()
        };
        set_cwd(tuppath, &mut map);

        assert_eq!(map.conf_map.get("PLATFORM"), Some(&"win64".to_owned()));
        assert_eq!(map.conf_map.get("CVAR"), Some(&"1".to_owned()));

        let mut stmts_ = stmts.subst(&mut map);
        stmts_.strip_trailing_ws();
        assert_eq!(stmts_.len(), 3);
        let resolvedexpr = [
            Statement::Rule(Link {
                source: Source {
                    primary: vec![
                        Literal("*.cxx impl/*.cxx *.cpp".to_string()),
                        Sp1,
                        Group(vec![Literal("../".to_string())], vec![Literal("grp".to_string())]),
                        Sp1,
                        Group(vec![Literal("../".to_string())],vec![Literal("grp2".to_string())]),
                    ],
                    foreach: true,
                    secondary: vec![],
                },
                target: Target {
                    primary: vec![Literal("command.pch".to_string())],
                    secondary: vec![],
                    exclude_pattern: Some(ExcludePattern("exclude_pattern.*".to_string())),
                    group : None,
                    bin: Some( Bucket("objs".to_string()) ),
                },
                rule_formula: RuleFormula {
                    description: "".to_string(),
                    formula: vec![
                        Literal("cl".to_string()), Sp1, Literal("%f".to_string()), Sp1,
                        Literal("/Fout:%o".to_string()), Sp1, Literal("%<grp>".to_string()),
                        Sp1, Literal("%<grp2>".to_string())
                    ],
                },
                pos: (3, 3),
            }),
            Statement::Rule(Link {
                source: Source {
                    primary: vec![Literal("./src/main.rs".to_string())],
                    foreach: false,
                    secondary: vec![],
                },
                target: Target {
                    primary: vec![Literal("file.txt".to_string())],
                    secondary: vec![],
                    exclude_pattern: None,
                    group : None,
                    bin: None,
                },
                rule_formula: RuleFormula {
                    description: "".to_string(),
                    formula : vec![Literal("type".to_string()), Sp1, Literal("%f".to_string()), Sp1,
                    Literal(">".to_string()), Sp1, Literal("file.txt".to_string())],
                    //formula: vec![Literal("type %f > file.txt ".to_string())],
                },
                pos: (5, 2),
            }),
            Statement::Rule(Link {
                source: Source {
                    primary: vec![],
                    foreach: false,
                    secondary: vec![],
                },
                target: Target {
                    primary: vec![],
                    secondary: vec![],
                    exclude_pattern: None,
                    group: None,
                    bin : None,
                },
                rule_formula: RuleFormula {
                    description: "".to_string(),
                    formula: vec![
                        Literal("type".to_string()),
                        Sp1,
                        Literal("./src/main.rs".to_string()),
                    ],
                },
                pos: (7, 2),
            }),
        ];

        assert_eq!(stmts_[0], resolvedexpr[0]);
        assert_eq!(stmts_[1], resolvedexpr[1]);
        assert_eq!(stmts_[2], resolvedexpr[2]);
    }
}

#[test]
fn test_parse() {
    use nom_locate::LocatedSpan;
    use statements::StripTrailingWs;
    use statements::PathExpr::DollarExpr;
    use statements::PathExpr::Group;
    use statements::PathExpr::Literal;
    use statements::PathExpr::Sp1;
    use statements::{EqCond, Link, RuleFormula, Source, Statement, Target};
    use transform::*;
    type Span<'a> = LocatedSpan<&'a [u8]>;

    {
        let sp0 = Span::new(b" ifeq($(DEBUG), 20)\n");
        let res1 = parser::parse_eq(sp0);
        let prog1 = EqCond {
            lhs: vec![DollarExpr("DEBUG".to_string())],
            rhs: vec![Literal("20".to_string())],
            not_cond: false,
        };
        assert_eq!(res1.unwrap().1, prog1);
    }
    {
        let sp = Span::new(b" ifneq($(DEBUG), 20)\n");
        let res1 = parser::parse_eq(sp);
        let prog1 = EqCond {
            lhs: vec![DollarExpr("DEBUG".to_string())],
            rhs: vec![Literal("20".to_string())],
            not_cond: true,
        };
        assert_eq!(res1.unwrap().1, prog1);
    }

    let comment = parser::parse_statement(Span::new(b"#Source files\n"));
    let res64 = comment.unwrap().1;
    assert_eq!(res64, Statement::Comment);
    let res65 = parser::parse_statement(Span::new(b"DEBUG =1\n")).unwrap().1;
    let res66 = parser::parse_statement(Span::new(b"SRCS=*.cxx\n"))
        .unwrap()
        .1;
    let res67 = parser::parse_statement(Span::new(b"SRCS +=*.cpp\n"))
        .unwrap().1;
    let res68 = parser::parse_macroassignment(Span::new(b"!CC = |> cl %f /Fout:a.o |> \n"))
        .unwrap().1;
    let res7 = parser::parse_statement(Span::new(
        b"ifeq ($(DEBUG),1)\n: foreach $(SRCS) |>\
                                 !CC %<grp> %<grp2> |> command.pch |\
                                 %B.o ../<grp3>\nelse\nx+=eere\nendif\n",
    ))
    .unwrap()
    .1;
    let mut stmts = vec![res64, res65, res66, res67, res68, res7];
    use std::path::Path;
    stmts.strip_trailing_ws();

    let mut map = SubstMap::default();
    set_cwd(Path::new("."), &mut map);
    let stmts_ = stmts.subst(&mut map);
    assert_eq!(stmts_.len(), 1);
    let prog = vec![Statement::Rule(Link {
        source: Source {
            primary: vec![Literal("*.cxx *.cpp".to_string())],
            foreach: true,
            secondary: vec![],
        },
        target: Target {
            primary: vec![Literal("command.pch".to_string())],
            secondary: vec![Literal("%B.o".to_string())],
            exclude_pattern: None,
            group: Some( Group(vec![Literal("../".to_string())],  vec![Literal("grp3".to_string())])),
            bin : None
        },
        rule_formula: RuleFormula {
            description: "".to_string(),
            formula: vec![
                Literal("cl".to_string()),
                Sp1,
                Literal("%f".to_string()),
                Sp1, Literal("/Fout:a.o".to_string()), Sp1, Literal("%<grp>".to_string()), Sp1,
                Literal("%<grp2>".to_string())
                //Group(vec![Literal("%grp".to_string())]),
                //Group(vec![Literal("%grp2".to_string())]),
            ],
        },
        pos: (2, 2),
    })];

    assert_eq!(prog[0], stmts_[0]);
    // assert_eq!(deglob(&prog[0]).len(), 18);
}
