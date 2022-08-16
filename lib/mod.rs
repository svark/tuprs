#[macro_use]
extern crate nom;
#[macro_use]
extern crate lazy_static;
extern crate daggy;
extern crate nom_locate;
extern crate petgraph;
extern crate regex;
extern crate walkdir;

pub mod decode;
pub mod errors;
mod glob;
pub mod parser;
mod platform;
mod scriptloader;
pub mod statements;
pub mod transform;
extern crate bimap;
extern crate bstr;
extern crate log;
extern crate path_absolutize;
extern crate pathdiff;
extern crate rlua;
extern crate thiserror;

#[test]
fn test_op() {
    use statements::CleanupPaths;
    use statements::PathExpr;
    use statements::PathExpr::Sp1;
    use std::fs::File;
    use std::io::Write;
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
                  !CC %<grp> %<grp2> \\\n |> command.pch | ^exclude_pattern.* {objs}\
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
        let stmts = parser::parse_tupfile("tupdata1.txt").expect("failed to parse tupdata1.txt");
        use statements::PathExpr::{Bin, ExcludePattern, Group, Literal};
        use statements::{Link, RuleFormula, Source, Statement, Target};
        use transform::*;

        use std::path::Path;
        let tuppath = Path::new("./tupdata1.txt");
        let mut map = SubstMap {
            conf_map: load_conf_vars(tuppath).expect("conf var open error from tupdata1.txt"),
            ..SubstMap::default()
        };
        set_cwd(tuppath, &mut map);

        assert_eq!(
            map.conf_map.get("PLATFORM").and_then(|x| x.first()),
            Some(&"win64".to_owned())
        );
        assert_eq!(
            map.conf_map.get("CVAR").and_then(|x| x.first()),
            Some(&"1".to_owned())
        );

        let mut stmts_ = stmts.subst(&mut map).unwrap();
        stmts_.cleanup();
        assert_eq!(stmts_.len(), 3);
        let resolvedexpr = [
            Statement::Rule(Link {
                source: Source {
                    primary: vec![
                        PathExpr::from("*.cxx".to_string()),
                        Sp1,
                        PathExpr::from("impl/*.cxx".to_string()),
                        Sp1,
                        PathExpr::from("*.cpp".to_string()),
                        Sp1,
                        Group(
                            vec![Literal("../".to_string())],
                            vec![Literal("grp".to_string())],
                        ),
                        Sp1,
                        Group(
                            vec![Literal("../".to_string())],
                            vec![Literal("grp2".to_string())],
                        ),
                    ],
                    for_each: true,
                    secondary: vec![],
                },
                target: Target {
                    secondary: vec![Literal("command.pch".to_string())],
                    primary: vec![],
                    exclude_pattern: Some(ExcludePattern("exclude_pattern.*".to_string())),
                    group: None,
                    bin: Some(Bin("objs".to_string())),
                },
                rule_formula: RuleFormula {
                    description: vec![],
                    formula: vec![
                        Literal("cl".to_string()),
                        Sp1,
                        Literal("%f".to_string()),
                        Sp1,
                        Literal("/Fout:%o".to_string()),
                        Sp1,
                        Literal("%<grp>".to_string()),
                        Sp1,
                        Literal("%<grp2>".to_string()),
                    ],
                },
                pos: (3, 3),
            }),
            Statement::Rule(Link {
                source: Source {
                    primary: vec![Literal("./src/main.rs".to_string())],
                    for_each: false,
                    secondary: vec![],
                },
                target: Target {
                    primary: vec![],
                    secondary: vec![Literal("file.txt".to_string())],
                    exclude_pattern: None,
                    group: None,
                    bin: None,
                },
                rule_formula: RuleFormula {
                    description: vec![],
                    formula: vec![
                        Literal("type".to_string()),
                        Sp1,
                        Literal("%f".to_string()),
                        Sp1,
                        Literal(">".to_string()),
                        Sp1,
                        Literal("file.txt".to_string()),
                    ],
                    //formula: vec![Literal("type %f > file.txt ".to_string())],
                },
                pos: (6, 2),
            }),
            Statement::Rule(Link {
                source: Source {
                    primary: vec![],
                    for_each: false,
                    secondary: vec![],
                },
                target: Target {
                    primary: vec![],
                    secondary: vec![],
                    exclude_pattern: None,
                    group: None,
                    bin: None,
                },
                rule_formula: RuleFormula {
                    description: vec![],
                    formula: vec![
                        Literal("type".to_string()),
                        Sp1,
                        Literal("./src/main.rs".to_string()),
                    ],
                },
                pos: (8, 2),
            }),
        ];

        assert_eq!(stmts_[0].statement, resolvedexpr[0]);
        assert_eq!(stmts_[1].statement, resolvedexpr[1]);
        assert_eq!(stmts_[2].statement, resolvedexpr[2]);
    }
}

#[test]
fn test_parse() {
    use nom_locate::LocatedSpan;
    use statements::CleanupPaths;
    //use statements::PathExpr;
    use statements::LocatedStatement;
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
    let res64 = comment.unwrap().1.statement;
    assert_eq!(res64, Statement::Comment);
    let res65 = parser::parse_statement(Span::new(b"DEBUG = 1\n"))
        .unwrap()
        .1
        .statement;
    let res66 = parser::parse_statement(Span::new(b"SRCS= *.cxx\n"))
        .unwrap()
        .1
        .statement;
    let res67 = parser::parse_statement(Span::new(b"SRCS +=*.cpp\n"))
        .unwrap()
        .1
        .statement;
    let res68 = parser::parse_macroassignment(Span::new(b"!CC = |> cl %f /Fout:a.o |> \n"))
        .unwrap()
        .1
        .statement;
    let res7 = parser::parse_statement(Span::new(
        b"ifeq ($(DEBUG),1)\n: foreach $(SRCS) |>\
                                 !CC %<grp> %<grp2> |> command.pch |\
                                 %B.o ../<grp3>\nelse\nx+=eere\nendif\n",
    ))
    .unwrap()
    .1
    .statement;
    let loc = statements::Loc::new(0, 0);
    let stmts_raw = vec![res64, res65, res66, res67, res68, res7];
    let mut stmtsloc: Vec<_> = stmts_raw
        .into_iter()
        .map(|x| LocatedStatement::new(x, loc))
        .collect();
    use std::path::Path;
    stmtsloc.cleanup();

    let mut map = SubstMap::default();
    set_cwd(Path::new("."), &mut map);
    let stmts_ = stmtsloc
        .subst(&mut map)
        .expect("subst failure")
        .into_iter()
        .map(|x| x.statement)
        .collect::<Vec<_>>();
    assert_eq!(stmts_.len(), 1);
    let prog = vec![Statement::Rule(Link {
        source: Source {
            primary: vec![
                Literal("*.cxx".to_string()),
                Sp1,
                Literal("*.cpp".to_string()),
            ],
            for_each: true,
            secondary: vec![],
        },
        target: Target {
            secondary: vec![Literal("command.pch".to_string())],
            primary: vec![Literal("%B.o".to_string())],
            exclude_pattern: None,
            group: Some(Group(
                vec![Literal("../".to_string())],
                vec![Literal("grp3".to_string())],
            )),
            bin: None,
        },
        rule_formula: RuleFormula {
            description: Vec::new(),
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

    assert_eq!(stmts_[0], prog[0], "\r\nfound first but expected second");
    let rule = parser::parse_rule(Span::new(b":|> ^ touch %o^ touch %o |> out.txt\n"))
        .unwrap()
        .1
        .statement;
    use statements::PathExpr;
    // use statements::Link;
    assert_eq!(
        rule,
        Statement::Rule(Link {
            target: Target {
                primary: vec![PathExpr::from("out.txt".to_string())],
                ..Default::default()
            },
            rule_formula: RuleFormula {
                description: vec![PathExpr::from(" touch %o".to_string())],
                formula: vec![
                    Literal("touch".to_string()),
                    Sp1,
                    Literal("%o".to_string()),
                    Sp1
                ],
            },
            pos: (1, 2),
            ..Default::default()
        })
    );
    use decode::*;
    let taginfo = OutputTagInfo::new();
    use decode::ResolvePaths;
    use statements::Loc;
    let mut bo = BufferObjects::default();
    let tup_desc = bo.add_tup(Path::new("./Tupfile")).0;
    let decodedrule = LocatedStatement::new(rule, Loc::new(0, 0))
        .resolve_paths(Path::new("."), &taginfo, &mut bo, &tup_desc)
        .unwrap();
    use statements::Cat;
    if let Some(deglobbed_link) = decodedrule.0.first() {
        assert_eq!(
            deglobbed_link.rule_formula.formula.cat(),
            "touch out.txt ".to_string()
        );
        assert_eq!(
            deglobbed_link.rule_formula.description.cat(),
            " touch out.txt".to_string()
        );
    }
    let rule1 = parser::parse_rule(Span::new(b": file.txt |> type %f|>"))
        .unwrap()
        .1
        .statement;
    let mut file = std::fs::File::create("file.txt").expect("cannot open file");
    use std::io::Write;
    file.write_all("-".as_bytes()).expect("file write error");
    let decodedrule1 = LocatedStatement::new(rule1, Loc::new(0, 0))
        .resolve_paths(Path::new("."), &taginfo, &mut bo, &tup_desc)
        .unwrap();
    if let Some(deglobbed_link) = decodedrule1.0.first() {
        let rf = deglobbed_link.rule_formula.formula.cat();
        let mut rule_exp = String::new();
        rule_exp.push_str("type ");
        rule_exp.push_str("file.txt");
        assert_eq!(rf, rule_exp);
    }

    // assert_eq!(deglob(&prog[0]).len(), 18);
}
