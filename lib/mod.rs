#[macro_use]
extern crate nom;
extern crate capturing_glob as glob;
pub mod parser;
mod platform;
pub mod statements;
pub mod transform;

#[test]
fn test_op() {
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
                  !CC = |> cl %i /Fout:%f |> \n";
        file.write_all(stmts).expect("write failed");
        let stmts1 = b"include tupdata0.txt\n\
                       ifeq ($(DEBUG),1) #comment\n \
                       : $(SRCS)|> \
                  !CC <%grp> <%grp2> |> command.pch |\
                  @(PLATFORM)/%B.o <grp>\n &v := src/main.rs\n\
                  :&(v) |> echo %f |> \n\
                  else\n  x+=eere #append\nendif\n";
        let mut file = File::create("tupdata1.txt").expect("cannot open file");
        file.write_all(stmts1).expect("write failed");

        let mut file = File::create("tup.config").expect("cannot open file");
        let stmts2 = b"CONFIG_PLATFORM=win64\nCONFIG_CVAR=1\n";
        file.write_all(stmts2).expect("write failed to config file");
    }
    {
        let stmts = parser::parse_tupfile("tupdata1.txt");
        use statements::RvalGeneral::Group;
        use statements::RvalGeneral::Literal;
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

        let stmts_ = stmts.subst(&mut map);
        let resolvedexpr = [
            Statement::Rule(Link {
                s: Source {
                    primary: vec![Literal("*.cxx impl/*.cxx *.cpp".to_string())],
                    foreach: false,
                    secondary: vec![],
                },
                t: Target {
                    primary: vec![
                        Literal("win64".to_string()),
                        Literal("/%B.o ".to_string()),
                        Group(vec![Literal("grp".to_string())]),
                    ],
                    secondary: vec![Literal("command.pch ".to_string())],
                    tag: vec![],
                },
                r: RuleFormula {
                    description: "".to_string(),
                    formula: vec![
                        Literal("cl %i /Fout:%f ".to_string()),
                        Group(vec![Literal("%grp".to_string())]),
                        Group(vec![Literal("%grp2".to_string())]),
                    ],
                },
            }),
            Statement::Rule(Link {
                s: Source {
                    primary: vec![Literal("./src/main.rs".to_string())],
                    foreach: false,
                    secondary: vec![],
                },
                t: Target {
                    primary: vec![Literal("else".to_string())],
                    secondary: vec![],
                    tag: vec![],
                },
                r: RuleFormula {
                    description: "".to_string(),
                    formula: vec![Literal("echo %f ".to_string())],
                },
            }),
        ];

        assert_eq!(stmts_[0], resolvedexpr[0]);
        assert_eq!(stmts_[1], resolvedexpr[1]);
    }
}

#[test]
fn test_parse() {
    use statements::RvalGeneral::DollarExpr;
    use statements::RvalGeneral::Group;
    use statements::RvalGeneral::Literal;
    use statements::{EqCond, Link, RuleFormula, Source, Statement, Target};
    use transform::*;

    let res1 = parser::parse_eq(b" ifeq($(DEBUG),20)\n");
    let prog1 = EqCond {
        lhs: vec![DollarExpr("DEBUG".to_string())],
        rhs: vec![Literal("20".to_string())],
        not_cond: false,
    };
    assert_eq!(res1.unwrap().1, prog1);
    let res1 = parser::parse_eq(b" ifneq($(DEBUG),20)\n");
    let prog1 = EqCond {
        lhs: vec![DollarExpr("DEBUG".to_string())],
        rhs: vec![Literal("20".to_string())],
        not_cond: true,
    };
    assert_eq!(res1.unwrap().1, prog1);

    let res64 = parser::parse_statement(b"#Source files\n").unwrap().1;
    assert_eq!(res64, Statement::Comment("Source files".to_owned()));
    let res65 = parser::parse_statement(b"DEBUG =1\n").unwrap().1;
    let res66 = parser::parse_statement(b"SRCS=*.cxx\n").unwrap().1;
    let res67 = parser::parse_statement(b"SRCS +=*.cpp\n").unwrap().1;
    let res68 = parser::parse_macroassignment(b"!CC = |> cl %i /Fout:%f |> \n")
        .unwrap()
        .1;
    let res7 = parser::parse_statement(
        b"ifeq ($(DEBUG),1)\n: foreach $(SRCS) |>\
                                 !CC <%grp> <%grp2> |> command.pch |\
                                 %B.o <grp>\nelse\nx+=eere\nendif\n",
    )
    .unwrap()
    .1;
    let stmts = vec![res64, res65, res66, res67, res68, res7];
    use std::path::Path;
    let mut map = SubstMap::default();
    set_cwd(Path::new("."), &mut map);
    let stmts_ = stmts.subst(&mut map);
    let prog = vec![Statement::Rule(Link {
        s: Source {
            primary: vec![Literal("*.cxx *.cpp".to_string())],
            foreach: true,
            secondary: vec![],
        },
        t: Target {
            primary: vec![
                Literal("%B.o ".to_string()),
                Group(vec![Literal("grp".to_string())]),
            ],
            secondary: vec![Literal("command.pch ".to_string())],
            tag: vec![],
        },
        r: RuleFormula {
            description: "".to_string(),
            formula: vec![
                Literal("cl %i /Fout:%f ".to_string()),
                Group(vec![Literal("%grp".to_string())]),
                Group(vec![Literal("%grp2".to_string())]),
            ],
        },
    })];

    assert_eq!(prog, stmts_);

    // assert_eq!(deglob(&prog[0]).len(), 18);
}
