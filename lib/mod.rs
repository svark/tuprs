#[macro_use]
extern crate nom;
pub mod statements;
pub mod parser;
pub mod transform;

#[test]
fn test_op() {
    use std::fs::File;
    use std::io::Write;
    {
        let mut file = File::create("tupdata0.txt").expect("cannot open file");
        let stmts = b"DEBUG =1\n\
                  SRCS=*.cxx\n\
                  #comment\n\
                  SRCS +=*.cpp\n\
                  !CC = |> cl %i /Fout:%f |> \n";
        file.write_all(stmts).expect("write failed");
        let stmts1 = b"include tupdata0.txt\n\
                       ifeq ($(DEBUG),1) #comment\n \
                       : $(SRCS)|> \
                  !CC <%grp> <%grp2> |> command.pch |\
                  @(PLATFORM)/%B.o <grp>\nelse\n  x+=eere #append\nendif\n";
        let mut file = File::create("tupdata1.txt").expect("cannot open file");
        file.write_all(stmts1).expect("write failed");

        let mut file = File::create("tup.config").expect("cannot open file");
        let stmts2 = b"PLATFORM=win64\n";
        file.write_all(stmts2).expect("write failed to config file");
    }
    {
        let stmts = parser::parse_tupfile("tupdata1.txt");
        use std::collections::HashMap;
        use statements::RvalGeneral::Literal;
        use statements::RvalGeneral::Group;
        use transform::*;
        use statements::{Statement, Source, Target, Link, RuleFormula};

       let mut map = SubstMap {
           expr_map: HashMap::new(),
           conf_map: load_conf_vars("tupdata1.txt"),
           rule_map: HashMap::new(),
           cur_file : std::path::Path::new("tupdata1.txt").canonicalize().unwrap()
       };

        assert_eq!(map.conf_map.get("PLATFORM"), Some(&"win64".to_owned()));

        let stmts_ = stmts.subst(&mut map);
        let resolvedexpr = [Statement::Rule(Link {
                                s: Source {
                                    primary: vec![Literal("*.cxx *.cpp".to_string())],
                                    foreach: false,
                                    secondary: vec![],
                                },
                                t: Target {
                                    primary: vec![Literal("win64".to_string()), Literal("/%B.o ".to_string()),
                                                  Group(vec![Literal("grp".to_string())]),
                                              Literal(" ".to_string())],
                                    secondary: vec![Literal("command.pch ".to_string())],
                                    tag: vec![],
                                },
                                r: RuleFormula {
                                    description: "".to_string(),
                                    formula: vec![Literal("cl %i /Fout:%f ".to_string()),
                                              Literal(" ".to_string()),
                                              Group(vec![Literal("%grp".to_string())]),
                                              Literal(" ".to_string()),
                                              Group(vec![Literal("%grp2".to_string())]),
                                              Literal(" ".to_string())],
                                },
        })];
        assert_eq!(resolvedexpr[0], stmts_[0]);
    }
}

#[test]
fn test_parse() {

    use statements::RvalGeneral::DollarExpr;
    use statements::RvalGeneral::Literal;
    use statements::RvalGeneral::Group;
    use transform::*;
    use statements::{Statement, Source, Target, Link, RuleFormula, EqCond};

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
    let res68 = parser::parse_macroassignment(b"!CC = |> cl %i /Fout:%f |> \n").unwrap().1;
    let res7 = parser::parse_statement(b"ifeq ($(DEBUG),1)\n: $(SRCS) |>\
                                 !CC <%grp> <%grp2> |> command.pch |\
                                 %B.o <grp>\nelse\nx+=eere\nendif\n")
                   .unwrap()
                   .1;
    let stmts = vec![res64, res65, res66, res67, res68, res7];
    use std::collections::HashMap;

    let cm: HashMap<String, String> = HashMap::new();
    let em: HashMap<String, String> = HashMap::new();
    let rm: HashMap<String, Link> = HashMap::new();
    let mut map = SubstMap {
        expr_map: em,
        conf_map: cm,
        rule_map: rm,
        cur_file : std::path::Path::new(".").canonicalize().unwrap(),
    };
    let stmts_ = stmts.subst(&mut map);
    let prog = vec![Statement::Rule(Link {
                        s: Source {
                            primary: vec![Literal("*.cxx *.cpp".to_string()),
                                          Literal(" ".to_string())],
                            foreach: false,
                            secondary: vec![],
                        },
                        t: Target {
                            primary: vec![Literal("%B.o ".to_string()),
                                          Group(vec![Literal("grp".to_string())]),
                                          Literal(" ".to_string())],
                            secondary: vec![Literal("command.pch ".to_string())],
                            tag: vec![],
                        },
                        r: RuleFormula {
                            description: "".to_string(),
                            formula: vec![Literal("cl %i /Fout:%f ".to_string()),
                                          Literal(" ".to_string()),
                                          Group(vec![Literal("%grp".to_string())]),
                                          Literal(" ".to_string()),
                                          Group(vec![Literal("%grp2".to_string())]),
                                          Literal(" ".to_string())],
                        },
                    })];

    assert_eq!(prog, stmts_);
}
