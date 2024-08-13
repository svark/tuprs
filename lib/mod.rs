//! Crate for parsing a tupfile and thereafter de-globbing and decoding variables in a Tupfile
#![warn(missing_docs)]
extern crate bstr;
extern crate crossbeam;
#[cfg(test)]
extern crate env_logger;
extern crate hashbrown;
#[macro_use]
extern crate lazy_static;
extern crate log;
extern crate mlua;
#[macro_use]
extern crate nom;
extern crate nom_locate;
extern crate parking_lot;
extern crate regex;
extern crate thiserror;
extern crate walkdir;

pub use buffers::BinDescriptor;
pub use buffers::GeneratedFiles;
pub use buffers::GroupPathDescriptor;
pub use buffers::PathSym;
pub use buffers::RuleDescriptor;
pub use buffers::TupPathDescriptor;
pub use decode::ResolvedLink;
pub use paths::InputResolvedType;
pub use transform::load_conf_vars_relative_to;
pub use transform::locate_file;
pub use transform::ReadWriteBufferObjects;
pub use transform::ResolvedRules;
pub use transform::TupParser;

pub mod buffers;
pub mod decode;
pub mod errors;
mod glob;
/// Parser for tupfiles
pub mod parser;
pub mod paths;
mod platform;
mod scriptloader;
pub mod statements;
pub mod transform;
pub mod writer;

pub mod intern;
#[test]
fn test_parse() {
    use crate::buffers::PathBuffers;
    use nom_locate::LocatedSpan;
    use statements::LocatedStatement;
    use transform::*;
    type Span<'a> = LocatedSpan<&'a [u8]>;
    use env_logger;
    let _ = env_logger::try_init();
    use decode::*;
    use statements::Loc;
    use std::path::Path;
    let mut bo = BufferObjects::new(Path::new("."));
    let mut dir_searcher = DirSearcher::new();
    let tup_desc = bo.add_tup(Path::new("./Tupfile"));
    let rule1 = parser::parse_rule(Span::new(b": file.txt |> type %f|>"))
        .unwrap()
        .1
        .statement;
    use crate::statements::*;
    let mut file = std::fs::File::create("file.txt").expect("cannot open file");
    use buffers::BufferObjects;
    use std::io::Write;
    file.write_all("-".as_bytes()).expect("file write error");
    let mut dir = DirSearcher::new();
    let (decodedrule1, _outs) = LocatedStatement::new(rule1, Loc::new(0, 0, 0))
        .resolve_paths(&tup_desc, &mut dir, &mut bo, &vec![])
        .unwrap();
    if let Some(deglobbed_link) = decodedrule1.get_resolved_links().first() {
        let rf = bo.get_rule(&deglobbed_link.get_rule_desc());
        let mut rule_exp = String::new();
        rule_exp.push_str("type file.txt");
        assert_eq!(rf.get_formula().cat(), rule_exp);
    }
    let mut d = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("tests/tuptest");

    // test
    let stmt = parser::parse_statement(Span::new(
        b"SOURCES := $(foreach suffix,*.cxx *.c, $(wildcard a/$(suffix)))\n",
    ))
    .unwrap()
    .1;
    let mut m = ParseState::new_at(d.join("Tupfile").as_path());
    use transform::Subst;
    let path_searcher = DirSearcher::new();
    let stmt = stmt.subst(&mut m, &path_searcher).expect("subst failure");
    let stmt2 = parser::parse_statement(Span::new(b"SOURCES := t1.cxx t2.c\n"))
        .unwrap()
        .1;
    let mut m = ParseState::default();

    let stmt2 = stmt2.subst(&mut m, &path_searcher).expect("subst falure");
    assert_eq!(stmt, stmt2);
    // assert_eq!(deglob(&prog[0]).len(), 18);

    let stmts = parser::parse_statements_until_eof(Span::new(
        b"CXX_FLAGS := -W3\nCXX_FLAGS \
         := $(subst -W3,-W4 -wd4100 -wd4324 -wd4127 -wd4244 -wd4505,$(CXX_FLAGS))\n",
    ))
    .expect("parse failure");
    let mut m = ParseState::new_at(Path::new("."));
    stmts.subst(&mut m, &path_searcher).expect("subst failure");
    assert_eq!(
        m.expr_map.get("CXX_FLAGS").unwrap().join(" "),
        "-W4 -wd4100 -wd4324 -wd4127 -wd4244 -wd4505"
    );

    let stmts = vec![
        parser::parse_statements_until_eof(Span::new(b"task{setup}:\n-echo hi\nendtask\n"))
            .unwrap()
            .first()
            .unwrap()
            .clone(),
        parser::parse_statements_until_eof(Span::new(
            b"task{process}: &task{setup}\n\techo processing...\nendtask\n",
        ))
        .unwrap()
        .first()
        .unwrap()
        .clone(),
    ];
    //use crate::transform::Subst;
    stmts.subst(&mut m, &path_searcher).expect("subst failure");
    let write_guard = m.path_buffers;
    stmts
        .resolve_paths(&tup_desc, &mut dir_searcher, write_guard.as_ref(), &vec![])
        .expect("resolve failure");
}

#[test]
fn parse_x() {
    /*  use env_logger;
    let _ = env_logger::try_init();
    let root = "c:/ws/nxtg/fb4/HmMshgNxtFeatTemp";
    std::env::set_current_dir(root).unwrap();
    let mut parser = TupParser::<crate::decode::DirSearcher>::try_new_from(root, crate::decode::DirSearcher::new()).unwrap();
    let arts = parser.parse("hwdesktop/batchmesh/Tupfile").map_err( |e| {
        eprintln!("{:?}", e.to_string());
        e
    }).unwrap();
    assert_eq!(arts.get_resolved_links().len(), 375); */
}
