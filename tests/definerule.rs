#[cfg(test)]
extern crate env_logger;
extern crate tupparser;

#[test]
fn parse_define_rule_basic() {
    let _ = env_logger::try_init();
    use std::fs;
    use std::io::Write;
    use tupparser::parser::testing::parse_tupfile;
    use tupparser::writer::convert_to_str;

    let mut tupdir = std::env::temp_dir();
    tupdir.push(format!("tuprs_test_{}_1", std::process::id()));
    let _ = fs::create_dir_all(&tupdir);
    let tupfile = tupdir.join("Tupfile");
    let mut f = fs::File::create(&tupfile).unwrap();
    write!(f, "define_rule out.txt : in.txt\n\techo hi > %o\nendef\n").unwrap();
    drop(f);
    let stmts = parse_tupfile(&tupfile).expect("parse error");
    let strings = convert_to_str(&stmts);
    assert_eq!(strings.len(), 1);
    assert_eq!(strings[0].trim(), ": in.txt |> echo hi > %o |> out.txt");
}

#[test]
fn parse_define_foreach_rule_basic() {
    let _ = env_logger::try_init();
    use std::fs;
    use std::io::Write;
    use tupparser::parser::testing::parse_tupfile;
    use tupparser::writer::convert_to_str;

    let mut tupdir = std::env::temp_dir();
    tupdir.push(format!("tuprs_test_{}_2", std::process::id()));
    let _ = fs::create_dir_all(&tupdir);
    let tupfile = tupdir.join("Tupfile");
    let mut f = fs::File::create(&tupfile).unwrap();
    write!(
        f,
        "define_foreach_rule foreach out%1.txt : in%1.txt\n\techo %f > %o\nendef\n"
    )
    .unwrap();
    drop(f);
    let stmts = parse_tupfile(&tupfile).expect("parse error");
    let strings = convert_to_str(&stmts);
    assert_eq!(strings.len(), 1);
    assert_eq!(
        strings[0].trim(),
        ":foreach  in%1.txt |> echo %f > %o |> out%1.txt"
    );
}
