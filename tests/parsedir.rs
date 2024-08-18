#[cfg(test)]
extern crate env_logger;
extern crate tupparser;

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use env_logger;

    use tupparser::decode::parse_dir;
    use tupparser::statements::LocatedStatement;
    use tupparser::transform::load_conf_vars;
    use tupparser::writer::convert_to_str;

    #[test]
    pub fn test_parsedir() {
        let _ = env_logger::try_init();
        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push("tests/tuptest");
        let (arts, _rwbuffers) = parse_dir(d.as_path()).expect("failed to parse!");
        let rlinks = arts.rules_by_tup();
        let mut outs = String::new();
        let mut strings = rlinks
            .iter()
            .map(|rl| rl.iter())
            .flatten()
            .collect::<Vec<_>>();

        strings.sort_by(|a, b| a.cmp(b));
        let strings = strings
            .iter()
            .map(|r| r.human_readable())
            .collect::<Vec<_>>();
        outs.pop();

        insta::with_settings!({filters => vec![(r"env: Descriptor\(([^=]+)=((?:[^()]*\([^()]*\))*[^()]*)\)",r"env: Descriptor($1)")]},
            {insta::assert_json_snapshot!(strings);}
        );
    }

    #[test]
    fn test_script() {
        let _ = env_logger::try_init();
        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push("tests/tupscripttest");
        let (arts, _rwbuffers) = parse_dir(d.as_path()).expect("failed to parse!");
        let rlinks = arts.rules_by_tup();
        let mut outs = Vec::new();
        for rlinks in rlinks {
            for r in rlinks {
                outs.push(r.human_readable());
            }
        }
        insta::with_settings!({filters => vec![(r"env: Descriptor\(([^=]+)=((?:[^()]*\([^()]*\))*[^()]*)\)",r"env: Descriptor($1)")]}, {
            if cfg!(target_os = "windows") {
                insta::assert_json_snapshot!("windows_script", outs);
            } else {
                insta::assert_json_snapshot!("linux_script", outs);
            }
        });
    }

    #[cfg(test)]
    fn parse_pathexprs(i: i32) -> Vec<LocatedStatement> {
        let _ = env_logger::try_init();
        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push("tests/pathexpr");
        let statements = tupparser::parser::testing::parse_tupfile(d.join(format!("Tupfile{}", i)))
            .expect("failed to parse!");
        statements
    }

    #[test]
    fn parse_pathexprs0() {
        let _ = env_logger::try_init();
        let statements = parse_pathexprs(0);
        let strings = convert_to_str(&statements);
        insta::assert_json_snapshot!(strings);

        let (stmts, v2) = tupparser::transform::testing::subst_statements(
            std::path::Path::new("Tupfile0"),
            statements,
        )
        .unwrap();
        assert_eq!(stmts.len(), 0);
        insta::assert_snapshot!(v2.get("O").unwrap().join(" "));
        insta::assert_snapshot!(v2.get("SOURCES").unwrap().join(" "));
        insta::assert_snapshot!(v2.get("CXX_SOURCES").unwrap().join(" "));
        insta::assert_snapshot!(v2.get("GEN_FILES").unwrap().join(" "));
        insta::assert_snapshot!(v2.get("FILES_JOINED").unwrap().join(" "));
        insta::assert_snapshot!(v2.get("FILES_JOINED_STRIPPED").unwrap().join(" "));
        insta::assert_snapshot!(v2.get("OBJS").unwrap().join(" "));
    }

    #[test]
    fn parse_pathexprs1() {
        let _ = env_logger::try_init();
        let statements = parse_pathexprs(1);
        let strings = convert_to_str(&statements);
        insta::assert_json_snapshot!(strings);
        let (_s, v2) = tupparser::transform::testing::subst_statements(
            std::path::Path::new("Tupfile2"),
            statements,
        )
        .unwrap();
        assert_eq!(v2.get("F").is_none(), true);
        insta::assert_snapshot!(v2.get("TARGET_CPU_IS_X86").unwrap().join(" "));
    }

    #[test]
    fn parse_pathexprs2() {
        let _ = env_logger::try_init();
        let statements = parse_pathexprs(2);
        let strings = convert_to_str(&statements);
        insta::assert_json_snapshot!(strings);

        let (_s, v2) = tupparser::transform::testing::subst_statements(
            std::path::Path::new("Tupfile2"),
            statements,
        )
        .unwrap();
        //assert_eq!(stmts.len(), 0);
        insta::assert_snapshot!(v2.get("CFLAGS").unwrap().join(" "));
        insta::assert_json_snapshot!(v2.get_func("D").unwrap());
        insta::assert_json_snapshot!(v2.get("E").unwrap());
    }

    #[test]
    fn parse_pathexprs3() {
        let _ = env_logger::try_init();
        let statements = parse_pathexprs(3);
        let strings = convert_to_str(&statements);
        insta::assert_json_snapshot!(strings);

        let (stmts, v2) = tupparser::transform::testing::subst_statements(
            std::path::Path::new("Tupfile3"),
            statements,
        )
        .unwrap();
        assert_eq!(stmts.len(), 0);
        insta::assert_snapshot!(v2.get("CXX_FLAGS").unwrap().join(" "));
    }

    #[test]
    fn parse_pathexprs4() {
        let _ = env_logger::try_init();
        let stmts = parse_pathexprs(4);
        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push("tests/pathexpr");

        let tupconf = d.join("Tupfile4.config");
        let conf_map = load_conf_vars(tupconf).expect("conf var open error from tupdata1.txt");
        assert_eq!(
            conf_map.get("PLATFORM").and_then(|x| x.first()),
            Some(&"win64".to_owned())
        );
        assert_eq!(
            conf_map.get("CVAR").and_then(|x| x.first()),
            Some(&"1".to_owned())
        );

        let (stmts_, _) = tupparser::transform::testing::subst_statements_with_conf(
            &*std::path::Path::join(&*d, "Tupfile4"),
            stmts,
            conf_map,
        )
        .expect("subst_statements_with_conf error");
        //assert_eq!(stmts_.len(), 3);
        let strings = convert_to_str(&stmts_);
        insta::assert_json_snapshot!(strings);
    }
}
