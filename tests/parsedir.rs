//extern crate env_logger;
extern crate tupparser;

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use tupparser::decode::parse_dir;

    //use env_logger;

    #[test]
    pub fn test_parsedir() {
        //env_logger::init();
        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push("tests/tuptest");
        let (arts, rwbuffers) = parse_dir(d.as_path()).expect("failed to parse!");
        //let statements0 = statements[0].get_statements();
        // println!("{:?}", statements);
        let rlinks = arts.rules_by_tup();
        let mut outs = String::new();
        let strings = rlinks
            .iter()
            .map(|rl| rl.iter())
            .flatten()
            .map(|r| r.human_readable(rwbuffers.get()))
            .collect::<Vec<_>>();

        outs.pop();
        if log::log_enabled!(log::Level::Debug) {
            let mut f = std::fs::File::create("rlinks_new.base").unwrap();
            use std::io::Write;
            for s in strings.iter() {
                f.write_all(s.as_bytes()).unwrap();
                f.write_all(b"\n").unwrap();
            }
        }

        //log::warn!("{}", outs);
        insta::assert_json_snapshot!(strings);
    }

    #[test]
    fn test_script() {
        //env_logger::init();
        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push("tests/tupscripttest");
        let (arts, rwbuffers) = parse_dir(d.as_path()).expect("failed to parse!");
        let rlinks = arts.rules_by_tup();
        let mut outs = String::new();
        for rlinks in rlinks {
            for r in rlinks {
                outs.push_str(r.human_readable(rwbuffers.get()).as_str());
                outs.push('\n')
            }
        }
        outs.pop();
        //        log::warn!("{}", outs);

        let expected = {
            r#"ResolvedLink { primary_sources: [Deglob(MatchingPath { path_descriptor: a/in0.txt, path: NormalPath { inner: "a/in0.txt" }, glob_descriptor: None, captured_globs: [] })], secondary_sources: [], rule_formula_desc: cp -r in0.txt outs.txt, primary_targets: [a/outs.txt], secondary_targets: [], excluded_targets: [], group: Some(<mygrp>), bin: None, tup_loc: TupLoc { tup_path_desc: a/Tupfile.lua, loc: Loc { line: 15, col: 0, span: 0 } }, env: EnvDescriptor(0), search_dirs: [] }
ResolvedLink { primary_sources: [Deglob(MatchingPath { path_descriptor: b/in1.txt, path: NormalPath { inner: "b/in1.txt" }, glob_descriptor: None, captured_globs: [] })], secondary_sources: [GroupEntry(<mygrp>, a/outs.txt)], rule_formula_desc: cp -r in1.txt outs.txt, primary_targets: [b/outs.txt], secondary_targets: [], excluded_targets: [], group: None, bin: Some(b/mybin), tup_loc: TupLoc { tup_path_desc: b/Tupfile.lua, loc: Loc { line: 15, col: 0, span: 0 } }, env: EnvDescriptor(0), search_dirs: [] }"#
        };
        assert_eq!(outs, expected);
    }
}
