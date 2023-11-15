extern crate env_logger;
extern crate tupparser;

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use env_logger;

    use tupparser::decode::parse_dir;

    #[test]
    pub fn test_parsedir() {
        env_logger::init();
        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push("tests/tuptest");
        let (arts, rwbuffers) = parse_dir(d.as_path()).expect("failed to parse!");
        //let statements0 = statements[0].get_statements();
        // println!("{:?}", statements);
        let rlinks = arts.rules_by_tup();
        let mut outs = String::new();
        for rlinks in rlinks {
            for r in rlinks {
                outs.push_str(r.human_readable(rwbuffers.get()).as_str());
                outs.push('\n')
            }
        }
        outs.pop();

        let expected = if cfg!(windows) {
            include_str!("rlinks.base")
        } else {
            include_str!("rlinks.base")
            //"ResolvedLink { primary_sources: [Deglob(MatchingPath { path_descriptor: b/in1.txt, path: NormalPath { inner: \"b/in1.txt\" }, glob_descriptor: Some(b/in*.txt), captured_globs: [\"1\"] })], secondary_sources: [], rule_formula_desc: echo in1.txt > outecho.txt, primary_targets: [b/outecho.txt], secondary_targets: [], excluded_targets: [], group: None, bin: None, rule_ref: TupLoc { tup_path_desc: b/Tupfile, loc: Loc { line: 3, col: 1, span: 235 } }, env: EnvDescriptor(0) }\nResolvedLink { primary_sources: [Deglob(MatchingPath { path_descriptor: b/in1.txt, path: NormalPath { inner: \"b/in1.txt\" }, glob_descriptor: None, captured_globs: [] })], secondary_sources: [], rule_formula_desc: cat in1.txt & cp in1.txt out0.txt, primary_targets: [b/out0.txt], secondary_targets: [], excluded_targets: [b/^.*FltMgrMsg], group: Some(<output0>), bin: None, rule_ref: TupLoc { tup_path_desc: b/Tupfile, loc: Loc { line: 5, col: 1, span: 192 } }, env: EnvDescriptor(0) }\nResolvedLink { primary_sources: [GroupEntry(<output2>, a/out2.txt)], secondary_sources: [], rule_formula_desc: cp %<output2> out3.txt, primary_targets: [b/out3.txt], secondary_targets: [], excluded_targets: [b/^.*FltMgrMsg], group: None, bin: None, rule_ref: TupLoc { tup_path_desc: b/Tupfile, loc: Loc { line: 6, col: 1, span: 123 } }, env: EnvDescriptor(0) }\nResolvedLink { primary_sources: [Deglob(MatchingPath { path_descriptor: b/b2/ib2.txt, path: NormalPath { inner: \"b/b2/ib2.txt\" }, glob_descriptor: Some(b/**/ib*.txt), captured_globs: [\"/b2/\", \"2\"] })], secondary_sources: [], rule_formula_desc: cp b2/ib2.txt out/b2/o2.txt, primary_targets: [b/out/b2/o2.txt], secondary_targets: [], excluded_targets: [], group: None, bin: None, rule_ref: TupLoc { tup_path_desc: b/Tupfile, loc: Loc { line: 7, col: 1, span: 50 } }, env: EnvDescriptor(0) }\nResolvedLink { primary_sources: [Deglob(MatchingPath { path_descriptor: b/b1/ib1.txt, path: NormalPath { inner: \"b/b1/ib1.txt\" }, glob_descriptor: Some(b/**/ib*.txt), captured_globs: [\"/b1/\", \"1\"] })], secondary_sources: [], rule_formula_desc: cp b1/ib1.txt out/b1/o1.txt, primary_targets: [b/out/b1/o1.txt], secondary_targets: [], excluded_targets: [], group: None, bin: None, rule_ref: TupLoc { tup_path_desc: b/Tupfile, loc: Loc { line: 7, col: 1, span: 50 } }, env: EnvDescriptor(0) }\nResolvedLink { primary_sources: [GroupEntry(<output0>, b/out0.txt)], secondary_sources: [], rule_formula_desc: cp %<output0> out1.txt, primary_targets: [a/out1.txt], secondary_targets: [], excluded_targets: [a/^.*FltMgrMsg], group: None, bin: None, rule_ref: TupLoc { tup_path_desc: a/Tupfile, loc: Loc { line: 2, col: 1, span: 367 } }, env: EnvDescriptor(0) }\nResolvedLink { primary_sources: [], secondary_sources: [GroupEntry(<output2>, a/out2.txt)], rule_formula_desc: touch out7.txt, primary_targets: [a/out7.txt], secondary_targets: [], excluded_targets: [], group: None, bin: Some(a/o7), rule_ref: TupLoc { tup_path_desc: a/Tupfile, loc: Loc { line: 3, col: 1, span: 306 } }, env: EnvDescriptor(0) }\nResolvedLink { primary_sources: [Deglob(MatchingPath { path_descriptor: a/in0.txt, path: NormalPath { inner: \"a/in0.txt\" }, glob_descriptor: None, captured_globs: [] })], secondary_sources: [], rule_formula_desc: cp in0.txt out2.txt, primary_targets: [a/out2.txt], secondary_targets: [], excluded_targets: [a/^.*FltMgrMsg], group: Some(<output2>), bin: None, rule_ref: TupLoc { tup_path_desc: a/Tupfile, loc: Loc { line: 6, col: 1, span: 238 } }, env: EnvDescriptor(0) }\nResolvedLink { primary_sources: [Deglob(MatchingPath { path_descriptor: a/out1.txt, path: NormalPath { inner: \"a/out1.txt\" }, glob_descriptor: Some(a/out[12].txt), captured_globs: [\"1\"] })], secondary_sources: [], rule_formula_desc: cp out1.txt out13.txt, primary_targets: [a/out13.txt], secondary_targets: [], excluded_targets: [], group: None, bin: None, rule_ref: TupLoc { tup_path_desc: a/Tupfile, loc: Loc { line: 8, col: 1, span: 181 } }, env: EnvDescriptor(0) }\nResolvedLink { primary_sources: [Deglob(MatchingPath { path_descriptor: a/out2.txt, path: NormalPath { inner: \"a/out2.txt\" }, glob_descriptor: Some(a/out[12].txt), captured_globs: [\"2\"] })], secondary_sources: [], rule_formula_desc: cp out2.txt out23.txt, primary_targets: [a/out23.txt], secondary_targets: [], excluded_targets: [], group: None, bin: None, rule_ref: TupLoc { tup_path_desc: a/Tupfile, loc: Loc { line: 8, col: 1, span: 181 } }, env: EnvDescriptor(0) }\nResolvedLink { primary_sources: [BinEntry(a/o7, a/out7.txt)], secondary_sources: [], rule_formula_desc: cp out7.txt outout7.txt, primary_targets: [a/outout7.txt], secondary_targets: [], excluded_targets: [a/^.*FltMgrMsg], group: None, bin: None, rule_ref: TupLoc { tup_path_desc: a/Tupfile, loc: Loc { line: 10, col: 1, span: 140 } }, env: EnvDescriptor(0) }\nResolvedLink { primary_sources: [Deglob(MatchingPath { path_descriptor: a/out2.txt, path: NormalPath { inner: \"a/out2.txt\" }, glob_descriptor: None, captured_globs: [] })], secondary_sources: [], rule_formula_desc: cp out2.txt outout2.txt, primary_targets: [a/outout2.txt], secondary_targets: [], excluded_targets: [a/^.*FltMgrMsg], group: None, bin: None, rule_ref: TupLoc { tup_path_desc: a/Tupfile, loc: Loc { line: 10, col: 1, span: 140 } }, env: EnvDescriptor(0) }\nResolvedLink { primary_sources: [Deglob(MatchingPath { path_descriptor: a/patches.txt, path: NormalPath { inner: \"a/patches.txt\" }, glob_descriptor: None, captured_globs: [] })], secondary_sources: [], rule_formula_desc: echo patches.txt > outpatches.txt.txt, primary_targets: [a/outpatches.txt.txt], secondary_targets: [], excluded_targets: [], group: None, bin: None, rule_ref: TupLoc { tup_path_desc: a/Tupfile, loc: Loc { line: 1, col: 1, span: 42 } }, env: EnvDescriptor(0) }\nResolvedLink { primary_sources: [Deglob(MatchingPath { path_descriptor: a/out1.txt, path: NormalPath { inner: \"a/out1.txt\" }, glob_descriptor: Some(a/out[1].txt), captured_globs: [\"1\"] })], secondary_sources: [], rule_formula_desc: cp out1.txt new_1.txt, primary_targets: [a/new_1.txt], secondary_targets: [], excluded_targets: [], group: None, bin: None, rule_ref: TupLoc { tup_path_desc: a/Tupfile, loc: Loc { line: 13, col: 1, span: 46 } }, env: EnvDescriptor(0) }"
        };
        //log::warn!("{}", outs);
        assert_eq!(outs, expected);

        assert_eq!(arts.len(), 14);
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
