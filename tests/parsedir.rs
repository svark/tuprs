extern crate tupparser;

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use tupparser::transform::parse_dir;
    #[test]
    pub fn test_parsedir() {
        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push("tests/tuptest");
        let statements = parse_dir(d.as_path()).expect("failed to parse!");
        //let statements0 = statements[0].get_statements();
        assert_eq!(statements.len(), 12);
    }
    #[test]
    fn test_script() {
        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push("tests/tupscripttest");
        let statements = parse_dir(d.as_path()).expect("failed to parse!");
        //let statements0 = statements[0].get_statements();
        assert_eq!(statements.len(), 2);
    }
}
