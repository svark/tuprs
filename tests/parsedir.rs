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
        let statements = parse_dir(d.as_path()).expect("failed to parse!");
        //let statements0 = statements[0].get_statements();
        // println!("{:?}", statements);
        assert_eq!(statements.len(), 12);
    }
    #[test]
    fn test_script() {
        env_logger::init();
        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push("tests/tupscripttest");
        let statements = parse_dir(d.as_path()).expect("failed to parse!");
        //let statements0 = statements[0].get_statements();
        log::error!("statements: {:?}", statements);
        assert_eq!(statements.len(), 2);
    }
}
