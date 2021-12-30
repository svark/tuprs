extern crate tupparser;

#[cfg(test)]
mod tests {
    use std::path::Path;
    use tupparser::transform::parse_dir;
    #[test]
    pub fn test_parsedir() {
        let statements = parse_dir(Path::new("c:/users/arun/tuptest/")).expect("failed to parse!");
        //let statements0 = statements[0].get_statements();
        assert_eq!(statements.len(), 6);
    }
}
