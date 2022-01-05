use statements::Loc;
use std::ffi::OsString;
use std::io::Error as IoErr;
use thiserror::Error as ThisError;
#[derive(Debug, ThisError)]
pub enum Error {
    #[error("Parsing error at line {0} and offset {1}")]
    ParseError(String, Loc),
    #[error("subst failure at line:{0}")]
    SubstError(u32, Loc),
    #[error("Path errors")]
    PathError(OsString, Loc),
    #[error("Io Error: {0}")]
    IoError(IoErr),
    #[error("Unknown macro reference:{0}")]
    UnknownMacroRef(String, Loc),
    #[error("Dependency cycle between {0}, {1}")]
    DependencyCycle(String, String),
    #[error("Root folder not found. Tupfile.ini is expected in the root.")]
    RootNotFound,
    #[error("Glob error")]
    GlobError(String),
    #[error("Multiple glob patterns match some paths")]
    MultipleGlobMatches(String, Loc),
}
