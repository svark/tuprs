use thiserror::Error as ThisError;
use std::ffi::OsString;
use std::io::Error as IoErr;
use statements::Loc;
#[derive(Debug, ThisError)]
pub enum Error {
    #[error("Parsing error at line {0} and offset {1}")]
    ParseError(String, Loc),
    #[error("subst failure at line:{0}")]
    SubstError(u32, Loc),
    #[error("Path errors")]
    PathError (OsString, Loc),
    #[error("Io Error: {0}")]
    IoError(IoErr),
    #[error("Unknown macro reference:{0}")]
    UnknownMacroRef(String, Loc)
}