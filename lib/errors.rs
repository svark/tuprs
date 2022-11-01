use decode::{PathDescriptor, RuleRef};
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
    PathError(OsString, RuleRef),
    #[error("Io Error: {0}")]
    IoError(IoErr, Loc),
    #[error("Unknown macro reference:{0}")]
    UnknownMacroRef(String, RuleRef),
    #[error("Dependency cycle between {0}, {1}")]
    DependencyCycle(String, String),
    #[error("Root folder not found. Tupfile.ini is expected in the root.")]
    RootNotFound,
    #[error("Glob error")]
    GlobError(String),
    #[error("Multiple glob patterns match some paths")]
    MultipleGlobMatches(String, RuleRef),
    #[error("Multiple rules writing to same output {0}: current rule: {1}, previous rule: {2}")]
    MultipleRulesToSameOutput(PathDescriptor, RuleRef, RuleRef),
    #[error("Groups reference {0} could not be resolved at input{0}")]
    StaleGroupRef(String, RuleRef),
    #[error("Bin reference {0} could not be resolved at input{0}")]
    StaleBinRef(String, RuleRef),
    #[error("%{0} could not be resolved for rule at: {1}")]
    StalePerc(char, RuleRef),
    #[error("Number reference %[num]{0} could not be resolved at input: {1}")]
    StalePercNumberedRef(char, RuleRef),
    #[error("Script Error: {0}")]
    ScriptError(String, u32),
    #[error(transparent)]
    LuaError(#[from] mlua::Error),
}
