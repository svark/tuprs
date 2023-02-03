//! Module for tracking errors during tupfile parsing
use std::io::Error as IoErr;

use thiserror::Error as ThisError;

use decode::{PathDescriptor, RuleRef};
use statements::Loc;

/// Errors returning during parsing and subst-ing Tupfiles
#[non_exhaustive]
#[derive(Debug, ThisError)]
pub enum Error {
    /// Parsing error when reading a Tupfile, usually reported by nom
    #[error("Parsing error {0} at {1}")]
    ParseError(String, Loc),
    /// Substitution failure at a location
    #[error("subst failure at line:{0}")]
    SubstError(u32, Loc),
    /// Error when opening a file
    #[error("Io Error: {0}")]
    IoError(IoErr, Loc),
    /// Macro with given name could not found for expansion
    #[error("Unknown macro reference:{0}")]
    UnknownMacroRef(String, RuleRef),
    /// Dependency cylcle  between rules of tupfile because groups refer to one another
    #[error("Dependency cycle between {0}, {1}")]
    DependencyCycle(String, String),
    /// Tupfile.ini could not be found, hence root directory could not established
    #[error("Root folder not found. Tupfile.ini is expected in the root.")]
    RootNotFound,
    /// Glob looks fishy as per glob rules
    #[error("Glob error")]
    GlobError(String),
    /// Overlapping results from different glob patterns
    #[error("Multiple glob patterns match some paths")]
    MultipleGlobMatches(String, RuleRef),
    /// Multiple rules return the same output file
    #[error("Multiple rules writing to same output {0}: current rule: {1}, previous rule: {2}")]
    MultipleRulesToSameOutput(PathDescriptor, RuleRef, RuleRef),
    /// Group reference could not resolved
    #[error("Groups reference {0} could not be resolved at input{0}")]
    StaleGroupRef(String, RuleRef),
    /// Bin reference could not be resolved
    #[error("Bin reference {0} could not be resolved at input{0}")]
    StaleBinRef(String, RuleRef),
    /// Percentage char in rules could not be resolved
    #[error("%{0} could not be resolved for rule at: {1}")]
    StalePerc(char, RuleRef),
    ///  Numbered reference could not be resolved
    #[error("Number reference %[num]{0} could not be resolved at input: {1}")]
    StalePercNumberedRef(char, RuleRef),
    /// Lua script error
    #[error("Script Error: {0}")]
    ScriptError(String, u32),
    /// Error running tup run
    #[error("Error running tup run at {0} : \n {1}")]
    RunError(RuleRef, String),
    /// Tuprules file could not be located from current Tupfile
    #[error("Tup rules could not be located from {0}")]
    TupRulesNotFound(RuleRef),
    /// Tuprules file could not be located from current Tupfile
    #[error("Include path {0} referred in {1} could not be located")]
    PathNotFound(String, RuleRef),
    /// input file could not be resolved
    #[error("Error resolving an input: {0} at {1}")]
    UnResolvedFile(String, RuleRef),
    /// Path search error
    #[error("Path search error: {0}")]
    PathSearchError(String),
    /// Path search error with context
    #[error("Path search error: {0} at {1}")]
    PathSearchErrorCtx(String, RuleRef),
    /// Raw lua errors
    #[error(transparent)]
    LuaError(#[from] mlua::Error),
    /// User error
    #[error("User error: {0} at {1}")]
    UserError(String, RuleRef),
}

impl Error {
    /// Create an error from outside this library to allow traits of this library
    /// to have  have fallible implementations outside of this library
    pub fn new_path_search_error(error_str: &str, _rule_ref: RuleRef) -> Error {
        Error::PathSearchError(error_str.to_string())
    }
}
