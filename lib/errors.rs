//! Module for tracking errors during tupfile parsing
use std::io::Error as IoErr;

use thiserror::Error as ThisError;

use crate::buffers::RuleDescriptor;
use crate::buffers::RuleRefDescriptor;
use crate::statements::Loc;
use crate::statements::TupLoc;
use tuppaths::descs::PathDescriptor;
/// Error along with the tupfile path where it occurred

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
    #[error("Io Error: {0} for {1}")]
    IoError(IoErr, String, Loc),
    /// Macro with given name could not be found
    #[error("Unknown macro reference:{0} at {1}")]
    UnknownMacroRef(String, String),
    /// Dependency cycle  between rules of tupfile because groups refer to one another
    #[error("Dependency cycle between {0}, {1}")]
    DependencyCycle(String, String),
    /// Tupfile.ini could not be found, hence root directory could not be established
    #[error("Root folder not found. Tupfile.ini is expected in the root.")]
    RootNotFound,
    /// Glob looks fishy as per glob rules
    #[error("Glob error")]
    GlobError(String),
    /// Overlapping results from different glob patterns
    #[error("Multiple glob patterns match some paths")]
    MultipleGlobMatches(String, TupLoc),
    /// Multiple rules return the same output file
    #[error("Multiple rules writing to same output {0}: current rule: {1}, previous rule: {2}")]
    MultipleRulesToSameOutput(PathDescriptor, RuleDescriptor, RuleDescriptor),
    /// Group reference could not resolved
    /// Bin reference could not be resolved
    #[error("Bin reference {0} could not be resolved at input {1}")]
    StaleBinRef(String, RuleRefDescriptor),
    /// Percentage char in rules could not be resolved
    #[error("%{0} could not be resolved from {2} for rule at: {1}")]
    StalePerc(char, TupLoc, String),
    ///  Numbered reference could not be resolved
    #[error("Number reference %[num]{0} could not be resolved from {2} for rule at {1}")]
    StalePercNumberedRef(char, TupLoc, String),
    /// Lua script error
    #[error("Script Error: {0}")]
    ScriptError(String, u32),
    /// Error running tup run
    #[error("Error running tup run at {0} : \n {1}")]
    RunError(TupLoc, String),
    /// Tuprules file could not be located from current Tupfile
    #[error("Tup rules could not be located from {0}")]
    TupRulesNotFound(TupLoc),
    /// Tuprules file could not be located from current Tupfile
    #[error("Path {0} referred in {1} could not be located")]
    PathNotFound(String, TupLoc),
    /// Rule creates a directory
    #[error("Output path is a directory: {0} defined at {1}")]
    OutputIsDir(String, String),
    /// Path search error
    #[error("Path search error: {0}")]
    PathSearchError(String),
    /// Path search error with context
    /// Raw lua errors
    #[error("Lua error: {0}")]
    LuaError(String),
    /// User error
    #[error("User error: {0} at {1}")]
    UserError(String, TupLoc),

    /// negative index specific for word
    #[error("Could not find task by name:{0} at {1}")]
    TaskNotFound(String, String),

    /// Failure during running a callback to fetch all groupids
    #[error("Call back error: {0}")]
    CallBackError(String),

    /// Path errors such as glob error, or missing file
    #[error("Error {0}")]
    PathError(#[from] tuppaths::errors::Error),

    /// Wrapped error with context
    #[error("Error {0} during \n {1}")]
    WithContext(Box<Error>, String),
}

impl Error {
    /// Create an error from outside this library to allow traits of this library
    /// to have fallible implementations outside of this library
    pub fn new_path_search_error(error_str: String) -> Error {
        Error::PathSearchError(error_str.to_string())
    }
    /// Create an error from outside this library, when invoking a callback
    pub fn new_callback_error(error_str: String) -> Error {
        Error::CallBackError(error_str.to_string())
    }
    /// Wrap an error with context
    pub fn with_context(e: Error, context: String) -> Error {
        Error::WithContext(Box::new(e), context)
    }
}
