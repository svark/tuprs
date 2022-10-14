// code taken mostly verbatim from globset crate glob
// adapted to return a regex with capturing groups corresponding to group

use platform::get_platform;
use regex;
use std::borrow::Cow;
use std::ops::{Deref, DerefMut};

use std::error::Error as StdError;
use std::fmt;
use std::hash;
use std::iter;
use std::path::{is_separator, Path};
use std::str;

//use aho_corasick::AhoCorasick;
use bstr::ByteVec;
use regex::bytes::{Regex, RegexBuilder};
//use bstr::{ByteSlice, ByteVec};
/// Represents an error that can occur when parsing a glob pattern.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Error {
    /// The original glob provided by the caller.
    glob: Option<String>,
    /// The kind of error.
    kind: ErrorKind,
}

/// The kind of error that can occur when parsing a glob pattern.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    /// **DEPRECATED**.
    ///
    /// This error used to occur for consistency with git's glob specification,
    /// but the specification now accepts all uses of `**`. When `**` does not
    /// appear adjacent to a path separator or at the beginning/end of a glob,
    /// it is now treated as two consecutive `*` patterns. As such, this error
    /// is no longer used.
    /// Occurs when a character class (e.g., `[abc]`) is not closed.
    UnclosedClass,
    /// Occurs when a range in a character (e.g., `[a-z]`) is invalid. For
    /// example, if the range starts with a lexicographically larger character
    /// than it ends with.
    InvalidRange(char, char),
    /// Occurs when a `}` is found without a matching `{`.
    UnopenedAlternates,
    /// Occurs when a `{` is found without a matching `}`.
    UnclosedAlternates,
    /// Occurs when an alternating group is nested inside another alternating
    /// group, e.g., `{{a,b},{c,d}}`.
    NestedAlternates,
    /// Occurs when an unescaped '\' is found at the end of a glob.
    DanglingEscape,
    /// An error associated with parsing or compiling a regex.
    Regex(String),
    /// Hints that destructuring should not be exhaustive.
    ///
    /// This enum may grow additional variants, so this makes sure clients
    /// don't count on exhaustive matching. (Otherwise, adding a new variant
    /// could break existing code.)
    #[doc(hidden)]
    __Nonexhaustive,
}

impl StdError for Error {
    fn description(&self) -> &str {
        self.kind.description()
    }
}

impl Error {
    /// Return the kind of this error.
    pub fn kind(&self) -> &ErrorKind {
        &self.kind
    }
}

impl ErrorKind {
    fn description(&self) -> &str {
        match *self {
            ErrorKind::UnclosedClass => "unclosed character class; missing ']'",
            ErrorKind::InvalidRange(_, _) => "invalid character range",
            ErrorKind::UnopenedAlternates => {
                "unopened alternate group; missing '{' \
                (maybe escape '}' with '[}]'?)"
            }
            ErrorKind::UnclosedAlternates => {
                "unclosed alternate group; missing '}' \
                (maybe escape '{' with '[{]'?)"
            }
            ErrorKind::NestedAlternates => "nested alternate groups are not allowed",
            ErrorKind::DanglingEscape => "dangling '\\'",
            ErrorKind::Regex(ref err) => err,
            ErrorKind::__Nonexhaustive => unreachable!(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.glob {
            None => self.kind.fmt(f),
            Some(ref glob) => {
                write!(f, "error parsing glob '{}': {}", glob, self.kind)
            }
        }
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            ErrorKind::UnclosedClass
            | ErrorKind::UnopenedAlternates
            | ErrorKind::UnclosedAlternates
            | ErrorKind::NestedAlternates
            | ErrorKind::DanglingEscape
            | ErrorKind::Regex(_) => write!(f, "{}", self.description()),
            ErrorKind::InvalidRange(s, e) => {
                write!(f, "invalid range; '{}' > '{}'", s, e)
            }
            ErrorKind::__Nonexhaustive => unreachable!(),
        }
    }
}

fn new_regex(pat: &str) -> Result<Regex, Error> {
    RegexBuilder::new(pat)
        .dot_matches_new_line(true)
        .size_limit(10 * (1 << 20))
        .dfa_size_limit(10 * (1 << 20))
        .build()
        .map_err(|err| Error {
            glob: Some(pat.to_string()),
            kind: ErrorKind::Regex(err.to_string()),
        })
}

/// Normalizes a path to use `/` as a separator everywhere, even on platforms
/// that recognize other characters as separators.
#[cfg(unix)]
pub fn normalize_path(path: Cow<'_, [u8]>) -> Cow<'_, [u8]> {
    // UNIX only uses /, so we're good.
    path
}

/// Normalizes a path to use `/` as a separator everywhere, even on platforms
/// that recognize other characters as separators.
#[cfg(not(unix))]
pub fn normalize_path(mut path: Cow<[u8]>) -> Cow<[u8]> {
    for i in 0..path.len() {
        if path[i] == b'/' || !is_separator(path[i] as char) {
            continue;
        }
        path.to_mut()[i] = b'/';
    }
    path
}

/// Glob represents a successfully parsed shell glob pattern.
///
/// It cannot be used directly to match file paths, but it can be converted
/// to a regular expression string or a matcher.
#[derive(Clone, Debug, Eq)]
pub struct Glob {
    glob: String,
    re: String,
    opts: GlobOptions,
    //tokens: Tokens,
}

impl PartialEq for Glob {
    fn eq(&self, other: &Glob) -> bool {
        self.glob == other.glob && self.opts == other.opts
    }
}

impl hash::Hash for Glob {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.glob.hash(state);
        self.opts.hash(state);
    }
}

impl fmt::Display for Glob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.glob.fmt(f)
    }
}

impl str::FromStr for Glob {
    type Err = Error;

    fn from_str(glob: &str) -> Result<Self, Self::Err> {
        Self::new(glob)
    }
}

/// A matcher for a single pattern.
#[derive(Clone, Debug)]
pub struct GlobMatcher {
    /// The underlying pattern.
    //pat: Glob,
    /// The pattern, as a compiled regex.
    re: Regex,
}
/// A candidate path for matching.
///
/// All glob matching in this crate operates on `Candidate` values.
/// Constructing candidates has a very small cost associated with it, so
/// callers may find it beneficial to amortize that cost when matching a single
/// path against multiple globs or sets of globs.
#[derive(Clone, Debug)]
pub struct Candidate<'a> {
    path: Cow<'a, [u8]>,
}

impl<'a> Candidate<'a> {
    /// Create a new candidate for matching from the given path.
    pub fn new<P: AsRef<Path> + ?Sized>(path: &'a P) -> Candidate<'a> {
        let path = normalize_path(Vec::from_path_lossy(path.as_ref()));
        Candidate { path }
    }

    pub fn path(&self) -> &Cow<'a, [u8]> {
        return &self.path;
    }
}
impl GlobMatcher {
    /// Tests whether the given path matches this pattern or not.

    pub fn is_match_candidate(&self, candidate: &Candidate) -> bool {
        self.re.is_match(candidate.path().as_ref())
    }
    pub fn is_match<P: AsRef<Path>>(&self, path: P) -> bool {
        self.is_match_candidate(&Candidate::new(path.as_ref()))
    }

    /// get the i-the matching capturing group in path. Each glob pattern has corresponds to a capturing group
    pub fn group<P: AsRef<Path>>(&self, path: P, i: usize) -> Option<String> {
        let lossy_str = path.as_ref().to_string_lossy();
        self.re
            .captures(lossy_str.as_bytes())
            .and_then(|c| c.get(i))
            .and_then(|m| std::str::from_utf8(m.as_bytes()).ok())
            .map(|s| s.to_string())
    }
}
/// A builder for a pattern.
///
/// This builder enables configuring the match semantics of a pattern. For
/// example, one can make matching case insensitive.
///
/// The lifetime `'a` refers to the lifetime of the pattern string.
#[derive(Clone, Debug)]
pub struct GlobBuilder<'a> {
    /// The glob pattern to compile.
    glob: &'a str,
    /// Options for the pattern.
    opts: GlobOptions,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct GlobOptions {
    /// Whether to match case insensitively.
    case_insensitive: bool,
    /// Whether to require a literal separator to match a separator in a file
    /// path. e.g., when enabled, `*` won't match `/`.
    literal_separator: bool,
    /// Whether or not to use `\` to escape special characters.
    /// e.g., when enabled, `\*` will match a literal `*`.
    backslash_escape: bool,
    /// Whether groups will be added in regex for each glob pattern
    capture_globs: bool,
}

impl GlobOptions {
    fn default() -> GlobOptions {
        GlobOptions {
            case_insensitive: get_platform().eq("win32"),
            literal_separator: false,
            backslash_escape: !is_separator('\\'),
            capture_globs: false,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct Tokens(Vec<Token>);

impl Deref for Tokens {
    type Target = Vec<Token>;
    fn deref(&self) -> &Vec<Token> {
        &self.0
    }
}

impl DerefMut for Tokens {
    fn deref_mut(&mut self) -> &mut Vec<Token> {
        &mut self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Token {
    Literal(char),
    Any,
    ZeroOrMore,
    RecursivePrefix,
    RecursiveSuffix,
    RecursiveZeroOrMore,
    Class {
        negated: bool,
        ranges: Vec<(char, char)>,
    },
    Alternates(Vec<Tokens>),
}

impl Glob {
    /// Builds a new pattern with default options.
    pub fn new(glob: &str) -> Result<Glob, Error> {
        GlobBuilder::new(glob).build()
    }

    /// Returns a matcher for this pattern.
    pub fn compile_matcher(&self) -> GlobMatcher {
        let re = new_regex(&self.re).expect("regex compilation shouldn't fail");
        GlobMatcher { re }
    }
}

impl<'a> GlobBuilder<'a> {
    /// Create a new builder for the pattern given.
    ///
    /// The pattern is not compiled until `build` is called.
    pub fn new(glob: &'a str) -> GlobBuilder<'a> {
        GlobBuilder {
            glob,
            opts: GlobOptions::default(),
        }
    }

    /// Parses and builds the pattern.
    pub fn build(&self) -> Result<Glob, Error> {
        let mut p = Parser {
            glob: &self.glob,
            stack: vec![Tokens::default()],
            chars: self.glob.chars().peekable(),
            prev: None,
            cur: None,
            opts: &self.opts,
        };
        p.parse()?;
        if p.stack.is_empty() {
            Err(Error {
                glob: Some(self.glob.to_string()),
                kind: ErrorKind::UnopenedAlternates,
            })
        } else if p.stack.len() > 1 {
            Err(Error {
                glob: Some(self.glob.to_string()),
                kind: ErrorKind::UnclosedAlternates,
            })
        } else {
            let tokens = p.stack.pop().unwrap();
            Ok(Glob {
                glob: self.glob.to_string(),
                re: tokens.to_regex_with(&self.opts),
                opts: self.opts,
            })
        }
    }

    /// Toggle whether a literal `/` is required to match a path separator.
    ///
    /// By default this is false: `*` and `?` will match `/`.
    pub fn literal_separator(&mut self, yes: bool) -> &mut GlobBuilder<'a> {
        self.opts.literal_separator = yes;
        self
    }

    /// When the option capture_globs is set to true, it will be possible to query
    /// a regex from Glob that will match with each glob captured in a capturing group
    pub fn capture_globs(&mut self, yes: bool) -> &mut GlobBuilder<'a> {
        self.opts.capture_globs = yes;
        self
    }
}

impl Tokens {
    /// Convert this pattern to a string that is guaranteed to be a valid
    /// regular expression and will represent the matching semantics of this
    /// glob pattern and the options given.
    fn to_regex_with(&self, options: &GlobOptions) -> String {
        let mut re = String::new();
        re.push_str("(?-u)");
        if options.case_insensitive {
            re.push_str("(?i)");
        }
        re.push('^');
        // Special case. If the entire glob is just `**`, then it should match
        // everything.
        if self.len() == 1 && self[0] == Token::RecursivePrefix {
            let rep = if options.capture_globs { "(.*)" } else { ".*" };
            re.push_str(rep);
            re.push('$');
            return re;
        }
        self.tokens_to_regex(options, &self, &mut re);
        re.push('$');
        re
    }

    fn tokens_to_regex(&self, options: &GlobOptions, tokens: &[Token], re: &mut String) {
        for tok in tokens {
            match *tok {
                Token::Literal(c) => {
                    re.push_str(&char_to_escaped_literal(c));
                }
                Token::Any => {
                    if options.capture_globs {
                        re.push('(');
                    }
                    if options.literal_separator {
                        re.push_str("[^/]");
                    } else {
                        re.push_str(".");
                    }
                    if options.capture_globs {
                        re.push(')');
                    }
                }
                Token::ZeroOrMore => {
                    if options.capture_globs {
                        re.push('(');
                    }
                    if options.literal_separator {
                        re.push_str("[^/]*");
                    } else {
                        re.push_str(".*");
                    }
                    if options.capture_globs {
                        re.push(')');
                    }
                }
                Token::RecursivePrefix => {
                    if options.capture_globs {
                        re.push_str("(/?|.*/)");
                    } else {
                        re.push_str("(?:/?|.*/)");
                    }
                }
                Token::RecursiveSuffix => {
                    if options.capture_globs {
                        re.push_str("/(.*)");
                    } else {
                        re.push_str("/.*");
                    }
                }
                Token::RecursiveZeroOrMore => {
                    if options.capture_globs {
                        re.push_str("(/|/.*/)");
                    } else {
                        re.push_str("(?:/|/.*/)");
                    }
                }
                Token::Class {
                    negated,
                    ref ranges,
                } => {
                    if options.capture_globs {
                        re.push('(');
                    }
                    re.push('[');
                    if negated {
                        re.push('^');
                    }
                    for r in ranges {
                        if r.0 == r.1 {
                            // Not strictly necessary, but nicer to look at.
                            re.push_str(&char_to_escaped_literal(r.0));
                        } else {
                            re.push_str(&char_to_escaped_literal(r.0));
                            re.push('-');
                            re.push_str(&char_to_escaped_literal(r.1));
                        }
                    }
                    re.push(']');
                    if options.capture_globs {
                        re.push(')');
                    }
                }
                Token::Alternates(ref patterns) => {
                    let mut parts = vec![];
                    for pat in patterns {
                        let mut altre = String::new();
                        self.tokens_to_regex(options, &pat, &mut altre);
                        if !altre.is_empty() {
                            parts.push(altre);
                        }
                    }

                    // It is possible to have an empty set in which case the
                    // resulting alternation '()' would be an error.
                    if !parts.is_empty() {
                        re.push('(');
                        re.push_str(&parts.join("|"));
                        re.push(')');
                    }
                }
            }
        }
    }
}

/// Convert a Unicode scalar value to an escaped string suitable for use as
/// a literal in a non-Unicode regex.
fn char_to_escaped_literal(c: char) -> String {
    bytes_to_escaped_literal(&c.to_string().into_bytes())
}

/// Converts an arbitrary sequence of bytes to a UTF-8 string. All non-ASCII
/// code units are converted to their escaped form.
fn bytes_to_escaped_literal(bs: &[u8]) -> String {
    let mut s = String::with_capacity(bs.len());
    for &b in bs {
        if b <= 0x7F {
            s.push_str(&regex::escape(&(b as char).to_string()));
        } else {
            s.push_str(&format!("\\x{:02x}", b));
        }
    }
    s
}

struct Parser<'a> {
    glob: &'a str,
    stack: Vec<Tokens>,
    chars: iter::Peekable<str::Chars<'a>>,
    prev: Option<char>,
    cur: Option<char>,
    opts: &'a GlobOptions,
}

impl<'a> Parser<'a> {
    fn error(&self, kind: ErrorKind) -> Error {
        Error {
            glob: Some(self.glob.to_string()),
            kind: kind,
        }
    }

    fn parse(&mut self) -> Result<(), Error> {
        while let Some(c) = self.bump() {
            match c {
                '?' => self.push_token(Token::Any)?,
                '*' => self.parse_star()?,
                '[' => self.parse_class()?,
                '{' => self.push_alternate()?,
                '}' => self.pop_alternate()?,
                ',' => self.parse_comma()?,
                '\\' => self.parse_backslash()?,
                c => self.push_token(Token::Literal(c))?,
            }
        }
        Ok(())
    }

    fn push_alternate(&mut self) -> Result<(), Error> {
        if self.stack.len() > 1 {
            return Err(self.error(ErrorKind::NestedAlternates));
        }
        Ok(self.stack.push(Tokens::default()))
    }

    fn pop_alternate(&mut self) -> Result<(), Error> {
        let mut alts = vec![];
        while self.stack.len() >= 2 {
            alts.push(self.stack.pop().unwrap());
        }
        self.push_token(Token::Alternates(alts))
    }

    fn push_token(&mut self, tok: Token) -> Result<(), Error> {
        if let Some(ref mut pat) = self.stack.last_mut() {
            return Ok(pat.push(tok));
        }
        Err(self.error(ErrorKind::UnopenedAlternates))
    }

    fn pop_token(&mut self) -> Result<Token, Error> {
        if let Some(ref mut pat) = self.stack.last_mut() {
            return Ok(pat.pop().unwrap());
        }
        Err(self.error(ErrorKind::UnopenedAlternates))
    }

    fn have_tokens(&self) -> Result<bool, Error> {
        match self.stack.last() {
            None => Err(self.error(ErrorKind::UnopenedAlternates)),
            Some(ref pat) => Ok(!pat.is_empty()),
        }
    }

    fn parse_comma(&mut self) -> Result<(), Error> {
        // If we aren't inside a group alternation, then don't
        // treat commas specially. Otherwise, we need to start
        // a new alternate.
        if self.stack.len() <= 1 {
            self.push_token(Token::Literal(','))
        } else {
            Ok(self.stack.push(Tokens::default()))
        }
    }

    fn parse_backslash(&mut self) -> Result<(), Error> {
        if self.opts.backslash_escape {
            match self.bump() {
                None => Err(self.error(ErrorKind::DanglingEscape)),
                Some(c) => self.push_token(Token::Literal(c)),
            }
        } else if is_separator('\\') {
            // Normalize all patterns to use / as a separator.
            self.push_token(Token::Literal('/'))
        } else {
            self.push_token(Token::Literal('\\'))
        }
    }

    fn parse_star(&mut self) -> Result<(), Error> {
        let prev = self.prev;
        if self.peek() != Some('*') {
            self.push_token(Token::ZeroOrMore)?;
            return Ok(());
        }
        assert_eq!(self.bump(), Some('*'));
        if !self.have_tokens()? {
            if !self.peek().map_or(true, is_separator) {
                self.push_token(Token::ZeroOrMore)?;
                self.push_token(Token::ZeroOrMore)?;
            } else {
                self.push_token(Token::RecursivePrefix)?;
                assert!(self.bump().map_or(true, is_separator));
            }
            return Ok(());
        }

        if !prev.map(is_separator).unwrap_or(false) {
            if self.stack.len() <= 1 || (prev != Some(',') && prev != Some('{')) {
                self.push_token(Token::ZeroOrMore)?;
                self.push_token(Token::ZeroOrMore)?;
                return Ok(());
            }
        }
        let is_suffix = match self.peek() {
            None => {
                assert!(self.bump().is_none());
                true
            }
            Some(',') | Some('}') if self.stack.len() >= 2 => true,
            Some(c) if is_separator(c) => {
                assert!(self.bump().map(is_separator).unwrap_or(false));
                false
            }
            _ => {
                self.push_token(Token::ZeroOrMore)?;
                self.push_token(Token::ZeroOrMore)?;
                return Ok(());
            }
        };
        match self.pop_token()? {
            Token::RecursivePrefix => {
                self.push_token(Token::RecursivePrefix)?;
            }
            Token::RecursiveSuffix => {
                self.push_token(Token::RecursiveSuffix)?;
            }
            _ => {
                if is_suffix {
                    self.push_token(Token::RecursiveSuffix)?;
                } else {
                    self.push_token(Token::RecursiveZeroOrMore)?;
                }
            }
        }
        Ok(())
    }

    fn parse_class(&mut self) -> Result<(), Error> {
        fn add_to_last_range(glob: &str, r: &mut (char, char), add: char) -> Result<(), Error> {
            r.1 = add;
            if r.1 < r.0 {
                Err(Error {
                    glob: Some(glob.to_string()),
                    kind: ErrorKind::InvalidRange(r.0, r.1),
                })
            } else {
                Ok(())
            }
        }
        let mut ranges = vec![];
        let negated = match self.chars.peek() {
            Some(&'!') | Some(&'^') => {
                let bump = self.bump();
                assert!(bump == Some('!') || bump == Some('^'));
                true
            }
            _ => false,
        };
        let mut first = true;
        let mut in_range = false;
        loop {
            let c = match self.bump() {
                Some(c) => c,
                // The only way to successfully break this loop is to observe
                // a ']'.
                None => return Err(self.error(ErrorKind::UnclosedClass)),
            };
            match c {
                ']' => {
                    if first {
                        ranges.push((']', ']'));
                    } else {
                        break;
                    }
                }
                '-' => {
                    if first {
                        ranges.push(('-', '-'));
                    } else if in_range {
                        // invariant: in_range is only set when there is
                        // already at least one character seen.
                        let r = ranges.last_mut().unwrap();
                        add_to_last_range(&self.glob, r, '-')?;
                        in_range = false;
                    } else {
                        assert!(!ranges.is_empty());
                        in_range = true;
                    }
                }
                c => {
                    if in_range {
                        // invariant: in_range is only set when there is
                        // already at least one character seen.
                        add_to_last_range(&self.glob, ranges.last_mut().unwrap(), c)?;
                    } else {
                        ranges.push((c, c));
                    }
                    in_range = false;
                }
            }
            first = false;
        }
        if in_range {
            // Means that the last character in the class was a '-', so add
            // it as a literal.
            ranges.push(('-', '-'));
        }
        self.push_token(Token::Class { negated, ranges })
    }

    fn bump(&mut self) -> Option<char> {
        self.prev = self.cur;
        self.cur = self.chars.next();
        self.cur
    }

    fn peek(&mut self) -> Option<char> {
        self.chars.peek().map(|&ch| ch)
    }
}