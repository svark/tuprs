//! This module contains the `InputsAsPaths` and `OutputsAsPaths` structs, which are used to manage
//! inputs and outputs for rules in a build system.
use crate::buffers::{InputResolvedType, PathBuffers, RuleRefDescriptor};
use crate::decode::GroupInputs;
use alloc::borrow::Cow;
use log::debug;
use std::collections::BTreeMap;
use tuppaths::descs::{PathDescriptor, RelativeDirEntry};
use tuppaths::paths::{MatchingPath, NormalPath};

/// `OutputsAsPaths` represents resolved outputs to pass to a rule
pub struct OutputsAsPaths {
    outputs: Vec<PathDescriptor>,
    rule_ref: RuleRefDescriptor,
}

impl OutputsAsPaths {
    /// Create a new instance of OutputsAsPaths from a list of paths and a rule reference
    pub fn new(outputs: Vec<PathDescriptor>, rule_ref: RuleRefDescriptor) -> Self {
        Self { outputs, rule_ref }
    }
    fn get_base(&self) -> PathDescriptor {
        self.rule_ref.get_tupfile_desc().get_parent_descriptor()
    }
    /// returns all the outputs as vector of strings
    pub fn get_paths(&self) -> Vec<String> {
        self.outputs
            .iter()
            .map(|x| RelativeDirEntry::new(self.get_base(), x.clone()))
            .map(|rd| rd.get_path().to_string())
            .collect()
    }
    ///  returns the stem portion of each output file.
    pub fn get_file_stem(&self) -> Vec<String> {
        self.outputs
            .iter()
            .flat_map(|x| {
                x.get_path_ref()
                    .as_path()
                    .file_stem()
                    .map(|x| x.to_string_lossy().to_string())
            })
            .collect()
    }
}
/// A trait to provide methods for formatting replacements in rule formulas and outputs
pub trait FormatReplacements {
    /// Get all paths as strings in a vector based on a token  i,f and such
    fn get_paths_str_from_tok(&self, tok: &char) -> Vec<String>;
    /// get bin paths stored against a bin name
    fn get_bin_paths(&self, bin_name: &str) -> Vec<String>;
}

/// `InputsAsPaths' represents resolved inputs to pass to a rule, classified according to bin or group or raw path
/// Bins are converted to raw paths, groups paths are expanded into a space separated path list
#[derive(Debug, Clone, Default)]
pub struct InputsAsPaths {
    raw_inputs: Vec<PathDescriptor>,
    groups_by_name: BTreeMap<String, Vec<PathDescriptor>>, // space separated paths against group name
    bins_by_name: BTreeMap<String, Vec<PathDescriptor>>,
    raw_inputs_glob_match: Option<InputResolvedType>,
    tup_dir: PathDescriptor,
}

impl GroupInputs for InputsAsPaths {
    /// Returns all paths  (space separated) associated with a given group name
    /// This is used for group name substitutions in rule formulas that appear as %<group_name>
    fn get_group_paths(&self, group_name: &str, _rule_id: i64, _rule_dir: i64) -> Option<String> {
        let paths = |group_name| {
            self.groups_by_name.get(group_name).cloned().map(|x| {
                let paths: Vec<_> = x.iter().map(|p| p.to_string()).collect();
                paths.join(" ")
            })
        };
        if group_name.starts_with('<') {
            paths(group_name)
        } else {
            paths(&*format!("<{}>", group_name))
        }
    }
}
impl InputsAsPaths {
    /// Check if there are no inputs
    pub fn is_empty(&self) -> bool {
        self.raw_inputs.is_empty() && self.groups_by_name.is_empty() && self.bins_by_name.is_empty()
    }
    /// Returns all paths as strings in a vector
    pub fn get_file_names(&self) -> Vec<String> {
        self.raw_inputs
            .iter()
            .filter_map(|x| {
                x.get_path_ref()
                    .as_path()
                    .file_name()
                    .and_then(|x| x.to_str())
                    .map(|x| x.to_string())
            })
            .collect()
    }

    #[allow(dead_code)]
    /// Returns the first parent folder name
    pub fn parent_folder_name(&self) -> &NormalPath {
        self.tup_dir.get_path_ref()
    }
    /// Returns all the inputs as a vector of strings
    pub fn get_paths(&self) -> Vec<String> {
        self.raw_inputs
            .iter()
            .chain(self.groups_by_name.values().flatten())
            //.chain(self.bins_by_name.values().flatten())
            .map(|x| {
                RelativeDirEntry::new(self.tup_dir.clone(), x.clone())
                    .get_path()
                    .to_string()
            })
            .collect()
    }
    /// returns parent folder paths for all inputs
    pub fn get_parent_paths(&self) -> Vec<String> {
        self.raw_inputs
            .iter()
            .chain(self.groups_by_name.values().flatten())
            //.chain(self.bins_by_name.values().flatten())
            .map(|x| x.get_parent_descriptor())
            .map(|x| {
                RelativeDirEntry::new(self.tup_dir.clone(), x.clone())
                    .get_path()
                    .to_string()
            })
            .collect()
    }

    /// Returns the extension portion of each input file.
    pub fn get_extension(&self) -> Vec<String> {
        self.raw_inputs
            .iter()
            .chain(self.groups_by_name.values().flatten())
            .filter_map(|x| {
                x.get_path_ref()
                    .as_path()
                    .extension()
                    .and_then(|x| x.to_str().map(|x| x.to_string()))
            })
            .collect()
    }
    /// Returns the stem portion of each input file.
    pub fn get_file_stem(&self) -> Vec<String> {
        self.raw_inputs
            .iter()
            .chain(self.groups_by_name.values().flatten())
            .filter_map(|x| {
                x.get_path_ref()
                    .as_path()
                    .file_stem()
                    .and_then(|x| x.to_str().map(|x| x.to_string()))
            })
            .collect()
    }

    /// Returns the glob match for the first input
    pub fn get_glob(&self) -> Vec<String> {
        self.raw_inputs_glob_match
            .as_ref()
            .and_then(InputResolvedType::as_glob_match)
            .cloned()
            .unwrap_or_default()
    }
}

impl FormatReplacements for InputsAsPaths {
    fn get_paths_str_from_tok(&self, tok: &char) -> Vec<String> {
        match tok {
            'f' | 'i' => self.get_paths(),
            'd' => self.get_parent_paths(),
            'e' => self.get_extension(),
            'B' => self.get_file_stem(),
            'b' => self.get_file_names(),
            'g' | 'h' => self.get_glob(),
            _ => Vec::new(),
        }
    }

    fn get_bin_paths(&self, bin_name: &str) -> Vec<String> {
        let paths = |bin_name| -> Vec<_> {
            let vals = self
                .bins_by_name
                .get(bin_name)
                .cloned()
                .map(|x| x.iter().map(|p| p.to_string()).collect())
                .unwrap_or_default();
            debug!("bin paths for {:?} are {:?}", bin_name, vals);
            vals
        };
        if bin_name.starts_with('{') {
            paths(bin_name)
        } else {
            vec!["".to_string()]
        }
    }
}

impl FormatReplacements for OutputsAsPaths {
    fn get_paths_str_from_tok(&self, tok: &char) -> Vec<String> {
        match tok {
            'o' => self.get_paths(),
            'O' => self.get_file_stem(),
            _ => Vec::new(),
        }
    }
    fn get_bin_paths(&self, _: &str) -> Vec<String> {
        unreachable!("bin paths not available for outputs")
    }
}

impl InputsAsPaths {
    /// Create a new instance of InputsAsPaths from a raw list of inputs
    pub fn new_from_raw(
        tup_cwd: &PathDescriptor,
        inp: Cow<str>,
        path_buffers: &impl PathBuffers,
    ) -> InputsAsPaths {
        let inp_resolved: Vec<_> = {
            let inp_desc = {
                let np = NormalPath::new_from_cow_str(inp);
                path_buffers.add_path_from(tup_cwd, np.as_path()).ok()
            };
            inp_desc
                .map(|inp_desc| {
                    InputResolvedType::Deglob(MatchingPath::new(inp_desc, tup_cwd.clone()))
                })
                .into_iter()
                .collect()
        };
        InputsAsPaths::new(tup_cwd, &inp_resolved, path_buffers)
    }
    /// Create a new instance of InputsAsPaths from a list of inputs
    pub fn new(
        tup_cwd: &PathDescriptor,
        inp: &[InputResolvedType],
        path_buffers: &impl PathBuffers,
    ) -> InputsAsPaths {
        let non_group = |x: &InputResolvedType| {
            !matches!(x, &InputResolvedType::GroupEntry(_, _))
                && !matches!(x, &InputResolvedType::UnResolvedGroupEntry(_))
        };
        if !inp.is_empty() {
            debug!(
                "processing inputs at {:?} first of which is {:?}",
                tup_cwd, inp[0]
            );
        }
        let try_bin = |x: &InputResolvedType| {
            if let &InputResolvedType::BinEntry(ref grp_desc, _) = x {
                Some((
                    path_buffers.get_bin_name(grp_desc).to_string(),
                    path_buffers.get_path_from(x),
                ))
            } else {
                None
            }
        };
        let try_grp = |x: &InputResolvedType| {
            if let &InputResolvedType::GroupEntry(ref grp_desc, _) = x {
                Some((
                    path_buffers.get_group_name(grp_desc),
                    path_buffers.get_path_from(x),
                ))
            } else if let &InputResolvedType::UnResolvedGroupEntry(ref grp_desc) = x {
                let grp_name = path_buffers.get_group_name(grp_desc);
                Some((grp_name.clone(), PathDescriptor::default()))
            } else {
                None
            }
        };
        let all_non_groups: Vec<_> = inp
            .iter()
            .filter(|&x| non_group(x))
            .map(|x| path_buffers.get_path_from(x))
            .collect();
        let mut namedgroupitems: BTreeMap<_, Vec<PathDescriptor>> = BTreeMap::new();
        let mut named_bin_items: BTreeMap<String, Vec<PathDescriptor>> = BTreeMap::new();
        for x in inp.iter().filter_map(|x| try_grp(x)) {
            namedgroupitems
                .entry(x.0)
                .or_insert_with(Default::default)
                .push(x.1)
        }
        for x in inp.iter().filter_map(|x| try_bin(x)) {
            named_bin_items
                .entry(x.0.to_string())
                .or_insert_with(Default::default)
                .push(x.1)
        }
        let raw_inputs_glob_match = inp.first().cloned();
        debug!("input glob match :{:?}", raw_inputs_glob_match);
        InputsAsPaths {
            raw_inputs: all_non_groups,
            groups_by_name: namedgroupitems,
            bins_by_name: named_bin_items,
            raw_inputs_glob_match,
            tup_dir: tup_cwd.clone(),
        }
    }
}
