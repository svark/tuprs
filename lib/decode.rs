use statements::*;
use std::collections::HashMap;
use std::path::PathBuf;

use glob::{glob, Entry};
// use std::ffi::OsStr;

pub struct OutputTagInfo {
    pub buckettags: HashMap<String, Vec<PathBuf>>,
    pub grouptags: HashMap<String, Vec<PathBuf>>,
}
// Types of decoded input to rules which includes
// files in glob, group paths, bucket entries
pub enum InputGlobType {
    Deglob(Entry),
    Group(String, PathBuf),
    Bucket(String, PathBuf),
}

pub trait DecodeInputPaths {
    fn decode(&self, taginfo: &OutputTagInfo) -> Vec<InputGlobType>;
}

impl DecodeInputPaths for RvalGeneral {
    // convert globs into regular paths, remember that matched groups
    fn decode(&self, taginfo: &OutputTagInfo) -> Vec<InputGlobType> {
        let mut vs: Vec<InputGlobType> = Vec::new();
        match self {
            RvalGeneral::Literal(src) => {
                for src in src.split_whitespace() {
                    if let Some(pos) = src.rfind('*') {
                        let (first, last) = src.split_at(pos);
                        let mut bstr: String = first.to_string();
                        bstr.push_str("(*)"); // replace * with (*) to capture the glob
                        bstr.push_str(&last[1..]);
                        for entry in glob(bstr.as_str())
                            .expect("Failed to read glob pattern")
                            .into_iter()
                            .filter_map(|x| x.ok())
                        {
                            vs.push(InputGlobType::Deglob(entry));
                        }
                    } else {
                        let g = glob(src).expect("Failed to read glob pattern");
                        for p in g.into_iter().filter_map(|x| x.ok()) {
                            vs.push(InputGlobType::Deglob(p))
                        }
                    }
                }
            }
            RvalGeneral::Group(grp) => {
                for rval in grp {
                    if let RvalGeneral::Literal(grp_name) = rval {
                        if let Some(paths) = taginfo.grouptags.get(grp_name) {
                            for p in paths {
                                vs.push(InputGlobType::Group(grp_name.clone(), p.to_path_buf()))
                            }
                        }
                    }
                    break; // only the first one since we expect subst process to have been done
                }
            }
            RvalGeneral::Bucket(str) => {
                if let Some(paths) = taginfo.buckettags.get(str) {
                    for p in paths {
                        vs.push(InputGlobType::Bucket(str.clone(), p.to_path_buf()))
                    }
                }
            }
            _ => {}
        }
        return vs;
    }
}

impl DecodeInputPaths for Vec<RvalGeneral> {
    fn decode(&self, taginfo: &OutputTagInfo) -> Vec<InputGlobType> {
        self.iter().map(|x| x.decode(&taginfo)).flatten().collect()
    }
}
