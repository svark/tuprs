# tuprs  
![Build Status](https://github.com/svark/tuprs/actions/workflows/rust.yml/badge.svg)
Library for parsing a tup file into resolved rules, its inputs and outputs. 
For convenience there are two versions of the api.
First version works directly with tupfile or the lua but may not resolve groups.
```rust
use parser::tup_file_path;
let tupf = parse_tup("Tupfile")?;
```
or a lua file
```rust
let tupf = parse_tup("Tupfile.lua")?;
```

The second version  scans the directory tree and runs the parser over all Tupfiles it finds.
This version assumes that group references will be completely resolved and errors out if there are no group providers for a group reference.
```rust
use parser::parse_dir;
let tupf = parse_dir("/tuproot")?;
```

