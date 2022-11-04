# tuprs  
![Build Status](https://github.com/svark/tuprs/actions/workflows/rust.yml/badge.svg)
Library for parsing a tup file into resolved rules, its inputs and outputs.
For convenience there are two versions of the api.
First version works directly with tupfile or the lua but may not resolve groups.
Parsing a single 
```rust
use tupparser::parse_tup;
let tupf = parse_tup("Tupfile")?;
```
or a lua file
```rust
let tupf = parse_tup("Tupfile.lua")?;
```

Second version of the api scans directory tree and runs the parser over all Tupfiles it finds.
This version assumes that group references will be completely resolved and errors if there are no group providers for a group reference.
```rust
use tupparser::parse_dir;
let tupf = parse_dir("/tuproot")?;
```
