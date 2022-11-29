# tuprs  
![Build Status](https://github.com/svark/tuprs/actions/workflows/rust.yml/badge.svg)
---
[Tup](https://gittup.org/tup) is a build system that works with files and has a light syntax describing rules, its inputs and outputs. It provides strong build guarantees in each run, executing only the rules affected by changes in file system. Furthermore, it can dynamically track rule dependencies as they are being run avoiding any manual tracking of inputs to rule commands. This library parses a tup file into resolved rules, its inputs and outputs. 
Rules can be specificed in Tupfile syntax or in lua as described in the tup manual.

First version works with directly with a Tupfile or the Tupfile.lua.
```rust
use tupparser::TupParser;
let p = TupParser::new();
let tupf = p.parse("Tupfile")?;
```
or a lua file
```rust
let tupf = p.parse("Tupfile.lua")?;
```

If you are inside a directory that is already initialized with tup init, the following will locate the root folder that contains Tupfile.ini and load config vars from tup.config automatically.
```rust
let curdir = std::env::current_dir().unwrap();
let p = TupParser::try_new_from(curdir).expect("Root not found");
let artifacts = p.parse(tupfile);
```

The second version  scans the directory tree and runs the parser over all Tupfiles it finds.
This version assumes that group references will be completely resolved and errors out if there are no group providers for a group reference. See [Tup manual](https://gittup.org/tup/manual.html)
```rust
use parser::parse_dir;
let tupf = parse_dir("/tuproot")?;
```

