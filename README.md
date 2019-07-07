# tuprs
Library for parsing a tup file. 
Reads files and converts the input into a Rust expression.
```
let tupf = parser::parse_tupfile("Tupfile")
```
To substitute assigned variables/ configuration variables and expand macros do the following to set up maps for these variable
```
let sm = parser::SubstMap(expr_map : HashMap::new(), conf_map : HashMap::new(),  rule_map : HashMap::new()) 
tupf.subst(sm)
```
This also reads included files.
