# tuprs  
[![Build Status](https://app.travis-ci.com/svark/tuprs.svg?branch=master)](https://app.travis-ci.com/svark/tuprs)

Library for parsing a tup file. 
Reads and converts data in Tupfile into parsed rust expressions.
```
let tupf = parser::parse_tupfile("Tupfile")
```
To substitute configuration ('@-') or  other variables ('$' variables) and expand 
macros  ('!'- refs),  do the following to set up maps and then call subst on the parsed content
to simplify parsed content with only rule, error, export and run statements.
`include` and `include_rules` statements will be processed as well at this stage recursively loading files as many times as is necessary.

```
let sm = parser::SubstMap(expr_map : HashMap::new(), conf_map : HashMap::new(),  rule_map : HashMap::new(), cur_file = "./Tupfile") 
tupf.subst(sm)
```

