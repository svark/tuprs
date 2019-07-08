# tuprs
Library for parsing a tup file. 
Reads and converts data in Tupfile into parsed rust expressions.
```
let tupf = parser::parse_tupfile("Tupfile")
```
To substitute configuration ('@-') or  other variables ('$' variables) and expand 
macros  ('!'- refs) do the following to set up maps and then call subst on the parsed content
to simplify parsed content with only rule, error, export and run statements.

```
let sm = parser::SubstMap(expr_map : HashMap::new(), conf_map : HashMap::new(),  rule_map : HashMap::new()) 
tupf.subst(sm)
```
This also reads included files.
