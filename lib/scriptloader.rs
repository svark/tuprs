use errors::Error as Err;
use mlua::{AnyUserData, HookTriggers, Lua, MultiValue, StdLib, ToLua, Value, Variadic};
use mlua::{UserData, UserDataMethods};
use nom::{AsBytes, InputTake};
use statements::{Link, RuleFormula, Source, Target};
use std::cell::RefMut;
use std::fs::File;
use std::io::Read;
use std::ops::DerefMut;
use std::path::Path;
use std::sync::Arc;
use std::vec::Drain;
use mlua::Error::SyntaxError;
use decode::{BufferObjects, discover_inputs_from_glob, OutputTagInfo, ResolvePaths };
use parser::locate_tuprules;
use transform::SubstMap;
lazy_static! {
    static ref LINENO: &'static str = "lineno";
    static ref CURDIR: &'static str = "curdir";
}
/*


tup.definerule{inputs = {'', ...}, command = '', outputs = {'', ...}}
Returns: none
Defines a rule. See the Tup manual for more information on rules. command will be executed without any modifications, either directly or in a shell, in the directory PROCESSING. inputs and outputs are optional and are used to determine dependencies.

tup.frule{inputs = {'', ...}, command = '', outputs = {'', ...}}
Returns: table of strings
A wrapper for tup.definerule that performs substitutions on all parameters based on format patterns. Returns a table containing the filenames of all outputs.

If there is a single input, it can be specified as a string argument input, and a single output can be specified as string argument output. In addition to sequential, numerically indexed elements, input can contain a table at index 'extra_inputs', the elements of which are treated like normal inputs but are not used when substituting %f. Likewise, output can contain a table at index 'extra_outputs', the elements of which are treated like normal outputs but are not used when substituting %o. Be aware that you are using input and output as an argument to frule in that case, rather than inputs and outputs!

The substitutions are roughly the same as the substitutions in non-Lua Tupfile rules. See the Tup manual for more information on the format patterns.

If a glob character appears in an input, the input string is replaced by its glob results.
Global variable and config variable values are substituted for $() and @() respectively.
%d is replaced in input strings.
%d, %f, %b, and %B are replaced in output strings.
%d, %f, %b, %B, and %o are replaced in the command string.
tup.rule(command)
tup.rule(command, outputs)
tup.rule(inputs, command)
tup.rule(inputs, command, outputs)
Returns: table of strings
A forwarding wrapper around tup.frule. Except for the 3-argument version, inputs and outputs must always be tables, and command must be a string. In the 3-argument version, inputs and outputs can be a string for a single input, or a table. Returns the result of tup.frule.

tup.foreach_rule(inputs, command)
tup.foreach_rule(inputs, command, outputs)
Returns: table of strings
A forwarding wrapper around tup.frule. inputs and outputs must always be tables, and command must be a string. For each input INPUT, runs tup.frule with an input table containing INPUT and inputs.extra_inputs if present. Returns the aggregate result of all tup.frule calls.

tup.export(variable)
Returns: none
Adds the environment variable named variable to the export list for future rules. See the Tup manual for more information.

tup.creategitignore()
Returns: none
Tells Tup to automatically generate a .gitignore file in PROCESSING which contains a list of the output files that are generated by Tup. See the Tup manual for more information.

tup.getcwd()
Returns: string
Returns the relative path from PROCESSING to RUNNING.

Example: If /a/b/Tupfile.lua included /a/include.lua, tup.getcwd() would return the path ../.

tup.getdirectory()
Returns: string
Returns the name of RUNNING within RUNNING's parent directory.

Example: Running tup.getdirectory() in /a/b/Tupfile.lua would return b.

tup.getrelativedir(directoryname)
Returns: string
Returns a path to directoryname relative from the active Tupfile.lua file.

tup.nodevariable(path)
Returns: node variable
Returns a node variable referencing a file indicated by path relative to RUNNING. Calling tostring or concatenating the node variable with a string will convert the node variable to the relative path from RUNNING to the referenced file.

Example: A node variable created from path ./data.txt in /a/b/Tupfile.lua would resolve to ../b/data.txt in /a/c/Tupfile.lua.

tup.getconfig(name)
Returns: string
Returns the value of the config item named 'CONFIG_' .. name or the empty string if the config item does not exist.

tup.glob(pattern)
Returns: table of strings
Returns a table of the relative paths of all files matching glob pattern pattern.

tup.append_table(a, b)
Returns: none
Modifies a by appending all elements of b.

tup.file(filename)
Returns: string
Strips all parent directories from the path string filename and returns the result.

tup.base(filename)
Returns: string
Strips all parent directories from the path string filename and the file extension (including the .), and returns the result.

tup.ext(filename)
Returns: string
Returns the extension in the filename filename (excluding the .) or the empty string if there is no extension.
 */
//use mlua::{Function, Lua, MetaMethod, Result, UserData, UserDataMethods, Variadic};
use statements::*;
use statements::Statement::Rule;

#[derive(Clone, Debug)]
pub struct TupScriptContext {
    smap: SubstMap,
    pub links: Vec<Link>,
    pub bo: BufferObjects,
    pub output_tag_info: OutputTagInfo,
}
#[derive(Debug, Default, Clone)]
pub struct ScriptInputBuilder {
    primary_inputs: Vec<PathExpr>,
    secondary_inputs: Vec<PathExpr>,
}
#[derive(Debug, Default, Clone)]
pub struct ScriptOutputBuilder {
    primary_outputs: Vec<PathExpr>,
    secondary_outputs: Vec<PathExpr>,
    group: Option<PathExpr>,
    bin: Option<PathExpr>,
    exclude_pattern: Option<PathExpr>,
}
/*
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
enum CaretFlag {
    None,
    OptimizeDag,
    BashPipeFail,
    CompileDB,
    TransientOutput,
}

impl Default for CaretFlag {
    fn default() -> Self {
        CaretFlag::None
    }
}*/
#[derive(Debug, Default, Clone)]
pub struct ScriptRuleCommand {
    display_fn: String,
    command: String,
    // caret_flags: HashSet<CaretFlag>,
}

impl ScriptInputBuilder {
    pub fn new() -> ScriptInputBuilder {
        return ScriptInputBuilder::default();
    }
    pub fn push(&mut self, s: &str) -> &mut Self {
        if let Some(bracket_pos) = s.find("{") {
            let (_, p2) = s.take_split(bracket_pos);
            let p2 = p2
                .trim()
                .strip_prefix("{")
                .and_then(|p| p.strip_suffix("}"));
            self.push_bin(p2.unwrap_or(""));
        } else if s.trim().starts_with("^") {
            self.push_exclude_pattern(&s[1..]);
        } else if let Some(bracket_pos) = s.find("<") {
            let (p1, p2) = s.take_split(bracket_pos);
            let p2 = p2.strip_prefix("<").and_then(|p| p.strip_suffix(">"));
            self.push_group(p1, p2.unwrap_or(""));
        } else {
            self.primary_inputs.push(s.to_string().into());
        }
        self
    }

    pub fn push_exclude_pattern(&mut self, f: &str) -> &mut Self {
        self.primary_inputs
            .push(PathExpr::ExcludePattern(f.to_string()));
        self
    }
    pub fn push_extra_exclude_pattern(&mut self, f: &str) -> &mut Self {
        self.secondary_inputs
            .push(PathExpr::ExcludePattern(f.to_string()));
        self
    }
    pub fn push_group(&mut self, grp_path: &str, grp_name: &str) -> &mut Self {
        self.primary_inputs.push(PathExpr::Group(
            vec![grp_path.to_string().into()],
            vec![grp_name.to_string().into()],
        ));
        self
    }
    pub fn push_bin(&mut self, bin: &str) -> &mut Self {
        self.primary_inputs.push(PathExpr::Bin(bin.to_owned()));
        self
    }

    pub fn push_extra(&mut self, s: &str) -> &mut Self {
        if let Some(bracket_pos) = s.find("{") {
            let (_, p2) = s.take_split(bracket_pos);
            let p2 = p2
                .trim()
                .strip_prefix("{")
                .and_then(|p| p.strip_suffix("}"));
            self.push_extra_bin(p2.unwrap_or(""));
        } else if s.starts_with("^") {
            self.push_extra_exclude_pattern(&s[1..]);
        } else if let Some(bracket_pos) = s.find("<") {
            let (p1, p2) = s.take_split(bracket_pos);
            let p2 = p2.strip_prefix("<").and_then(|p| p.strip_suffix(">"));
            self.push_extra_group(p1, p2.unwrap_or(""));
        } else {
            self.secondary_inputs.push(s.to_string().into());
        }
        self
    }

    pub fn push_extra_group(&mut self, grp_path: &str, grp_name: &str) -> &mut Self {
        self.secondary_inputs.push(PathExpr::Group(
            vec![grp_path.to_string().into()],
            vec![grp_name.to_string().into()],
        ));
        self
    }
    pub fn push_extra_bin(&mut self, bin: &str) -> &mut Self {
        self.secondary_inputs.push(PathExpr::Bin(bin.to_owned()));
        self
    }
    pub fn build(self) -> Source {
        Source {
            primary: self.primary_inputs,
            for_each: false,
            secondary: self.secondary_inputs,
        }
    }
    pub fn build_foreach(self) -> Source {
        Source {
            primary: self.primary_inputs,
            for_each: true,
            secondary: self.secondary_inputs,
        }
    }
}

impl ScriptOutputBuilder {
    pub fn new() -> ScriptOutputBuilder {
        return ScriptOutputBuilder::default();
    }
    pub fn push(&mut self, s: &str) -> &mut Self {
        self.primary_outputs.push(s.to_string().into());
        self
    }

    pub fn set_group(&mut self, grp_path: &str, grp_name: &str) -> &mut Self {
        self.group = Some(PathExpr::Group(
            vec![grp_path.to_string().into()],
            vec![grp_name.to_string().into()],
        ));
        self
    }
    pub fn set_bin(&mut self, bin: &str) -> &mut Self {
        self.bin = Some(PathExpr::Bin(bin.to_owned()));
        self
    }

    pub fn set_exclude_pattern(&mut self, regex: &str) -> &mut Self {
        //todo: add multiple exclude patterns
        self.exclude_pattern = Some(PathExpr::ExcludePattern(regex.to_owned()));
        self
    }

    pub fn push_extra(&mut self, s: &str) -> &mut Self {
        self.secondary_outputs.push(s.to_string().into());
        self
    }
    pub fn build(self) -> Target {
        Target {
            primary: self.primary_outputs,
            secondary: self.secondary_outputs,
            exclude_pattern: self.exclude_pattern,
            group: self.group,
            bin: self.bin,
        }
    }
}

impl ScriptRuleCommand {
    pub fn new() -> ScriptRuleCommand {
        ScriptRuleCommand::default()
    }
    pub fn set_command(&mut self, command: String) -> &mut Self {
        self.command = command;
        self
    }
    pub fn set_display_str(&mut self, display_fn: String) -> &mut Self {
        self.display_fn = display_fn;
        self
    }
    pub fn build(self) -> RuleFormula {
        RuleFormula {
            description: vec![self.display_fn.into()],
            formula: vec![self.command.into()],
        }
    }
}

impl TupScriptContext {
    pub fn new(smap: SubstMap) -> TupScriptContext {
        TupScriptContext {
            links: vec![],
            smap,
            output_tag_info: OutputTagInfo::new(),
            bo: Default::default()
        }
    }

    pub fn for_each_rule(
        &mut self,
        lineno: u32,
        inp: ScriptInputBuilder,
        rule_command: ScriptRuleCommand,
        out: ScriptOutputBuilder,
    ) -> Result<Vec<String>, mlua::Error> {
        let source = inp.build_foreach();
        let rule_formula = rule_command.build();
        let target = out.build();
        let l = Link {
            source,
            target,
            rule_formula,
            pos: (lineno, 0),
        };
        self.links.push(l);
        let l = self.links.last().unwrap();
        let statement = LocatedStatement{statement:Rule(l.clone()),  loc: Loc::new( lineno,  0 ) };
        let (_, out) = statement.resolve_paths(self.smap.cur_file.as_path(), &self.output_tag_info, &mut self.bo, &self.smap.cur_file_desc).expect("unable to resolve paths");
        let mut paths = Vec::new();
        for i in out.output_files {
            let path = self.bo.pbo.get(&i);
            paths.push(path.as_path().to_string_lossy().to_string());
        }
        Ok(paths)
    }

    pub fn rule(
        &mut self,
        lineno: u32,
        inp: ScriptInputBuilder,
        rule_command: ScriptRuleCommand,
        out: ScriptOutputBuilder,
    ) -> Result<Vec<String>, mlua::Error> {
        let source = inp.build();
        let rule_formula = rule_command.build();
        let target = out.build();
        let l = Link {
            source,
            target,
            rule_formula,
            pos: (lineno, 0),
        };
        self.links.push(l);
        let l = self.links.last().unwrap();
        let statement = LocatedStatement{statement:Rule(l.clone()),  loc: Loc::new(lineno, 0)};
        let (_, out) = statement.resolve_paths(self.smap.cur_file.as_path(), &self.output_tag_info, &mut self.bo, &self.smap.cur_file_desc).expect("unable to resolve paths");
        let mut paths = Vec::new();
        for i in out.output_files {
            let path = self.bo.pbo.get(&i);
            paths.push(path.as_path().to_string_lossy().to_string());
        }
        Ok(paths)
    }

    pub fn get_links(&mut self) -> Drain<'_, Link> {
        self.links.drain(..)
    }

    pub fn config(&self, name: &str) -> String {
        self.smap
            .conf_map
            .get(name)
            .map(|x| x.join(""))
            .unwrap_or("".to_string())
    }
    pub fn get_cwd(&self) -> String {
        self.smap
            .cur_file
            .parent()
            .unwrap_or(Path::new(""))
            .to_string_lossy()
            .to_string()
    }
    pub fn dir(a: &String) -> String {
        Path::new(a.as_str())
            .parent()
            .unwrap()
            .to_string_lossy()
            .to_string()
    }
    pub fn file(a: &String) -> String {
        Path::new(a.as_str())
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string()
    }
    pub fn extension(a: &String) -> String {
        Path::new(a.as_str())
            .extension()
            .unwrap()
            .to_string_lossy()
            .to_string()
    }
    pub fn base(a: &String) -> String {
        Path::new(a.as_str())
            .file_stem()
            .unwrap()
            .to_string_lossy()
            .to_string()
    }
    pub fn convert_to_table<'a>(
        lua: &'a mlua::Lua,
        v: &'a Value,
    ) -> mlua::Result<Value<'a>> {
        let t = match v {
            Value::Table(t) => t.clone(),
            _ => {
                let table1 = lua.create_table()?;
                table1.set(1, v.clone())?;
                table1
            }
        };
        t.to_lua(lua)
    }
}
trait ConvToString {
    fn convert_to_string(&self, v: &Value) -> mlua::Result<String>;
}

impl ConvToString for Lua {
    // wrapper around tostring method in lua
    fn convert_to_string(&self, v: &Value) -> mlua::Result<String> {
        let val_str: String = match v {
            Value::Table(t) => {
                let chunk = self.load(
                    "function f(t) {\
                      table.concat(t, ' ')
                    }
                    )",
                );
                chunk.call(t.clone())?
            }
            Value::String(s) => s.to_string_lossy().to_string(),
            _ => self.load("realtostring").call(v.clone())?,
        };
        Ok(val_str)
    }
}

impl UserData for TupScriptContext {
    fn add_methods<'lua, M: UserDataMethods<'lua, Self>>(methods: &mut M) {
        methods.add_function("getconfig", |lua, var: (mlua::String,) | {
            let globals = lua.globals();
            let tup_shared: AnyUserData = globals.get("tup")?;
            let  ctx: RefMut<TupScriptContext> = tup_shared.borrow_mut()?;
            let varstr = var.0.to_string_lossy().to_string();
            let conf = ctx.config(varstr.as_str());
            Ok(conf)
        });
        methods.add_function("getcwd", |lua, _: ()|
            {
                let globals = lua.globals();
                let tup_shared: AnyUserData = globals.get("tup")?;
                let  scriptctx: RefMut<TupScriptContext> = tup_shared.borrow_mut()?;
                Ok(scriptctx.get_cwd())
            });

        methods.add_function("base", |_,  path: (mlua::String,)| {
            let v = path.0.to_string_lossy().to_string();
            let bname = TupScriptContext::base(&v);
            Ok(bname)
        });

        methods.add_function("file", |_, path: (mlua::String,)| {
            let v = path.0.to_string_lossy().to_string();
            let fname = TupScriptContext::file(&v);
            Ok(fname)
        });
        methods.add_function("getdirectory", |_, path: (mlua::String,)| {
            let v = path.0.to_string_lossy().to_string();
            let d = TupScriptContext::dir(&v);
            Ok(d)
        });

        methods.add_function("ext", |_, path: (mlua::String,)| {
            let v = path.0.to_string_lossy().to_string();
            let ext = TupScriptContext::extension(&v);
            Ok(ext)
        });

        methods.add_function("tup_tostring", |lua, inp: MultiValue| {
            Ok(inp
                .iter()
                .filter_map(|i| lua.convert_to_string(i).ok())
                .collect::<Vec<_>>())
        });

        methods.add_function("rule", |lua_ctx,  inps1: Variadic<Value>|  {
            let mut inputs = ScriptInputBuilder::new();
            let mut outputs = ScriptOutputBuilder::new();
            let mut rulcmd = ScriptRuleCommand::new();
            for  inp in inps1.iter() {
                if let Value::String(s) = inp {
                    println!("vals:{:?}", s.to_string_lossy().to_string());
                }
            }
            let command_at_index = if inps1.iter().count() == 3 {
                Some(1)
            } else {
                inps1.iter().position(|v| v.type_name().eq("string"))
            };
            let numinps = command_at_index
                .map(|i| i)
                .unwrap_or(std::cmp::min(inps1.iter().count(), 1));
            let outindex = command_at_index
                .map(|i| (i + 1))
                .unwrap_or(std::cmp::min(inps1.iter().skip(1).count(), 1));
            let inps: Vec<_> = inps1
                .iter()
                .take(numinps)
                .filter_map(|x| TupScriptContext::convert_to_table(lua_ctx, x).ok())
                .collect();
            let outs: Vec<_> = inps1
                .iter()
                .skip(outindex)
                .filter_map(|x| TupScriptContext::convert_to_table(lua_ctx, x).ok())
                .collect();
            if let Some(Value::Table(t)) = inps.first() {
                t.clone().pairs().for_each(|x| {
                    if let Ok((k, ref v)) = x {
                        if let Value::String(ref s) = k {
                            if s.as_bytes().eq("extra_inputs".as_bytes()) {
                                if let Value::String(ref s) = v {
                                    if let Some(extra_inp) = s.to_str().ok() {
                                        inputs.push_extra(extra_inp);
                                    }
                                }
                                if let Value::Table(t) = v {
                                    t.clone()
                                        .sequence_values()
                                        .into_iter()
                                        .filter_map(|x| x.ok())
                                        .for_each(|val: Value| {
                                            if let Some(s) = lua_ctx.convert_to_string(&val).ok() {
                                                inputs.push_extra(s.as_str());
                                            }
                                        });
                                }
                            } else if s.as_bytes().eq("bin".as_bytes()) {
                                if let Value::String(ref s) = v {
                                    if let Some(binname) = s.to_str().ok() {
                                        inputs.push_bin(binname);
                                    }
                                }
                            }
                        }
                        if let Value::Integer(_) = k {
                            if let Value::String(ref i) = v {
                                if let Some(inp) = i.to_str().ok() {
                                    inputs.push(inp);
                                }
                            }
                        }
                    };
                    ()
                });
            }
            if let Some(Value::Table(t)) = outs.first() {
                t.clone().pairs().for_each(|x| {
                    if let Ok((k, ref v)) = x {
                        if let Value::String(s) = &k {
                            if s.as_bytes().eq("extra_outputs".as_bytes()) {
                                if let Value::String(s) = v {
                                    if let Some(out) = s.to_str().ok() {
                                        if let Some(bracket_pos) = out.find("<") {
                                            let (p1, p2) = out.take_split(bracket_pos);
                                            let p2 = p2
                                                .strip_prefix("<")
                                                .and_then(|p| p.strip_suffix(">"));
                                            outputs.set_group(p1, p2.unwrap_or(""));
                                        } else if out.starts_with("{") {
                                            outputs.set_bin(&out[1..]);
                                        } else if out.starts_with("^") {
                                            outputs.set_exclude_pattern(&out[1..]);
                                        } else {
                                            outputs.push_extra(out);
                                        }
                                    }
                                }
                            }
                            if s.as_bytes().eq("bin".as_bytes()) {
                                if let Ok(out) = lua_ctx.convert_to_string(v) {
                                    outputs.set_bin(out.as_str());
                                }
                            }
                        }

                        if let Value::Integer(_) = &k {
                            if let Ok(s) = lua_ctx.convert_to_string(v) {
                                outputs.push(s.as_str());
                            }
                        }
                    }
                });
            }
            if let Some(rule) = command_at_index.and_then(|i| inps1.get(i)) {
                let mut desc: String = String::new();
                let mut cmd: String = String::new();
                if let Value::String(s) = rule {
                    if let Some(r) = s.to_str().ok() {
                        let r = r.trim_start();
                        if r.starts_with('^') {
                            let r = &r[1..];
                            desc = r.to_string();
                            cmd = "".to_string();
                            let pos = r.find('^');
                            pos.map(|p| {
                                desc = r[0..p].to_string();
                                cmd = r[p + 1..].to_string();
                            });
                        } else {
                            cmd = r.to_string();
                        }
                    }
                }
                rulcmd.set_command(cmd);
                rulcmd.set_display_str(desc);
                let i: u32 = lua_ctx
                    .named_registry_value(LINENO.as_bytes())
                    .expect("line number missing lua registry");
                let globals = lua_ctx.globals();
                let tup_shared: AnyUserData = globals.get("tup")?;
                let mut scriptctx: RefMut<TupScriptContext> = tup_shared.borrow_mut()?;
                let paths = scriptctx.rule(i, inputs, rulcmd, outputs)?;
                let t = lua_ctx.create_table()?;
                let mut cnt: usize = 1;
                for p in paths {
                    t.set(cnt, p)?;
                    cnt = cnt + 1;
                }
                Ok(Value::Table(t))
            }
            else {
                let t = lua_ctx.create_table()?;
                Ok(Value::Table(t))
            }
        }
        );
        methods.add_function_mut("frule", |luactx, inps1: Variadic<Value>| -> Result<Value, mlua::Error> {
            luactx.load("tup.rule").call(inps1)
            //Ok(())
        });
        methods.add_function_mut(
            "foreach_rule",
            |luactx, inps1: Variadic<Value>| -> Result<Value, mlua::Error> {
                let mut inputs = ScriptInputBuilder::new();
                let mut outputs = ScriptOutputBuilder::new();
                let mut rulcmd = ScriptRuleCommand::new();
                for  inp in inps1.iter() {
                    if let Value::String(s) = inp {
                        println!("vals:{:?}", s.to_string_lossy().to_string());
                    }
                }
                let command_at_index = if inps1.len() == 3  { Some(1) } else {
                   inps1.iter().position(|v| v.type_name().eq("string"))
                };
                let numinps = command_at_index
                    .unwrap_or(std::cmp::min(inps1.iter().count(), 1));
                let outindex = command_at_index
                    .map(|i| (i + 1))
                    .unwrap_or(std::cmp::min(inps1.iter().skip(1).count(), 1));
                let inps : Vec<_> = inps1.iter().take(numinps).filter_map(|x| TupScriptContext::convert_to_table(luactx, x).ok())
                    .collect();
                let outs : Vec<_> = inps1.iter().skip(outindex).filter_map(|x| TupScriptContext::convert_to_table(luactx, x).ok())
                    .collect();
                if let Some(Value::Table(t)) = inps.first() {
                    t.clone().pairs().for_each(|x| {
                        if let Ok((k, ref v)) = x {
                            if let Value::String(ref s) = k {
                                if s.as_bytes().eq("extra_inputs".as_bytes()) {
                                    if let Value::String(ref s) = v {
                                        if let Some(extra_inp) = s.to_str().ok() {
                                            inputs.push_extra(extra_inp);
                                        }
                                    }
                                    if let Value::Table(t) = v {
                                        t.clone()
                                            .sequence_values()
                                            .into_iter()
                                            .filter_map(|x| x.ok())
                                            .for_each(|v: Value| {
                                                if let Value::String(ref s) = v {
                                                    if let Some(inp) = s.to_str().ok() {
                                                        inputs.push_extra(inp);
                                                    }
                                                }
                                            });
                                    }
                                }
                            }
                            if let Value::Integer(_) = k {
                                if let Value::String(ref i) = v {
                                    if let Some(inp) = i.to_str().ok() {
                                        inputs.push(inp);
                                    }
                                }
                            }
                        };
                        ()
                    });
                }

                if let Some(Value::Table(t)) = outs.first() {
                    t.clone().pairs().for_each(|x| {
                        if let Ok((k, ref v)) = x {
                            if let Value::String(s) = &k {
                                if s.as_bytes().eq("extra_outputs".as_bytes()) {
                                    if let Value::String(s) = v {
                                        if let Some(out) = s.to_str().ok() {
                                            if let Some(bracket_pos) = out.find("<") {
                                                let (p1, p2) = out.take_split(bracket_pos);
                                                let p2 = p2
                                                    .strip_prefix("<")
                                                    .and_then(|p| p.strip_suffix(">"));
                                                outputs.set_group(p1, p2.unwrap_or(""));
                                            } else {
                                                outputs.push_extra(out);
                                            }
                                        }
                                    }
                                }
                            }
                            if let Value::Integer(_) = &k {
                                if let Value::String(s) = &v {
                                    if let Some(out) = s.to_str().ok() {
                                        outputs.push(out);
                                    }
                                }
                            }
                        }
                    });
                }

                if let Some(rule) = command_at_index.and_then(|i| inps1.get(i)) {
                    let mut desc: String = String::new();
                    let mut cmd: String = String::new();
                    if let Value::String(s) = rule {
                        if let Some(r) = s.to_str().ok() {
                            let r = r.trim_start();
                            if r.starts_with('^') {
                                let r = &r[1..];
                                desc = r.to_string();
                                cmd = "".to_string();
                                let pos = r.find('^');
                                pos.map(|p| {
                                    desc = r[0..p].to_string();
                                    cmd = r[p + 1..].to_string();
                                });
                            } else {
                                cmd = r.to_string();
                            }
                        }
                    }
                    rulcmd.set_command(cmd);
                    rulcmd.set_display_str(desc);
                    let i: u32 = luactx
                        .named_registry_value(LINENO.as_bytes())
                        .expect("line number missing lua registry");
                    let globals = luactx.globals();
                    let tup_shared: AnyUserData = globals.get("tup")?;
                    let mut scriptctx: RefMut<TupScriptContext> = tup_shared.borrow_mut()?;
                    let paths = scriptctx.for_each_rule(i, inputs, rulcmd, outputs)?;
                    let t = luactx.create_table()?;
                    let mut cnt : usize = 1;
                    for p in paths {
                        t.set(cnt, p)?;
                        cnt = cnt + 1;
                    }
                    Ok(Value::Table(t))
                }else {
                    let t = luactx.create_table()?;
                    Ok(Value::Table(t))
                }
            },
        );
        methods.add_function("glob", |luactx, pattern: Value| {
             let path = if let Value::String(ref s) = pattern {
                            s.to_str().unwrap()
                        } else {
                 ""
             };
            //let globals = luactx.globals();
            //let tup_shared: AnyUserData = globals.get("tup")?;
            //let scriptctx: RefMut<TupScriptContext> = tup_shared.borrow_mut()?;
            let outputs   = OutputTagInfo::new();
            let mut bo = BufferObjects::default();
            let matching_paths = discover_inputs_from_glob(Path::new(path), &outputs, &mut bo.pbo).expect("Glob expansion failed");
            let glob_out = luactx.create_table()?;
            let mut cnt = 1;
            for m in matching_paths {
                glob_out.set(cnt as mlua::Integer, m.as_path(&bo.pbo).to_string_lossy().to_string())?;
                cnt = cnt + 1;
            }
            Ok(glob_out)
        });
        methods.add_function_mut(
            "include",
            |luactx,  path: Value| -> Result<(), mlua::Error> {
                luactx
                    .scope(|_scope| -> Result<(), mlua::Error> {
                        let path = if let Value::String(ref s) = path {
                            s.to_str().unwrap()
                        } else {
                            ""
                        };
                        let curdir: String = luactx.named_registry_value(CURDIR.as_bytes())?;
                        let incpath = Path::new(&curdir).join(Path::new(path));
                        println!("include:{}", incpath.to_string_lossy().to_string());

                        let mut file = File::open(&incpath)?;
                        luactx.set_named_registry_value(
                            CURDIR.as_bytes(),
                            incpath
                                .parent()
                                .expect("parent path")
                                .to_string_lossy()
                                .to_string(),
                        )?;
                        let mut contents = Vec::new();
                        file.read_to_end(&mut contents)?;
                        luactx.load(contents.as_bytes()).exec()?;
                         luactx.set_named_registry_value(
                            CURDIR.as_bytes(),
                             curdir
                        )?;
                        Ok(())
                    })
                    .map_err(|e| mlua::Error::ExternalError(Arc::new(e)))?;
                Ok(())
            },
        );
    }
}

pub fn parse_script(script_path: &Path, cfg: SubstMap) -> Result<Vec<Link>, Err> {
    let lua = unsafe {mlua::Lua::unsafe_new()};

    let r = lua.scope(|scope| {
        let tupscriptctx = TupScriptContext::new(cfg);
        let tup_shared = scope.create_userdata(tupscriptctx)?;
        lua.load_from_std_lib(StdLib::DEBUG|StdLib::STRING|StdLib::UTF8|StdLib::IO|StdLib::OS)?;

        let globals = lua.globals();
        globals.set("tup", tup_shared)?;
        globals.set(
            "TUP_CWD",
            script_path.parent().unwrap().to_string_lossy().to_string(),
        )?;
        lua.set_hook(
            HookTriggers {
                every_line: true,
                ..Default::default()
            },
            |lua_context, debug| {
                lua_context
                    .set_named_registry_value(LINENO.as_bytes(), debug.curr_line())
                    .expect("could not set registry value");
                Ok(())
            },
        )?;
        lua.set_named_registry_value(
            CURDIR.as_bytes(),
            script_path
                .parent()
                .expect("could not find script path")
                .to_string_lossy()
                .to_string(),
        )?;
        let tup_append_table = lua.create_function( |luactx, (a,b):(Value, Value)| {
            let mut t = luactx.create_table()?;
            if let Value::String(s) = a {
                t.set(1 as mlua::Integer, s)?;
            } else if let Value::Table(t0) = a {
                t = t0;
            }else if let Value::Nil = a {
                // keep it empty
            }else {
                return Err(SyntaxError{message: "+= operator only works when the source is a table or string".to_string(), incomplete_input: true});
            }
            if let Value::String(s) = b {
                t.set(t.len()? + 1 as i64, s)?;
            }else if let Value::Table(t0) = b {
                let n1 = t.len()?;
                let mut n2 = 1;
                for pair in t0.pairs::<Value, Value>() {
                    let (_,val) = pair?;
                    t.set(n2 + n1, val)?;
                    n2 = n2 + 1;
                }
            }else if let Value::Nil = b {
                // no additions
            }else {
                return Err(SyntaxError {message: "+= operator only works when the value is a table or string".to_string(), incomplete_input: true});
            }
            return Ok(Value::Table(t));
        })?;
        globals.set("tup_append_assignment", tup_append_table)?;

        locate_tupconfig();
        let prelude = r#"
            realtostring = tostring
            tostring = tup_tostring
        "#;
        lua.load(prelude).exec()?;
        let mut file = File::open(script_path)?;
        let mut contents = Vec::new();
        if let  Some(tup_rules) = locate_tuprules(script_path) {
            let mut tup_rules_file = File::open(tup_rules)?;
            tup_rules_file.read_to_end(&mut contents)?;
            lua.load(contents.as_bytes()).exec()?;
            contents.clear();
        }
        file.read_to_end(&mut contents)?;
        lua.load(contents.as_bytes()).exec()?;
        let tup_shared: AnyUserData = globals.get("tup")?;
        let mut scriptctx: RefMut<TupScriptContext> = tup_shared.borrow_mut()?;
        Ok(scriptctx.deref_mut().get_links().collect())
    })?;
    Ok(r)
}
