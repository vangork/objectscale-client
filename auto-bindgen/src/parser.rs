use anyhow::{anyhow, Result};
use convert_case::{Case, Casing};
use indoc::formatdoc;
use std::collections::HashMap;
use std::convert::From;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use syn::{Attribute, Expr, Fields, FnArg, GenericArgument, ImplItem, Item, ItemImpl, ItemStruct, Lit, Meta, Pat, PathArguments, ReturnType, Type, TypePath};
use syn::Visibility;

#[derive(Debug, Eq, PartialEq)]
enum Ty {
    RefSelf,
    Str,
    String,
    Boolean,
    Int,
    Float,
    Object(String),
    Array(String),
    // could be Result("")
    Result(String),
    ResultArray(String),
    Unknown,
}

impl Ty {
    fn from_str(input: &str) -> Ty {
        match input {
            "str" => Ty::Str,
            "String"  => Ty::String,
            "bool" => Ty::Boolean,
            "i32" => Ty::Int,
            "f64" => Ty::Float,
            _ => Ty::Object(input.to_string()),
        }
    }

    fn to_string(&self) -> String {
        match self {
            Ty::Str => "string".to_string(),
            Ty::String => "string".to_string(),
            Ty::Boolean => "bool".to_string(),
            Ty::Int => "int".to_string(),
            Ty::Float => "float".to_string(),
            Ty::Object(name) => format!("*{}", name),
            Ty::Array(name) => format!("[]{}", name),
            _ => "invalid".to_string(),
        }
    }

    fn to_cstring(&self) -> String {
        match self {
            Ty::Str => "intoRCString".to_string(),
            Ty::Boolean => "cbool".to_string(),
            Ty::Result(str) => format!("*{}", str),
            Ty::ResultArray(str) => format!("[]{}", str),
            _ => "invalid".to_string(),
        }
    }

    fn is_std(&self) -> bool {
        match self {
            Ty::Str | Ty::Boolean | Ty::Float | Ty::Int | Ty::String => true,
            _ => false,
        }
    }
}

#[derive(Debug)]
struct Field {
    name: String,
    ty: Ty,
    annotation: Vec<String>,
    is_input: bool,
    is_output: bool,
    is_optional: bool,
    is_mutable: bool,
}

#[derive(Debug)]
struct Method {
    name: String,
    params: Vec<(String, Ty)>,
    return_ty: Ty,
    annotation: Vec<String>,
}

#[derive(Debug)]
struct Struct {
    fields: Vec<Field>,
    methods: Vec<Method>,
    annotation: Vec<String>,
}

impl From<ItemStruct> for Struct {
    fn from(item: ItemStruct) -> Self {
        let mut fields = Vec::new();
        if let Fields::Named(fields_named) = item.fields {
            for field in fields_named.named {
                if let (Visibility::Public(..), Some(ident), Type::Path(path)) = (field.vis, field.ident, field.ty) {
                    let name = ident.to_string();

                    let annotation = Parser::parse_annotation(field.attrs);

                    let ty = Parser::parse_type(&path);

                    fields.push(Field { name, ty, annotation, is_input: false, is_output: false, is_optional: false, is_mutable: false });
                }
            }
        }

        let annotation = Parser::parse_annotation(item.attrs);

        Self { fields, methods: Vec::new(), annotation }
    }
}

impl From<ItemImpl> for Struct {
    fn from(item: ItemImpl) -> Self {
        let mut methods =  Vec::new();

        for item in item.items {
            if let ImplItem::Fn(item_fn) = item {
                if let Visibility::Public(..) = item_fn.vis {
                    let annotation = Parser::parse_annotation(item_fn.attrs);

                    let sig = item_fn.sig;

                    let mut params = Vec::new();
                    for input in sig.inputs {
                        if let FnArg::Typed(pat_type) = input {
                            if let Pat::Ident(ident) = pat_type.pat.as_ref() {
                                let name = ident.ident.to_string();

                                if let Type::Path(path) = pat_type.ty.as_ref() {
                                    if let Some(ident) = path.path.get_ident() {
                                        params.push((name, Ty::from_str(ident.to_string().as_str())));
                                    }
                                } else if let Type::Reference(reference)  = pat_type.ty.as_ref() {
                                    if let Type::Path(path) = reference.elem.as_ref() {
                                        if let Some(ident) = path.path.get_ident() {
                                            if ident.to_string() == "str" {
                                                params.push((name, Ty::from_str("str")));
                                            }
                                        }
                                    }
                                }
                            }
                         } else if let FnArg::Receiver(receiver) = input {
                            if let Type::Reference(reference)  = receiver.ty.as_ref() {
                                if let Type::Path(path) = reference.elem.as_ref() {
                                    if let Some(ident) = path.path.get_ident() {
                                        if ident.to_string() == "Self" {
                                            params.push(("Self".to_string(), Ty::RefSelf));
                                        }
                                    }
                                }
                            }
                        }
                    }

                    let mut return_ty = Ty::Unknown;
                    if let ReturnType::Type(.., box_path) = sig.output {
                        if let Type::Path(path) = box_path.as_ref() {
                            return_ty = Parser::parse_type(path);
                        }
                    }

                    methods.push(Method { name: sig.ident.to_string(), params, return_ty, annotation });
                }
            }
        }

        Self { fields: Vec::new(), methods, annotation: Vec::new() }
    }
}

pub struct Parser {
    mods: HashMap<(String, String), Struct>,
}

impl Parser {
    fn parse_type(path: &TypePath) -> Ty {
        let path = &path.path;
        let mut ty = Ty::Unknown;
        if let Some(ident) = path.get_ident() {
            ty = Ty::from_str(&ident.to_string())
        } else if path.segments.len() == 1 {
            let segment = path.segments.first().unwrap();
            if segment.ident.to_string() == "Vec" {
                if let PathArguments::AngleBracketed(args) = &segment.arguments {
                    if args.args.len() == 1 {
                        if let GenericArgument::Type(Type::Path(path)) = args.args.first().unwrap() {
                            if let Some(ident) = path.path.get_ident()  {
                                ty = Ty::Array(ident.to_string());
                            }
                        }
                    }
                }
            } else if segment.ident.to_string() == "Result" {
                if let PathArguments::AngleBracketed(args) = &segment.arguments {
                    if args.args.len() == 1 {
                        if let GenericArgument::Type(Type::Path(path)) = args.args.first().unwrap() {
                            if let Some(ident) = path.path.get_ident()  {
                                ty = Ty::Result(ident.to_string());
                            } else if path.path.segments.len() == 1 {
                                let segment = path.path.segments.first().unwrap();
                                if segment.ident.to_string() == "Vec" {
                                    if let PathArguments::AngleBracketed(args) = &segment.arguments {
                                        if args.args.len() == 1 {
                                            if let GenericArgument::Type(Type::Path(path)) = args.args.first().unwrap() {
                                                if let Some(ident) = path.path.get_ident()  {
                                                    ty = Ty::ResultArray(ident.to_string());
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        } else if let GenericArgument::Type(Type::Tuple(tuple)) = args.args.first().unwrap() {
                            if tuple.elems.len() == 0 {
                                ty = Ty::Result("".to_string());
                            }
                        }
                    }
                }
            }
        }
        ty
    }

    fn parse_annotation(attributes: Vec<Attribute>) -> Vec<String> {
        let mut annotation: Vec<String> = Vec::new();

        for attr in attributes {
            if attr.style == syn::AttrStyle::Outer {
                if let Meta::NameValue(meta) = attr.meta {
                    if meta.path.is_ident("doc") {
                        if let Expr::Lit(expr) = meta.value {
                            if let Lit::Str(lit) = expr.lit {
                                annotation.push(lit.value().trim().to_string());
                            }
                        }
                    }
                }
            }
        }
        annotation
    }

    fn parse_dir(dir: &PathBuf, mods: &mut HashMap<(String, String), Struct>) -> Result<()> {
        let files = std::fs::read_dir(dir)?;
        for file in files {
            if let Ok(file) = file {
                if file.file_type()?.is_file() {
                    Self::parse_file(&file.path(), mods)?
                } else if file.file_type()?.is_dir() {
                    Self::parse_dir(&file.path(), mods)?
                }
            }
        }

        Ok(())
    }

    fn parse_file(file_path: &PathBuf, mods: &mut HashMap<(String, String), Struct>) -> Result<()> {
        let mut file: File = File::open(file_path)?;
        let mut content = String::new();
        file.read_to_string(&mut content)?;

        let ast = syn::parse_file(&content)?;
        for item in ast.items {
            let file_name = file_path
                        .file_stem()
                        .ok_or_else(|| anyhow!("No file name"))?
                        .to_str()
                        .ok_or_else(|| anyhow!("Fail to convert file name"))?
                        .to_string();
            if let Item::Struct(item) = item {
                if let Visibility::Public(..) = item.vis {
                    let struct_name = item.ident.to_string();
                    mods.insert((file_name.clone(), struct_name), Struct::from(item));
                }
            } else if let Item::Impl(item) = item {
                if let Type::Path(path) = item.self_ty.as_ref() {
                    if let Some(ident) = path.path.get_ident() {
                        let impl_name = ident.to_string();

                        let has_public_method = item.items.iter().any(|item| {
                            if let ImplItem::Fn(item_fn) = item {
                                if let Visibility::Public(..) = item_fn.vis {
                                    return true
                                }
                            }
                            false
                        });

                        if has_public_method {
                            if let Some(value) = mods.get_mut(&(file_name, impl_name)) {
                                value.methods = Struct::from(item).methods;
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub fn parse(crate_dir: &PathBuf) -> Result<Parser> {
        let mut mods = HashMap::new();
        Self::parse_dir(crate_dir, &mut mods)?;
        Ok(Parser { mods })
    }

    pub fn print(&self) {
        for (name, item) in &self.mods {
            println!("{}/{} :{:?}", name.0, name.1, item);
        }

        for (name, item) in &self.mods {
            if item.fields.len() == 0 {
                continue;
            }
            println!("{}.go", name.0);
            println!("// {}", item.annotation.get(0).unwrap_or(&"".to_string()));
            println!("type {} struct {{", name.1);
            for field in &item.fields {
                println!("    // {}", field.annotation.get(0).unwrap_or(&"".to_string()));
                println!("    {} {} `attr:\"{}\"`", field.name.to_case(Case::Pascal), field.ty.to_string(), field.name);
            }
            println!("}}");
        }

        for (name, item) in &self.mods {
            if item.methods.len() == 0 {
                continue;
            }
            println!("{}.go", name.0);

            for annotation in &item.annotation {
                if annotation.is_empty() {
                    break;
                }
                println!("// {}", annotation);
            }
            let class = formatdoc!(r#"
                type {} struct {{
                    {} *C.{}
                }}"#, 
                name.1,
                name.1.to_case(Case::Camel), name.1
            );
            println!("{}", class);

            for method in &item.methods {
                if method.name == "new" {

                    for annotation in &method.annotation {
                        println!("// {}", annotation);
                    }

                    let params = method.params.iter().map(|param| format!("{} {}", param.0, param.1.to_string())).collect::<Vec<String>>().join(", ");
                    let mut variables = String::new();
                    for param in &method.params {
                        variables.push_str(&format!("    c{} := {}({})\n", param.0.to_case(Case::Pascal), param.1.to_cstring(), param.0));
                    }
                    let cparams = method.params.iter().map(|param| format!("c{}", param.0.to_case(Case::Pascal))).collect::<Vec<String>>().join(", ");

                    let new = formatdoc!(r#"
                        func New{}({}) (*{}, error) {{
                            msg := C.RCString{{}}
                        {}
                            {}, err := C.new_{}({}, &msg)
                            if err != nil {{
                                return nil, errorWithMessage(err, msg)
                            }}
                            return &{}{{
                                {},
                            }}, nil
                        }}
                        
                        // Close the {}.
                        // Make sure to call this function when you are done using the {}.
                        func ({} *{}) Close() {{
                            C.destroy_{}({}.{})
                        }}"#,
                        name.1, params, name.1,
                        variables,
                        name.1.to_case(Case::Camel), name.1.to_case(Case::Snake), cparams,
                        name.1,
                        name.1,

                        name.1,
                        name.1,
                        name.1.to_case(Case::Camel), name.1,
                        name.1.to_case(Case::Snake), name.1.to_case(Case::Camel), name.1.to_case(Case::Camel),
                    );
                    println!("{}", new);

                } else {
                    if method.params.len() > 0 && method.params.get(0).unwrap().1 == Ty::RefSelf {
                        for annotation in &method.annotation {
                            println!("// {}", annotation);
                        }

                        let params = method.params.split_first().unwrap().1;
                        let params_str = params.iter().map(|param| format!("{} {}", param.0.to_case(Case::Camel), param.1.to_string())).collect::<Vec<String>>().join(", ");
                        let mut variables = String::new();
                        for param in params {
                            if param.1.is_std() {
                                variables.push_str(&format!("    c{} := {}({})\n", param.0.to_case(Case::Pascal), param.1.to_cstring(), param.0));
                            } else if let Ty::Object(_) = &param.1 {
                                variables.push_str(&format!("    {}Json, err := json.Marshal({})\n", param.0.to_case(Case::Camel), param.0.to_case(Case::Camel)));
                                variables.push_str(&format!("    if err != nil {{ return nil, err }}\n"));
                                variables.push_str(&format!("    c{} := intoRCString(string({}Json))\n", param.0.to_case(Case::Pascal), param.0.to_case(Case::Camel)));
                            }
                        }
                        let cparams = params.iter().map(|param| format!("c{}", param.0.to_case(Case::Pascal))).collect::<Vec<String>>().join(", ");

                        let (return_str, creturn_str) = if method.return_ty == Ty::Result("".to_string()) {
                            (
                                "error".to_string(), 
                                formatdoc!(r#"
                                    _, errFn := C.{}_{}({}.{}, {}, &msg)
                                        if errFn != nil {{
                                            return nil, errorWithMessage(errFn, msg)
                                        }}
                                        return nil
                                    "#, 
                                    name.1.to_case(Case::Snake), method.name, name.1.to_case(Case::Camel), name.1.to_case(Case::Camel), cparams
                                )
                            )
                        } else if let Ty::Result(str) = &method.return_ty {
                            (
                                format!("({}, error)", method.return_ty.to_cstring()),
                                formatdoc!(
                                    r#"
                                    c{}Fn, errFn := C.{}_{}({}.{}, {}, &msg)
                                        if errFn != nil {{
                                            return nil, errorWithMessage(errFn, msg)
                                        }}
                                        {}JsonFn := fromRCString(c{}Fn)
                                        var {}Fn {}
                                        errUnmarshal := json.Unmarshal([]byte({}Json), &{}Fn)
                                        if errUnmarshal != nil {{
                                            return nil, errUnmarshal
                                        }}
                                        return &{}Fn, nil
                                    "#, 
                                    str, name.1.to_case(Case::Snake), method.name, name.1.to_case(Case::Camel), name.1.to_case(Case::Camel), cparams,
                                    str.to_case(Case::Camel), str,
                                    str.to_case(Case::Camel), str,
                                    str.to_case(Case::Camel), str.to_case(Case::Camel),
                                    str.to_case(Case::Camel),
                                )
                            )
                        } else if let Ty::ResultArray(str) = &method.return_ty {
                            (
                                format!("({}, error)", method.return_ty.to_cstring()),
                                formatdoc!(
                                    r#"
                                    c{}sFn, errFn := C.{}_{}({}.{}, {}, &msg)
                                        if errFn != nil {{
                                            return nil, errorWithMessage(errFn, msg)
                                        }}
                                        {}sJsonFn := fromRCString(c{}sFn)
                                        var {}sFn []{}
                                        errUnmarshal := json.Unmarshal([]byte({}JsonFn), &{}Fn)
                                        if errUnmarshal != nil {{
                                            return nil, errUnmarshal
                                        }}
                                        return &{}sFn, nil
                                    "#, 
                                    str, name.1.to_case(Case::Snake), method.name, name.1.to_case(Case::Camel), name.1.to_case(Case::Camel), cparams,
                                    str.to_case(Case::Camel), str,
                                    str.to_case(Case::Camel), str,
                                    str.to_case(Case::Camel), str.to_case(Case::Camel),
                                    str.to_case(Case::Camel),
                                )
                            )
                        } else {
                            ("todo".to_string(), "todo".to_string())
                        };

                        let block = formatdoc!(r#"
                            func ({} *{}) {}({}) {} {{
                                msg := C.RCString{{}}
                            {}
                                {}
                            }}"#,
                            name.1.to_case(Case::Camel), name.1, method.name.to_case(Case::Pascal), params_str, return_str,
                            variables,
                            creturn_str,
                        );
                        println!("{}", block);
                    }
                }
            }
        }
    }
}
