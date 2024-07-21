use crate::serde::SerdeInfo;
use anyhow::{anyhow, Result};
use convert_case::{Case, Casing};
use indoc::formatdoc;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::convert::From;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;
use syn::Visibility;
use syn::{
    Attribute, Expr, Fields, FnArg, GenericArgument, ImplItem, Item, ItemImpl, ItemStruct, Lit,
    Meta, Pat, PathArguments, ReturnType, Type, TypePath,
};

#[derive(Debug, Eq, PartialEq)]
enum Ty {
    RefSelf,
    Str,
    String,
    Boolean,
    Int32,
    Int64,
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
            "String" => Ty::String,
            "bool" => Ty::Boolean,
            "i32" => Ty::Int32,
            "u32" => Ty::Int32,
            "i64" => Ty::Int64,
            "u64" => Ty::Int64,
            "f64" => Ty::Float,
            _ => Ty::Object(input.to_string()),
        }
    }

    fn to_rust_string(&self) -> String {
        match self {
            Ty::Str => "&str".to_string(),
            Ty::String => "String".to_string(),
            Ty::Boolean => "bool".to_string(),
            Ty::Int32 => "i32".to_string(),
            Ty::Int64 => "i64".to_string(),
            Ty::Float => "f32".to_string(),
            Ty::Object(name) => format!("{}", name),
            Ty::Array(name) => format!("Vec<{}>", name),
            Ty::Result(name) => format!("Result<{}>", name),
            Ty::ResultArray(name) => format!("Result<Vec<{}>>", name),
            _ => "invalid".to_string(),
        }
    }

    fn to_string(&self) -> String {
        match self {
            Ty::Str => "string".to_string(),
            Ty::String => "string".to_string(),
            Ty::Boolean => "bool".to_string(),
            Ty::Int32 => "int32".to_string(),
            Ty::Int64 => "int64".to_string(),
            Ty::Float => "float".to_string(),
            Ty::Object(name) => format!("*{}", name),
            Ty::Array(name) => format!("[]{}", if name == "String" { "string" } else { name }),
            _ => "invalid".to_string(),
        }
    }

    fn to_obj_string(&self) -> String {
        match self {
            Ty::Str => "string".to_string(),
            Ty::String => "string".to_string(),
            Ty::Boolean => "bool".to_string(),
            Ty::Int32 => "int32".to_string(),
            Ty::Int64 => "int64".to_string(),
            Ty::Float => "float".to_string(),
            Ty::Object(name) => format!("{}", name),
            Ty::Array(name) => format!("[]{}", if name == "String" { "string" } else { name }),
            _ => "invalid".to_string(),
        }
    }

    fn to_ffi_string(&self) -> String {
        match self {
            Ty::Str => "RCString".to_string(),
            Ty::String => "RCString".to_string(),
            Ty::Boolean => "bool".to_string(),
            Ty::Object(_) => "RCString".to_string(),
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
            Ty::Str | Ty::Boolean | Ty::Float | Ty::Int32 | Ty::Int64 | Ty::String => true,
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
    serde_info: Option<SerdeInfo>,
    has_builder: bool,
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
    serde_info: Option<SerdeInfo>,
    has_builder: bool,
}

impl From<ItemStruct> for Struct {
    fn from(item: ItemStruct) -> Self {
        // parse struct serde
        let mut serde_info = None;
        let mut has_builder = false;
        for attr in &item.attrs {
            if let Meta::List(meta_list) = &attr.meta {
                if meta_list.path.is_ident("serde") {
                    let tokens = meta_list.tokens.clone();
                    let value = syn::parse2::<SerdeInfo>(tokens).unwrap();
                    if value.is_valid() {
                        serde_info = Some(value);
                    }
                }
                if meta_list.path.is_ident("builder") {
                    has_builder = true;
                }
            }
        }

        let mut fields = Vec::new();
        if let Fields::Named(fields_named) = item.fields {
            for field in fields_named.named {
                if let (Visibility::Public(..), Some(ident), Type::Path(path)) =
                    (&field.vis, &field.ident, &field.ty)
                {
                    let name = ident.to_string();

                    // parse field serde
                    let mut serde_info = None;
                    let mut has_builder = false;
                    for attr in &field.attrs {
                        if let Meta::List(meta_list) = &attr.meta {
                            if meta_list.path.is_ident("serde") {
                                let tokens = meta_list.tokens.clone();
                                let value = syn::parse2::<SerdeInfo>(tokens).unwrap();
                                if value.is_valid() {
                                    serde_info = Some(value);
                                }
                            }
                            if meta_list.path.is_ident("builder") {
                                has_builder = true;
                            }
                        }
                    }

                    let annotation = Bindgen::parse_annotation(field.attrs);

                    let ty = Bindgen::parse_type(&path);

                    fields.push(Field {
                        name,
                        ty,
                        annotation,
                        is_input: false,
                        is_output: false,
                        is_optional: false,
                        is_mutable: false,
                        serde_info,
                        has_builder,
                    });
                }
            }
        }

        let annotation = Bindgen::parse_annotation(item.attrs);

        Self {
            fields,
            methods: Vec::new(),
            annotation,
            serde_info,
            has_builder,
        }
    }
}

impl From<ItemImpl> for Struct {
    fn from(item: ItemImpl) -> Self {
        let mut methods = Vec::new();

        for item in item.items {
            if let ImplItem::Fn(item_fn) = item {
                if let Visibility::Public(..) = item_fn.vis {
                    let annotation = Bindgen::parse_annotation(item_fn.attrs);

                    let sig = item_fn.sig;

                    let mut params = Vec::new();
                    for input in sig.inputs {
                        if let FnArg::Typed(pat_type) = input {
                            if let Pat::Ident(ident) = pat_type.pat.as_ref() {
                                let name = ident.ident.to_string();

                                if let Type::Path(path) = pat_type.ty.as_ref() {
                                    if let Some(ident) = path.path.get_ident() {
                                        params
                                            .push((name, Ty::from_str(ident.to_string().as_str())));
                                    }
                                } else if let Type::Reference(reference) = pat_type.ty.as_ref() {
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
                            if let Type::Reference(reference) = receiver.ty.as_ref() {
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
                            return_ty = Bindgen::parse_type(path);
                        }
                    }

                    methods.push(Method {
                        name: sig.ident.to_string(),
                        params,
                        return_ty,
                        annotation,
                    });
                }
            }
        }

        Self {
            fields: Vec::new(),
            methods,
            annotation: Vec::new(),
            serde_info: None,
            has_builder: false,
        }
    }
}

pub struct Bindgen {
    // <<file_name, struct_name>, strcuct>
    mods: BTreeMap<(String, String), Struct>,
    // <struct_name, file_name>
    structs: HashMap<String, String>,
}

impl Bindgen {
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
                        if let GenericArgument::Type(Type::Path(path)) = args.args.first().unwrap()
                        {
                            if let Some(ident) = path.path.get_ident() {
                                ty = Ty::Array(ident.to_string());
                            }
                        }
                    }
                }
            } else if segment.ident.to_string() == "Result" {
                if let PathArguments::AngleBracketed(args) = &segment.arguments {
                    if args.args.len() == 1 {
                        if let GenericArgument::Type(Type::Path(path)) = args.args.first().unwrap()
                        {
                            if let Some(ident) = path.path.get_ident() {
                                ty = Ty::Result(ident.to_string());
                            } else if path.path.segments.len() == 1 {
                                let segment = path.path.segments.first().unwrap();
                                if segment.ident.to_string() == "Vec" {
                                    if let PathArguments::AngleBracketed(args) = &segment.arguments
                                    {
                                        if args.args.len() == 1 {
                                            if let GenericArgument::Type(Type::Path(path)) =
                                                args.args.first().unwrap()
                                            {
                                                if let Some(ident) = path.path.get_ident() {
                                                    ty = Ty::ResultArray(ident.to_string());
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        } else if let GenericArgument::Type(Type::Tuple(tuple)) =
                            args.args.first().unwrap()
                        {
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

    fn parse_dir(
        dir: &PathBuf,
        mods: &mut BTreeMap<(String, String), Struct>,
        structs: &mut HashMap<String, String>,
    ) -> Result<()> {
        let files = std::fs::read_dir(dir)?;
        for file in files {
            if let Ok(file) = file {
                if file.file_type()?.is_file() {
                    Self::parse_file(&file.path(), mods, structs)?
                } else if file.file_type()?.is_dir() {
                    Self::parse_dir(&file.path(), mods, structs)?
                }
            }
        }

        Ok(())
    }

    fn parse_file(
        file_path: &PathBuf,
        mods: &mut BTreeMap<(String, String), Struct>,
        structs: &mut HashMap<String, String>,
    ) -> Result<()> {
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
                    mods.insert((file_name.clone(), struct_name.clone()), Struct::from(item));
                    structs.insert(struct_name, file_name);
                }
            } else if let Item::Impl(item) = item {
                if let Type::Path(path) = item.self_ty.as_ref() {
                    if let Some(ident) = path.path.get_ident() {
                        let impl_name = ident.to_string();

                        let has_public_method = item.items.iter().any(|item| {
                            if let ImplItem::Fn(item_fn) = item {
                                if let Visibility::Public(..) = item_fn.vis {
                                    return true;
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

    fn get_serde_type(&self, struct_name: &str) -> String {
        let file_name = self.structs.get(struct_name).unwrap();
        let serde_info = &self
            .mods
            .get(&(file_name.to_owned(), struct_name.to_owned()))
            .unwrap()
            .serde_info;
        let mut serde_type = "json".to_string();
        if let Some(serde_info) = serde_info {
            if serde_info.serialize_case != serde_info.deserialize_case {
                serde_type = "yaml".to_string();
            }
        }
        serde_type
    }

    pub fn parse(crate_dir: &PathBuf) -> Result<Self> {
        let mut mods = BTreeMap::new();
        let mut structs = HashMap::new();
        Self::parse_dir(crate_dir, &mut mods, &mut structs)?;
        Ok(Self { mods, structs })
    }

    fn gen_c(&self, gen_dir: &PathBuf) {
        let c_dir = gen_dir.join("c").join("src");
        if std::fs::read_dir(&c_dir).is_err() {
            std::fs::create_dir_all(&c_dir).unwrap();
        }

        let mut file_writers: HashMap<String, File> = HashMap::new();

        for (name, item) in &self.mods {
            if item.methods.len() == 0 {
                continue;
            }
            //println!("{}.rs", name.0);
            let file_name = format!("{}.rs", name.0);
            let mut writer = if let Some(file) = file_writers.get_mut(&file_name) {
                file
            } else {
                let file_path = c_dir.join(&file_name);
                let file = OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(file_path)
                    .unwrap();
                file_writers.insert(file_name.clone(), file);
                let mut w = file_writers.get_mut(&file_name).unwrap();
                writeln!(&mut w, "use crate::error::{{clear_error, set_error}};").unwrap();
                writeln!(&mut w, "use crate::ffi::RCString;").unwrap();
                writeln!(&mut w, "use anyhow::anyhow;").unwrap();
                writeln!(&mut w, "use objectscale_client::{};", name.0).unwrap();
                writeln!(
                    &mut w,
                    "use std::panic::{{catch_unwind, AssertUnwindSafe}};"
                )
                .unwrap();
                writeln!(&mut w, "use std::ptr;\n").unwrap();
                w
            };

            for annotation in &item.annotation {
                if annotation.is_empty() {
                    break;
                }
                writeln!(&mut writer, "/// {}", annotation).unwrap();
            }
            let class = formatdoc!(
                r#"
                pub struct {} {{
                    {}: {}::{},
                }}"#,
                name.1,
                name.1.to_case(Case::Snake),
                name.0,
                name.1,
            );
            writeln!(&mut writer, "{}\n", class).unwrap();

            for method in &item.methods {
                if method.name == "new" {
                    for annotation in &method.annotation {
                        writeln!(&mut writer, "/// {}", annotation).unwrap();
                    }

                    let mut params = method
                        .params
                        .iter()
                        .map(|param| format!("{}: {}", param.0, param.1.to_ffi_string()))
                        .collect::<Vec<String>>()
                        .join(", ");
                    if !params.is_empty() {
                        params = format!("{}, ", params);
                    }

                    let mut variables = String::new();
                    for param in &method.params {
                        if param.1 == Ty::Str || param.1 == Ty::String {
                            variables.push_str(&format!(
                                "        let {} = {}.to_string();\n",
                                param.0, param.0
                            ));
                        } else if let Ty::Object(ty) = &param.1 {
                            variables.push_str(&format!(
                                "        let {} = {}.to_string();\n",
                                param.0, param.0
                            ));
                            variables.push_str(&format!(
                                "        let {}: objectscale_client::{}::{} = serde_json::from_str(&{}).expect(\"deserialize {}\");\n",
                                param.0, self.structs.get(ty).unwrap(), ty, param.0, param.0
                            ));
                        }
                    }

                    let cparams = method
                        .params
                        .iter()
                        .map(|param| {
                            if param.1 == Ty::Str {
                                format!("&{}", param.0)
                            } else {
                                param.0.clone()
                            }
                        })
                        .collect::<Vec<String>>()
                        .join(", ");

                    let new = formatdoc!(
                        r#"
                        #[no_mangle]
                        pub unsafe extern "C" fn new_{}(
                            {}err: Option<&mut RCString>,
                        ) -> *mut {} {{
                            match catch_unwind(|| {{
                        {}
                                {}::{}::new({})
                            }}) {{
                                Ok(result) => {{
                                    clear_error();
                                    match result {{
                                        Ok({}) => {{
                                            let {} = {} {{ {} }};
                                            Box::into_raw(Box::new({}))
                                        }}
                                        Err(e) => {{
                                            set_error(e.to_string().as_str(), err);
                                            ptr::null_mut()
                                        }}
                                    }}
                                }}
                                Err(_) => {{
                                    set_error("caught panic during {} creation", err);
                                    ptr::null_mut()
                                }}
                            }}
                        }}

                        #[no_mangle]
                        pub extern "C" fn destroy_{}({}: *mut {}) {{
                            if !{}.is_null() {{
                                unsafe {{
                                    drop(Box::from_raw({}));
                                }}
                            }}
                        }}"#,
                        name.1.to_case(Case::Snake),
                        params,
                        name.1,
                        variables,
                        name.0,
                        name.1,
                        cparams,
                        name.1.to_case(Case::Snake),
                        name.1.to_case(Case::Snake),
                        name.1,
                        name.1.to_case(Case::Snake),
                        name.1.to_case(Case::Snake),
                        name.1.to_case(Case::Lower),
                        name.1.to_case(Case::Snake),
                        name.1.to_case(Case::Snake),
                        name.1,
                        name.1.to_case(Case::Snake),
                        name.1.to_case(Case::Snake),
                    );
                    writeln!(&mut writer, "{}\n", new).unwrap();
                } else {
                    if method.params.len() > 0 && method.params.get(0).unwrap().1 == Ty::RefSelf {
                        for annotation in &method.annotation {
                            writeln!(&mut writer, "/// {}", annotation).unwrap();
                        }

                        let params = method.params.split_first().unwrap().1;
                        let mut params_str = params
                            .iter()
                            .map(|param| format!("{}: {}", param.0, param.1.to_ffi_string()))
                            .collect::<Vec<String>>()
                            .join(", ");
                        if !params_str.is_empty() {
                            params_str = format!("{},", params_str);
                        }

                        let return_val = if method.name.starts_with("new") {
                            if let Ty::Result(name) = &method.return_ty {
                                format!(" -> *mut {} ", name)
                            } else {
                                " invalid ".to_string()
                            }
                        } else {
                            if Ty::Result("".to_string()) == method.return_ty {
                                " ".to_string()
                            } else if let Ty::Result(_) = method.return_ty {
                                " -> RCString ".to_string()
                            } else if let Ty::ResultArray(_) = method.return_ty {
                                " -> RCString ".to_string()
                            } else {
                                " invalid ".to_string()
                            }
                        };

                        let mut variables = String::new();
                        for param in &method.params {
                            if param.1 == Ty::Str || param.1 == Ty::String {
                                variables.push_str(&format!(
                                    "        let {} = {}.to_string();\n",
                                    param.0, param.0
                                ));
                            } else if let Ty::Object(ty) = &param.1 {
                                variables.push_str(&format!(
                                    "        let {} = {}.to_string();\n",
                                    param.0, param.0
                                ));
                                variables.push_str(&format!(
                                    "        let {}: objectscale_client::{}::{} = serde_json::from_str(&{}).expect(\"deserialize {}\");\n",
                                    param.0, self.structs.get(ty).unwrap(), ty, param.0, param.0
                                ));
                            }
                        }

                        let cparams = params
                            .iter()
                            .map(|param| {
                                if param.1 == Ty::Str {
                                    format!("&{}", param.0)
                                } else {
                                    param.0.clone()
                                }
                            })
                            .collect::<Vec<String>>()
                            .join(", ");

                        let return_nul = if method.name.starts_with("new") {
                            "ptr::null_mut()"
                        } else {
                            if Ty::Result("".to_string()) == method.return_ty {
                                ""
                            } else {
                                "RCString::null()"
                            }
                        };

                        let (return_return_transform, return_return_variable, return_return_val) =
                            if method.name.starts_with("new") {
                                if let Ty::Result(ty) = &method.return_ty {
                                    (
                                        "clear_error();".to_string(),
                                        ty.to_case(Case::Snake),
                                        format!(
                                            "Box::into_raw(Box::new({} {{ {} }}))",
                                            ty,
                                            ty.to_case(Case::Snake)
                                        ),
                                    )
                                } else {
                                    ("".to_string(), "invalid".to_string(), "invalid".to_string())
                                }
                            } else {
                                if Ty::Result("".to_string()) == method.return_ty {
                                    ("".to_string(), "_".to_string(), "return".to_string())
                                } else if let Ty::Result(ty) = &method.return_ty {
                                    let serde_type = self.get_serde_type(ty);
                                    (
                                        format!("let result = result.and_then(|{}| serde_{}::to_string(&{}).map_err(|e| anyhow!(e)));", ty.to_case(Case::Snake), serde_type, ty.to_case(Case::Snake)),
                                        ty.to_case(Case::Snake),
                                        format!("RCString::from_str({}.as_str())", ty.to_case(Case::Snake)),
                                    )
                                } else if let Ty::ResultArray(ty) = &method.return_ty {
                                    let serde_type = self.get_serde_type(ty);
                                    (
                                    format!("let result = result.and_then(|{}s| serde_{}::to_string(&{}s).map_err(|e| anyhow!(e)));", ty.to_case(Case::Snake), serde_type, ty.to_case(Case::Snake)),
                                    format!("{}s", ty.to_case(Case::Snake)),
                                    format!("RCString::from_str({}s.as_str())", ty.to_case(Case::Snake))
                                )
                                } else {
                                    (
                                        "invalid".to_string(),
                                        "invalid".to_string(),
                                        "invalid".to_string(),
                                    )
                                }
                            };

                        let block = formatdoc!(
                            r#"
                            #[no_mangle]
                            pub unsafe extern "C" fn {}_{}(
                                {}: *mut {}, {}
                                err: Option<&mut RCString>,
                            ){}{{
                                let {} = &mut *{};
                                match catch_unwind(AssertUnwindSafe(move || {{
                            {}
                                    {}.{}.{}({})
                                }})) {{
                                    Ok(result) => {{
                                        {}
                                        clear_error();
                                        match result {{
                                            Ok({}) => {},
                                            Err(e) => {{
                                                set_error(e.to_string().as_str(), err);
                                                {}
                                            }}
                                        }}
                                    }}
                                    Err(_) => {{
                                        set_error("caught panic during {}", err);
                                        {}
                                    }}
                                }}
                            }}"#,
                            name.1.to_case(Case::Snake),
                            method.name,
                            name.1.to_case(Case::Snake),
                            name.1,
                            params_str,
                            return_val,
                            name.1.to_case(Case::Snake),
                            name.1.to_case(Case::Snake),
                            variables,
                            name.1.to_case(Case::Snake),
                            name.1.to_case(Case::Snake),
                            method.name,
                            cparams,
                            return_return_transform,
                            return_return_variable,
                            return_return_val,
                            return_nul,
                            method.name.to_case(Case::Lower),
                            return_nul,
                        );
                        writeln!(&mut writer, "{}\n", block).unwrap();

                        if method.name.starts_with("new") {
                            if let Ty::Result(ty) = &method.return_ty {
                                let block = formatdoc!(
                                    r#"
                                    #[no_mangle]
                                    pub extern "C" fn destroy_{}({}: *mut {}) {{
                                        if !{}.is_null() {{
                                            unsafe {{
                                                drop(Box::from_raw({}));
                                            }}
                                        }}
                                    }}"#,
                                    ty.to_case(Case::Snake),
                                    ty.to_case(Case::Snake),
                                    ty,
                                    ty.to_case(Case::Snake),
                                    ty.to_case(Case::Snake),
                                );
                                writeln!(&mut writer, "{}\n", block).unwrap();
                            }
                        }
                    }
                }
            }
        }
    }

    fn gen_go_over_c(&self, gen_dir: &PathBuf) {
        let go_dir = gen_dir.join("golang").join("pkg");
        if std::fs::read_dir(&go_dir).is_err() {
            std::fs::create_dir_all(&go_dir).unwrap();
        }

        let mut file_writers: HashMap<String, File> = HashMap::new();

        for (name, item) in &self.mods {
            if item.fields.len() == 0 {
                continue;
            }

            let file_name = format!("{}.go", name.0);
            let mut writer = if let Some(file) = file_writers.get_mut(&file_name) {
                file
            } else {
                let file_path = go_dir.join(&file_name);
                let file = OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(file_path)
                    .unwrap();
                file_writers.insert(file_name.clone(), file);
                let mut w = file_writers.get_mut(&file_name).unwrap();
                let header = formatdoc!(
                    r#"
                    package pkg

                    // #include "objectscale_client.h"
                    import "C"
                    "#
                );
                writeln!(&mut w, "{}", header).unwrap();
                w
            };

            //println!("{}.go", name.0);
            writeln!(
                &mut writer,
                "// {}",
                item.annotation.get(0).unwrap_or(&"".to_string())
            )
            .unwrap();
            writeln!(&mut writer, "type {} struct {{", name.1).unwrap();
            for field in &item.fields {
                writeln!(
                    &mut writer,
                    "    // {}",
                    field.annotation.get(0).unwrap_or(&"".to_string())
                )
                .unwrap();

                let tag = if let Some(serde_info) = item.serde_info.as_ref() {
                    if serde_info.serialize_case == serde_info.deserialize_case {
                        if let Some(serde_info) = field.serde_info.as_ref() {
                            if serde_info.rename_deserialize != serde_info.rename_serialize {
                                println!(
                                    "{}/{}::{} has invalid serde rename",
                                    name.0, name.1, field.name
                                );
                            }
                            format!(
                                r#"`attr:"{}" json:"{}"`"#,
                                field.name,
                                serde_info.rename_deserialize.as_ref().unwrap()
                            )
                        } else {
                            if let Some(case) = serde_info.deserialize_case.as_ref() {
                                if case.to_owned() != Case::Pascal {
                                    format!(
                                        r#"`attr:"{}" json:"{}"`"#,
                                        field.name,
                                        field.name.to_case(case.to_owned())
                                    )
                                } else {
                                    format!(r#"`attr:"{}"`"#, field.name)
                                }
                            } else {
                                format!(r#"`attr:"{}"`"#, field.name)
                            }
                        }
                    } else {
                        if let Some(field_serde_info) = field.serde_info.as_ref() {
                            let serialize_name =
                                if let Some(name) = field_serde_info.rename_serialize.as_ref() {
                                    name
                                } else if let Some(case) = serde_info.serialize_case.as_ref() {
                                    &field.name.to_case(case.to_owned())
                                } else {
                                    &field.name
                                };
                            let deserialize_name =
                                if let Some(name) = field_serde_info.rename_deserialize.as_ref() {
                                    name
                                } else if let Some(case) = serde_info.deserialize_case.as_ref() {
                                    &field.name.to_case(case.to_owned())
                                } else {
                                    &field.name
                                };
                            format!(
                                r#"`attr:"{}" yaml:"{}" json:"{}"`"#,
                                field.name, serialize_name, deserialize_name
                            )
                        } else {
                            let serialize_case =
                                if let Some(case) = serde_info.serialize_case.as_ref() {
                                    case.to_owned()
                                } else {
                                    Case::Snake
                                };

                            let deserialize_case =
                                if let Some(case) = serde_info.deserialize_case.as_ref() {
                                    case.to_owned()
                                } else {
                                    Case::Snake
                                };
                            format!(
                                r#"`attr:"{}" yaml:"{}" json:"{}"`"#,
                                field.name,
                                field.name.to_case(serialize_case),
                                field.name.to_case(deserialize_case)
                            )
                        }
                    }
                } else {
                    format!(r#"`attr:"{}"`"#, field.name)
                };
                writeln!(
                    &mut writer,
                    "    {} {} {}",
                    field.name.to_case(Case::Pascal),
                    field.ty.to_obj_string(),
                    tag,
                )
                .unwrap();
            }
            writeln!(&mut writer, "}}\n").unwrap();
        }

        for (name, item) in &self.mods {
            if item.methods.len() == 0 {
                continue;
            }
            //println!("{}.go", name.0);
            let file_name = format!("{}.go", name.0);
            let mut writer = if let Some(file) = file_writers.get_mut(&file_name) {
                file
            } else {
                let file_path = go_dir.join(&file_name);
                let file = OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(file_path)
                    .unwrap();
                file_writers.insert(file_name.clone(), file);
                let mut w = file_writers.get_mut(&file_name).unwrap();
                let header = formatdoc!(
                    r#"
                    package pkg

                    // #include "objectscale_client.h"
                    import "C"
                    import (
                        "encoding/json"
                        "gopkg.in/yaml.v3"
                    )
                    "#
                );
                writeln!(&mut w, "{}", header).unwrap();
                w
            };

            for annotation in &item.annotation {
                if annotation.is_empty() {
                    break;
                }
                writeln!(&mut writer, "// {}", annotation).unwrap();
            }
            let class = formatdoc!(
                r#"
                type {} struct {{
                    {} *C.{}
                }}"#,
                name.1,
                name.1.to_case(Case::Camel),
                name.1
            );
            writeln!(&mut writer, "{}", class).unwrap();

            for method in &item.methods {
                if method.name == "new" {
                    for annotation in &method.annotation {
                        writeln!(&mut writer, "// {}", annotation).unwrap();
                    }

                    let params = method
                        .params
                        .iter()
                        .map(|param| format!("{} {}", param.0, param.1.to_string()))
                        .collect::<Vec<String>>()
                        .join(", ");
                    let mut variables = String::new();
                    for param in &method.params {
                        variables.push_str(&format!(
                            "    c{} := {}({})\n",
                            param.0.to_case(Case::Pascal),
                            param.1.to_cstring(),
                            param.0
                        ));
                    }
                    let mut cparams = method
                        .params
                        .iter()
                        .map(|param| format!("c{}", param.0.to_case(Case::Pascal)))
                        .collect::<Vec<String>>()
                        .join(", ");
                    if !cparams.is_empty() {
                        cparams = format!("{}, ", cparams);
                    }

                    let new = formatdoc!(
                        r#"
                        func New{}({}) (*{}, error) {{
                            msg := C.RCString{{}}
                        {}
                            {}, err := C.new_{}({}&msg)
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
                        name.1,
                        params,
                        name.1,
                        variables,
                        name.1.to_case(Case::Camel),
                        name.1.to_case(Case::Snake),
                        cparams,
                        name.1,
                        name.1.to_case(Case::Camel),
                        name.1,
                        name.1,
                        name.1.to_case(Case::Camel),
                        name.1,
                        name.1.to_case(Case::Snake),
                        name.1.to_case(Case::Camel),
                        name.1.to_case(Case::Camel),
                    );
                    writeln!(&mut writer, "{}\n", new).unwrap();
                } else {
                    if method.params.len() > 0 && method.params.get(0).unwrap().1 == Ty::RefSelf {
                        for annotation in &method.annotation {
                            writeln!(&mut writer, "// {}", annotation).unwrap();
                        }

                        let params = method.params.split_first().unwrap().1;
                        let params_str = params
                            .iter()
                            .map(|param| {
                                format!("{} {}", param.0.to_case(Case::Camel), param.1.to_string())
                            })
                            .collect::<Vec<String>>()
                            .join(", ");
                        let mut variables = String::new();
                        for param in params {
                            if param.1.is_std() {
                                variables.push_str(&format!(
                                    "    c{} := {}({})\n",
                                    param.0.to_case(Case::Pascal),
                                    param.1.to_cstring(),
                                    param.0.to_case(Case::Camel)
                                ));
                            } else if let Ty::Object(_) = &param.1 {
                                variables.push_str(&format!(
                                    "    {}Json, err := json.Marshal({})\n",
                                    param.0.to_case(Case::Camel),
                                    param.0.to_case(Case::Camel)
                                ));
                                variables.push_str(&format!(
                                    "{}",
                                    if method.return_ty == Ty::Result("".to_string()) {
                                        "    if err != nil { return err }\n"
                                    } else {
                                        "    if err != nil { return nil, err }\n"
                                    }
                                ));
                                variables.push_str(&format!(
                                    "    c{} := intoRCString(string({}Json))\n",
                                    param.0.to_case(Case::Pascal),
                                    param.0.to_case(Case::Camel)
                                ));
                            }
                        }
                        let mut cparams = params
                            .iter()
                            .map(|param| format!("c{}", param.0.to_case(Case::Pascal)))
                            .collect::<Vec<String>>()
                            .join(", ");
                        if !cparams.is_empty() {
                            cparams = format!("{}, ", cparams);
                        }

                        let (return_str, creturn_str) = if method.name.starts_with("new") {
                            if let Ty::Result(ty) = &method.return_ty {
                                (
                                    format!("(*{}, error)", ty),
                                    formatdoc!(
                                        r#"
                                    {}, err := C.{}_{}({}.{}, {}&msg)
                                        if err != nil {{
                                            return nil, errorWithMessage(err, msg)
                                        }}
                                        return &{}{{
                                            {},
                                        }}, nil"#,
                                        ty.to_case(Case::Camel),
                                        name.1.to_case(Case::Snake),
                                        method.name,
                                        name.1.to_case(Case::Camel),
                                        name.1.to_case(Case::Camel),
                                        cparams,
                                        ty,
                                        ty.to_case(Case::Camel),
                                    ),
                                )
                            } else {
                                ("invalid".to_string(), "invalid".to_string())
                            }
                        } else {
                            if method.return_ty == Ty::Result("".to_string()) {
                                (
                                    "error".to_string(),
                                    formatdoc!(
                                        r#"
                                    _, errFn := C.{}_{}({}.{}, {}&msg)
                                        if errFn != nil {{
                                            return errorWithMessage(errFn, msg)
                                        }}
                                        return nil
                                    "#,
                                        name.1.to_case(Case::Snake),
                                        method.name,
                                        name.1.to_case(Case::Camel),
                                        name.1.to_case(Case::Camel),
                                        cparams
                                    ),
                                )
                            } else if let Ty::Result(str) = &method.return_ty {
                                let serde_type = self.get_serde_type(str);
                                (
                                    format!("({}, error)", method.return_ty.to_cstring()),
                                    formatdoc!(
                                        r#"
                                    c{}Fn, errFn := C.{}_{}({}.{}, {}&msg)
                                        if errFn != nil {{
                                            return nil, errorWithMessage(errFn, msg)
                                        }}
                                        {}{}Fn := fromRCString(c{}Fn)
                                        var {}Fn {}
                                        errUnmarshal := {}.Unmarshal([]byte({}{}Fn), &{}Fn)
                                        if errUnmarshal != nil {{
                                            return nil, errUnmarshal
                                        }}
                                        return &{}Fn, nil"#,
                                        str,
                                        name.1.to_case(Case::Snake),
                                        method.name,
                                        name.1.to_case(Case::Camel),
                                        name.1.to_case(Case::Camel),
                                        cparams,
                                        str.to_case(Case::Camel),
                                        serde_type.to_case(Case::Pascal),
                                        str,
                                        str.to_case(Case::Camel),
                                        str,
                                        serde_type,
                                        str.to_case(Case::Camel),
                                        serde_type.to_case(Case::Pascal),
                                        str.to_case(Case::Camel),
                                        str.to_case(Case::Camel),
                                    ),
                                )
                            } else if let Ty::ResultArray(str) = &method.return_ty {
                                let serde_type = self.get_serde_type(str);
                                (
                                    format!("({}, error)", method.return_ty.to_cstring()),
                                    formatdoc!(
                                        r#"
                                    c{}sFn, errFn := C.{}_{}({}.{}, {}&msg)
                                        if errFn != nil {{
                                            return nil, errorWithMessage(errFn, msg)
                                        }}
                                        {}s{}Fn := fromRCString(c{}sFn)
                                        var {}sFn []{}
                                        errUnmarshal := {}.Unmarshal([]byte({}s{}Fn), &{}sFn)
                                        if errUnmarshal != nil {{
                                            return nil, errUnmarshal
                                        }}
                                        return {}sFn, nil"#,
                                        str,
                                        name.1.to_case(Case::Snake),
                                        method.name,
                                        name.1.to_case(Case::Camel),
                                        name.1.to_case(Case::Camel),
                                        cparams,
                                        str.to_case(Case::Camel),
                                        serde_type.to_case(Case::Pascal),
                                        str,
                                        str.to_case(Case::Camel),
                                        str,
                                        serde_type,
                                        str.to_case(Case::Camel),
                                        serde_type.to_case(Case::Pascal),
                                        str.to_case(Case::Camel),
                                        str.to_case(Case::Camel),
                                    ),
                                )
                            } else {
                                ("invalid".to_string(), "invalid".to_string())
                            }
                        };
                        let block = formatdoc!(
                            r#"
                            func ({} *{}) {}({}) {} {{
                                msg := C.RCString{{}}
                            {}
                                {}
                            }}"#,
                            name.1.to_case(Case::Camel),
                            name.1,
                            method.name.to_case(Case::Pascal),
                            params_str,
                            return_str,
                            variables,
                            creturn_str,
                        );
                        writeln!(&mut writer, "{}\n", block).unwrap();

                        if method.name.starts_with("new") {
                            if let Ty::Result(ty) = &method.return_ty {
                                let block = formatdoc!(
                                    r#"
                                    // Close the {}.
                                    // Make sure to call this function when you are done using the {}.
                                    func ({} *{}) Close() {{
                                        C.destroy_{}({}.{})
                                    }}"#,
                                    ty,
                                    ty.to_case(Case::Lower),
                                    ty.to_case(Case::Camel),
                                    ty,
                                    ty.to_case(Case::Snake),
                                    ty.to_case(Case::Camel),
                                    ty.to_case(Case::Camel)
                                );
                                writeln!(&mut writer, "{}\n", block).unwrap();
                            }
                        }
                    }
                }
            }
        }
    }

    fn gen_python(&self, gen_dir: &PathBuf) {
        let python_dir = gen_dir.join("python").join("src");
        if std::fs::read_dir(&python_dir).is_err() {
            std::fs::create_dir_all(&python_dir).unwrap();
        }

        let mut file_writers: HashMap<String, File> = HashMap::new();
        let mut objects: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

        // resources definition
        for (name, item) in &self.mods {
            if item.fields.len() == 0 {
                objects.insert(name.0.to_string(), BTreeSet::new());
                continue;
            }

            if let Some(array) = objects.get_mut(&name.0) {
                array.insert(name.1.to_string());
            } else {
                objects.insert(name.0.to_string(), BTreeSet::from([name.1.to_string()]));
            }

            let file_name = format!("{}.rs", name.0);
            let mut writer = if let Some(file) = file_writers.get_mut(&file_name) {
                file
            } else {
                let file_path = python_dir.join(&file_name);
                let file = OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(file_path)
                    .unwrap();
                file_writers.insert(file_name.clone(), file);
                let mut w = file_writers.get_mut(&file_name).unwrap();
                let header = formatdoc!(
                    r#"
                    use objectscale_client::{};
                    use pyo3::prelude::*;
                    use std::convert::From;
                    "#,
                    name.0,
                );
                writeln!(&mut w, "{}", header).unwrap();
                w
            };

            writeln!(
                &mut writer,
                "// {}",
                item.annotation.get(0).unwrap_or(&"".to_string())
            )
            .unwrap();

            let struct_header = formatdoc!(
                r#"
                #[derive(Clone, Debug, Default)]
                #[pyclass(get_all)]
                pub(crate) struct {} {{"#,
                name.1,
            );
            writeln!(&mut writer, "{}", struct_header).unwrap();
            for field in &item.fields {
                writeln!(
                    &mut writer,
                    "    // {}",
                    field.annotation.get(0).unwrap_or(&"".to_string())
                )
                .unwrap();

                if !item.has_builder || field.has_builder {
                    writeln!(&mut writer, "    #[pyo3(set)]").unwrap();
                }

                writeln!(
                    &mut writer,
                    "    {}: {},",
                    field.name,
                    field.ty.to_rust_string()
                )
                .unwrap();
            }
            writeln!(&mut writer, "}}\n").unwrap();

            let struct_header = formatdoc!(
                r#"
                impl From<{}::{}> for {} {{
                    fn from({}: {}::{}) -> Self {{
                        Self {{"#,
                name.0,
                name.1,
                name.1,
                name.1.to_case(Case::Snake),
                name.0,
                name.1
            );
            writeln!(&mut writer, "{}", struct_header).unwrap();
            for field in &item.fields {
                if let Ty::Array(obj) = &field.ty {
                    if obj != "String" {
                        writeln!(
                            &mut writer,
                            "            {}: {}.{}.into_iter().map({}::from).collect(),",
                            field.name,
                            name.1.to_case(Case::Snake),
                            field.name,
                            obj
                        )
                        .unwrap();
                    } else {
                        writeln!(
                            &mut writer,
                            "            {}: {}.{},",
                            field.name,
                            name.1.to_case(Case::Snake),
                            field.name
                        )
                        .unwrap();
                    }
                } else if let Ty::Object(ty) = &field.ty {
                    writeln!(
                        &mut writer,
                        "            {}: {}::from({}.{}),",
                        field.name,
                        ty,
                        name.1.to_case(Case::Snake),
                        field.name
                    )
                    .unwrap();
                } else {
                    writeln!(
                        &mut writer,
                        "            {}: {}.{},",
                        field.name,
                        name.1.to_case(Case::Snake),
                        field.name
                    )
                    .unwrap();
                }
            }
            let struct_footer = formatdoc!(
                r#"
                        }}
                    }}
                }}
                "#
            );
            writeln!(&mut writer, "{}", struct_footer).unwrap();

            let struct_header = formatdoc!(
                r#"
                impl From<{}> for {}::{} {{
                    fn from({}: {}) -> Self {{
                        Self {{"#,
                name.1,
                name.0,
                name.1,
                name.1.to_case(Case::Snake),
                name.1,
            );
            writeln!(&mut writer, "{}", struct_header).unwrap();
            for field in &item.fields {
                if let Ty::Array(obj) = &field.ty {
                    if obj != "String" {
                        writeln!(
                            &mut writer,
                            "            {}: {}.{}.into_iter().map({}::{}::from).collect(),",
                            field.name,
                            name.1.to_case(Case::Snake),
                            field.name,
                            name.0,
                            obj
                        )
                        .unwrap();
                    } else {
                        writeln!(
                            &mut writer,
                            "            {}: {}.{},",
                            field.name,
                            name.1.to_case(Case::Snake),
                            field.name
                        )
                        .unwrap();
                    }
                } else if let Ty::Object(ty) = &field.ty {
                    writeln!(
                        &mut writer,
                        "            {}: {}::{}::from({}.{}),",
                        field.name,
                        name.0,
                        ty,
                        name.1.to_case(Case::Snake),
                        field.name
                    )
                    .unwrap();
                } else {
                    writeln!(
                        &mut writer,
                        "            {}: {}.{},",
                        field.name,
                        name.1.to_case(Case::Snake),
                        field.name
                    )
                    .unwrap();
                }
            }
            let struct_footer = formatdoc!(
                r#"
                        }}
                    }}
                }}
                "#
            );
            writeln!(&mut writer, "{}", struct_footer).unwrap();

            let impl_struct = formatdoc!(
                r#"
                #[pymethods]
                impl {} {{
                    #[new]
                    fn new() -> Self {{
                        Self::default()
                    }}

                    fn __str__(&self) -> String {{
                        format!("{{:?}}", self)
                    }}
                }}
                "#,
                name.1,
            );
            writeln!(&mut writer, "{}", impl_struct).unwrap();
        }

        for (name, item) in &self.mods {
            if item.methods.len() == 0 {
                continue;
            }

            if let Some(array) = objects.get_mut(&name.0) {
                array.insert(name.1.to_string());
            } else {
                objects.insert(name.0.to_string(), BTreeSet::from([name.1.to_string()]));
            }

            let file_name = format!("{}.rs", name.0);
            let mut writer = if let Some(file) = file_writers.get_mut(&file_name) {
                file
            } else {
                let file_path = python_dir.join(&file_name);
                let file = OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(file_path)
                    .unwrap();
                file_writers.insert(file_name.clone(), file);
                let mut w = file_writers.get_mut(&file_name).unwrap();

                let mut use_crate = String::new();
                for (key, value) in objects.iter() {
                    if key == &name.0 {
                        continue;
                    }
                    if value.len() == 1 {
                        use_crate.push_str(&format!(
                            "use crate::{}::{};\n",
                            key,
                            value.first().unwrap()
                        ));
                    } else if value.len() > 1 {
                        use_crate.push_str(&format!(
                            "use crate::{}::{{{}}};\n",
                            key,
                            value
                                .iter()
                                .map(|v| v.clone())
                                .collect::<Vec<String>>()
                                .join(", ")
                        ));
                    }
                }
                let use_mod = format!(
                    "use objectscale_client::{{{}}};",
                    objects
                        .keys()
                        .map(|v| v.clone())
                        .collect::<Vec<String>>()
                        .join(", ")
                );

                let header = formatdoc!(
                    r#"
                    #![allow(unused_imports)]

                    {}{}
                    use pyo3::prelude::*;
                    use pyo3::{{exceptions, PyResult}};
                    "#,
                    use_crate,
                    use_mod,
                );
                writeln!(&mut w, "{}", header).unwrap();
                w
            };

            for annotation in &item.annotation {
                if annotation.is_empty() {
                    break;
                }
                writeln!(&mut writer, "// {}", annotation).unwrap();
            }
            let class = formatdoc!(
                r#"
                #[pyclass]
                pub(crate) struct {} {{
                    {}: {}::{},
                }}

                #[pymethods]
                impl {} {{"#,
                name.1,
                name.1.to_case(Case::Snake),
                name.0,
                name.1,
                name.1
            );
            writeln!(&mut writer, "{}", class).unwrap();

            for method in &item.methods {
                if method.name == "new" {
                    for annotation in &method.annotation {
                        writeln!(&mut writer, "    /// {}", annotation).unwrap();
                    }

                    let params = method
                        .params
                        .iter()
                        .map(|param| {
                            format!(
                                "{}: {}",
                                param.0,
                                if let Ty::Object(obj) = &param.1 {
                                    format!("&{}", obj)
                                } else {
                                    param.1.to_rust_string()
                                }
                            )
                        })
                        .collect::<Vec<String>>()
                        .join(", ");

                    let mut variables = String::new();
                    for param in &method.params {
                        if let Ty::Object(ty) = &param.1 {
                            variables.push_str(&format!(
                                "        let {} = {}::{}::from({}.clone());\n",
                                param.0,
                                self.structs.get(ty).unwrap(),
                                ty,
                                param.0,
                            ));
                        }
                    }

                    let cparams = method
                        .params
                        .iter()
                        .map(|param| param.0.clone())
                        .collect::<Vec<String>>()
                        .join(", ");

                    let new = formatdoc!(
                        r#"
                        #[new]
                            fn new({}) -> PyResult<{}> {{
                        {}        let result = {}::{}::new({});
                                match result {{
                                    Ok({}) => Ok(Self {{ {} }}),
                                    Err(e) => Err(exceptions::PyValueError::new_err(format!("{{:?}}", e))),
                                }}
                            }}
                        "#,
                        params,
                        name.1,
                        variables,
                        name.0,
                        name.1,
                        cparams,
                        name.1.to_case(Case::Snake),
                        name.1.to_case(Case::Snake),
                    );
                    writeln!(&mut writer, "    {}\n", new).unwrap();
                } else {
                    if method.params.len() > 0 && method.params.get(0).unwrap().1 == Ty::RefSelf {
                        for annotation in &method.annotation {
                            writeln!(&mut writer, "    /// {}", annotation).unwrap();
                        }

                        let params = method.params.split_first().unwrap().1;
                        let params_str = params
                            .iter()
                            .map(|param| {
                                format!(
                                    "{}: {}",
                                    param.0,
                                    if let Ty::Object(obj) = &param.1 {
                                        format!("&{}", obj)
                                    } else {
                                        param.1.to_rust_string()
                                    }
                                )
                            })
                            .collect::<Vec<String>>()
                            .join(", ");

                        let return_val = if Ty::Result("".to_string()) == method.return_ty {
                            "PyResult<()>".to_string()
                        } else {
                            format!("Py{}", method.return_ty.to_rust_string())
                        };

                        let (return_obj, return_ty) = if method.name.starts_with("new") {
                            if let Ty::Result(name) = &method.return_ty {
                                (
                                    name.to_case(Case::Snake),
                                    format!("{} {{{}}}", name, name.to_case(Case::Snake)),
                                )
                            } else {
                                ("invalid".to_string(), "invalid".to_string())
                            }
                        } else {
                            if method.return_ty == Ty::Result("".to_string()) {
                                ("_".to_string(), "()".to_string())
                            } else if let Ty::Result(name) = &method.return_ty {
                                (
                                    name.to_case(Case::Snake),
                                    format!("{}::from({})", name, name.to_case(Case::Snake)),
                                )
                            } else if let Ty::ResultArray(name) = &method.return_ty {
                                (
                                    format!("{}s", name.to_case(Case::Snake)),
                                    format!(
                                        "{}s.into_iter().map({}::from).collect()",
                                        name.to_case(Case::Snake),
                                        name
                                    ),
                                )
                            } else {
                                ("invalid".to_string(), "invalid".to_string())
                            }
                        };

                        let mut variables = String::new();
                        for param in params {
                            if let Ty::Object(ty) = &param.1 {
                                variables.push_str(&format!(
                                    "        let {} = {}::{}::from({}.clone());\n",
                                    param.0,
                                    self.structs.get(ty).unwrap(),
                                    ty,
                                    param.0,
                                ));
                            }
                        }

                        let cparams = params
                            .iter()
                            .map(|param| param.0.clone())
                            .collect::<Vec<String>>()
                            .join(", ");

                        let prefix = if method.name.starts_with("new") {
                            ""
                        } else {
                            "mut "
                        };

                        let block = formatdoc!(
                            r#"
                            pub fn {}(&{}self, {}) -> {} {{
                            {}        let result = self.{}.{}({});
                                    match result {{
                                        Ok({}) => Ok({}),
                                        Err(e) => Err(exceptions::PyValueError::new_err(format!("{{:?}}", e))),
                                    }}
                                }}
                            "#,
                            method.name,
                            prefix,
                            params_str,
                            return_val,
                            variables,
                            name.1.to_case(Case::Snake),
                            method.name,
                            cparams,
                            return_obj,
                            return_ty
                        );
                        writeln!(&mut writer, "    {}\n", block).unwrap();
                    }
                }
            }

            writeln!(&mut writer, "}}\n").unwrap();
        }

        let file_name = format!("lib.rs");
        let file_path = python_dir.join(&file_name);
        let mut file_writer = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(file_path)
            .unwrap();

        let mut mods = String::new();
        for key in objects.keys() {
            mods.push_str(&format!("mod {};\n", key,));
        }
        let mut use_crate = String::new();
        for (key, value) in objects.iter() {
            if value.len() == 1 {
                use_crate.push_str(&format!("use {}::{};\n", key, value.first().unwrap()));
            } else if value.len() > 1 {
                use_crate.push_str(&format!(
                    "use {}::{{{}}};\n",
                    key,
                    value
                        .iter()
                        .map(|v| v.clone())
                        .collect::<Vec<String>>()
                        .join(", ")
                ));
            }
        }

        let header = formatdoc!(
            r#"
            {}
            {}
            use pyo3::prelude::*;
            "#,
            mods,
            use_crate,
        );
        writeln!(&mut file_writer, "{}", header).unwrap();

        let mut module = String::new();
        for (key, value) in objects.iter() {
            if value.len() > 0 {
                module.push_str(&format!(
                    "    let module = PyModule::new_bound(py, \"{}\")?;\n",
                    key.to_case(Case::Snake),
                ));
                for v in value {
                    module.push_str(&format!("    module.add_class::<{}>()?;\n", v));
                }
                module.push_str(&format!("    m.add_submodule(&module)?;\n\n",))
            }
        }

        let block = formatdoc!(
            r#"
            #[pymodule]
            fn objectscale_client(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {{
            {}    Ok(())
            }}
            "#,
            module
        );
        writeln!(&mut file_writer, "{}", block).unwrap();
    }

    pub fn print(&self, gen_dir: &PathBuf) {
        // for (name, item) in &self.mods {
        //     println!("{}/{} :{:?}", name.0, name.1, item);
        // }

        if std::fs::read_dir(&gen_dir).is_err() {
            std::fs::create_dir_all(&gen_dir).unwrap();
        }

        self.gen_c(gen_dir);
        self.gen_go_over_c(gen_dir);
        self.gen_python(gen_dir);
    }
}
