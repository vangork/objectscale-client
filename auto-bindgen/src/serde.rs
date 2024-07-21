use convert_case::Case;
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::token::Paren;
use syn::{parenthesized, Ident, LitStr, Result, Token};

#[derive(Debug)]
pub(crate) struct SerdeInfo {
    pub(crate) rename_serialize: Option<String>,
    pub(crate) rename_deserialize: Option<String>,
    pub(crate) serialize_case: Option<Case>,
    pub(crate) deserialize_case: Option<Case>,
}

#[derive(Clone, Debug)]
struct SerdeValue {
    name: Ident,
    value: LitStr,
}

#[derive(Debug)]
struct SerdeItem {
    name: Ident,
    value: Vec<SerdeValue>,
}

impl Parse for SerdeValue {
    fn parse(input: ParseStream) -> Result<Self> {
        let name: Ident = input.parse()?;
        let _: Token![=] = input.parse()?;
        let value: LitStr = input.parse()?;

        Ok(Self { name, value })
    }
}

impl Parse for SerdeItem {
    fn parse(input: ParseStream) -> Result<Self> {
        let name: Ident = input.parse()?;
        let span = name.span().clone();
        if input.is_empty() {
            return Ok(Self {
                name,
                value: vec![],
            });
        }
        let lookahead = input.lookahead1();
        if lookahead.peek(Token![,]) {
            Ok(Self {
                name,
                value: vec![],
            })
        } else if lookahead.peek(Token![=]) {
            let _: Token![=] = input.parse()?;
            let value: LitStr = input.parse()?;
            Ok(Self {
                name,
                value: vec![SerdeValue {
                    name: Ident::new("luis", span),
                    value,
                }],
            })
        } else {
            let content;
            let _: Paren = parenthesized!(content in input);
            let values: Punctuated<SerdeValue, Token![,]> =
                content.parse_terminated(SerdeValue::parse, Token![,])?;
            let value = values.iter().map(|value| value.to_owned()).collect();
            Ok(Self { name, value })
        }
    }
}

fn parse_str_to_case(str: &str) -> Case {
    match str {
        "camelCase" => Case::Camel,
        "snake_case" => Case::Snake,
        "PascalCase" => Case::Pascal,
        "SCREAMING_SNAKE_CASE" => Case::ScreamingSnake,
        "kebab-case" => Case::Kebab,
        "UPPERCASE" => Case::Upper,
        "lowercase" => Case::Lower,
        _ => Case::Snake,
    }
}

impl Parse for SerdeInfo {
    fn parse(input: ParseStream) -> Result<Self> {
        let items: Punctuated<SerdeItem, Token![,]> =
            input.parse_terminated(SerdeItem::parse, Token![,])?;

        let mut rename_serialize = None;
        let mut rename_deserialize = None;
        let mut serialize_case = None;
        let mut deserialize_case = None;

        if let Some(rename) = items.iter().find(|&item| item.name.to_string() == "rename") {
            if rename.value.len() > 0 {
                let value = &rename.value[0];
                if value.name.to_string() == "luis" {
                    rename_serialize = Some(value.value.value());
                    rename_deserialize = Some(value.value.value());
                } else {
                    if let Some(value) = rename
                        .value
                        .iter()
                        .find(|&item| item.name.to_string() == "serialize")
                    {
                        rename_serialize = Some(value.value.value());
                    }
                    if let Some(value) = rename
                        .value
                        .iter()
                        .find(|&item| item.name.to_string() == "deserialize")
                    {
                        rename_deserialize = Some(value.value.value());
                    }
                }
            }
        }

        if let Some(rename) = items
            .iter()
            .find(|&item| item.name.to_string() == "rename_all")
        {
            if rename.value.len() > 0 {
                let value = &rename.value[0];
                if value.name.to_string() == "luis" {
                    deserialize_case = Some(parse_str_to_case(&value.value.value()));
                    serialize_case = Some(parse_str_to_case(&value.value.value()));
                } else {
                    if let Some(value) = rename
                        .value
                        .iter()
                        .find(|&item| item.name.to_string() == "serialize")
                    {
                        serialize_case = Some(parse_str_to_case(&value.value.value()));
                    }
                    if let Some(value) = rename
                        .value
                        .iter()
                        .find(|&item| item.name.to_string() == "deserialize")
                    {
                        deserialize_case = Some(parse_str_to_case(&value.value.value()));
                    }
                }
            }
        }

        Ok(Self {
            rename_serialize,
            rename_deserialize,
            serialize_case,
            deserialize_case,
        })
    }
}

impl SerdeInfo {
    pub fn is_valid(&self) -> bool {
        self.serialize_case.is_some()
            || self.deserialize_case.is_some()
            || self.rename_serialize.is_some()
            || self.rename_deserialize.is_some()
    }
}
