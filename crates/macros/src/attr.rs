use darling::FromDeriveInput;

#[derive(Default, FromDeriveInput)]
#[darling(default, attributes(model))]
pub struct ModelArgs {
    pub table_name: Option<String>,
}
