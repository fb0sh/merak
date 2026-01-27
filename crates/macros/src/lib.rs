use darling::FromDeriveInput;
use heck::ToSnakeCase;
use proc_macro::TokenStream;
use quote::quote;
use syn::{DeriveInput, Ident, parse_macro_input};

use crate::attr::ModelArgs;

mod attr;

#[proc_macro_derive(Model, attributes(model, field))]
pub fn merak_model(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    expand_model(input).unwrap_or_else(|err| err.to_compile_error().into())
}

fn expand_model(input: DeriveInput) -> syn::Result<TokenStream> {
    let vis = &input.vis;
    let ident = &input.ident;

    let fields = match &input.data {
        syn::Data::Struct(data) => (&data.fields).into_iter(),
        _ => panic!(),
    };
    let fields_record = fields.clone();

    let ident_name = ident.to_string();
    let ident_with_id = Ident::new(&format!("{}WithId", ident_name), ident.span());
    let ident_record = Ident::new(&format!("{}Record", ident_name), ident.span());

    let model_args = ModelArgs::from_derive_input(&input)?;

    let table_name = model_args.table_name.unwrap_or(ident_name.to_snake_case());

    Ok(quote! {
        #[derive(::serde::Serialize, ::serde::Deserialize)]
        #vis struct #ident_with_id {
            id: String,
            #(#fields),*
        }

        #[derive(::serde::Serialize, ::serde::Deserialize)]
        #vis struct #ident_record {
            id: surrealdb::RecordId,
            #(#fields_record),*
        }

        impl #ident {
            #vis fn table_name() -> &'static str { #table_name }

            #vis async fn create(db: &::merak_core::SurrealClient, data: Self) -> surrealdb::Result<Option<#ident_record>> {
                db.create(Self::table_name()).content(data).await
            }

            #vis async fn create_with_id(db: &::merak_core::SurrealClient, id: String, data: Self) -> surrealdb::Result<Option<#ident_record>> {
                db.create((Self::table_name(), id)).content(data).await
            }
        }
    }
    .into())
}
