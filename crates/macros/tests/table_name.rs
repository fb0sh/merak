use merak_macros::Model;
use serde::{Deserialize, Serialize};

#[test]
pub fn default_table_name() {
    #[derive(Model, Serialize, Deserialize)]
    struct AnyModel {}

    assert_eq!(AnyModel::table_name(), "any_model");
}

#[test]
pub fn specified_table_name() {
    #[derive(Model, Serialize, Deserialize)]
    #[model(table_name = "any_table")]
    struct AnyModel {}

    assert_eq!(AnyModel::table_name(), "any_table");
}
