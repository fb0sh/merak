use merak_macros::Model;
use serde::{Deserialize, Serialize};
use surrealdb::RecordId;

#[derive(Model, Serialize, Deserialize)]
pub struct Account {
    #[field(primary)]
    pub id: RecordId,
}
