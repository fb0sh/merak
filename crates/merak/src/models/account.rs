use merak_macros::Model;
use serde::{Deserialize, Serialize};

#[derive(Model, Serialize, Deserialize)]
pub struct Account {}
