use surrealdb::{Surreal, engine::remote::ws::Client};

pub type SurrealClient = Surreal<Client>;
