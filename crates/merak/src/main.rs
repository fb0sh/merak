use std::net::Ipv4Addr;
use std::{env, sync::Arc};

use axum::http::StatusCode;
use serde::Serialize;
use surrealdb::Surreal;
use surrealdb::engine::remote::ws::Ws;
use surrealdb::opt::auth::Root;
use utoipa::{OpenApi, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};
use utoipa_swagger_ui::SwaggerUi;

#[derive(ToSchema, Serialize)]
struct HelloResponse {
    message: String,
}

#[utoipa::path(method(get, head), path = "/hello", operation_id = "hello", responses(
    (status = 200, description = "Successful response", body = HelloResponse),
))]
async fn hello() -> axum::Json<HelloResponse> {
    axum::Json(HelloResponse {
        message: "Hello, World!".to_string(),
    })
}

async fn not_found() -> (StatusCode, axum::Json<HelloResponse>) {
    (
        StatusCode::NOT_FOUND,
        axum::Json(HelloResponse {
            message: "Not Found".to_string(),
        }),
    )
}

#[derive(OpenApi)]
#[openapi(paths(hello))]
struct ApiDoc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load .env if present and read SurrealDB connection info
    let _ = dotenv::dotenv();

    let url = env::var("SURREAL_URL").unwrap_or("127.0.0.1:5070".to_string());
    let ns = env::var("SURREAL_NS").unwrap_or("test".to_string());
    let db_name = env::var("SURREAL_DB").unwrap_or("test".to_string());

    // Prepare credentials as Root
    let creds = Root {
        username: &env::var("SURREAL_USER").unwrap_or("root".to_string()),
        password: &env::var("SURREAL_PASS").unwrap_or("root".to_string()),
    };

    // Connect to SurrealDB (ws)
    let db = Surreal::new::<Ws>(&url).await?;
    db.use_ns(&ns).use_db(&db_name).await?;
    db.signin(creds).await?;
    let state = Arc::new(db);

    // build openapi + base router
    let (router, api) = OpenApiRouter::with_openapi(ApiDoc::openapi())
        .routes(routes!(hello))
        .with_state(state)
        .fallback(not_found)
        .split_for_parts();

    let router = router.merge(SwaggerUi::new("/swagger-ui").url("/apidoc/openapi.json", api));

    let listener = tokio::net::TcpListener::bind((Ipv4Addr::UNSPECIFIED, 8080)).await?;
    println!("Serving on http://127.0.0.1:8080...");
    axum::serve(listener, router).await?;
    Ok(())
}
