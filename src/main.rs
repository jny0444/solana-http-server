use axum::Router;
use axum::routing::post;

mod handlers;
mod models;

#[tokio::main]
async fn main() {
    let app = Router::new().route("/keypair", post())
}
