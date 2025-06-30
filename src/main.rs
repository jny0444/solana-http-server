use std::net::SocketAddr;
use std::process::exit;

use axum::Router;
use axum::routing::post;
use handlers::{
    post_create_token, post_keypair, post_mint_token, post_sign_message, post_sol_send,
    post_token_send, post_verify_message,
};
use tokio::net::TcpListener;

mod handlers;
mod models;

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/keypair", post(post_keypair))
        .route("/token/create", post(post_create_token))
        .route("/token/mint", post(post_mint_token))
        .route("/message/sign", post(post_sign_message))
        .route("/message/verify", post(post_verify_message))
        .route("/send/sol", post(post_sol_send))
        .route("/send/token", post(post_token_send));

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));

    let listener = match TcpListener::bind(addr).await {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("Error on binding address {addr}; {e}");
            exit(1);
        }
    };

    println!("Server running on http://{addr}");

    axum::serve(listener, app.into_make_service())
        .await
        .unwrap_or_else(|e| panic!("Server failed to start: {e}"));
}
