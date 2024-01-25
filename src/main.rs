use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use warp::{Filter, Rejection, Reply};
use reqwest::{self, Client};
use uuid::Uuid;

#[derive(Serialize)]
struct ErrorMessage {
    code: u16,
    message: String,
}

#[derive(Debug, Deserialize)]
struct ValueResponse {
    value: String,
}

const API_TOKEN: &str = "HJ7xSxLPknSvawhxsq02wSVcurowCr55uz_9D2Hk";
// Function to store a value in Cloudflare KV
async fn store_value(store_name: &str, key: &str, value: &str) -> Result<(), String> {
    let client = Client::new();
    let url = format!("https://api.cloudflare.com/client/v4/accounts/c47108641b30e868d9950f1adf09c9b1/storage/kv/namespaces/{}/values/{}", store_name, key);

    let response = client
        .put(&url)
        .header("Authorization", format!("Bearer {}", API_TOKEN))
        .body(value.to_string())
        .send()
        .await.unwrap();

    if response.status().is_success() {
        println!("Value stored successfully");
        Ok(())
    } else {
        println!("Failed to store value. Status code: {}", response.status());
        // Err(reqwest::Error::custom(format!("Failed to store value. Status code: {}", response.status())))
        Err(format!("Failed to store value. Status code: {}", response.status()))
    }
}

// Function to retrieve a value from Cloudflare KV
async fn get_value(store_name: &str, key: &str) -> Result<String, String> {
    let client = Client::new();
    let url = format!("https://api.cloudflare.com/client/v4/accounts/c47108641b30e868d9950f1adf09c9b1/storage/kv/namespaces/{}/values/{}", store_name, key);

    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", API_TOKEN))
        .send()
        .await.unwrap();

    if response.status().is_success() {
        let value_response: Result<String, reqwest::Error> = response.text().await;
        let res = value_response.unwrap();
        println!("meow {:?}", res);
        Ok(res)
    } else {
        println!("Failed to retrieve value. Status code: {}", response.status());
        Err(format!("Failed to retrieve value. Status code: {}", response.status()))
    }
}

#[tokio::main]
async fn main() {
    let login_route = warp::path!("login")
        .and(warp::filters::query::query())
        .and_then(login_handler);

    let login_verify_route = warp::path!("login" / "verify")
        .and(warp::filters::query::query())
        .and_then(login_verify_handler);

    let default_route = warp::any().map(|| warp::reply::html("Default Route"));

    let routes = login_route.or(login_verify_route).or(default_route);

    warp::serve(routes).run(([127, 0, 0, 1], 3030)).await;
}

async fn login_handler(query_params: HashMap<String, String>) -> Result<impl Reply, Rejection> {
    if let Some(did) = query_params.get("did") {
        println!("Tried login with did: {}", did);

        let token = Uuid::new_v4().to_string();

        store_value("312e3b25d4e74cfc9fbbd045ca76c34b", did, &token).await.unwrap();

        println!("Generated token: {}", token);

        Ok(warp::reply::with_status(token, warp::http::StatusCode::OK))
    } else {
        Ok(warp::reply::with_status("Something went wrong".to_string(), warp::http::StatusCode::OK))
    }
}

async fn login_verify_handler(query_params: HashMap<String, String>) -> Result<impl Reply, Rejection> {
    if let (Some(did), Some(sig), Some(pub_key)) =
        (query_params.get("did"), query_params.get("signature"), query_params.get("publicKey"))
    {
        println!("Verify login with did: {}", did);

        let is_valid = true;

        if is_valid {
            let token = get_value("312e3b25d4e74cfc9fbbd045ca76c34b", did).await.unwrap();
            // let token = Uuid::new_v4().to_string();

            println!("Generated token: {}", token);

            Ok(warp::reply::with_status(token, warp::http::StatusCode::OK))
        } else {
            Ok(warp::reply::with_status("Something went wrong".to_string(), warp::http::StatusCode::OK))
        }
    } else {
        Ok(warp::reply::with_status("Something went wrong".to_string(), warp::http::StatusCode::OK))
    }
}
