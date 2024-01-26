use std::collections::HashMap;
use serde_json::{json, to_string};
use ring::digest;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use warp::{Filter, Rejection, Reply};
use reqwest::{self, Client};
use uuid::Uuid;

use did_key::{CoreSign, PatchedKeyPair};

use hex::decode;
fn build_message_raw(data: serde_json::Value) -> Vec<u8> {
    let payload_string = to_string(&data).expect("Error serializing JSON");

    let payload_bytes = payload_string.into_bytes();

    let hash = digest::digest(&digest::SHA256, &payload_bytes);

    let hash_bytes = Bytes::from(hash.as_ref().to_vec());

    hash_bytes.to_vec()
}

#[derive(Serialize)]
struct ErrorMessage {
    code: u16,
    message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Proxy {
    id: String,
    port: u16,
    max_conn_count: u8,
    url: String,
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

    let default_route = warp::path::full()
        .and(warp::query::<HashMap<String, String>>())
        .and_then(default_handler);

    let routes = login_route.or(login_verify_route).or(default_route);

    warp::serve(routes).run(([127, 0, 0, 1], 3030)).await;
}

async fn default_handler(path: warp::path::FullPath, query_params: HashMap<String, String>) -> Result<impl Reply, Rejection> {
    let path = path.as_str();
    let query = serde_urlencoded::to_string(&query_params).unwrap_or_default();
    println!("Default route: {}, {}", path, query);

    let dest_path = format!("https://proxy-sg.ad4m.dev{}?{}", path.to_lowercase(), query);
    println!("Default route: {}", dest_path);

    let client = Client::new();

    let response = client
        .get(&dest_path)
        .header("Authorization", format!("Bearer {}", API_TOKEN))
        .send()
        .await.unwrap();

    if response.status().is_success() {
        let value_response = response.json::<Proxy>().await;
        let res = value_response.unwrap();
        println!("meow {:?}", res);
        Ok(warp::reply::json(&res))
    } else {
        println!("Failed to retrieve value. Status code: {}", response.status());
        Ok(warp::reply::json(&"error".to_string()))
    }

    // Ok(warp::reply::with_status("error".to_string(), warp::http::StatusCode::INTERNAL_SERVER_ERROR))
}


async fn login_handler(query_params: HashMap<String, String>) -> Result<impl Reply, Rejection> {
    if let Some(did) = query_params.get("did") {
        println!("Tried login with did: {}", did);

        let token = Uuid::new_v4().to_string();

        store_value("2dbbef15e98a4b918e572ec41729e6d0", did, &token).await.unwrap();

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
        println!("Verify login with did: {} | {}", did, sig);
        let did_with_key = format!("did:key:{}", did).to_string();

        println!("Verify login with did 1: {}", did_with_key);
        if let Ok(key_pair) = PatchedKeyPair::try_from(did_with_key.as_str()) {
            let raw_message = json!({ "data": get_value("2dbbef15e98a4b918e572ec41729e6d0", did).await.unwrap() });

            let result = build_message_raw(raw_message);
            
            let key = did_key::resolve(&did_with_key).unwrap();

            let bytes = decode(sig).unwrap_or_else(|e| {
                panic!("Error decoding hexadecimal string: {:?}", e);
            });

            println!("meow 0000 {:?} | {:?}", result, bytes);
            println!("meow 1111 {:?}", key.verify(&result, &bytes));


            match key_pair.verify(&result, &bytes) {
                Ok(_) => {
                    let token = Uuid::new_v4().to_string();
                    store_value("be670d144dc64cc28d51fcf56e31ad4e", did.to_lowercase().as_str(), &token).await.unwrap();

                    println!("Generated token: {}", token);

                    Ok(warp::reply::with_status(token, warp::http::StatusCode::OK))
                },
                Err(e) => {
                    let err = format!("Signature verification failed: {:?}", e).to_string();
                    Ok(warp::reply::with_status(err.to_string(), warp::http::StatusCode::OK))
                }
            }
        } else {
            Ok(warp::reply::with_status("Failed to parse DID as key method".to_string(), warp::http::StatusCode::OK))
        }
    } else {
        Ok(warp::reply::with_status("Missing parameters".to_string(), warp::http::StatusCode::OK))
    }
}
