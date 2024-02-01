use std::{collections::HashMap, env, net::{IpAddr, SocketAddr}};
use maxminddb::geoip2::{self, enterprise::Continent};
use std::str::FromStr;
use serde_json::{json, to_string};
use ring::digest;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use warp::{Filter, Rejection, Reply};
use reqwest::{self, Client};
use uuid::Uuid;
use lazy_static::lazy_static;

use did_key::{CoreSign, PatchedKeyPair};

use hex::decode;

const SG_PROXY_SERVER: &str = "https://proxy-sg.ad4m.dev";
const US_PROXY_SERVER: &str = "https://proxy-us.ad4m.dev";
const DE_PROXY_SERVER: &str = "https://proxy-de.ad4m.dev";

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

lazy_static! {
    static ref API_TOKEN: String = env::var("API_TOKEN").unwrap_or_else(|_| panic!("No API_TOKEN set"));
    static ref ACCOUNT_ID: String = env::var("ACCOUNT_ID").unwrap_or_else(|_| panic!("No ACCOUNT_ID set"));
    static ref RAND_KV: String = env::var("RAND_KV").unwrap_or_else(|_| panic!("No RAND_KV set"));
    static ref CREDENTIALS_KV: String = env::var("CREDENTIALS_KV").unwrap_or_else(|_| panic!("No CREDENTIALS_KV set"));
}

async fn store_value(store_name: &str, key: &str, value: &str) -> Result<(), String> {
    let client = Client::new();
    let url = format!("https://api.cloudflare.com/client/v4/accounts/{}/storage/kv/namespaces/{}/values/{}", ACCOUNT_ID.as_str(), store_name, key);

    let response = client
        .put(&url)
        .header("Authorization", format!("Bearer {}", API_TOKEN.as_str()))
        .body(value.to_string())
        .send()
        .await.unwrap();

    if response.status().is_success() {
        println!("Value stored successfully");
        Ok(())
    } else {
        println!("Failed to store value. Status code: {}", response.status());
        Err(format!("Failed to store value. Status code: {}", response.status()))
    }
}

async fn get_value(store_name: &str, key: &str) -> Result<String, String> {
    let client = Client::new();
    let url = format!("https://api.cloudflare.com/client/v4/accounts/{}/storage/kv/namespaces/{}/values/{}", ACCOUNT_ID.as_str(), store_name, key);

    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", API_TOKEN.as_str()))
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

async fn get_continent(ip: &str) -> Result<String, Box<dyn std::error::Error>> {
    let reader = maxminddb::Reader::open_readfile("src/GeoLite2-City.mmdb").unwrap();
    let ip: IpAddr = FromStr::from_str(ip).unwrap();
    let city: geoip2::City = reader.lookup(ip).unwrap_or(geoip2::City {
        continent: Some(Continent {
            code: Some("AS"),
            geoname_id: None,
            names: None,
        }),
        country: None,
        location: None,
        postal: None,
        registered_country: None,
        represented_country: None,
        traits: None,
        city: None,
        subdivisions: None,
    });

    match city.continent {
        Some(continent) => {
            match continent.code {
                Some(code) => Ok(code.to_string()),
                None => Ok(String::from("AS")),
            }
        },
        None => Ok(String::from("AS")),
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
        .and(warp::addr::remote())
        .and_then(default_handler);

    let routes = login_route.or(login_verify_route).or(default_route);

    warp::serve(routes).run(([127, 0, 0, 1], 3030)).await;
}

async fn default_handler(path: warp::path::FullPath, query_params: HashMap<String, String>, remote_addr: Option<SocketAddr>,) -> Result<impl Reply, Rejection> {
    let ip = match remote_addr {
        Some(addr) => addr.ip().to_string(),
        None => return Ok(warp::reply::json(&"error".to_string())),
    };

    let ip_addr = remote_addr.unwrap().ip().to_string();

    let continent_result = get_continent(ip_addr.as_str()).await.unwrap();

    let mut continent_map: HashMap<&str, &str> = HashMap::new();
    continent_map.insert("AF", DE_PROXY_SERVER);
    continent_map.insert("AN", US_PROXY_SERVER);
    continent_map.insert("AS", SG_PROXY_SERVER);
    continent_map.insert("EU", DE_PROXY_SERVER);
    continent_map.insert("NA", US_PROXY_SERVER);
    continent_map.insert("OC", SG_PROXY_SERVER);
    continent_map.insert("SA", US_PROXY_SERVER);

    let url = continent_map.get(continent_result.as_str()).unwrap().to_string();

    let path = path.as_str();
    let query = serde_urlencoded::to_string(&query_params).unwrap_or_default();

    let dest_path = format!("{}{}?{}", url,path.to_lowercase(), query);

    let client = Client::new();

    let response = client
        .get(&dest_path)
        .send()
        .await.unwrap();

    if response.status().is_success() {
        let value_response = response.json::<Proxy>().await;
        let res = value_response.unwrap();
        Ok(warp::reply::json(&res))
    } else {
        Ok(warp::reply::json(&"error".to_string()))
    }
}


async fn login_handler(query_params: HashMap<String, String>) -> Result<impl Reply, Rejection> {
    if let Some(did) = query_params.get("did") {

        let token = Uuid::new_v4().to_string();

        store_value(RAND_KV.as_str(), did, &token).await.unwrap();

        Ok(warp::reply::with_status(token, warp::http::StatusCode::OK))
    } else {
        Ok(warp::reply::with_status("Something went wrong".to_string(), warp::http::StatusCode::OK))
    }
}

async fn login_verify_handler(query_params: HashMap<String, String>) -> Result<impl Reply, Rejection> {
    if let (Some(did), Some(sig)) =
        (query_params.get("did"), query_params.get("signature"))
    {
        let did_with_key = format!("did:key:{}", did).to_string();

        if let Ok(key_pair) = PatchedKeyPair::try_from(did_with_key.as_str()) {
            let raw_message = json!({ "data": get_value(RAND_KV.as_str(), did).await.unwrap() });

            let result = build_message_raw(raw_message);
            
            let bytes = decode(sig).map_err(|e| {
                eprintln!("Error decoding hexadecimal string: {:?}", e);
                std::io::Error::new(std::io::ErrorKind::InvalidData, "Error decoding hexadecimal string")
            }).unwrap();

            match key_pair.verify(&result, &bytes) {
                Ok(_) => {
                    let token = Uuid::new_v4().to_string();
                    store_value(CREDENTIALS_KV.as_str(), did.to_lowercase().as_str(), &token).await.unwrap();

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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_get_continent() {
        let ip = "0.0.0.0"; 
        let continent = get_continent(ip).await.unwrap();
        assert_eq!(continent, "NA");
    }
}