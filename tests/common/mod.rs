#![allow(dead_code)]

use objectscale_client::client::{ManagementClient, ObjectstoreClient};
use reqwest::Url;
use std::net::TcpStream;
use std::time::Duration;

pub fn create_management_client() -> ManagementClient {
    let endpoint = "https://10.225.108.189:443";
    let username = "root";
    let password = "Password123@";
    let insecure = true;

    let url = Url::parse(endpoint).expect("parse url");
    let addrs = url.socket_addrs(|| None).expect("resolve socker addrs");
    assert!(!addrs.is_empty());
    TcpStream::connect_timeout(&addrs[0], Duration::from_secs(3)).expect("connect");

    ManagementClient::new(endpoint, username, password, insecure).expect("management client")
}

pub fn create_objectstore_client() -> ObjectstoreClient {
    let management_client = create_management_client();
    let objectstore_endpoint = "https://10.225.108.187:4443";
    management_client
        .new_objectstore_client(objectstore_endpoint)
        .expect("objectstore client")
}
