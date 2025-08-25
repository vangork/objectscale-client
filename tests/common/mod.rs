#![allow(dead_code)]

use objectscale_client::client::ManagementClient;
use reqwest::Url;
use std::net::TcpStream;
use std::time::Duration;

pub fn create_management_client() -> ManagementClient {
    let endpoint = "https://10.225.108.217:4443";
    let username = "root";
    let password = "Password123!";
    let insecure = true;

    let url = Url::parse(endpoint).expect("parse url");
    let addrs = url.socket_addrs(|| None).expect("resolve socker addrs");
    assert!(!addrs.is_empty());
    TcpStream::connect_timeout(&addrs[0], Duration::from_secs(3)).expect("connect");

    ManagementClient::new(endpoint, username, password, insecure).expect("management client")
}
