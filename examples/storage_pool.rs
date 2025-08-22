use objectscale_client::client::ManagementClient;

fn main() {
    let endpoint = "https://10.225.108.217:4443";
    let username = "root";
    let password = "Password123!";
    let insecure = true;

    let id = "urn:storageos:VirtualArray:2a36f1a7-4281-453d-8927-788f8033416b";

    let mut client: ManagementClient =
        ManagementClient::new(endpoint, username, password, insecure).expect("management client");

    let sp = client.get_storage_pool(id).expect("get storage pool");
    println!("Get storage pool: {:?}", sp);

    let sps = client.list_storage_pools().expect("list storage pools");
    println!("List storage pools: {:?}", sps);
}
