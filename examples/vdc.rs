use objectscale_client::client::ManagementClient;

fn main() {
    // let endpoint = "https://10.225.108.217:4443";
    // let password = "Password123!";
    let endpoint = "https://10.245.131.122:4443";
    let password = "ChangeMe";
    let username = "root";
    let insecure = true;

    let name = "vdc1";

    let mut client: ManagementClient =
        ManagementClient::new(endpoint, username, password, insecure).expect("management client");

    let vdc = client.get_vdc(name).expect("get vdc");
    println!("Get vdc: {:?}", vdc);

    let id = "urn:storageos:VirtualDataCenterData:f360245e-f2ab-4408-91f4-00f8d36bed89";
    client.delete_vdc(id).expect("delete vdc");
    println!("Deleted vdc: {}", id);

    let vdcs = client.list_vdcs().expect("list vdcs");
    println!("List vdcs: {:?}", vdcs);
}
