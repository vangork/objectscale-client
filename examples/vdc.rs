use objectscale_client::client::ManagementClient;

fn main() {
    let endpoint = "https://10.225.108.217:4443";
    let username = "root";
    let password = "Password123!";
    let insecure = true;

    let name = "vdc1";

    let mut client: ManagementClient =
        ManagementClient::new(endpoint, username, password, insecure).expect("management client");

    let vdc = client.get_vdc(name).expect("get vdc");
    println!("Get vdc keystore: {:?}", vdc);

    // store.chain = "chain".to_string();
    // store.private_key = "pvk".to_string();
    // let store = client
    //     .update_vdc_keystore(store)
    //     .expect("update vdc keystore");
    // println!("Updated vdc keystore: {:?}", store);

    let vdcs = client.list_vdcs().expect("list vdcs");
    println!("List vdcs: {:?}", vdcs);
}
