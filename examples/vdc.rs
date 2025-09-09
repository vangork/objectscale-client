use objectscale_client::client::ManagementClient;
// use objectscale_client::provisioning::VdcBuilder;

fn main() {
    let endpoint = "https://10.225.108.217:4443";
    let password = "Password123!";
    // let endpoint = "https://10.245.131.122:4443";
    // let password = "ChangeMe";
    let username = "root";
    let insecure = true;

    // let name = "vdc1";

    let mut client: ManagementClient =
        ManagementClient::new(endpoint, username, password, insecure).expect("management client");

    // let vdc = VdcBuilder::default()
    //     .vdc_name("vdc2")
    //     .inter_vdc_endpoints("10.225.108.151")
    //     .inter_vdc_cmd_endpoints("10.225.108.151")
    //     .management_endpoints("10.225.108.151")
    //     .secret_keys("12345678")
    //     .build()
    //     .expect("build vdc");
    // let vdc = client.create_vdc(vdc).expect("create vdc");
    // println!("Create vdc: {:?}", vdc);

    // let mut vdc = client.get_vdc(name).expect("get vdc");
    // println!("Get vdc: {:?}", vdc);
    // vdc.name = "vdc2".to_string();
    // vdc.secret_keys = "12345678".to_string();
    // let state = client.update_vdc(vdc).expect("update vdc");
    // println!("Update vdc: {}", state);

    // let id = "urn:storageos:VirtualDataCenterData:f360245e-f2ab-4408-91f4-00f8d36bed89";
    // client.delete_vdc(id).expect("delete vdc");
    // println!("Deleted vdc: {}", id);

    let vdcs = client.list_vdcs().expect("list vdcs");
    println!("List vdcs: {:?}", vdcs);
}
