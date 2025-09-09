use objectscale_client::client::ManagementClient;
use objectscale_client::replication::{ReplicationGroupBuilder, VarrayMapping};

fn main() {
    let endpoint = "https://10.225.108.151:4443";
    let password = "Password123!";
    //let endpoint = "https://10.236.125.200:4443";
    // let endpoint = "https://10.245.131.122:4443";
    // let password = "ChangeMe";
    let username = "root";
    let insecure = true;

    let mut client: ManagementClient =
        ManagementClient::new(endpoint, username, password, insecure).expect("management client");

    let rg_name = "rg1";
    let vdc_name = "vdc2";
    let sp_name = "sp2";

    let vdc = client.get_vdc(vdc_name).expect("get vdc");
    let sps = client.list_storage_pools().expect("list storage pools");
    let sp = sps
        .into_iter()
        .find(|sp| sp.name == sp_name)
        .expect("get storage pool");

    let rg = ReplicationGroupBuilder::default()
        .description(rg_name)
        .name(rg_name)
        .varray_mappings(vec![VarrayMapping {
            name: vdc.id.clone(),
            value: sp.id.clone(),
            is_replication_target: false,
        }])
        .build()
        .expect("build replication group");

    let rg = client
        .create_replication_group(rg)
        .expect("create replication group");
    println!("Created replication group: {:?}", rg);

    // let mut rg = client
    //     .get_replication_group(id)
    //     .expect("get replication group");
    // println!("Get replication group: {:?}", rg);

    // rg.name = "luis".to_string();
    // rg.description = "luis description".to_string();
    // rg.enable_rebalancing = true;
    // rg.is_allow_all_namespaces = true;
    // let state = client
    //     .update_replication_group(&rg)
    //     .expect("update replication group");
    // println!("Updated replication group: {:?}", state);

    // let rg = client
    //     .get_replication_group(id)
    //     .expect("get replication group");
    // println!("Get replication group: {:?}", rg);

    let rgs = client
        .list_replication_groups()
        .expect("list replication groups");
    println!("List replication groups: {:?}", rgs);
}
