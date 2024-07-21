use objectscale_client::client::ManagementClient;

fn main() {
    let endpoint = "https://10.225.108.189:443";
    let username = "root";
    let password = "Password123@";
    let insecure = true;

    let policy_arn = "urn:osc:iam:::policy/CRRFullAccess";
    //let arn = "urn:osc:iam:::policy/CRRSameAccountFullAccess";
    let namespace = "osai0a9250592a131336";

    let mut client: ManagementClient =
        ManagementClient::new(endpoint, username, password, insecure).expect("management client");

    let entities_for_policy = client
        .get_entities_for_policy(policy_arn, namespace, "", "")
        .expect("get entities for policy");
    println!("Get entities for policy: {:?}", entities_for_policy);
}
