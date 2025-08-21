use objectscale_client::client::ManagementClient;

fn main() {
    let endpoint = "https://10.225.108.217:4443";
    let username = "root";
    let password = "Password123!";
    let insecure = true;

    let namespace = "ns1";
    let policy_arn = "urn:ecs:iam:::policy/ECSS3ReadOnlyAccess";
    //let arn = "urn:ecs:iam:::policy/ECSDenyAll";

    let mut client: ManagementClient =
        ManagementClient::new(endpoint, username, password, insecure).expect("management client");

    let entities_for_policy = client
        .get_entities_for_policy(policy_arn, namespace, "", "")
        .expect("get entities for policy");
    println!("Get entities for policy: {:?}", entities_for_policy);
}
