use objectscale_client::client::ManagementClient;
use objectscale_client::iam::PolicyBuilder;

fn main() {
    let endpoint = "https://10.225.108.189:443";
    let username = "root";
    let password = "Password123@";
    let insecure = true;

    let namespace = "osai0a9250592a131336";
    let document = "%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Action%22%3A%5B%22s3%3AListBucket%22%2C%22s3%3AListAllMyBuckets%22%5D%2C%22Resource%22%3A%22*%22%2C%22Effect%22%3A%22Allow%22%2C%22Sid%22%3A%22VisualEditor0%22%7D%5D%7D";
    let policy_name = "test";

    let mut client: ManagementClient =
        ManagementClient::new(endpoint, username, password, insecure).expect("management client");
    let policy = PolicyBuilder::default()
        .policy_name(policy_name)
        .policy_document(document)
        .namespace(namespace)
        .build()
        .expect("access key");
    let policy = client.create_policy(policy).expect("create policy");
    println!("Created policy: {:?}", policy);

    let policy = client
        .get_policy(&policy.arn, namespace)
        .expect("get policy");
    println!("Get policy: {:?}", policy);

    client
        .delete_policy(&policy.arn, namespace)
        .expect("delete policy");
    println!("Deleted policy: {}", policy.arn);

    let policies = client.list_policies(namespace).expect("list policies");
    println!("List policies: {:?}", policies);
}
