use objectscale_client::client::ManagementClient;
use objectscale_client::iam::UserPolicyAttachmentBuilder;

fn main() {
    let endpoint = "https://10.225.108.217:4443";
    let username = "root";
    let password = "Password123!";
    let insecure = true;

    let user_name = "luis_user";
    let namespace = "ns1";
    let arn = "urn:ecs:iam:::policy/ECSS3FullAccess";
    //let arn = "urn:ecs:iam:::policy/ECSDenyAll";

    let mut client: ManagementClient =
        ManagementClient::new(endpoint, username, password, insecure).expect("management client");

    let user_policy_attachment = UserPolicyAttachmentBuilder::default()
        .user_name(user_name)
        .policy_arn(arn)
        .namespace(namespace)
        .build()
        .expect("user policy attachment");

    let user_policy_attachment = client
        .create_user_policy_attachment(user_policy_attachment)
        .expect("create user policy attachment");
    println!(
        "Created user policy attachment: {:?}",
        user_policy_attachment
    );

    let user_policy_attachments = client
        .list_user_policy_attachments(user_name, namespace)
        .expect("list user policy attachment");
    println!(
        "List user policy attachments: {:?}",
        user_policy_attachments
    );

    client
        .delete_user_policy_attachment(user_policy_attachment)
        .expect("delete user policy attachment");
    println!("Deleted user policy attachment");

    let user_policy_attachments = client
        .list_user_policy_attachments(user_name, namespace)
        .expect("list user policy attachment");
    println!(
        "List user policy attachments: {:?}",
        user_policy_attachments
    );
}
