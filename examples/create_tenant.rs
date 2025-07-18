use objectscale_client::client::ManagementClient;
use objectscale_client::tenant::TenantBuilder;

fn main() {
    let endpoint = "https://10.225.108.189:443";
    let username = "root";
    let password = "Password123@";
    let insecure = true;

    let objectstore_endpoint = "https://10.225.108.187:4443";
    let account_name = "osaif1859d99b0ef9087";
    let alias = "yimin";

    let management_client =
        ManagementClient::new(endpoint, username, password, insecure).expect("management client");
    let mut objectstore_client = management_client
        .new_objectstore_client(&objectstore_endpoint)
        .expect("objectstore client");

    let tenant = TenantBuilder::default()
        .id(account_name)
        .is_encryption_enabled(true)
        .alias(alias)
        .build()
        .expect("tenant");
    let tenant = objectstore_client
        .create_tenant(tenant)
        .expect("create tenant");

    println!("Created tenant: {:?}", tenant);
}
