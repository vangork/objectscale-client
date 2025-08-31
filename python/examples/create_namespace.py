import objectscale_client

def main():
    endpoint = "https://10.225.108.217:4443"
    username = "root"
    password = "Password123!"
    insecure = True

    name = "luis_namespace"
    rg = "urn:storageos:ReplicationGroupInfo:0e953ad1-94a5-4eb1-825a-d58d29e85434:global";
    namespace = objectscale_client.tenancy.Namespace()
    namespace.name = name
    namespace.default_data_services_vpool = rg
    namespace.default_bucket_block_size = -1
    namespace.block_size = 2
    namespace.notification_size = 2
    namespace.notification_size_in_count = -1
    namespace.block_size_in_count = -1

    try:
        client = objectscale_client.client.ManagementClient(endpoint, username, password, insecure)
        new_namespace = client.create_namespace(namespace)
        print("Created namespace:", new_namespace)
    except Exception as e:
        print("Failed to create namespace:", e)


if __name__ == '__main__':
    main()
