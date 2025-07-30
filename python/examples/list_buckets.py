import objectscale_client

def main():
    endpoint = "https://10.225.108.217:4443"
    username = "root"
    password = "Password123!"
    insecure = True

    namespace = "ns1"

    try:
        client = objectscale_client.client.ManagementClient(endpoint, username, password, insecure)
        buckets = client.list_buckets(namespace, "")
        for bucket in buckets:
            print(bucket)
    except Exception as e:
        print("Failed to list buckets:", e)


if __name__ == '__main__':
    main()
