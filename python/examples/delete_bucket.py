import objectscale_client

def main():
    endpoint = "https://10.225.108.217:4443"
    username = "root"
    password = "Password123!"
    insecure = True

    namespace = "ns1"
    bucket_name = "luis_bucket"

    try:
        client = objectscale_client.client.ManagementClient(endpoint, username, password, insecure)
        client.delete_bucket(bucket_name, namespace, False)
        print("Deleted bucket:", bucket_name)
    except Exception as e:
        print("Failed to delete bucket:", e)


if __name__ == '__main__':
    main()
