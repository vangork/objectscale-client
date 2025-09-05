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
        bucket = client.get_bucket(bucket_name, namespace)
        bucket.owner = "object_admin1"
        state = client.update_bucket(bucket)
        print("Update bucket:", state)
    except Exception as e:
        print("Failed to update bucket:", e)


if __name__ == '__main__':
    main()
