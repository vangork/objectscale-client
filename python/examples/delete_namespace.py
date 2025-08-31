import objectscale_client

def main():
    endpoint = "https://10.225.108.217:4443"
    username = "root"
    password = "Password123!"
    insecure = True

    name = "luis_namespace"

    try:
        client = objectscale_client.client.ManagementClient(endpoint, username, password, insecure)
        client.delete_namespace(name)
        print("Deleted namespace:", name)
    except Exception as e:
        print("Failed to delete namespace:", e)


if __name__ == '__main__':
    main()
