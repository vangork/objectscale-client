import objectscale_client

def main():
    endpoint = "https://10.225.108.217:4443"
    username = "root"
    password = "Password123!"
    insecure = True

    name = "luis_namespace"

    try:
        client = objectscale_client.client.ManagementClient(endpoint, username, password, insecure)
        namespace = client.get_namespace(name)
        print("Get namespace:", namespace)
    except Exception as e:
        print("Failed to get namespace:", e)


if __name__ == '__main__':
    main()
