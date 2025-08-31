import objectscale_client

def main():
    endpoint = "https://10.225.108.217:4443"
    username = "root"
    password = "Password123!"
    insecure = True

    try:
        client = objectscale_client.client.ManagementClient(endpoint, username, password, insecure)
        namespaces = client.list_namespaces("")
        for namespace in namespaces:
            print(namespace)
    except Exception as e:
        print("Failed to list namespaces:", e)


if __name__ == '__main__':
    main()
