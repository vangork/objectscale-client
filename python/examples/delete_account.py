import objectscale_client

def main():
    endpoint = "https://10.225.108.189:443"
    username = "root"
    password = "Password123@"
    insecure = True

    account_id = "osai67352f19dfb5bba6"

    client = objectscale_client.ManagementClient(endpoint, username, password, insecure)

    try:
        client.delete_account(account_id)
        print("Deleted account:", account_id)
    except Exception as e:
        print("Failed to delete account:", e)


if __name__ == '__main__':
    main()
