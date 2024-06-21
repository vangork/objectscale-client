import objectscale_client
from pprint import pprint

endpoint = "https://10.225.108.186:443"
username = "root"
password = "Password123!"
insecure = True

account_id = "osai0c9d3dd97edcb0d9"

client = objectscale_client.Client(endpoint, username, password, insecure)

try:
    client.delete_account(account_id)
    print("Deleted account:", account_id)
except Exception as e:
    print("Failed to delete account:", e)
