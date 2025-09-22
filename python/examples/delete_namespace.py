#
# Copyright (c) Dell Inc., or its subsidiaries. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#

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
