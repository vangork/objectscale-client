/* Copyright (c) Dell Inc., or its subsidiaries. All Rights Reserved. */

#ifndef OBJECTSCALE_CLIENT_H
#define OBJECTSCALE_CLIENT_H

/* Generated with cbindgen:0.26.0 */

/* Warning, this file is autogenerated by cbindgen. Don't modify this manually. */

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct ManagementClient ManagementClient;

typedef struct RCString {
  uint8_t *ptr;
  uintptr_t len;
  uintptr_t cap;
} RCString;

struct ManagementClient *new_management_client(struct RCString endpoint,
                                               struct RCString username,
                                               struct RCString password,
                                               bool insecure,
                                               struct RCString *err);

void destroy_management_client(struct ManagementClient *management_client);

struct RCString management_client_create_account(struct ManagementClient *management_client,
                                                 struct RCString caccount,
                                                 struct RCString *err);

struct RCString management_client_get_account(struct ManagementClient *management_client,
                                              struct RCString account_id,
                                              struct RCString *err);

void management_client_delete_account(struct ManagementClient *management_client,
                                      struct RCString account_id,
                                      struct RCString *err);

struct RCString management_client_list_accounts(struct ManagementClient *management_client,
                                                struct RCString *err);

void free_rcstring(struct RCString rcstring);

#endif /* OBJECTSCALE_CLIENT_H */
