/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

#pragma once

#include <memory>
#include <string>
#include <unordered_map>

#include "meta/meta_service.h"
#include "meta/server_state.h"
#include "ranger_resource_policy.h"
#include "runtime/api_task.h"
#include "runtime/task/task_tracker.h"
#include "utils/error_code.h"

namespace dsn {

namespace replication {
class meta_service;
class server_state;
}

namespace ranger {

enum resource_type
{
    GLOBAL = 0,
    DATABASE,
    DATABASE_TABLE,
    UNKNOWN,
};

ENUM_BEGIN(resource_type, UNKNOWN)
ENUM_REG(GLOBAL)
ENUM_REG(DATABASE)
ENUM_REG(DATABASE_TABLE)
ENUM_END(resource_type)

ENUM_TYPE_SERIALIZATION(resource_type, UNKNOWN)

// Policies corresponding to a resource
using ranger_resource_policies_set =
    std::unordered_set<ranger_resource_policy, hash_ranger_resource_policy>;
// Used to save the policies corresponding to all resources
using resource_policies_type = std::map<std::string, ranger_resource_policies_set>;
// Match the acl_type according to rpc_code
using rpc_match_acl_type = std::unordered_map<int, ranger::access_type>;

class ranger_resource_policy_manager
{
public:
    ranger_resource_policy_manager(dsn::replication::meta_service *meta_svc,
                                   const std::string &ranger_policy_meta_root);

    ~ranger_resource_policy_manager() = default;

    // When using ranger for acl, periodically pull policies from Ranger service.
    void start();

    // Update policies from Ranger service.
    void start_update_policies_from_ranger_service();

    // Return true if the `user_name` is allowed to access `app_name` via `rpc_code`.
    bool allowed(const int rpc_code, const std::string &user_name, const std::string &app_name);

private:
    // Create the path to save policies in remote_storage, and update using resources policies.
    void update_policies_from_ranger_service();

    // Sync policies in use from ranger service.
    void start_sync_ranger_policies();

    // Dump policies to remote storage.
    dsn::error_code dump_policies_to_remote_storage();

    // Update global/database resources policies.
    dsn::error_code update_using_resources_policies();

    // Sync policies to app_envs(REPLICA_ACCESS_CONTROLLER_RANGER_POLICIES).
    dsn::error_code sync_policies_to_app_envs();

    // Resolve the policies(json string) into struct `ranger_resource_policy`
    dsn::error_code parse_json_str_to_policies(const std::string &resp);

    void resource_policy_constructor(resource_type resource_type,
                                     const rapidjson::Value &d,
                                     ranger_resource_policy &acl);

    void policy_setter(std::vector<policy_item> &policy_list, const rapidjson::Value &d);

    // pull policies from Ranger service.
    dsn::error_code load_ranger_resource_policy();

private:
    dsn::task_tracker _tracker;

    // The path where policies are saved in remote storage.
    std::string _ranger_policy_meta_root;

    std::chrono::milliseconds _load_ranger_policy_retry_delay_ms;

    replication::meta_service *_meta_svc;

    // The cache stores the policies of the global resources.
    utils::rw_lock_nr _global_policies_lock; // [
    ranger_resource_policies_set _global_policies;
    // ]

    // The cache stores the policies of the database resources.
    utils::rw_lock_nr _database_policies_lock; // [
    ranger_resource_policies_set _database_policies;
    // ]

    // Save the rpc_codes that match the global resources.
    rpc_match_acl_type _rpc_match_global_acl;

    // Save the rpc_codes that match the global resources.
    rpc_match_acl_type _rpc_match_database_acl;

    // Record the policies version number to determine whether to update the policies.
    int _ranger_service_version;

    // ACLs for access_controller.
    resource_policies_type _resource_policies;

    DEFINE_JSON_SERIALIZATION(_ranger_service_version, _resource_policies);

    // Used to map `access_type` matched resources policies json string.
    std::map<std::string, access_type> _access_type_map;

    // The ranger policis(json string) pulled from Ranger service, this is a demo json.
    /*
    {
        "serviceName": "PEGASUS1",
        "serviceId": 1069,
        "policyVersion": 60,
        "policyUpdateTime": 1673254471000,
        "policies": [{
            "id": 5334,
            "guid": "c7918f8c-921a-4f3d-b9d7-bce7009ee5f8",
            "isEnabled": true,
            "version": 13,
            "service": "PEGASUS1",
            "name": "all - database",
            "policyType": 0,
            "policyPriority": 0,
            "description": "Policy for all - database",
            "isAuditEnabled": true,
            "resources": {
                "database": {
                    "values": ["PEGASUS1"],
                    "isExcludes": false,
                    "isRecursive": true
                }
            },
            "policyItems": [{
                "accesses": [{
                    "type": "create",
                    "isAllowed": true
                }, {
                    "type": "drop",
                    "isAllowed": true
                }, {
                    "type": "control",
                    "isAllowed": true
                }, {
                    "type": "metadata",
                    "isAllowed": true
                }, {
                    "type": "list",
                    "isAllowed": true
                }],
                "users": ["PEGASUS1"],
                "groups": [],
                "roles": [],
                "conditions": [],
                "delegateAdmin": true
            }],
            "denyPolicyItems": [],
            "allowExceptions": [],
            "denyExceptions": [],
            "dataMaskPolicyItems": [],
            "rowFilterPolicyItems": [],
            "serviceType": "pegasus",
            "options": {},
            "validitySchedules": [],
            "policyLabels": [],
            "zoneName": "",
            "isDenyAllElse": false
        }, {
            "id": 5335,
            "guid": "4503eab8-b3c0-4ae6-a512-4e8dfa9eda29",
            "isEnabled": true,
            "version": 2,
            "service": "PEGASUS1",
            "name": "read_write_test",
            "policyType": 0,
            "policyPriority": 0,
            "description": "",
            "isAuditEnabled": true,
            "resources": {
                "database": {
                    "values": ["*"],
                    "isExcludes": false,
                    "isRecursive": true
                },
                "table": {
                    "values": ["*"],
                    "isExcludes": false,
                    "isRecursive": false
                }
            },
            "policyItems": [{
                "accesses": [{
                    "type": "read",
                    "isAllowed": true
                }, {
                    "type": "write",
                    "isAllowed": true
                }],
                "users": ["PEGASUS2"],
                "groups": [],
                "roles": [],
                "conditions": [],
                "delegateAdmin": false
            }],
            "denyPolicyItems": [],
            "allowExceptions": [],
            "denyExceptions": [],
            "dataMaskPolicyItems": [],
            "rowFilterPolicyItems": [],
            "serviceType": "pegasus",
            "options": {},
            "validitySchedules": [],
            "policyLabels": [],
            "zoneName": "",
            "isDenyAllElse": false
        }, {
            "id": 5336,
            "guid": "196b2eb0-d498-4c2d-945a-18b1b9140aa6",
            "isEnabled": true,
            "version": 18,
            "service": "PEGASUS1",
            "name": "admintool",
            "policyType": 0,
            "policyPriority": 0,
            "description": "",
            "isAuditEnabled": true,
            "resources": {
                "global": {
                    "values": ["*"],
                    "isExcludes": false,
                    "isRecursive": false
                }
            },
            "policyItems": [{
                "accesses": [{
                    "type": "control",
                    "isAllowed": true
                }, {
                    "type": "metadata",
                    "isAllowed": true
                }],
                "users": ["PEGASUS2"],
                "groups": [],
                "roles": [],
                "conditions": [],
                "delegateAdmin": false
            }],
            "denyPolicyItems": [],
            "allowExceptions": [],
            "denyExceptions": [],
            "dataMaskPolicyItems": [],
            "rowFilterPolicyItems": [],
            "serviceType": "pegasus",
            "options": {},
            "validitySchedules": [],
            "policyLabels": [],
            "zoneName": "",
            "isDenyAllElse": false
        }, {
            "id": 5425,
            "guid": "544b1069-41a8-4e0c-a1cf-0aa05e6fb5aa",
            "isEnabled": true,
            "version": 13,
            "service": "PEGASUS1",
            "name": "read_write_PEGASUS1",
            "policyType": 0,
            "policyPriority": 0,
            "description": "",
            "isAuditEnabled": true,
            "resources": {
                "database": {
                    "values": ["PEGASUS1"],
                    "isExcludes": false,
                    "isRecursive": true
                },
                "table": {
                    "values": ["*"],
                    "isExcludes": false,
                    "isRecursive": false
                }
            },
            "policyItems": [{
                "accesses": [{
                    "type": "read",
                    "isAllowed": true
                }, {
                    "type": "write",
                    "isAllowed": true
                }],
                "users": ["PEGASUS1"],
                "groups": [],
                "roles": [],
                "conditions": [],
                "delegateAdmin": false
            }],
            "denyPolicyItems": [],
            "allowExceptions": [],
            "denyExceptions": [],
            "dataMaskPolicyItems": [],
            "rowFilterPolicyItems": [],
            "serviceType": "pegasus",
            "options": {},
            "validitySchedules": [],
            "policyLabels": [],
            "zoneName": "",
            "isDenyAllElse": false
        }, {
            "id": 5456,
            "guid": "48fde191-13de-43b2-9b6b-f4550dcc6d03",
            "isEnabled": true,
            "version": 1,
            "service": "PEGASUS1",
            "name": "database, old_table",
            "policyType": 0,
            "policyPriority": 0,
            "description": "",
            "isAuditEnabled": true,
            "resources": {
                "database": {
                    "values": ["*"],
                    "isExcludes": false,
                    "isRecursive": true
                }
            },
            "policyItems": [{
                "accesses": [{
                    "type": "create",
                    "isAllowed": true
                }, {
                    "type": "drop",
                    "isAllowed": true
                }, {
                    "type": "control",
                    "isAllowed": true
                }, {
                    "type": "metadata",
                    "isAllowed": true
                }, {
                    "type": "list",
                    "isAllowed": true
                }],
                "users": ["PEGASUS2"],
                "groups": [],
                "roles": [],
                "conditions": [],
                "delegateAdmin": false
            }],
            "denyPolicyItems": [],
            "allowExceptions": [],
            "denyExceptions": [],
            "dataMaskPolicyItems": [],
            "rowFilterPolicyItems": [],
            "serviceType": "pegasus",
            "options": {},
            "validitySchedules": [],
            "policyLabels": [],
            "zoneName": "",
            "isDenyAllElse": false
        }, {
            "id": 6192,
            "guid": "25cc567c-305a-45a7-ad55-fe0d111688bc",
            "isEnabled": true,
            "version": 1,
            "service": "PEGASUS1",
            "name": "admintool1",
            "policyType": 0,
            "policyPriority": 0,
            "description": "",
            "isAuditEnabled": true,
            "resources": {
                "database": {
                    "values": ["12"],
                    "isExcludes": false,
                    "isRecursive": true
                }
            },
            "policyItems": [],
            "denyPolicyItems": [],
            "allowExceptions": [],
            "denyExceptions": [],
            "dataMaskPolicyItems": [],
            "rowFilterPolicyItems": [],
            "serviceType": "pegasus",
            "options": {},
            "validitySchedules": [],
            "policyLabels": [],
            "zoneName": "",
            "isDenyAllElse": false
        }],
        "serviceDef": {
            "id": 208,
            "guid": "232a0145-a0d6-4ace-815f-0b2353571443",
            "isEnabled": true,
            "createdBy": "Admin",
            "updatedBy": "Admin",
            "createTime": 1668395612000,
            "updateTime": 1668395612000,
            "version": 1,
            "name": "pegasus",
            "displayName": "Pegasus",
            "label": "Apache Pegasus",
            "description": "Apache Pegasus",
            "options": {
                "enableDenyAndExceptionsInPolicies": "true"
            },
            "configs": [{
                "itemId": 1,
                "name": "username",
                "type": "string",
                "mandatory": true,
                "validationRegEx": "",
                "validationMessage": "",
                "uiHint": "",
                "label": "Username"
            }, {
                "itemId": 2,
                "name": "password",
                "type": "password",
                "mandatory": true,
                "validationRegEx": "",
                "validationMessage": "",
                "uiHint": "",
                "label": "Password"
            }, {
                "itemId": 4,
                "name": "pegasus.address",
                "type": "string",
                "mandatory": true,
                "defaultValue": "",
                "validationRegEx": "",
                "validationMessage": "",
                "uiHint": "{\"TextFieldWithIcon\":true, \"info\": \"Such as ip1:port1,ip2:port2,...
    \"}"
            }, {
                "itemId": 101,
                "name": "service.admin.users",
                "type": "string",
                "subType": "",
                "mandatory": false,
                "validationRegEx": "",
                "validationMessage": "",
                "uiHint": "",
                "label": "Service Admin Users"
            }, {
                "itemId": 102,
                "name": "policy.download.auth.users",
                "type": "string",
                "subType": "",
                "mandatory": false,
                "validationRegEx": "",
                "validationMessage": "",
                "uiHint": "",
                "label": "Users allowed to download policy"
            }, {
                "itemId": 103,
                "name": "policy.grantrevoke.auth.users",
                "type": "string",
                "subType": "",
                "mandatory": false,
                "validationRegEx": "",
                "validationMessage": "",
                "uiHint": "",
                "label": "Users allowed to modify policy (grant/revoke)"
            }],
            "resources": [{
                "itemId": 1,
                "name": "database",
                "type": "string",
                "level": 10,
                "mandatory": true,
                "lookupSupported": false,
                "recursiveSupported": true,
                "excludesSupported": true,
                "matcher": "org.apache.ranger.plugin.resourcematcher.RangerDefaultResourceMatcher",
                "matcherOptions": {
                    "wildCard": "true",
                    "ignoreCase": "true"
                },
                "validationRegEx": "",
                "validationMessage": "",
                "uiHint": "",
                "label": "Pegasus Database",
                "description": "Pegasus Database",
                "accessTypeRestrictions": [],
                "isValidLeaf": true
            }, {
                "itemId": 9,
                "name": "global",
                "type": "string",
                "level": 10,
                "mandatory": false,
                "lookupSupported": false,
                "recursiveSupported": false,
                "excludesSupported": false,
                "matcher": "org.apache.ranger.plugin.resourcematcher.RangerDefaultResourceMatcher",
                "matcherOptions": {
                    "wildCard": "true",
                    "ignoreCase": "false"
                },
                "validationRegEx": "",
                "validationMessage": "",
                "uiHint": "",
                "label": "Global",
                "description": "Global",
                "accessTypeRestrictions": [],
                "isValidLeaf": true
            }, {
                "itemId": 2,
                "name": "table",
                "type": "string",
                "level": 20,
                "parent": "database",
                "mandatory": true,
                "lookupSupported": false,
                "recursiveSupported": false,
                "excludesSupported": true,
                "matcher": "org.apache.ranger.plugin.resourcematcher.RangerDefaultResourceMatcher",
                "matcherOptions": {
                    "wildCard": "true",
                    "ignoreCase": "true"
                },
                "validationRegEx": "",
                "validationMessage": "",
                "uiHint": "",
                "label": "Pegasus Table",
                "description": "Pegasus Table",
                "accessTypeRestrictions": [],
                "isValidLeaf": true
            }],
            "accessTypes": [{
                "itemId": 1,
                "name": "read",
                "label": "read",
                "impliedGrants": []
            }, {
                "itemId": 2,
                "name": "write",
                "label": "write",
                "impliedGrants": []
            }, {
                "itemId": 3,
                "name": "create",
                "label": "create",
                "impliedGrants": []
            }, {
                "itemId": 4,
                "name": "drop",
                "label": "drop",
                "impliedGrants": []
            }, {
                "itemId": 5,
                "name": "control",
                "label": "control",
                "impliedGrants": []
            }, {
                "itemId": 6,
                "name": "metadata",
                "label": "metadata",
                "impliedGrants": []
            }, {
                "itemId": 7,
                "name": "list",
                "label": "list",
                "impliedGrants": []
            }, {
                "itemId": 9,
                "name": "all",
                "label": "ALL",
                "impliedGrants": ["read", "write", "create", "drop", "control", "metadata", "list"]
            }],
            "policyConditions": [],
            "contextEnrichers": [],
            "enums": [],
            "dataMaskDef": {
                "maskTypes": [],
                "accessTypes": [],
                "resources": []
            },
            "rowFilterDef": {
                "accessTypes": [],
                "resources": []
            }
        },
        "auditMode": "audit-default",
        "serviceConfig": {}
    }
    */
    std::string _ranger_policies_json_string;
};

// Register the matching between rpc_code and access contol type in resources.
void register_rpc_match_acl(rpc_match_acl_type &resource,
                            const std::vector<std::string> &rpc_code_list,
                            const access_type &type);

// Check whether the app_name is valid when enable ranger.
// When using ranger for acl, the constraint app naming rule is `{database_name}.{table_name}`,
// use
// `.` to split database_name and table_name.
bool is_app_name_vaild(const std::string &app_name);

// check whether `app_name` is valid. valid `app_name` will get `database_name`, invalid `app_name`
// will use `""` as the database_name
std::string get_database_name_from_app_name(const std::string &app_name);
} // namespace ranger
} // namespace dsn
