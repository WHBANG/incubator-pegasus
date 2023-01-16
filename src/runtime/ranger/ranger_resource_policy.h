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

#include <map>
#include <string>
#include <set>
#include <vector>

#include <rapidjson/document.h>

#include "common/json_helper.h"
#include "utils/fmt_logging.h"

namespace dsn {
namespace ranger {

enum access_type
{
    READ = 0,
    WRITE = 1,
    CREATE = 1 << 1,
    DROP = 1 << 2,
    LIST = 1 << 3,
    METADATA = 1 << 4,
    CONTROL = 1 << 5,
    ALL = 1 << 6,
    INVALID = 1 << 7,
};

ENUM_BEGIN(access_type, INVALID)
ENUM_REG(READ)
ENUM_REG(WRITE)
ENUM_REG(CREATE)
ENUM_REG(DROP)
ENUM_REG(LIST)
ENUM_REG(METADATA)
ENUM_REG(CONTROL)
ENUM_REG(ALL)
ENUM_END(access_type)

ENUM_TYPE_SERIALIZATION(access_type, INVALID)

struct policy_item
{
    std::set<access_type> accesses; // acls

    std::set<std::string> users;

    std::set<std::string> groups; // not use

    std::set<std::string> roles; // not use

    DEFINE_JSON_SERIALIZATION(accesses, users, groups, roles);
};

struct policy_priority_level
{
    // policy priority: deny_policy_exclude > deny_policy > allow_policy_exclude > allow_policy
    std::vector<policy_item> allow_policy;

    std::vector<policy_item> allow_policy_exclude;

    std::vector<policy_item> deny_policy;

    std::vector<policy_item> deny_policy_exclude;

    DEFINE_JSON_SERIALIZATION(allow_policy, allow_policy_exclude, deny_policy, deny_policy_exclude);

    // whetherer user has permission
    bool allowed(const std::string &user_name, const access_type &acl_type)
    {
        for (const auto &deny_item : deny_policy) {
            if (deny_item.accesses.find(acl_type) != deny_item.accesses.end() &&
                deny_item.users.find(user_name) != deny_item.users.end()) {
                for (const auto &deny_exclude_item : deny_policy_exclude) {
                    if (deny_exclude_item.accesses.find(acl_type) ==
                            deny_exclude_item.accesses.end() &&
                        deny_exclude_item.users.find(user_name) == deny_exclude_item.users.end())
                        return false;
                }
            }
        }
        for (const auto &allow_item : allow_policy) {
            if (allow_item.accesses.find(acl_type) != allow_item.accesses.end() &&
                allow_item.users.find(user_name) != allow_item.users.end()) {
                for (const auto &allow_exclude_item : allow_policy_exclude) {
                    if (allow_exclude_item.accesses.find(acl_type) !=
                            allow_exclude_item.accesses.end() &&
                        allow_exclude_item.users.find(user_name) !=
                            allow_exclude_item.users.end()) {
                        return false;
                    }
                }
                return true;
            }
        }
        return false;
    }
};

class ranger_resource_policy
{
public:
    ranger_resource_policy() = default;

    ~ranger_resource_policy() = default;

    // resource name
    std::string _resource_name;

    // 'global' resouce matchs values
    std::set<std::string> _global_values;

    // 'database' resouce matchs values
    std::set<std::string> _database_values;

    // 'table' resouce matchs values
    std::set<std::string> _table_values;

    // policy_priority
    policy_priority_level _policies;

    DEFINE_JSON_SERIALIZATION(
        _resource_name, _global_values, _database_values, _table_values, _policies)

    // generate a default policy for older versions or old environment.
    static void default_database_resource_builder(ranger_resource_policy &acl);

    // ranger support priority policy list.
    static std::vector<std::string> _policy_item_list;
};

} // namespace security
} // namespace dsn
