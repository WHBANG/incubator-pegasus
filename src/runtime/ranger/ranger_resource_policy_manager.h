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
#include <map>
#include <string>

#include <rapidjson/document.h>

#include "ranger_resource_policy.h"
#include "utils/errors.h"

namespace dsn {
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

using ranger_resource_policies_set =
    std::unordered_set<ranger_resource_policy, hash_ranger_resource_policy>;
using resource_acls_type = std::map<std::string, ranger_resource_policies_set>;
class ranger_resource_policy_manager
{
public:
    ranger_resource_policy_manager();

    ~ranger_resource_policy_manager() = default;

    // periodically pull a policy from ranger.
    dsn::error_code load_ranger_resource_policy();

    resource_acls_type get_acls();

private:
    // record the policy version number to determine whether to update the policy
    int _ranger_service_version;

    // ACLs for access_controller
    resource_acls_type _acls;

    DEFINE_JSON_SERIALIZATION(_ranger_service_version, _acls);

    // string to enum(access_type)
    std::map<std::string, access_type> _access_type_map;

    // parse json
    dsn::error_code parse(const std::string &resp);

    void resource_policy_constructor(resource_type resource_type,
                                     const rapidjson::Value &d,
                                     ranger_resource_policy &acl);

    void policy_setter(std::vector<policy_item> &policy_list, const rapidjson::Value &d);

    // friend class ranger_resource_policy_manager_test;
};

} // namespace ranger
} // namespace dsn
