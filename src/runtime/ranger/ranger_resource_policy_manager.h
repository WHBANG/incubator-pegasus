// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

#pragma once

#include <memory>
#include <string>
#include <unordered_map>

#include "meta/meta_service.h"
#include "ranger_resource_policy.h"
#include "runtime/api_task.h"
#include "utils/error_code.h"

namespace dsn {

namespace replication {
class meta_service;
}

enum class resource_type
{
    KGlobal = 0,
    Kdatabase,
    KDatabase_table,
    KUnknown,
};

ENUM_BEGIN(resource_type, resource_type::KUnknown)
ENUM_REG(resource_type::KGlobal)
ENUM_REG(resource_type::Kdatabase)
ENUM_REG(resource_type::KDatabase_table)
ENUM_END(resource_type)

ENUM_TYPE_SERIALIZATION(resource_type, resource_type::KUnknown)

namespace ranger {

// Policies corresponding to a resource
using resource_policies = std::vector<ranger_resource_policy>;
// Policies corresponding to all resources
using all_resource_policies = std::map<std::string, resource_policies>;
// Range access type of rpc codes
using access_type_of_rpc_code = std::unordered_map<int, ranger::access_type>;

class ranger_resource_policy_manager
{
public:
    ranger_resource_policy_manager(dsn::replication::meta_service *meta_svc);

    ~ranger_resource_policy_manager() = default;

private:
    // The path where policies to be saved in remote storage.
    std::string _ranger_policy_meta_root;

    replication::meta_service *_meta_svc;

    // The access type of RPCs which access global level resources.
    access_type_of_rpc_code _ac_type_of_global_rpcs;

    // The access type of RPCs which access database level resources.
    access_type_of_rpc_code _ac_type_of_database_rpcs;

    // The Ranger policy version to determine whether to update.
    int _local_policy_version;

    // All Ranger ACL policies.
    all_resource_policies _all_resource_policies;

    DEFINE_JSON_SERIALIZATION(_local_policy_version, _all_resource_policies);
};
// Provide a method to test the 'parse_policies_from_json' function.
void parse_policies_from_json_for_test(const rapidjson::Value &data,
                                       std::vector<policy_item> &policies);
} // namespace ranger
} // namespace dsn
