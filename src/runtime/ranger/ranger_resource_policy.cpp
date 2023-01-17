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

#include "ranger_resource_policy.h"

namespace dsn {
namespace ranger {

std::vector<std::string> ranger_resource_policy::_policy_item_list = {
    "policyItems", "denyPolicyItems", "allowExceptions", "denyExceptions"};

void ranger_resource_policy::default_database_resource_builder(ranger_resource_policy &acl)
{
    acl._resource_name = "defalut database policy";
    acl._database_values = {"*"};
    policy_item item;
    item.accesses.insert(access_type::ALL);
    acl._policies.allow_policy.emplace_back(item);
}

} // namespace security
} // namespace dsn
