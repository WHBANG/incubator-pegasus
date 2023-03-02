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

#include <gtest/gtest.h>

#include "runtime/ranger/ranger_resource_policy.h"
#include "runtime/ranger/ranger_resource_policy_manager.h"

namespace dsn {
namespace ranger {

TEST(ranger_resource_policy_manager_test, parse_policies_from_json_for_test)
{
    std::string data =
        "[{\"accesses\":[{\"type\":\"create\",\"isAllowed\":true},{\"type\":\"drop\",\"isAllowed\":"
        "true},{\"type\":\"control\",\"isAllowed\":true},{\"type\":\"metadata\",\"isAllowed\":true}"
        ",{\"type\":\"list\",\"isAllowed\":true}],\"users\":[\"user1\",\"user2\"],\"groups\":[],"
        "\"roles\":[],\"conditions\":[],\"delegateAdmin\":true},{\"accesses\":[{\"type\":\"read\","
        "\"isAllowed\":true},{\"type\":\"write\",\"isAllowed\":true}],\"users\":[\"user2\"],"
        "\"groups\":[],\"roles\":[],\"conditions\":[],\"delegateAdmin\":true}]";

    std::vector<policy_item> policies;

    rapidjson::Document doc;
    doc.Parse(data.c_str());
    ranger::parse_policies_from_json_for_test(doc, policies);

    EXPECT_EQ(2, policies.size());

    ASSERT_EQ(access_type::KCreate | access_type::KDrop | access_type::KList |
                  access_type::KMetadata | access_type::KControl,
              policies[0].access_types);

    ASSERT_EQ(access_type::KRead | access_type::KWrite, policies[1].access_types);

    struct test_case
    {
        policy_item item;
        access_type ac_type;
        std::string user_name;
        bool expected_result;
    } tests[] = {{policies[0], access_type::KRead, "", false},
                 {policies[0], access_type::KRead, "user", false},
                 {policies[0], access_type::KRead, "user1", false},
                 {policies[0], access_type::KWrite, "user1", false},
                 {policies[0], access_type::KCreate, "user1", true},
                 {policies[0], access_type::KDrop, "user1", true},
                 {policies[0], access_type::KList, "user1", true},
                 {policies[0], access_type::KMetadata, "user1", true},
                 {policies[0], access_type::KControl, "user1", true},
                 {policies[0], access_type::KRead, "user2", false},
                 {policies[0], access_type::KWrite, "user2", false},
                 {policies[0], access_type::KCreate, "user2", true},
                 {policies[0], access_type::KDrop, "user2", true},
                 {policies[0], access_type::KList, "user2", true},
                 {policies[0], access_type::KMetadata, "user2", true},
                 {policies[0], access_type::KControl, "user2", true},
                 {policies[1], access_type::KRead, "user1", false},
                 {policies[1], access_type::KWrite, "user1", false},
                 {policies[1], access_type::KCreate, "user1", false},
                 {policies[1], access_type::KDrop, "user1", false},
                 {policies[1], access_type::KList, "user1", false},
                 {policies[1], access_type::KMetadata, "user1", false},
                 {policies[1], access_type::KControl, "user1", false},
                 {policies[1], access_type::KRead, "user2", true},
                 {policies[1], access_type::KWrite, "user2", true},
                 {policies[1], access_type::KCreate, "user2", false},
                 {policies[1], access_type::KDrop, "user2", false},
                 {policies[1], access_type::KList, "user2", false},
                 {policies[1], access_type::KMetadata, "user2", false},
                 {policies[1], access_type::KControl, "user2", false}};
    for (const auto &test : tests) {
        auto actual_result = test.item.match(test.ac_type, test.user_name);
        EXPECT_EQ(test.expected_result, actual_result);
    }
}
} // namespace ranger
} // namespace dsn
