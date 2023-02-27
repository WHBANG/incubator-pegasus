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

namespace dsn {
namespace ranger {

TEST(ranger_resource_policy_test, policy_item_match)
{
    policy_item item = {READ | WRITE | CREATE, {"user1", "user2"}};
    struct test_case
    {
        access_type ac_type;
        std::string user_name;
        bool expected_result;
    } tests[] = {{READ, "", false},
                 {READ, "user", false},
                 {READ, "user1", true},
                 {WRITE, "user1", true},
                 {CREATE, "user1", true},
                 {DROP, "user1", false},
                 {LIST, "user1", false},
                 {METADATA, "user1", false},
                 {CONTROL, "user1", false},
                 {WRITE, "user2", true}};
    for (const auto &test : tests) {
        auto actual_result = item.match(test.ac_type, test.user_name);
        EXPECT_EQ(test.expected_result, actual_result);
    }
}

TEST(ranger_resource_policy_test, acl_policies_allowed)
{
    acl_policies policy;
    policy.allow_policies = {{READ | WRITE | CREATE, {"user1", "user2", "user3", "user4"}}};
    policy.allow_policies_exclude = {{WRITE | CREATE, {"user2"}}};
    policy.deny_policies = {{READ | WRITE, {"user3", "user4"}}};
    policy.deny_policies_exclude = {{READ, {"user4"}}};
    struct test_case
    {
        access_type ac_type;
        std::string user_name;
        bool expected_result;
    } tests[] = {{READ, "user", false},      {READ, "user1", true},      {WRITE, "user1", true},
                 {CREATE, "user1", true},    {DROP, "user1", false},     {LIST, "user1", false},
                 {METADATA, "user1", false}, {CONTROL, "user1", false},  {READ, "user2", true},
                 {WRITE, "user2", false},    {CREATE, "user2", false},   {DROP, "user2", false},
                 {LIST, "user2", false},     {METADATA, "user2", false}, {CONTROL, "user2", false},
                 {READ, "user3", false},     {CREATE, "user3", true},    {LIST, "user3", false},
                 {READ, "user4", true},      {WRITE, "user4", false},    {CREATE, "user4", true},
                 {LIST, "user4", false}};
    for (const auto &test : tests) {
        auto actual_result = policy.allowed(test.ac_type, test.user_name);
        EXPECT_EQ(test.expected_result, actual_result);
    }
}
} // namespace ranger
} // namespace dsn
