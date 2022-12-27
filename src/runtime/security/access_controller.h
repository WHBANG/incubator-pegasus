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
#include <unordered_set>
#include <vector>

namespace dsn {
class message_ex;

namespace ranger {
class ranger_policy_provider;
}
namespace security {

enum class client_request_replica_type
{
    KRead,
    KWrite
};

class access_controller
{
public:
    access_controller();
    virtual ~access_controller() = 0;

    /**
     * update the access controller
     *    acls - the new acls to update
     **/
    virtual void update_allowed_users(const std::string &users) {}

    /**
    * check whether enable ranger acl
    **/
    bool is_enable_ranger_acl();

    /**
     * update the access controller policy
     */
    virtual void update_policies(const std::string &policies) {}

    /**
     * check if the message received is allowd to do something.
     *   msg - the message received
     **/
    virtual bool allowed(message_ex *msg, client_request_replica_type req_type) { return false; }

    /**
     *  access_controller preforms acl.
     *  msg - the message received
     *  app_name - tables involved in acl
     */
    virtual bool allowed(message_ex *msg, const std::string &app_name = "") { return false; }

protected:
    /**
     *  check if user_name is super_user.
     * */
    bool is_super_user(const std::string &user_name) const;
    friend class meta_access_controller_test;

    std::unordered_set<std::string> _super_users;
};

std::shared_ptr<access_controller> create_meta_access_controller(
    const std::shared_ptr<ranger::ranger_policy_provider> &policy_provider);

std::unique_ptr<access_controller> create_replica_access_controller(const std::string &name);
} // namespace security
} // namespace dsn
