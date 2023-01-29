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

#include "access_controller.h"
#include "meta_access_controller.h"
#include "replica_access_controller.h"
#include "utils/flags.h"
#include "utils/strings.h"
#include "utils/smart_pointers.h"

namespace dsn {
namespace security {
DSN_DEFINE_bool(security, enable_acl, false, "whether enable access controller or not");
DSN_TAG_VARIABLE(enable_acl, FT_MUTABLE);

<<<<<<< HEAD
DSN_DEFINE_string(security, super_users, "", "super user for access controller");

access_controller::access_controller() { utils::split_args(FLAGS_super_users, _super_users, ','); }
=======
DSN_DEFINE_bool("security", enable_ranger_acl, false, "whether enable access controller or not");
DSN_TAG_VARIABLE(enable_ranger_acl, FT_MUTABLE);

// DSN_DEFINE_group_validator(enable_ranger_acl_allow, [](std::string &message) -> bool {
//     if (FLAGS_enable_ranger_acl && !FLAGS_enable_acl) {
//         return false;
//     }
//     return true;
// });

DSN_DEFINE_string("security", super_users, "", "super user for access controller");

access_controller::access_controller()
{
    CHECK(!(FLAGS_enable_ranger_acl && !FLAGS_enable_acl), "not allow use ranger");
    utils::split_args(FLAGS_super_users, _super_users, ',');
}
>>>>>>> 523e1ceee (ranger access controller code review)

access_controller::~access_controller() {}

bool access_controller::is_super_user_or_disable_acl(const std::string &user_name)
{
    if (!FLAGS_enable_acl || _super_users.find(user_name) != _super_users.end()) {
        return true;
    }
    return false;
}

bool access_controller::is_disable_ranger_acl() { return !FLAGS_enable_ranger_acl; }

std::shared_ptr<access_controller>
create_meta_access_controller(std::shared_ptr<ranger::ranger_policy_provider> policy_provider)
{
    return std::make_shared<meta_access_controller>(policy_provider);
}

std::unique_ptr<access_controller> create_replica_access_controller(const std::string &name)
{
    return std::make_unique<replica_access_controller>(name);
}
} // namespace security
} // namespace dsn
