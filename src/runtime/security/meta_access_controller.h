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

#include "access_controller.h"
#include "runtime/ranger/ranger_policy_provider.h"

#include <unordered_set>
#include <unordered_map>

namespace dsn {
class message_ex;

namespace ranger {
class ranger_policy_provider;
}
namespace security {

class meta_access_controller : public access_controller
{
public:
    meta_access_controller(std::shared_ptr<ranger::ranger_policy_provider> policy_provider);

    bool allowed(message_ex *msg, std::shared_ptr<std::vector<std::string>> match);

private:
    std::unordered_set<int> _rpc_code_write_list;

    void register_rpc_code_write_list(const std::string &rpc_code);

    std::shared_ptr<ranger::ranger_policy_provider> _policy_provider;
};
} // namespace security
} // namespace dsn
