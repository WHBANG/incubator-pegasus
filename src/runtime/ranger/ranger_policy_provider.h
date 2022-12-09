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
#include "ranger_resource_policy_manager.h"
#include "runtime/api_task.h"
#include "runtime/task/task_tracker.h"
#include "utils/error_code.h"

namespace dsn {

namespace replication {
class meta_service;
class server_state;
}

namespace ranger {

using rpc_match_acl_type = std::unordered_map<int, ranger::access_type>;

class ranger_policy_provider
{

public:
    ranger_policy_provider(dsn::replication::meta_service *meta_svc,
                           const std::string &ranger_policy_meta_root);

    ~ranger_policy_provider() = default;

    // update ranger policy.
    void update();

    // use the policy in ranger for acl.
    bool allowed(const int rpc_code, const std::string &user_name, const std::string &app_name);

private:
    std::unique_ptr<ranger_resource_policy_manager> _manager;

    dsn::task_tracker _tracker;

    // the path where policies is saved in remote storage.
    std::string _ranger_policy_meta_root;

    std::chrono::milliseconds _load_ranger_policy_retry_delay_ms;

    replication::meta_service *_meta_svc;

    std::unique_ptr<dsn::replication::replication_ddl_client> _ddl_client;

    // the cache stores the policy of the global resource.
    utils::rw_lock_nr _global_policies_lock; // [
    ranger_resource_policies_set _global_policies;
    // ]

    // the cache stores the policy of the database resource.
    utils::rw_lock_nr _database_policies_lock; // [
    ranger_resource_policies_set _database_policies;
    // ]

    // save the rpc_codes that match the global resource.
    rpc_match_acl_type _rpc_match_global_acl;

    // save the rpc_codes that match the global resource.
    rpc_match_acl_type _rpc_match_database_acl;

    // create the path to save policies in remote_storage.
    void create_ranger_policy_root(dsn::task_ptr callback);

    // update policies in use from ranger service.
    void start_sync_ranger_policies();

    // dump policies to remote storage.
    dsn::error_code sync_policies_to_remote_storage();

    // update global/database sources policy.
    dsn::error_code sync_policies_to_cache();

    // update app_envs REPLICA_ACCESS_CONTROLLER_RANGER_POLICIES.
    dsn::error_code sync_policies_to_apps();

    // register the matching between rpc and ranger resources.
    void register_rpc_match_acl(rpc_match_acl_type &resource,
                                const std::string &rpc_code,
                                const access_type &type);
};

std::shared_ptr<ranger_policy_provider>
create_ranger_policy_provider(dsn::replication::meta_service *meta_svc,
                              const std::string ranger_policy_meta_root);

} // namespace ranger
} // namespace dsn
