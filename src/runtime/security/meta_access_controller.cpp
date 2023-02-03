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

#include "meta_access_controller.h"
#include "runtime/rpc/network.h"
#include "runtime/rpc/rpc_message.h"
#include "utils/flags.h"
#include "utils/fmt_logging.h"
#include "utils/strings.h"

namespace dsn {
namespace security {
DSN_DEFINE_string(security,
                  meta_acl_rpc_allow_list,
                  "",
                  "allowed list of rpc codes for meta_access_controller");

DSN_DEFINE_uint32(
    security,
    update_ranger_policy_interval_sec,
    5,
    "The interval seconds meta server to pull the latest access control policy from Ranger server");
DSN_DECLARE_bool(enable_acl);
DSN_DECLARE_bool(enable_ranger_acl);

meta_access_controller::meta_access_controller(
    const std::shared_ptr<ranger::ranger_resource_policy_manager> &policy_manager)
{
    // MetaServer serves the allow-list RPC from all users. RPCs unincluded are accessible to only
    // superusers.
    if (utils::is_empty(FLAGS_meta_acl_rpc_allow_list)) {
        register_allowed_rpc_code_list({"RPC_CM_LIST_APPS",
                                        "RPC_CM_LIST_NODES",
                                        "RPC_CM_CLUSTER_INFO",
                                        "RPC_CM_QUERY_PARTITION_CONFIG_BY_INDEX"});
    } else {
        std::vector<std::string> rpc_code_white_list;
        utils::split_args(FLAGS_meta_acl_rpc_allow_list, rpc_code_white_list, ',');
        register_allowed_rpc_code_list(rpc_code_white_list);
    }
    _ranger_resource_policy_manager = policy_manager;

    // use ranger policy
    if (FLAGS_enable_ranger_acl) {
        register_allowed_rpc_code_list({"RPC_CM_UPDATE_PARTITION_CONFIGURATION",
                                        "RPC_CM_CONFIG_SYNC",
                                        "RPC_CM_DUPLICATION_SYNC",
                                        "RPC_CM_QUERY_PARTITION_CONFIG_BY_INDEX",
                                        "RPC_CM_REPORT_RESTORE_STATUS",
                                        "RPC_CM_NOTIFY_STOP_SPLIT",
                                        "RPC_CM_QUERY_CHILD_STATE",
                                        "RPC_NEGOTIATION",
                                        "RPC_CALL_RAW_MESSAGE",
                                        "RPC_CALL_RAW_SESSION_DISCONNECT",
                                        "RPC_NFS_GET_FILE_SIZE",
                                        "RPC_FD_FAILURE_DETECTOR_PING",
                                        "RPC_CALL_RAW_MESSAGE",
                                        "RPC_CALL_RAW_SESSION_DISCONNECT",
                                        "RPC_CONFIG_PROPOSAL",
                                        "RPC_GROUP_CHECK",
                                        "RPC_QUERY_REPLICA_INFO",
                                        "RPC_QUERY_LAST_CHECKPOINT_INFO",
                                        "RPC_PREPARE",
                                        "RPC_GROUP_CHECK",
                                        "RPC_QUERY_APP_INFO",
                                        "RPC_LEARN_COMPLETION_NOTIFY",
                                        "RPC_LEARN_ADD_LEARNER",
                                        "RPC_REMOVE_REPLICA",
                                        "RPC_COLD_BACKUP",
                                        "RPC_CLEAR_COLD_BACKUP",
                                        "RPC_SPLIT_NOTIFY_CATCH_UP",
                                        "RPC_SPLIT_UPDATE_CHILD_PARTITION_COUNT",
                                        "RPC_BULK_LOAD",
                                        "RPC_GROUP_BULK_LOAD"});

        do_update_ranger_policies();
    }
}

void meta_access_controller::do_update_ranger_policies()
{
    CHECK(_ranger_resource_policy_manager, "ranger policy can not null");
    tasking::enqueue_timer(LPC_CM_GET_RANGER_POLICY,
                           &_tracker,
                           [this]() { _ranger_resource_policy_manager->update(); },
                           std::chrono::seconds(FLAGS_update_ranger_policy_interval_sec),
                           0,
                           std::chrono::milliseconds(1));
}

bool meta_access_controller::allowed(message_ex *msg, const std::string &app_name)
{
    const auto rpc_code = msg->rpc_code().code();
    const auto user_name = msg->io_session->get_client_username();

    // when the ranger acl is not enabled, the old acl will be used in these three cases, the ACL
    // will be allowed:
    // 1. enable_acl is false
    // 2. the user_name is super user
    // 3. the rpc_code is in _allowed_rpc_code_list
    if (!FLAGS_enable_ranger_acl) {
        return !FLAGS_enable_acl || is_super_user(user_name) ||
               _allowed_rpc_code_list.find(rpc_code) != _allowed_rpc_code_list.end();
    }

    // in this case, the ranger acl is enabled. In both cases, the ACL will be allowed:
    // 1. the rpc_code is in _allowed_rpc_code_list.(usually internal rpc)
    // 2. the user_name and resource have passed the validation of ranger policy
    if (_allowed_rpc_code_list.find(rpc_code) != _allowed_rpc_code_list.end()) {
        return true;
    }
    auto parse_ranger_policy_database_name = [](const std::string &app_name) -> std::string {
        std::vector<std::string> lv;
        std::size_t previous = 0;
        std::size_t current = app_name.find('.');
        while (current != std::string::npos) {
            if (current > previous) {
                lv.emplace_back(app_name.substr(previous, current - previous));
            }
            if (lv.size() > 2) {
                return "";
            }
            previous = current + 1;
            current = app_name.find('.', previous);
        }
        if (previous != app_name.size() && lv.size() == 1) {
            return lv[0];
        }
        return "";
    };
    std::string database_name = parse_ranger_policy_database_name(app_name);
    LOG_DEBUG_F("ranger access controller with user_name = {}, rpc = {}, database_name = {}",
                user_name,
                msg->rpc_code(),
                database_name);
    return _ranger_resource_policy_manager->allowed(rpc_code, user_name, database_name);
}

void meta_access_controller::register_allowed_rpc_code_list(
    const std::vector<std::string> &rpc_list)
{
    _allowed_rpc_code_list.clear();
    for (const auto &rpc_code : rpc_list) {
        auto code = task_code::try_get(rpc_code, TASK_CODE_INVALID);
        CHECK_NE_MSG(code, TASK_CODE_INVALID, "invalid task code({})", rpc_code);

        _allowed_rpc_code_list.insert(code);
    }
}

} // namespace security
} // namespace dsn
