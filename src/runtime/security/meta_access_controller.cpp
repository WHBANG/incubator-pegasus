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

meta_access_controller::meta_access_controller(
    std::shared_ptr<ranger::ranger_policy_provider> policy_provider)
{
    _policy_provider = policy_provider;
    register_rpc_code_write_list("RPC_CM_UPDATE_PARTITION_CONFIGURATION");
    register_rpc_code_write_list("RPC_CM_CONFIG_SYNC");
    register_rpc_code_write_list("RPC_CM_DUPLICATION_SYNC");
    register_rpc_code_write_list("RPC_CM_QUERY_PARTITION_CONFIG_BY_INDEX");
    register_rpc_code_write_list("RPC_CM_REPORT_RESTORE_STATUS");
    register_rpc_code_write_list("RPC_CM_NOTIFY_STOP_SPLIT");
    register_rpc_code_write_list("RPC_CM_QUERY_CHILD_STATE");
    register_rpc_code_write_list("RPC_NEGOTIATION");
    register_rpc_code_write_list("RPC_CALL_RAW_MESSAGE");
    register_rpc_code_write_list("RPC_CALL_RAW_SESSION_DISCONNECT");
    register_rpc_code_write_list("RPC_NFS_GET_FILE_SIZE");
    register_rpc_code_write_list("RPC_NFS_COPY");
    register_rpc_code_write_list("RPC_FD_FAILURE_DETECTOR_PING");
    register_rpc_code_write_list("RPC_CALL_RAW_MESSAGE");
    register_rpc_code_write_list("RPC_CALL_RAW_SESSION_DISCONNECT");
    register_rpc_code_write_list("RPC_CONFIG_PROPOSAL");
    register_rpc_code_write_list("RPC_GROUP_CHECK");
    register_rpc_code_write_list("RPC_QUERY_REPLICA_INFO");
    register_rpc_code_write_list("RPC_QUERY_LAST_CHECKPOINT_INFO");
    register_rpc_code_write_list("RPC_PREPARE");
    register_rpc_code_write_list("RPC_GROUP_CHECK");
    register_rpc_code_write_list("RPC_QUERY_APP_INFO");
    register_rpc_code_write_list("RPC_LEARN");
    register_rpc_code_write_list("RPC_LEARN_COMPLETION_NOTIFY");
    register_rpc_code_write_list("RPC_LEARN_ADD_LEARNER");
    register_rpc_code_write_list("RPC_REMOVE_REPLICA");
    register_rpc_code_write_list("RPC_COLD_BACKUP");
    register_rpc_code_write_list("RPC_CLEAR_COLD_BACKUP");
    register_rpc_code_write_list("RPC_SPLIT_NOTIFY_CATCH_UP");
    register_rpc_code_write_list("RPC_SPLIT_UPDATE_CHILD_PARTITION_COUNT");
    register_rpc_code_write_list("RPC_BULK_LOAD");
    register_rpc_code_write_list("RPC_GROUP_BULK_LOAD");
}

bool meta_access_controller::allowed(message_ex *msg,
                                     std::shared_ptr<std::vector<std::string>> match)
{
    auto rpc_code = msg->rpc_code().code();
    auto user_name = msg->io_session->get_client_username();

    if (pre_check() || _rpc_code_write_list.find(rpc_code) != _rpc_code_write_list.end()) {
        return true;
    }
    LOG_INFO_F("access controller with user_name = {}, rpc = {}, rpc_code = {}",
               user_name,
               msg->rpc_code(),
               rpc_code);

    return _policy_provider->allowed(rpc_code, user_name, match);
}

void meta_access_controller::register_rpc_code_write_list(const std::string &rpc_code)
{
    auto code = task_code::try_get(rpc_code, TASK_CODE_INVALID);
    CHECK_NE_MSG(code,
                 TASK_CODE_INVALID,
                 "invalid task code({}) in rpc_code_white_list of security section",
                 rpc_code);

    _rpc_code_write_list.insert(code);
}

} // namespace security
} // namespace dsn
