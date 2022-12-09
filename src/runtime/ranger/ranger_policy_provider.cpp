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

#include <memory>
#include <string>

#include "common/replication.codes.h"
#include "common/replica_envs.h"
#include "ranger_policy_provider.h"
#include "runtime/task/async_calls.h"
#include "utils/fmt_logging.h"

namespace dsn {
namespace ranger {

std::shared_ptr<ranger_policy_provider>
create_ranger_policy_provider(dsn::replication::meta_service *meta_svc,
                              const std::string ranger_policy_meta_root)
{
    return make_unique<ranger_policy_provider>(meta_svc, ranger_policy_meta_root);
}

ranger_policy_provider::ranger_policy_provider(dsn::replication::meta_service *meta_svc,
                                               const std::string &ranger_policy_meta_root)
    : _ranger_policy_meta_root(ranger_policy_meta_root),
      _load_ranger_policy_retry_delay_ms(10000),
      _meta_svc(meta_svc)
{
    _manager = make_unique<ranger_resource_policy_manager>();
    std::vector<::dsn::rpc_address> meta_servers;
    replica_helper::load_meta_servers(meta_servers);
    _ddl_client = make_unique<dsn::replication::replication_ddl_client>(meta_servers);
    // RESOURCE_TYPE::GLOBAL - metadata
    register_rpc_match_acl(_rpc_match_global_acl, "RPC_CM_LIST_NODES", access_type::METADATA);
    register_rpc_match_acl(_rpc_match_global_acl, "RPC_CM_CLUSTER_INFO", access_type::METADATA);
    register_rpc_match_acl(_rpc_match_global_acl, "RPC_CM_LIST_APPS", access_type::METADATA);
    register_rpc_match_acl(_rpc_match_global_acl, "RPC_QUERY_DISK_INFO", access_type::METADATA);
    // RESOURCE_TYPE::GLOBAL - control
    register_rpc_match_acl(_rpc_match_global_acl, "RPC_HTTP_SERVICE", access_type::CONTROL);
    register_rpc_match_acl(_rpc_match_global_acl, "RPC_CM_CONTROL_META", access_type::CONTROL);
    register_rpc_match_acl(_rpc_match_global_acl, "RPC_CM_START_RECOVERY", access_type::CONTROL);
    register_rpc_match_acl(_rpc_match_global_acl, "RPC_REPLICA_DISK_MIGRATE", access_type::CONTROL);
    register_rpc_match_acl(_rpc_match_global_acl, "RPC_ADD_NEW_DISK", access_type::CONTROL);
    register_rpc_match_acl(_rpc_match_global_acl, "RPC_DETECT_HOTKEY", access_type::CONTROL);
    register_rpc_match_acl(_rpc_match_global_acl, "RPC_CLI_CLI_CALL_ACK", access_type::CONTROL);
    // RESOURCE_TYPE::DATABASE - list
    register_rpc_match_acl(_rpc_match_database_acl, "RPC_CM_LIST_APPS", access_type::LIST);
    // RESOURCE_TYPE::DATABASE - create
    register_rpc_match_acl(_rpc_match_database_acl, "RPC_CM_CREATE_APP", access_type::CREATE);
    // RESOURCE_TYPE::DATABASE - drop
    register_rpc_match_acl(_rpc_match_database_acl, "RPC_CM_DROP_APP", access_type::DROP);
    register_rpc_match_acl(_rpc_match_database_acl, "RPC_CM_RECALL_APP", access_type::DROP);
    // RESOURCE_TYPE::DATABASE - metadata
    register_rpc_match_acl(
        _rpc_match_database_acl, "RPC_CM_QUERY_BACKUP_STATUS", access_type::METADATA);
    register_rpc_match_acl(
        _rpc_match_database_acl, "RPC_CM_QUERY_RESTORE_STATUS", access_type::METADATA);
    register_rpc_match_acl(
        _rpc_match_database_acl, "RPC_CM_QUERY_DUPLICATION", access_type::METADATA);
    register_rpc_match_acl(
        _rpc_match_database_acl, "RPC_CM_QUERY_PARTITION_SPLIT", access_type::METADATA);
    register_rpc_match_acl(
        _rpc_match_database_acl, "RPC_CM_QUERY_BULK_LOAD_STATUS", access_type::METADATA);
    register_rpc_match_acl(
        _rpc_match_database_acl, "RPC_CM_QUERY_MANUAL_COMPACT_STATUS", access_type::METADATA);
    register_rpc_match_acl(
        _rpc_match_database_acl, "RPC_CM_GET_MAX_REPLICA_COUNT", access_type::METADATA);
    // RESOURCE_TYPE::DATABASE - control
    register_rpc_match_acl(
        _rpc_match_database_acl, "RPC_CM_START_BACKUP_APP", access_type::CONTROL);
    register_rpc_match_acl(_rpc_match_database_acl, "RPC_CM_START_RESTORE", access_type::CONTROL);
    register_rpc_match_acl(
        _rpc_match_database_acl, "RPC_CM_PROPOSE_BALANCER", access_type::CONTROL);
    register_rpc_match_acl(_rpc_match_database_acl, "RPC_CM_ADD_DUPLICATION", access_type::CONTROL);
    register_rpc_match_acl(
        _rpc_match_database_acl, "RPC_CM_MODIFY_DUPLICATION", access_type::CONTROL);
    register_rpc_match_acl(_rpc_match_database_acl, "RPC_CM_UPDATE_APP_ENV", access_type::CONTROL);
    register_rpc_match_acl(_rpc_match_database_acl, "RPC_CM_DDD_DIAGNOSE", access_type::CONTROL);
    register_rpc_match_acl(
        _rpc_match_database_acl, "RPC_CM_START_PARTITION_SPLIT", access_type::CONTROL);
    register_rpc_match_acl(
        _rpc_match_database_acl, "RPC_CM_CONTROL_PARTITION_SPLIT", access_type::CONTROL);
    register_rpc_match_acl(_rpc_match_database_acl, "RPC_CM_START_BULK_LOAD", access_type::CONTROL);
    register_rpc_match_acl(
        _rpc_match_database_acl, "RPC_CM_CONTROL_BULK_LOAD", access_type::CONTROL);
    register_rpc_match_acl(_rpc_match_database_acl, "RPC_CM_CLEAR_BULK_LOAD", access_type::CONTROL);
    register_rpc_match_acl(
        _rpc_match_database_acl, "RPC_CM_START_MANUAL_COMPACT", access_type::CONTROL);
    register_rpc_match_acl(
        _rpc_match_database_acl, "RPC_CM_SET_MAX_REPLICA_COUNT", access_type::CONTROL);
}

void ranger_policy_provider::register_rpc_match_acl(rpc_match_acl_type &resource,
                                                    const std::string &rpc_code,
                                                    const access_type &type)
{
    auto code = task_code::try_get(rpc_code, TASK_CODE_INVALID);
    CHECK_NE_MSG(code,
                 TASK_CODE_INVALID,
                 "invalid task code({}) in rpc_code_white_list of security section",
                 rpc_code);

    resource.insert(std::make_pair(code, type));
}

bool ranger_policy_provider::allowed(const int rpc_code,
                                     const std::string &user_name,
                                     const std::string &database_name)
{
    {
        utils::auto_read_lock l(_global_policies_lock);
        if (_rpc_match_global_acl.find(rpc_code) != _rpc_match_global_acl.end()) {
            for (auto &item : _global_policies) {
                const access_type &type = _rpc_match_global_acl[rpc_code];
                if (item._policies.allowed(user_name, type)) {
                    return true;
                }
            }
            if (rpc_code != RPC_CM_LIST_APPS.code()) {
                return false;
            }
        }
    }
    {
        utils::auto_read_lock l(_database_policies_lock);
        if (_rpc_match_database_acl.find(rpc_code) != _rpc_match_database_acl.end()) {
            for (auto &item : _database_policies) {
                const access_type &type = _rpc_match_database_acl[rpc_code];
                if (item._policies.allowed(user_name, type)) {
                    if ("" == database_name &&
                        item._database_values.find("*") != item._database_values.end()) {
                        return true;
                    }
                    if (item._database_values.find(database_name) != item._database_values.end()) {
                        return true;
                    }
                }
            }
            return false;
        }
    }
    // old env deal way: todo
    return false;
}

void ranger_policy_provider::update()
{
    dsn::error_code err_code = _manager->load_ranger_resource_policy();
    if (err_code == dsn::ERR_RANGER_POLICIES_NO_NEED_UPDATE) {
        LOG_DEBUG_F("No need to update ACLs policies with error code = {}", err_code);
        err_code = sync_policies_to_apps();
        if (err_code != dsn::ERR_OK) {
            LOG_DEBUG_F("update app policies failed with error code = {}", err_code);
        }
        return;
    }
    if (err_code != dsn::ERR_OK) {
        LOG_WARNING_F("get ranger policy failed, {}.", err_code);
    } else {
        LOG_DEBUG_F("get ranger policy success, {}.", err_code);
        dsn::task_ptr after_create_ranger_policy_meta_root = dsn::tasking::create_task(
            LPC_CM_GET_RANGER_POLICY, &_tracker, [this]() { start_sync_ranger_policies(); });
        create_ranger_policy_root(after_create_ranger_policy_meta_root);
    }
}

void ranger_policy_provider::create_ranger_policy_root(dsn::task_ptr callback)
{
    LOG_DEBUG_F("create ranger policy meta root({}) on remote_storage",
                _ranger_policy_meta_root.c_str());
    _meta_svc->get_remote_storage()->create_node(
        _ranger_policy_meta_root, LPC_CM_GET_RANGER_POLICY, [this, callback](dsn::error_code err) {
            if (err == dsn::ERR_OK || err == ERR_NODE_ALREADY_EXIST) {
                LOG_DEBUG_F("create ranger policy meta root({}) succeed, with err ({})",
                            _ranger_policy_meta_root.c_str(),
                            err.to_string());
                callback->enqueue();
            } else if (err == dsn::ERR_TIMEOUT) {
                LOG_ERROR_F("create ranger policy meta root({}) timeout, try it later",
                            _ranger_policy_meta_root.c_str());
                dsn::tasking::enqueue(
                    LPC_CM_GET_RANGER_POLICY,
                    &_tracker,
                    std::bind(&ranger_policy_provider::create_ranger_policy_root, this, callback),
                    0,
                    _load_ranger_policy_retry_delay_ms);
            } else {
                CHECK(false, "we can't handle this error({}) right now", err.to_string());
            }
        });
}

void ranger_policy_provider::start_sync_ranger_policies()
{
    LOG_DEBUG_F("start to sync rannger policies to remote storage");
    dsn::error_code err = sync_policies_to_remote_storage();
    if (err == dsn::ERR_OK) {
        LOG_DEBUG_F("sync ranger policies to remote storage succeed, with err ({})",
                    err.to_string());
        err = sync_policies_to_cache();
        if (err == dsn::ERR_OK) {
            LOG_DEBUG_F("updata rannger policies to cahce, err with {}", err.to_string());
            err = sync_policies_to_apps();
            if (err == dsn::ERR_OK) {
                LOG_DEBUG_F("updata rannger policies to apps, err with {}", err.to_string());
            }
        }
    } else {
        CHECK(false,
              "sync policies to cache error({}), we can't handle this right now",
              err.to_string());
    }
}

dsn::error_code ranger_policy_provider::sync_policies_to_remote_storage()
{
    dsn::error_code err;
    dsn::blob value = json::json_forwarder<resource_acls_type>::encode(_manager->get_acls());
    _meta_svc->get_remote_storage()->set_data(
        _ranger_policy_meta_root, value, LPC_CM_GET_RANGER_POLICY, [this, &err](dsn::error_code e) {
            err = e;
            if (e == ERR_OK) {
                LOG_DEBUG_F("updata rannger policies to remote storage succeed, err with {}",
                            err.to_string());
            } else if (e == ERR_TIMEOUT) {
                LOG_ERROR_F(
                    "updata rannger policies to remote storage failed, err with = {}, retry "
                    "after %" PRId64 "(ms)",
                    err.to_string(),
                    _load_ranger_policy_retry_delay_ms.count());
                dsn::tasking::enqueue(
                    LPC_CM_GET_RANGER_POLICY,
                    &_tracker,
                    std::bind(&ranger_policy_provider::sync_policies_to_remote_storage, this),
                    0,
                    _load_ranger_policy_retry_delay_ms);
            } else {
                CHECK(false,
                      "we can't handle this when update ranger policy, err with {}",
                      err.to_string());
            }
        });
    return err;
}

dsn::error_code ranger_policy_provider::sync_policies_to_cache()
{
    {
        utils::auto_write_lock l(_global_policies_lock);
        _global_policies.clear();
        _global_policies.swap(_manager->get_acls()[enum_to_string(resource_type::GLOBAL)]);
        dsn::blob value =
            json::json_forwarder<ranger_resource_policies_set>::encode(_global_policies);
        LOG_DEBUG_F("update global_policies cahce, value = {}", value.to_string());
    }
    {
        utils::auto_write_lock l(_database_policies_lock);
        _database_policies.clear();
        _database_policies.swap(_manager->get_acls()[enum_to_string(resource_type::DATABASE)]);
        dsn::blob value =
            json::json_forwarder<ranger_resource_policies_set>::encode(_database_policies);
        LOG_DEBUG_F("update database_policies cahce, value = {}", value.to_string());
    }
    return dsn::ERR_OK;
}

dsn::error_code ranger_policy_provider::sync_policies_to_apps()
{
    if (_manager->get_acls().count(enum_to_string(resource_type::DATABASE_TABLE)) == 0) {
        LOG_DEBUG_F("database_table is null");
        return dsn::ERR_OK;
    }
    auto table_policies = _manager->get_acls()[enum_to_string(resource_type::DATABASE_TABLE)];

    dsn::blob value = json::json_forwarder<ranger_resource_policies_set>::encode(table_policies);
    LOG_DEBUG_F("table policy value = {}", value.to_string());

    dsn::replication::configuration_list_apps_response list_apps_resp;
    dsn::replication::configuration_list_apps_request list_apps_req;
    list_apps_req.status = dsn::app_status::AS_AVAILABLE;

    _meta_svc->get_server_state()->list_apps(list_apps_req, list_apps_resp);

    if (list_apps_resp.err != dsn::ERR_OK) {
        return list_apps_resp.err;
    }
    std::vector<::dsn::app_info> &apps = list_apps_resp.infos;

    for (const auto &app : apps) {
        std::vector<std::string> lv;
        ::dsn::utils::split_args(app.app_name.c_str(), lv, '.');
        std::string app_name_prefix_match = "";
        std::string app_name = "";
        if (lv.size() == 1) {
            app_name_prefix_match = "*";
            app_name = lv[0];
        } else if (lv.size() == 2) {
            app_name_prefix_match = lv[0];
            app_name = lv[1];
        } else {
            LOG_ERROR_F("update app() envs failed with error_code(ERR_INVALID_APP_NAME)",
                        app.app_name);
            continue;
        }
        auto req = dsn::make_unique<dsn::replication::configuration_update_app_env_request>();
        req->__set_app_name(app.app_name);
        req->__set_keys(std::vector<std::string>{
            dsn::replication::replica_envs::REPLICA_ACCESS_CONTROLLER_RANGER_POLICIES});
        bool has_match_policy = false;
        for (const auto &policy : table_policies) {
            // a policy was matched
            if ((std::find(policy._database_values.begin(),
                           policy._database_values.end(),
                           app_name_prefix_match) == policy._database_values.end())) {
                continue;
            }
            if ((std::find(policy._table_values.begin(), policy._table_values.end(), "*") !=
                 policy._table_values.end()) ||
                (std::find(policy._table_values.begin(), policy._table_values.end(), app_name) !=
                 policy._table_values.end())) {
                has_match_policy = true;
                req->__set_op(dsn::replication::app_env_operation::type::APP_ENV_OP_SET);
                req->__set_values(std::vector<std::string>{
                    json::json_forwarder<policy_priority_level>::encode(policy._policies)
                        .to_string()});
                dsn::replication::update_app_env_rpc rpc(std::move(req), LPC_CM_GET_RANGER_POLICY);
                _meta_svc->get_server_state()->set_app_envs(rpc);
                auto rpc_resp = rpc.response();
                if (rpc_resp.err != dsn::ERR_OK) {
                    return rpc_resp.err;
                }
                break;
            }
        }
        // no match policy, clear app ranger policy
        if (!has_match_policy) {
            req->__set_op(dsn::replication::app_env_operation::type::APP_ENV_OP_DEL);
            dsn::replication::update_app_env_rpc rpc(std::move(req), LPC_CM_GET_RANGER_POLICY);
            _meta_svc->get_server_state()->del_app_envs(rpc);
            auto rpc_resp = rpc.response();
            if (rpc_resp.err != dsn::ERR_OK) {
                return rpc_resp.err;
            }
        }
    }
    return dsn::ERR_OK;
}

} // namespace security
} // namespace dsn
