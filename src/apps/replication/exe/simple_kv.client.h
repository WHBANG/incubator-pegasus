# pragma once
# include <dsn/dist/replication.h>
# include "simple_kv.code.definition.h"
# include <iostream>

namespace dsn { namespace replication { namespace application { 
class simple_kv_client 
	: public ::dsn::replication::replication_app_client_base
{
public:
	simple_kv_client(
		const std::vector<end_point>& meta_servers,
        const char* app_name)
		: ::dsn::replication::replication_app_client_base(meta_servers, app_name) 
	{
	}
	
	virtual ~simple_kv_client() {}
	
	// from requests to partition index
	// PLEASE DO RE-DEFINE THEM IN A SUB CLASS!!!
	virtual int get_partition_index(const std::string& key) { return 0;};
	virtual int get_partition_index(const ::dsn::replication::application::kv_pair& key) { return 0;};

	// ---------- call RPC_SIMPLE_KV_SIMPLE_KV_READ ------------
	// - synchronous 
	::dsn::error_code read(
		const std::string& key, 
		__out_param std::string& resp, 
		int timeout_milliseconds = 0
		)
	{
		auto resp_task = ::dsn::replication::replication_app_client_base::read<std::string, std::string>(
            get_partition_index(key),
            RPC_SIMPLE_KV_SIMPLE_KV_READ,
            key,
            nullptr,
            nullptr,
            timeout_milliseconds
            );
		resp_task->wait();
		if (resp_task->error() == ::dsn::ERR_SUCCESS)
		{
			unmarshall(resp_task->get_response()->reader(), resp);
		}
		return resp_task->error();
	}
	
	// - asynchronous with on-stack std::string and std::string 
	::dsn::rpc_response_task_ptr begin_read(
		const std::string& key, 		
		int timeout_milliseconds = 0, 
		int reply_hash = 0
		)
	{
		return ::dsn::replication::replication_app_client_base::read<simple_kv_client, std::string, std::string>(
            get_partition_index(key),
            RPC_SIMPLE_KV_SIMPLE_KV_READ, 
            key,
            this,
            &simple_kv_client::end_read, 
            timeout_milliseconds,
			reply_hash
            );
	}

	virtual void end_read(
		::dsn::error_code err, 
		const std::string& resp)
	{
		if (err != ::dsn::ERR_SUCCESS) std::cout << "reply RPC_SIMPLE_KV_SIMPLE_KV_READ err : " << err.to_string() << std::endl;
		else
		{
			std::cout << "reply RPC_SIMPLE_KV_SIMPLE_KV_READ ok" << std::endl;
		}
	}
	
	// - asynchronous with on-heap std::shared_ptr<std::string> and std::shared_ptr<std::string> 
	::dsn::rpc_response_task_ptr begin_read2(
		std::shared_ptr<std::string>& key, 		
		int timeout_milliseconds = 0, 
		int reply_hash = 0
		)
	{
		return ::dsn::replication::replication_app_client_base::read<simple_kv_client, std::string, std::string>(
            get_partition_index(*key),
            RPC_SIMPLE_KV_SIMPLE_KV_READ,
            key,
            this,
            &simple_kv_client::end_read2, 
            timeout_milliseconds,
			reply_hash
            );
	}

	virtual void end_read2(
		::dsn::error_code err, 
		std::shared_ptr<std::string>& key, 
		std::shared_ptr<std::string>& resp)
	{
		if (err != ::dsn::ERR_SUCCESS) std::cout << "reply RPC_SIMPLE_KV_SIMPLE_KV_READ err : " << err.to_string() << std::endl;
		else
		{
			std::cout << "reply RPC_SIMPLE_KV_SIMPLE_KV_READ ok" << std::endl;
		}
	}
	

	// ---------- call RPC_SIMPLE_KV_SIMPLE_KV_WRITE ------------
	// - synchronous 
	::dsn::error_code write(
		const ::dsn::replication::application::kv_pair& pr, 
		__out_param int32_t& resp, 
		int timeout_milliseconds = 0
		)
	{
		auto resp_task = ::dsn::replication::replication_app_client_base::read<::dsn::replication::application::kv_pair, int32_t>(
            get_partition_index(pr),
            RPC_SIMPLE_KV_SIMPLE_KV_WRITE,
            pr,
            nullptr,
            nullptr,
            timeout_milliseconds
            );
		resp_task->wait();
		if (resp_task->error() == ::dsn::ERR_SUCCESS)
		{
			unmarshall(resp_task->get_response()->reader(), resp);
		}
		return resp_task->error();
	}
	
	// - asynchronous with on-stack ::dsn::replication::application::kv_pair and int32_t 
	::dsn::rpc_response_task_ptr begin_write(
		const ::dsn::replication::application::kv_pair& pr, 		
		int timeout_milliseconds = 0, 
		int reply_hash = 0
		)
	{
		return ::dsn::replication::replication_app_client_base::read<simple_kv_client, ::dsn::replication::application::kv_pair, int32_t>(
            get_partition_index(pr),
            RPC_SIMPLE_KV_SIMPLE_KV_WRITE, 
            pr,
            this,
            &simple_kv_client::end_write, 
            timeout_milliseconds,
			reply_hash
            );
	}

	virtual void end_write(
		::dsn::error_code err, 
		const int32_t& resp)
	{
		if (err != ::dsn::ERR_SUCCESS) std::cout << "reply RPC_SIMPLE_KV_SIMPLE_KV_WRITE err : " << err.to_string() << std::endl;
		else
		{
			std::cout << "reply RPC_SIMPLE_KV_SIMPLE_KV_WRITE ok" << std::endl;
		}
	}
	
	// - asynchronous with on-heap std::shared_ptr<::dsn::replication::application::kv_pair> and std::shared_ptr<int32_t> 
	::dsn::rpc_response_task_ptr begin_write2(
		std::shared_ptr<::dsn::replication::application::kv_pair>& pr, 		
		int timeout_milliseconds = 0, 
		int reply_hash = 0
		)
	{
		return ::dsn::replication::replication_app_client_base::read<simple_kv_client, ::dsn::replication::application::kv_pair, int32_t>(
            get_partition_index(*pr),
            RPC_SIMPLE_KV_SIMPLE_KV_WRITE,
            pr,
            this,
            &simple_kv_client::end_write2, 
            timeout_milliseconds,
			reply_hash
            );
	}

	virtual void end_write2(
		::dsn::error_code err, 
		std::shared_ptr<::dsn::replication::application::kv_pair>& pr, 
		std::shared_ptr<int32_t>& resp)
	{
		if (err != ::dsn::ERR_SUCCESS) std::cout << "reply RPC_SIMPLE_KV_SIMPLE_KV_WRITE err : " << err.to_string() << std::endl;
		else
		{
			std::cout << "reply RPC_SIMPLE_KV_SIMPLE_KV_WRITE ok" << std::endl;
		}
	}
	

	// ---------- call RPC_SIMPLE_KV_SIMPLE_KV_APPEND ------------
	// - synchronous 
	::dsn::error_code append(
		const ::dsn::replication::application::kv_pair& pr, 
		__out_param int32_t& resp, 
		int timeout_milliseconds = 0
		)
	{
		auto resp_task = ::dsn::replication::replication_app_client_base::read<::dsn::replication::application::kv_pair, int32_t>(
            get_partition_index(pr),
            RPC_SIMPLE_KV_SIMPLE_KV_APPEND,
            pr,
            nullptr,
            nullptr,
            timeout_milliseconds
            );
		resp_task->wait();
		if (resp_task->error() == ::dsn::ERR_SUCCESS)
		{
			unmarshall(resp_task->get_response()->reader(), resp);
		}
		return resp_task->error();
	}
	
	// - asynchronous with on-stack ::dsn::replication::application::kv_pair and int32_t 
	::dsn::rpc_response_task_ptr begin_append(
		const ::dsn::replication::application::kv_pair& pr, 		
		int timeout_milliseconds = 0, 
		int reply_hash = 0
		)
	{
		return ::dsn::replication::replication_app_client_base::read<simple_kv_client, ::dsn::replication::application::kv_pair, int32_t>(
            get_partition_index(pr),
            RPC_SIMPLE_KV_SIMPLE_KV_APPEND, 
            pr,
            this,
            &simple_kv_client::end_append, 
            timeout_milliseconds,
			reply_hash
            );
	}

	virtual void end_append(
		::dsn::error_code err, 
		const int32_t& resp)
	{
		if (err != ::dsn::ERR_SUCCESS) std::cout << "reply RPC_SIMPLE_KV_SIMPLE_KV_APPEND err : " << err.to_string() << std::endl;
		else
		{
			std::cout << "reply RPC_SIMPLE_KV_SIMPLE_KV_APPEND ok" << std::endl;
		}
	}
	
	// - asynchronous with on-heap std::shared_ptr<::dsn::replication::application::kv_pair> and std::shared_ptr<int32_t> 
	::dsn::rpc_response_task_ptr begin_append2(
		std::shared_ptr<::dsn::replication::application::kv_pair>& pr, 		
		int timeout_milliseconds = 0, 
		int reply_hash = 0
		)
	{
		return ::dsn::replication::replication_app_client_base::read<simple_kv_client, ::dsn::replication::application::kv_pair, int32_t>(
            get_partition_index(*pr),
            RPC_SIMPLE_KV_SIMPLE_KV_APPEND,
            pr,
            this,
            &simple_kv_client::end_append2, 
            timeout_milliseconds,
			reply_hash
            );
	}

	virtual void end_append2(
		::dsn::error_code err, 
		std::shared_ptr<::dsn::replication::application::kv_pair>& pr, 
		std::shared_ptr<int32_t>& resp)
	{
		if (err != ::dsn::ERR_SUCCESS) std::cout << "reply RPC_SIMPLE_KV_SIMPLE_KV_APPEND err : " << err.to_string() << std::endl;
		else
		{
			std::cout << "reply RPC_SIMPLE_KV_SIMPLE_KV_APPEND ok" << std::endl;
		}
	}
	
};

} } } 