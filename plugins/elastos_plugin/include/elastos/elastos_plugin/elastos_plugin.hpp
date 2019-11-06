// Copyright (c) 2012-2018 The Elastos Open Source Project
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <eosio/chain_plugin/chain_plugin.hpp>
#include <eosio/history_plugin/history_plugin.hpp>
#include <eosio/http_plugin/http_plugin.hpp>
#include <eosio/producer_plugin/producer_plugin.hpp>

#include <appbase/application.hpp>

namespace elastos {

	using namespace appbase;
	using namespace eosio;
	using namespace eosio::chain;

	static inline name to_name(const std::string &account) {
		return name("alex");
	}

	static inline asset to_asset(const std::string &amount) {
		std::string s = fc::trim(amount);
		auto dot_pos = s.find('.');
		if (dot_pos == std::string::npos) { return asset::from_string(s + ".00000000 ELA"); }
		for (auto p = s.size() - dot_pos; p < 9; ++p) { s += '0'; }
		return asset::from_string(s + " ELA");
	}

	static inline std::string to_amount(const asset &asset) {
		std::string s = fc::trim(asset.to_string());
		auto space_pos = s.find(' ');
		return s.substr(0, space_pos);
	}

	namespace apis {

		using namespace history_apis;

		struct request {
			std::string method;
			optional<fc::variant> params;
		};

		struct error {
			int64_t code;
			std::string message;
		};

		struct response {
			optional<fc::variant> result;
			optional<error> error;
		};

		struct withdraw_info {
			std::string crosschainaddress;
			std::string crosschainamount;
			std::string outputamount;
		};

		struct withdraw_tx {
			std::string txid;
			std::vector<withdraw_info> crosschainassets;
		};

		struct illegal_data {
			uint8_t illegaltype;
			uint32_t height;
			std::string illegalsigner;
			std::string evidence;
			std::string compareevidence;
		};

		class apis_impl {
		public:
			chain_plugin &chain_plug;
			history_plugin &history_plug;
			read_only history_apis;
			const name account, act_name;
			std::map<std::string, std::function<fc::variant(const request &)>> handlers;

			apis_impl();

			virtual ~apis_impl();

		private:
			uint32_t getblockcount(uint32_t);

			std::vector<withdraw_tx> getwithdrawtransactionsbyheight(uint32_t height);

			withdraw_tx getwithdrawtransaction(const std::string &txid);

			std::vector<illegal_data> getillegalevidencebyheight(uint32_t height);

			bool checkillegalevidence(const illegal_data &evidence);
		};
	}

	class elastos_plugin : public appbase::plugin<elastos_plugin> {
	public:
		APPBASE_PLUGIN_REQUIRES((chain_plugin) (producer_plugin) (history_plugin)(http_plugin))

		elastos_plugin();

		virtual ~elastos_plugin();

		virtual void set_program_options(options_description &, options_description &cfg) override;

		void plugin_initialize(const variables_map &options);

		void plugin_startup();

		void plugin_shutdown();

	private:
		std::unique_ptr<class elastos_plugin_impl> my;
	};
}

FC_REFLECT(elastos::apis::request, (method)(params))
FC_REFLECT(elastos::apis::error, (code)(message))
FC_REFLECT(elastos::apis::response, (result)(error))
FC_REFLECT(elastos::apis::withdraw_info, (crosschainaddress)(crosschainamount)(outputamount))
FC_REFLECT(elastos::apis::withdraw_tx, (txid)(crosschainassets))
FC_REFLECT(elastos::apis::illegal_data, (illegaltype)(height)(illegalsigner)(evidence)(compareevidence))
