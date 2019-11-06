// Copyright (c) 2012-2018 The Elastos Open Source Project
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <eosio/chain/exceptions.hpp>
#include <eosio/producer_plugin/producer_plugin.hpp>
#include <elastos/elastos_plugin/elastos_plugin.hpp>

#include <fc/io/json.hpp>

#include <Implement/SPVModule.h>
#include <Plugin/Transaction/Payload/TransferCrossChainAsset.h>
#include <Plugin/Transaction/TransactionOutput.h>

#define INSERT(api_method, params_name, params_type) \
handlers.insert(std::make_pair(#api_method, [&](const request &api_req) mutable { \
    params_type req_params; \
    try { \
        FC_ASSERT(api_req.params.valid(), "invalid api request params"); \
        auto obj = api_req.params->get_object(); \
        auto it = obj.find(#params_name); \
        FC_ASSERT(it != obj.end(), "parameter ${name} not found", ("name", #params_name)); \
        req_params = it->value().as<params_type>(); \
    } catch (...) {} \
    return fc::variant(api_method(req_params)); \
})) \

namespace elastos {

	namespace apis {
		apis_impl::apis_impl() :
			chain_plug(app().get_plugin<chain_plugin>()),
			history_plug(app().get_plugin<history_plugin>()),
			history_apis(history_plug.get_read_only_api()),
			account("eosio.token"), act_name("withdraw") {
			INSERT(getblockcount, height, uint32_t);
			INSERT(getwithdrawtransactionsbyheight, height, uint32_t);
			INSERT(getwithdrawtransaction, txid, std::string);
			INSERT(getillegalevidencebyheight, height, uint32_t);
			INSERT(checkillegalevidence, evidence, illegal_data);

			auto api_handler = [&](std::string, std::string body, url_response_callback cb) mutable {
				request api_req;
				response api_resp;
				try {
					if (body.empty()) body = "{}";
					api_req = fc::json::from_string(body).as<apis::request>();
					auto handler_itr = handlers.find(api_req.method);
					if (handler_itr == handlers.end()) {
						api_resp.error = error{404, "method \"" + api_req.method + "\" not found"};
					} else {
						api_resp.result = handler_itr->second(api_req);
					}
					cb(200, fc::variant(api_resp));
				} catch (fc::exception &e) {
					api_resp.error = error{e.code(), e.to_detail_string()};
					cb(500, fc::variant(api_resp));
				}
			};
			app().get_plugin<http_plugin>().add_handler("/", api_handler);
		}

		apis_impl::~apis_impl() {}

		uint32_t apis_impl::getblockcount(uint32_t) { return chain_plug.chain().last_irreversible_block_num(); }

		std::vector<withdraw_tx> apis_impl::getwithdrawtransactionsbyheight(uint32_t height) {
			EOS_ASSERT(height > 0, block_id_type_exception, "Invalid Block number, must be greater than 0");

			auto abis = chain_plug.chain().get_abi_serializer(account, chain_plug.get_abi_serializer_max_time());
			EOS_ASSERT(abis.valid(), abi_not_found_exception, "No ABI found for eosio.token");

			auto act_type = abis->get_action_type(act_name);
			EOS_ASSERT(!act_type.empty(), action_not_found_exception,
					   "Unknown action withdraw in contract eosio.token");

			std::vector<withdraw_tx> txs;
			auto blk = chain_plug.chain().fetch_block_by_number(height);
			if (!blk) { return txs; }

			for (const auto &tx: blk->transactions) {
				if (!tx.trx.contains<packed_transaction>()) { continue; }

				auto &pt = tx.trx.get<packed_transaction>();
				withdraw_tx wtx{.txid = pt.id().str()};
				auto &actions = pt.get_transaction().actions;
				for (const auto &act : actions) {
					if (act.account == account && act.name == act_name) {
						auto &obj = abis->binary_to_variant(act_type, act.data,
															chain_plug.get_abi_serializer_max_time()).get_object();
						name to = obj.find("to")->value().as<name>();
						asset quantity = obj.find("quantity")->value().as<asset>();
						asset fee = obj.find("fee")->value().as<asset>();
						asset output = quantity + fee;
						wtx.crosschainassets.push_back(withdraw_info{
							.crosschainaddress = to.to_string(),
							.crosschainamount = to_amount(quantity),
							.outputamount = to_amount(output)
						});
					}
				}
				txs.push_back(wtx);
			}
			return txs;
		}

		withdraw_tx apis_impl::getwithdrawtransaction(const std::string &txid) {
			auto res = history_apis.get_transaction(read_only::get_transaction_params{.id = txid});
			auto trx = res.trx.get_object().find("trx")->value();
			EOS_ASSERT(!trx.is_null(), unknown_transaction_exception, "Unknown transaction for ${id}", ("id", res.id));
			withdraw_tx wtx{.txid = res.id.str()};
			auto &actions = trx.get_object().find("actions")->value().get_array();
			for (const auto &act : actions) {
				auto &act_obj = act.get_object();
				const name &act_acct = act_obj.find("account")->value().as<name>();
				const name &action_name = act_obj.find("name")->value().as<name>();
				if (act_acct == account && action_name == act_name) {
					auto &obj = act_obj.find("data")->value().get_object();
					name to = obj.find("to")->value().as<name>();
					asset quantity = obj.find("quantity")->value().as<asset>();
					asset fee = obj.find("fee")->value().as<asset>();
					asset output = quantity + fee;
					wtx.crosschainassets.push_back(withdraw_info{
						.crosschainaddress = to.to_string(),
						.crosschainamount = to_amount(quantity),
						.outputamount = to_amount(output)
					});
				}
			}
			return wtx;
		}

		std::vector<illegal_data> apis_impl::getillegalevidencebyheight(uint32_t height) {
			return std::vector<illegal_data>{};
		}

		bool apis_impl::checkillegalevidence(const illegal_data &evidence) { return false; }
	}

	using namespace Elastos::ElaWallet;

	static appbase::abstract_plugin &_elastos_plugin = app().register_plugin<elastos_plugin>();

	class elastos_plugin_impl : public SPVModule::Listener {
	public:
		std::string genesis_hash;
		SPVModulePtr spv_module;
		std::map<fc::uint256, uint8_t> failed_txs;
		std::unique_ptr<class chain_plugin> chain_plug;
		std::unique_ptr<class producer_plugin> producer_plug;
		std::unique_ptr<class apis::apis_impl> elastos_apis;
		const name account, act_name;

		elastos_plugin_impl() : account("eosio.token"), act_name("recharge") {}

		void start() {
			chain_plug.reset(app().find_plugin<chain_plugin>());
			producer_plug.reset(app().find_plugin<producer_plugin>());
			elastos_apis.reset(new apis::apis_impl());

			// Get genesis hash from chain.
			if (genesis_hash.empty()) {
				genesis_hash = chain_plug->get_chain_id().str();
			}

			bfs::path root_path = app().data_dir() / "elastos";
			bfs::create_directories(root_path);
			spv_module = SPVModule::Create(genesis_hash, root_path.string());
			spv_module->RegisterListener(this);
			spv_module->SyncStart();
		}

		void stop() {
			spv_module->SyncStop();
		}

		void OnDepositTxConfirmed(const TransactionPtr &tx) {
			try {
				auto abis = chain_plug->chain().get_abi_serializer(account, chain_plug->get_abi_serializer_max_time());
				FC_ASSERT(abis.valid(), "No ABI found for eosio.token");

				auto action_type = abis->get_action_type(act_name);
				FC_ASSERT(!action_type.empty(), "Unknown action recharge in contract eosio.token");

				auto producer_name = chain_plug->chain().pending_block_producer();
				auto public_key = chain_plug->chain().pending_block_signing_key();
				if (!producer_plug->is_producer_key(public_key)) { return; }
				ilog("pending producer is ${pr}, public key is ${pk}", ("pr", producer_name)("pk", public_key));
				// Create Tx2 according to the deposit transaction.
				signed_transaction trx;

				// NOTE: For now we only support single recharge info.
				auto *payload = dynamic_cast<TransferCrossChainAsset *>(tx->GetPayload());
				FC_ASSERT(payload->Info().size() == 1, "Deposit payload info count must equal to one");
				auto info = payload->Info()[0];
				auto output = tx->OutputOfIndex(info.OutputIndex());
				auto fee = output->Amount() - info.CrossChainAmount();
				auto action_args = fc::mutable_variant_object
					("tx_id_hex", tx->GetHash().GetHex())
					("to", to_name(info.CrossChainAddress()))
					("quantity", to_asset(info.CrossChainAmount().getDec()))
					("fee", to_asset(fee.getDec()));

				trx.expiration = chain_plug->chain().head_block_time() + fc::seconds(30);
				trx.set_reference_block(chain_plug->chain().last_irreversible_block_id());
				vector<chain::permission_level> permissions{permission_level{producer_name, act_name}};
				bytes data = abis->variant_to_binary(action_type, action_args,
													 chain_plug->get_abi_serializer_max_time());
				trx.actions.push_back(action(permissions, account, act_name, data));

				auto digest = trx.sig_digest(chain_plug->chain().get_chain_id(), trx.context_free_data);
				auto signature = producer_plug->sign_compact(public_key, digest);
				trx.signatures.push_back(signature);
				FC_ASSERT(trx.signatures.size() > 0, "no signature provided for recharge transaction");

				using namespace chain_apis;
				packed_transaction ptx(trx, packed_transaction::none);
				auto trx_id = trx.id();
				auto next = [&](
					const fc::static_variant<fc::exception_ptr, read_write::push_transaction_results> &result) {
					if (result.contains<fc::exception_ptr>()) {
						const auto &e = result.get<fc::exception_ptr>();
						elog(e->to_detail_string());
						// TODO delete transaction if it is duplicated or retried over 12 times.
						++failed_txs[trx_id];
						if (failed_txs[trx_id] >= 11) {
							failed_txs.erase(trx_id);
							spv_module->SubmitTxReceipt(tx->GetHash());
						}
					} else {
						const auto &r = result.get<read_write::push_transaction_results>();
						spv_module->SubmitTxReceipt(tx->GetHash());
					}
				};
				chain_plug->get_read_write_api().push_transaction(fc::variant(ptx).get_object(), next);
			} catch (fc::exception &e) {
				elog(e.to_detail_string());
			}
		}
	};

	elastos_plugin::elastos_plugin() : my(new elastos_plugin_impl()) {}

	elastos_plugin::~elastos_plugin() {}

	void elastos_plugin::set_program_options(options_description &, options_description &cfg) {
		cfg.add_options()("genesis-hash", bpo::value<std::string>(), "Specify a genesis hash for the elastos plugin");
	}

	void elastos_plugin::plugin_initialize(const variables_map &options) {
		ilog("initializing elastos plugin");

		try {
			if (options.count("genesis-hash")) {
				// Use the option instead of getting genesis hash from chain.
				my->genesis_hash = options["genesis-hash"].as<std::string>();
			}
		}
		FC_LOG_AND_RETHROW()
	}

	void elastos_plugin::plugin_startup() {
		my->start();
	}

	void elastos_plugin::plugin_shutdown() {
		my->stop();
	}
} // namespace elastos
