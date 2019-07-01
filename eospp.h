#ifndef EOSPP_EOSPP_H
#define EOSPP_EOSPP_H

#include <iostream>
#include <sstream>
#include <string>
#include <curlpp/cURLpp.hpp>
#include <curlpp/Options.hpp>
#include <nlohmann/json.hpp>
#include <curlpp/Easy.hpp>
#include <array>
#include <time.h>
#include <ctime>
#include <iomanip>
#include <boost/endian/conversion.hpp>
#include <list>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include "elliptic.h"
#include <openssl/ripemd.h>
#include "base58.h"
#include "sha256.h"
#include "private_key.h"

const std::string SIG_PREFIX = "K1";
const int COMPACT_SIG_LEN = 65;


using json = nlohmann::json;

template<class T>
std::string to_little_endian_hex(T t) {
// convert to long little endian hex
    long lNum = (long) boost::endian::endian_reverse(t);
// convert to string
    std::ostringstream oss;
    oss << std::hex << lNum;
    std::string mystring = oss.str();
    return mystring;
}


std::string to_iso_format(time_t &time) { // TODO переделать генерацию времени
    char buf[sizeof "2011-10-08T07:07:09"];
    strftime(buf, sizeof buf, "%FT%T", gmtime(&time));
    return std::string(buf);
}

unsigned char *hexstr_to_char(const char *hexstr) {
    size_t len = strlen(hexstr);
    size_t final_len = len / 2;
    unsigned char *chrs = (unsigned char *) malloc((final_len + 1) * sizeof(*chrs));
    for (size_t i = 0, j = 0; j < final_len; i += 2, j++)
        chrs[j] = (hexstr[i] % 32 + 9) % 25 * 16 + (hexstr[i + 1] % 32 + 9) % 25;
    chrs[final_len] = '\0';
    return chrs;
}


static constexpr uint64_t char_to_symbol(char c) {
    if (c >= 'a' && c <= 'z')
        return (c - 'a') + 6;
    if (c >= '1' && c <= '5')
        return (c - '1') + 1;
    return 0;
}


static uint64_t string_to_name(std::string str) {
    uint64_t name = 0;
    int i = 0;
    for (; str[i] && i < 12; ++i) {
        // NOTE: char_to_symbol() returns char type, and without this explicit
        // expansion to uint64 type, the compilation fails at the point of usage
        // of string_to_name(), where the usage requires constant (compile time) expression.
        name |= (char_to_symbol(str[i]) & 0x1f) << (64 - 5 * (i + 1));
    }

    // The for-loop encoded up to 60 high bits into uint64 'name' variable,
    // if (strlen(str) > 12) then encode str[12] into the low (remaining)
    // 4 bits of 'name'
    if (i == 12)
        name |= char_to_symbol(str[12]) & 0x0F;
    return name;
}

std::string encode_name(std::string name) {
    auto encoded_name = to_little_endian_hex((unsigned long long) string_to_name(name));
    std::string result = "";
    if (encoded_name.length() < 16) {
        for (int i = 0; i < 16 - encoded_name.length(); i += 2) {
            result += "00";
        }
    }
    result += encoded_name;
    return result;
}

class Transaction {
    json _data;

public:

    Transaction(json data, json chain_info, json lib_info) {
        data["ref_block_num"] = get_ref_blocknum(chain_info["last_irreversible_block_num"]);
        data["ref_block_prefix"] = lib_info["ref_block_prefix"];
        data["net_usage_words"] = 0;
        data["max_cpu_usage_ms"] = 0;
        data["delay_sec"] = 0;
        data["context_free_actions"] = "[]"_json;
        _data = data;
    }

    int get_ref_blocknum(int head_blocknum) const {
        return ((head_blocknum / 0xffff) * 0xffff) + head_blocknum % 0xffff;
    }

    json get_tx_json() {
        return _data;
    }


    std::string encode_hdr() {
        std::string exp = to_little_endian_hex((uint32_t) _data["expiration"]);
        std::string ref_blk = to_little_endian_hex((uint16_t) _data["ref_block_num"]);
        std::string ref_block_prefix = to_little_endian_hex((uint32_t) _data["ref_block_prefix"]);
        std::string net_usage_words = "00";
        std::string max_cpu_usage_ms = "00";
        std::string delay_sec = "00";
        return exp + ref_blk + ref_block_prefix + net_usage_words + max_cpu_usage_ms + delay_sec;
    }


    template<typename Value>
    std::string serializeVarInt(Value inValue) {
        std::stringstream ss;
        ss << std::hex << inValue;
        return ss.str();
    }


    std::string encode_authorization(std::unordered_map<std::string, std::string> authorization) {
        std::string actor = encode_name(authorization["actor"]);
        std::string permission = encode_name(authorization["permission"]);
        return actor + permission;
    }

    std::string encode_action(json action) {
        std::string acct = encode_name(action["account"]);
        std::string name = encode_name(action["name"]);
        std::string auth = "01" + encode_authorization(action["authorization"][0]);
        std::string data = action["data"];
        std::string data_len = serializeVarInt(data.length() / 2);
        return acct + name + auth + data_len + data;
    }

    std::string encode() {
        std::string hdr_buf = encode_hdr();
        std::string context_actions = "00";
        std::string action = "01" + encode_action(_data["actions"][0]);
        std::string trans_exts = "00";
        return hdr_buf + context_actions + action + trans_exts;
    }

};

class Eos {

public:
    Eos(std::string nodeeos_url, std::string v) : nodeeos_url(nodeeos_url), v(v) { ; }

    json abi_json_to_bin(std::string code, std::string action, json args) {
        json params = {{"code",   code},
                       {"action", action},
                       {"args",   args}};
        std::string resp = make_request("chain/abi_json_to_bin", params.dump());
        return json::parse(resp);
    }


    json
    sign_action(std::string account, std::string action, std::string actor, std::string permission, std::string key,
                json args, int expiration_sec) {
        json binargs_resp = abi_json_to_bin(account, action, args);
        std::unordered_map<std::string, std::string> authorization[1] = {{{"actor", actor}, {"permission", permission}}};
        json action_json = {{"account",       account},
                            {"name",          action},
                            {"authorization", authorization},
                            {"data",          binargs_resp["binargs"]}};
        json actions[1] = {action_json};
        time_t expiration;
        time(&expiration);
        expiration += expiration_sec;

        json trx = {{"actions",    actions},
                    {"expiration", expiration}};

        return sign_transaction(trx, key);
    }


    sha256 sig_digest(std::string payload, std::string chain_id) {
        std::string full_payload = chain_id + payload;
        std::string context_free_data = "";
        for (int i = 0; i < 32; i++) {
            context_free_data += "00";
        }

        full_payload += context_free_data;

        unsigned char *bin_payload = hexstr_to_char(full_payload.c_str());

        return sha256::hash((char *) bin_payload, full_payload.length() / 2);
    }


    static unsigned int calculate_checksum(compact_signature *sig) {
        RIPEMD160_CTX ctx;
        RIPEMD160_Init(&ctx);
        RIPEMD160_Update(&ctx, (const char *) sig, COMPACT_SIG_LEN);
        RIPEMD160_Update(&ctx, SIG_PREFIX.c_str(), SIG_PREFIX.length());
        unsigned int hash[5];
        RIPEMD160_Final((unsigned char *) hash, &ctx);
        return hash[0];
    }


    static std::string sig_to_str(compact_signature *sig) {
        unsigned int check = calculate_checksum(sig);
        unsigned char data[COMPACT_SIG_LEN + sizeof(check)];
        memcpy(data, (const char *) &sig[0], COMPACT_SIG_LEN);
        memcpy(reinterpret_cast<unsigned char *>(reinterpret_cast<unsigned long long>(&data) + COMPACT_SIG_LEN),
               (char *) &check,
               sizeof(check));
        std::string data_str = EncodeBase58((const unsigned char *) &data,
                                            (const unsigned char *) &data + sizeof(data));
        data_str = "SIG_" + SIG_PREFIX + "_" + data_str;
        return data_str;
    }


    json sign_transaction(json &transaction, std::string &priv_key) {
        json chain_info = get_chain_info();
        json lib_info = get_block(chain_info["last_irreversible_block_num"]);
        Transaction trx = Transaction(transaction, chain_info, lib_info);
        std::string encoded_trx = trx.encode();
        sha256 digest = sig_digest(encoded_trx, chain_info["chain_id"]);

        EC_KEY *ec_key = from_wif(priv_key);
        compact_signature sig[COMPACT_SIG_LEN];

        sign_dig(digest, ec_key, sig);

        std::string sig_str = sig_to_str(sig);

        // TODO fix shitcode
        json tx_json = trx.get_tx_json();
        auto expiration = tx_json["expiration"].get<time_t>();
        tx_json["expiration"] = to_iso_format(expiration);

        json final_trx = {{"compression", "none"},
                          {"transaction", tx_json},
                          {"signatures",  {sig_str}}};

        return final_trx;
    }

    json get_block(int block_num) {
        json params = {{"block_num_or_id", block_num}};
        std::string resp = make_request("chain/get_block", params.dump());
        return json::parse(resp);
    }

    json get_chain_info() {
        std::string resp = make_request("chain/get_info", "");
        return json::parse(resp);
    }


private:
    std::string nodeeos_url;
    std::string v;

    std::string make_request(std::string method, std::string params) {
        curlpp::Cleanup myCleanup;

        curlpp::Easy request;

        std::stringstream response;

        request.setOpt(new curlpp::options::Url(
                nodeeos_url + "/" + v + "/" + method)); // https://nodeos-stage-2.detokex.com/v1/chain/get_block
        std::list<std::string> header;
        header.emplace_back("Content-Type: application/json");
        header.emplace_back("Accept: application/json");
        request.setOpt(new curlpp::options::HttpHeader(header));
        request.setOpt(new curlpp::options::PostFields(params));
//        request.setOpt(new curlpp::options::Verbose(true));
        request.setOpt(new curlpp::options::WriteStream(&response));

        request.perform();

        return response.str();
    }

};

#endif
