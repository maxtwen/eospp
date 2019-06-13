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
#include <openssl/sha.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>

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

std::string sha256(std::string line) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, line.c_str(), line.length());
    SHA256_Final(hash, &sha256);

    std::string output = "";
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        output += to_little_endian_hex(hash[i]);
    }
    return output;
}


class Transaction {
public:
    json data;

    Transaction(json data_, json chain_info, json lib_info) {
        data_["ref_block_num"] = get_ref_blocknum(chain_info["last_irreversible_block_num"]);
        data_["ref_block_prefix"] = lib_info["ref_block_prefix"];
        data = data_;
    }

    int get_ref_blocknum(int head_blocknum) const {
        return ((head_blocknum / 0xffff) * 0xffff) + head_blocknum % 0xffff;
    }


    std::string encode_hdr() {
        std::string exp = to_little_endian_hex((uint32_t) data["expiration"]);
        std::string ref_blk = to_little_endian_hex((uint16_t) data["ref_block_num"]);
        std::string ref_block_prefix = to_little_endian_hex((uint32_t) data["ref_block_prefix"]);
        std::string net_usage_words = "00";
        std::string max_cpu_usage_ms = "00";
        std::string delay_sec = "00";
        return exp + ref_blk + ref_block_prefix + net_usage_words + max_cpu_usage_ms + delay_sec;
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

    template<typename Value>
    std::string serializeVarInt(Value inValue) {
        std::stringstream ss;
        Value value = inValue;

        bool more = true;
        while (more) {
            Value outputByte = value & 127;
            value >>= 7;
            more = std::is_signed<Value>::value
                   ? (value != 0 && value != Value(-1)) || (value >= 0 && (outputByte & 0x40)) ||
                     (value < 0 && !(outputByte & 0x40))
                   : (value != 0);
            if (more) { outputByte |= 0x80; }
            ss << outputByte;
        };

        return ss.str();
    }

    std::string encode_name(std::string name) {
        return to_little_endian_hex((unsigned long long) string_to_name(name));
    }

    std::string encode_authorization(std::unordered_map<std::string, std::string> authorization) {
        std::string actor = encode_name(authorization["actor"]);
        std::string permission = encode_name(authorization["permission"]);
        return actor + permission;
    }

    std::string encode_action(json action) {
        std::string acct = encode_name(action["account"]);
        std::string name = encode_name(action["name"]);
        std::string auth = encode_authorization(action["authorization"][0]);
        std::string data = action["data"];
        std::string data_len = serializeVarInt(data.size() / 2);
        return acct + name + auth + data_len + data;
    }

    std::string encode() {
        std::string hdr_buf = encode_hdr();
        std::string context_actions = "00";
        std::string action = encode_action(data["actions"][0]);
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


    int push_action(std::string account, std::string action, std::string actor, std::string permission, std::string key,
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

        push_transaction(trx, key);
        return 0;
    }


    std::string sig_digest(std::string payload, std::string chain_id) {
        std::string full_payload = payload + chain_id;
        char char_array[full_payload.length() + 32 + 1];
//        for (int i = 0; i < sizeof(char_array)/ sizeof(const char*); i++) {
//            char_array[i] = '\0';
//        }
        std::strcpy(char_array, full_payload.c_str());
        return sha256(char_array);
    }


    int push_transaction(json transaction, std::string key) {
        json chain_info = get_chain_info();
        json lib_info = get_block(chain_info["last_irreversible_block_num"]);
        Transaction trx = Transaction(transaction, chain_info, lib_info);
        std::string encoded_trx = trx.encode();
        std::string digest = sig_digest(encoded_trx, chain_info["chain_id"]);
        std::string priv_key = "d2653ff7cbb2d8ff129ac27ef5781ce68b2558c41a74af1f2ddca635cbeef07d";
        unsigned char * sig;
        EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
        BIGNUM *priv = NULL;
        BN_hex2bn(&priv, priv_key.c_str());
        EC_KEY_set_private_key(ec_key, priv);
        char * private_key = BN_bn2hex(EC_KEY_get0_private_key(ec_key));
        std::cout << private_key << std::endl;
        unsigned char digest_arr[digest.length()];
        strcpy((char*) digest_arr, digest.c_str());
        unsigned int siglen = 65;
        unsigned int *siglen_ptr = &siglen;
        ECDSA_SIG *signature = ECDSA_do_sign(digest_arr, sizeof(digest_arr), ec_key);
        std::cout << BN_bn2hex(signature->r) << std::endl;
        std::cout << BN_bn2hex(signature->s) << std::endl;
        std::cout << ECDSA_do_verify(digest_arr, sizeof(digest_arr), signature, ec_key) << std::endl;
        return 0;
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

int sign(std::string token_account, std::string from_account, std::string to_account, std::string quantity,
         std::string memo, std::string private_key) {


    Eos eos = Eos("http://localhost:8888", "v1");
    json args = {{"from",     from_account},
                 {"to",       to_account},
                 {"quantity", quantity},
                 {"memo",     memo}};
    json resp = eos.push_action(token_account, "transfer", from_account, "active", "", args, 60);

    json action_json = {};


    return 0;
}

int main() {

    std::string token_account = "eosdtsttoken";
    std::string from_account = "tester5";
    std::string to_account = "exchange";
    std::string quantity = "0.024048000 EOSDT";
    std::string memo = "{marketid:1,side:buy,price:0.008,quantity:3,nonce:7876584,type:gtc,post_only:true}";
    std::string private_key = "5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3";

    sign(token_account, from_account, to_account, quantity, memo, private_key);

    return 0;
}