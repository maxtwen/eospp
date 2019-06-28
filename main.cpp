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
#include "base58.cpp"
#include "sha256.cpp"

const std::string SIG_PREFIX = "K1";
const int COMPACT_SIG_LEN = 65;

typedef unsigned char compact_signature;

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


std::string to_iso_format(time_t &time) {
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
    json _chain_info;

public:

    Transaction(json data, json chain_info, json lib_info) {
        data["ref_block_num"] = get_ref_blocknum(chain_info["last_irreversible_block_num"]);
        data["ref_block_prefix"] = lib_info["ref_block_prefix"];
        data["net_usage_words"] = 0;
        data["max_cpu_usage_ms"] = 0;
        data["delay_sec"] = 0;
        data["context_free_actions"] = "[]"_json;
        _data = data;
        _chain_info = chain_info;
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
    push_action(std::string account, std::string action, std::string actor, std::string permission, std::string key,
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

        return push_transaction(trx, key);
    }


    sha256 sig_digest(std::string payload, std::string chain_id) {
        std::string full_payload = chain_id + payload;
        std::string context_free_data = "";
        for (int i = 0; i < 32; i++) {
            context_free_data += "00";
        }

        full_payload += context_free_data;

        std::cout << full_payload << std::endl;


        unsigned char *bin_payload = hexstr_to_char(full_payload.c_str());

        return sha256::hash((char *) bin_payload, full_payload.length() / 2);
    }

    static std::vector<char> from_base58(const std::string &base58_str) {
        std::vector<unsigned char> out;
        if (!DecodeBase58(base58_str.c_str(), out)) {
            throw "Unable to decode base58 string ${base58_str}";
        }
        return std::vector<char>((const char *) out.data(), ((const char *) out.data()) + out.size());
    }

    int static inline EC_KEY_regenerate_key(EC_KEY *eckey, const BIGNUM *priv_key) {
        int ok = 0;
        BN_CTX *ctx = NULL;
        EC_POINT *pub_key = NULL;

        if (!eckey) return 0;

        const EC_GROUP *group = EC_KEY_get0_group(eckey);

        if ((ctx = BN_CTX_new()) == NULL)
            goto err;

        pub_key = EC_POINT_new(group);

        if (pub_key == NULL)
            goto err;

        if (!EC_POINT_mul(group, pub_key, priv_key, NULL, NULL, ctx))
            goto err;

        EC_KEY_set_private_key(eckey, priv_key);
        EC_KEY_set_public_key(eckey, pub_key);

        ok = 1;

        err:

        if (pub_key) EC_POINT_free(pub_key);
        if (ctx != NULL) BN_CTX_free(ctx);

        return (ok);
    }

    static EC_KEY *from_wif(const std::string &priv) {

        auto wif_bytes = from_base58(priv);
        auto key_bytes = std::vector<char>(wif_bytes.begin() + 1, wif_bytes.end() - 4);
        auto key_hex = to_hex(key_bytes.data(), key_bytes.size());

        sha256 tmp;
        memcpy(&tmp, key_bytes.data(), std::min<size_t>(key_bytes.size(), sizeof(tmp)));
        BIGNUM *bn = BN_new();
        BN_bin2bn((const unsigned char *) &tmp, 32, bn);

        std::cout << BN_bn2hex(bn) << std::endl;
        EC_KEY *key = EC_KEY_new_by_curve_name(NID_secp256k1);
        if (!EC_KEY_regenerate_key(key, bn)) {
            throw "unable to regenerate key";
        };
        return key;
    }


    static EC_KEY *get_public_key(EC_KEY *private_key) {
        EC_KEY *pub = EC_KEY_new_by_curve_name(NID_secp256k1);
        EC_KEY_set_public_key(pub, EC_KEY_get0_public_key(private_key));
        EC_KEY_set_conv_form(pub, POINT_CONVERSION_COMPRESSED);
        return pub;
    }

    static void public_to_buf(EC_KEY *key, char *buf) {
        char *from = &buf[0];
        i2o_ECPublicKey(key, (unsigned char **) (&from));
    }


    static void sign_dig(sha256 &digest,
                         EC_KEY *ec_key,
                         compact_signature *sig) { // see eos/libraries/fc/src/crypto/elliptic_openssl.cpp compact_signature private_key::sign_compact
        ECDSA_SIG *ecdsa_sig = nullptr;

        char public_key[33];
        public_to_buf(get_public_key(ec_key), public_key);

        std::cout << to_hex((const char *) &public_key, sizeof(public_key)) << std::endl;

        char key_data[33];

        while (true) {
            ecdsa_sig = ECDSA_do_sign((unsigned char *) &digest, sizeof(digest),
                                      ec_key); //TODO size of используется не правильно, там нужна длина

            int nBitsR = BN_num_bits(ecdsa_sig->r);
            int nBitsS = BN_num_bits(ecdsa_sig->s);
            if (nBitsR > 256 || nBitsS > 256) continue;
            int nRecId = -1;
            EC_KEY *key = EC_KEY_new_by_curve_name(NID_secp256k1);
            EC_KEY_set_conv_form(key, POINT_CONVERSION_COMPRESSED);
            for (int i = 0; i < 4; i++) {
                if (ECDSA_SIG_recover_key_GFp(key, ecdsa_sig, (unsigned char *) &digest,
                                              sizeof(digest), i, 1) == 1) {
                    public_to_buf(key, key_data);
                    if (0 == memcmp(key_data, public_key, 33 * sizeof(char))) {
                        nRecId = i;
                        break;
                    }
                }
            }
            EC_KEY_free(key);
            unsigned char *result = nullptr;
            auto bytes = i2d_ECDSA_SIG(ecdsa_sig, &result);
            auto lenR = result[3];
            auto lenS = result[5 + lenR];

            if (lenR != 32) {
                free(result);
                continue;
            }
            if (lenS != 32) {
                free(result);
                continue;
            }

            memcpy(&sig[1], &result[4], lenR);
            memcpy(&sig[33], &result[6 + lenR], lenS);
            sig[0] = nRecId + 27 + 4;

            std::cout << ECDSA_do_verify((unsigned char *) digest.data(), sizeof(digest), ecdsa_sig, ec_key)
                      << std::endl;
            return;
        }


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


    json push_transaction(json transaction, std::string key) {
        json chain_info = get_chain_info();
        json lib_info = get_block(chain_info["last_irreversible_block_num"]);
        Transaction trx = Transaction(transaction, chain_info, lib_info);
        std::string encoded_trx = trx.encode();
        sha256 digest = sig_digest(encoded_trx, chain_info["chain_id"]);

        std::string priv_key = "5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3";
        EC_KEY *ec_key = from_wif(priv_key);

//        ECDSA_SIG *signature = sign_dig(digest_arr, ec_key);
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

int sign(std::string token_account, std::string from_account, std::string to_account, std::string quantity,
         std::string memo, std::string private_key) {


    Eos eos = Eos("http://localhost:8888", "v1");
    json args = {{"from",     from_account},
                 {"to",       to_account},
                 {"quantity", quantity},
                 {"memo",     memo}};
    json resp = eos.push_action(token_account, "transfer", from_account, "active", "", args, 60);

    std::cout << resp << std::endl;

    return 0;
}


int main() {
//    char b[32];
//    memset(b, 0, sizeof(b));
//    auto sb = sha256::hash(b, sizeof(b));

//    std::string payload = "1f47065124d50319cd457a8440b1004b18ca5b51934bc64b344310bc836b3a0d052ebd94f1df4c23ec482146a7088ec7a502d575aa168e552b749e3197b0c3ca49";
//    unsigned char * bin_payload = hexstr_to_char(payload.c_str());
//    std::cout << to_hex((const char*)&sb, sizeof(sb)) << std::endl;

//    char b[32];
//    memset(b, 0, sizeof(b));
//    auto sb = sha256::hash(b, sizeof(b));
//    std::cout << sb.str() << std::endl;
//    return 0;

//    std::cout << encode_name("active") << std::endl;


//    return 0;

//    char b[32];
//    memset(b, 0, sizeof(b));
//    auto sb = sha256(b, sizeof(b));
//    auto strpkey = std::string("5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3");
//    auto pkey = Eos::from_wif(strpkey);
//    compact_signature sig[COMPACT_SIG_LEN];
//    Eos::sign_dig(sb, pkey, sig);
//    std::stringstream ss;
//    for (int i = 0; i < 65; i++) {
//        ss << std::hex << (int) sig[i];
//    }
//    std::cout << ss.str() << std::endl;
//
//    std::cout << Eos::sig_to_str(sig) << std::endl;


    std::string token_account = "eosdtsttoken";
    std::string from_account = "tester5";
    std::string to_account = "exchange";
    std::string quantity = "0.024048000 EOSDT";
    std::string memo = "{marketid:1,side:buy,price:0.008,quantity:3,nonce:7876584,type:gtc,post_only:true}";
    std::string private_key = "5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3";

    sign(token_account, from_account, to_account, quantity, memo, private_key);

    return 0;
}