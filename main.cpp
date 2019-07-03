#include "eospp.h"


int sign(std::string &token_account, std::string &from_account, std::string &to_account, std::string &quantity,
         std::string &memo, std::string &private_key) {


    Eos eos = Eos("https://nodeos-stage-2.detokex.com:443");
    json args = {{"from",     from_account},
                 {"to",       to_account},
                 {"quantity", quantity},
                 {"memo",     memo}};
    std::string action = "transfer";
    std::string permission = "active";
    int expiration_sec = 60;
    json resp = eos.sign_action(token_account, action, from_account, permission, private_key, args, expiration_sec);


    std::cout << resp << std::endl;

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