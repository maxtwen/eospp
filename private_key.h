#ifndef EOSPP_PRIVATE_KEY_H
#define EOSPP_PRIVATE_KEY_H
int EC_KEY_regenerate_key(EC_KEY *eckey, const BIGNUM *priv_key)
{
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

    EC_KEY_set_private_key(eckey,priv_key);
    EC_KEY_set_public_key(eckey,pub_key);

    ok = 1;

    err:

    if (pub_key) EC_POINT_free(pub_key);
    if (ctx != NULL) BN_CTX_free(ctx);

    return(ok);
}

static std::vector<char> from_base58(const std::string &base58_str) {
    std::vector<unsigned char> out;
    if (!DecodeBase58(base58_str.c_str(), out)) {
        throw "Unable to decode base58 string ${base58_str}";
    }
    return std::vector<char>((const char *) out.data(), ((const char *) out.data()) + out.size());
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
    EC_KEY* key = EC_KEY_new_by_curve_name( NID_secp256k1 );
    if (!EC_KEY_regenerate_key(key, bn)) {
        throw "unable to regenerate key";
    };
    return key;
}

#endif
