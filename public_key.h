#ifndef EOSPP_PUBLIC_KEY_H
#define EOSPP_PUBLIC_KEY_H

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

#endif
