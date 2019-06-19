#include <openssl/sha.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>

void ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps) {
    if (pr != NULL)
        *pr = sig->r;
    if (ps != NULL)
        *ps = sig->s;
}

static int
ECDSA_SIG_recover_key_GFp(EC_KEY *eckey, ECDSA_SIG *ecsig, const unsigned char *msg, int msglen, int recid, int check) {
    int ret = 0;
    BN_CTX *ctx = NULL;

    BIGNUM *x = NULL;
    BIGNUM *e = NULL;
    BIGNUM *order = NULL;
    BIGNUM *sor = NULL;
    BIGNUM *eor = NULL;
    BIGNUM *field = NULL;
    EC_POINT *R = NULL;
    EC_POINT *O = NULL;
    EC_POINT *Q = NULL;
    BIGNUM *rr = NULL;
    BIGNUM *zero = NULL;
    int n = 0;
    int i = recid / 2;

    const BIGNUM *r, *s;
    ECDSA_SIG_get0(ecsig, &r, &s);

    const EC_GROUP *group = EC_KEY_get0_group(eckey);
    if ((ctx = BN_CTX_new()) == NULL) {
        ret = -1;
        goto err;
    }
    BN_CTX_start(ctx);
    order = BN_CTX_get(ctx);
    if (!EC_GROUP_get_order(group, order, ctx)) {
        ret = -2;
        goto err;
    }
    x = BN_CTX_get(ctx);
    if (!BN_copy(x, order)) {
        ret = -1;
        goto err;
    }
    if (!BN_mul_word(x, i)) {
        ret = -1;
        goto err;
    }
    if (!BN_add(x, x, r)) {
        ret = -1;
        goto err;
    }
    field = BN_CTX_get(ctx);
    if (!EC_GROUP_get_curve_GFp(group, field, NULL, NULL, ctx)) {
        ret = -2;
        goto err;
    }
    if (BN_cmp(x, field) >= 0) {
        ret = 0;
        goto err;
    }
    if ((R = EC_POINT_new(group)) == NULL) {
        ret = -2;
        goto err;
    }
    if (!EC_POINT_set_compressed_coordinates_GFp(group, R, x, recid % 2, ctx)) {
        ret = 0;
        goto err;
    }
    if (check) {
        if ((O = EC_POINT_new(group)) == NULL) {
            ret = -2;
            goto err;
        }
        if (!EC_POINT_mul(group, O, NULL, R, order, ctx)) {
            ret = -2;
            goto err;
        }
        if (!EC_POINT_is_at_infinity(group, O)) {
            ret = 0;
            goto err;
        }
    }
    if ((Q = EC_POINT_new(group)) == NULL) {
        ret = -2;
        goto err;
    }
    n = EC_GROUP_get_degree(group);
    e = BN_CTX_get(ctx);
    if (!BN_bin2bn(msg, msglen, e)) {
        ret = -1;
        goto err;
    }
    if (8 * msglen > n) BN_rshift(e, e, 8 - (n & 7));
    zero = BN_CTX_get(ctx);
    if (!BN_zero(zero)) {
        ret = -1;
        goto err;
    }
    if (!BN_mod_sub(e, zero, e, order, ctx)) {
        ret = -1;
        goto err;
    }
    rr = BN_CTX_get(ctx);
    if (!BN_mod_inverse(rr, r, order, ctx)) {
        ret = -1;
        goto err;
    }
    sor = BN_CTX_get(ctx);
    if (!BN_mod_mul(sor, s, rr, order, ctx)) {
        ret = -1;
        goto err;
    }
    eor = BN_CTX_get(ctx);
    if (!BN_mod_mul(eor, e, rr, order, ctx)) {
        ret = -1;
        goto err;
    }
    if (!EC_POINT_mul(group, Q, eor, R, sor, ctx)) {
        ret = -2;
        goto err;
    }
    if (!EC_KEY_set_public_key(eckey, Q)) {
        ret = -2;
        goto err;
    }

    ret = 1;

    err:
    if (ctx) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    if (R != NULL) EC_POINT_free(R);
    if (O != NULL) EC_POINT_free(O);
    if (Q != NULL) EC_POINT_free(Q);
    return ret;
}