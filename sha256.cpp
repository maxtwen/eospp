#include <openssl/sha.h>
#include <stdint.h>
#include <string.h>

#ifndef SHA256_CPP
#define SHA256_CPP

std::string to_hex( const char* d, uint32_t s )
{
    std::string r;
    const char* to_hex="0123456789abcdef";
    uint8_t* c = (uint8_t*)d;
    for( uint32_t i = 0; i < s; ++i )
        (r += to_hex[(c[i]>>4)]) += to_hex[(c[i] &0x0f)];
    return r;
}


class sha256 {
    unsigned long long _hash[4];

public:
    explicit sha256() { memset(_hash, 0, sizeof(_hash)); }

    sha256(const char *data, size_t size) {
        if (size != sizeof(_hash))
            throw "sha256: size mismatch";
        memcpy(_hash, data, size);
    }

    char *data() const {
        return (char *) &_hash[0];
    }

    static sha256 hash(const char *d, uint32_t dlen) {
        encoder e;
        e.write(d, dlen);
        return e.result();
    }

    static sha256 hash(const sha256 &s) {
        return hash(s.data(), sizeof(s._hash));
    }

    std::string str()const {
        return to_hex( (char*)_hash, sizeof(_hash) );
    }

    class encoder {
    public:

        ~encoder() {}

        encoder() {
            reset();
        }

        void reset() {
            SHA256_Init(&ctx);
        }

        void write(const char *d, uint32_t dlen) {
            SHA256_Update(&ctx, d, dlen);
        }

        void put(char c) { write(&c, 1); }

        sha256 result() {
            sha256
                    h;
            SHA256_Final((uint8_t *) h.data(), &ctx);
            return h;
        }

    private:
        SHA256_CTX ctx;
    };


};

#endif