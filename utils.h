#ifndef EOSPP_UTILS_H
#define EOSPP_UTILS_H

std::string to_hex(const char *d, uint32_t s) {
    std::string r;
    const char *to_hex = "0123456789abcdef";
    uint8_t *c = (uint8_t *) d;
    for (uint32_t i = 0; i < s; ++i)
        (r += to_hex[(c[i] >> 4)]) += to_hex[(c[i] & 0x0f)];
    return r;
}

std::string to_hex(unsigned long long value) {
    std::stringstream ss;
    ss << std::hex << value;
    return ss.str();
}



template<class T>
std::string to_little_endian_hex(T t) {
// convert to long little endian hex
    long l_num = (long) boost::endian::endian_reverse(t);
// convert to string
    std::ostringstream oss;
    oss << std::hex << l_num;
    std::string mystring = oss.str();
    return mystring;
}


std::string to_iso_format(time_t &time) {
    char buf[20];
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


uint64_t char_to_symbol(char c) {
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
    auto encoded_name = to_little_endian_hex((unsigned long long) string_to_name(std::move(name)));
    std::string result = "";
    if (encoded_name.length() < 16) {
        for (int i = 0; i < 16 - encoded_name.length(); i += 2) {
            result += "00";
        }
    }
    result += encoded_name;
    return result;
}

#endif
