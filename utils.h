//
// Created by mafanasevsky on 2019-07-01.
//

#ifndef EOSPP_UTILS_H
#define EOSPP_UTILS_H
std::string to_hex( const char* d, uint32_t s )
{
    std::string r;
    const char* to_hex="0123456789abcdef";
    uint8_t* c = (uint8_t*)d;
    for( uint32_t i = 0; i < s; ++i )
        (r += to_hex[(c[i]>>4)]) += to_hex[(c[i] &0x0f)];
    return r;
}

#endif //EOSPP_UTILS_H
