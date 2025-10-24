//
// Created by Вероника on 03.10.2025.
//

#ifndef CRYPTOGRAPHY_BITPERMUTE_H
#define CRYPTOGRAPHY_BITPERMUTE_H

#include <vector>
#include <string>
#include<algorithm>


enum class BitDir {
    LIT_END,
    BIG_END
};

enum class BitBase {
    ZERO_BASE,
    ONE_BASE
};

std::vector<unsigned char> permute(
        const std::vector<unsigned char>& input,
        const std::vector<int>& p_block,
        BitDir direction,
        BitBase base
);


void print_binary(const std::string& label, const std::vector<unsigned char>& data);

#endif //CRYPTOGRAPHY_BITPERMUTE_H
