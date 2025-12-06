//
// Created by Вероника Мельцова on 24.11.2025.
//

#include "RC4.h"
#include <numeric>
#include <utility>
#include <stdexcept>

RC4::RC4() : i(0), j(0) {
    S.resize(256);
}

void RC4::setKey(const byte_array& key) {
    if (key.empty() || key.size() > 256) {
        throw std::invalid_argument("RC4 key length must be between 1 and 256 bytes.");
    }
    std::iota(S.begin(), S.end(), 0);
    uint8_t j_local = 0;
    for (int i_local = 0; i_local < 256; ++i_local) {
        j_local = j_local + S[i_local] + key[i_local % key.size()];
        std::swap(S[i_local], S[j_local]);
    }
    i = 0;
    j = 0;
}

uint8_t RC4::getNextKeystreamByte() {
    i = i + 1;
    j = j + S[i];
    std::swap(S[i], S[j]);
    uint8_t K = S[static_cast<uint8_t>(S[i] + S[j])];
    return K;
}

byte_array RC4::encryptBlock(const byte_array& block) {
    byte_array result;
    result.reserve(block.size());
    for (uint8_t plain_byte : block) {
        uint8_t keystream_byte = getNextKeystreamByte();
        result.push_back(plain_byte ^ keystream_byte);
    }

    return result;
}

byte_array RC4::decryptBlock(const byte_array& block) {
    return encryptBlock(block);
}

size_t RC4::getBlockSize() const {
    return 1;
}