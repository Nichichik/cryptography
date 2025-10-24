//
// Created by Вероника on 13.10.2025.
//
#include "FeistelCipher.h"
#include <algorithm>
#include <iostream>


FeistelCipher::FeistelCipher(
        std::unique_ptr<IKeyExpander> keyExpander,
        std::unique_ptr<IRoundFunction> roundFunction,
        int numRounds,
        size_t blockSize
) : m_keyExpander(std::move(keyExpander)),
    m_roundFunction(std::move(roundFunction)),
    m_numRounds(numRounds),
    m_blockSize(blockSize)
{
    if (!m_keyExpander || !m_roundFunction){
        std::cout << "Components must not be null." << std::endl;
    }
    if (m_numRounds <= 0){
        std::cout << "Number of rounds must be positive." << std::endl;
    }
    if (m_blockSize % 2 != 0) {
        std::cout << "Block size must be even."<< std::endl;
    }
}

void FeistelCipher::setKey(const std::vector<unsigned char>& key) {
    m_encryptionKeys = m_keyExpander->generateRoundKeys(key);
    if (m_encryptionKeys.size() < m_numRounds) {
        std::cout << "Key expander generated fewer keys than rounds required."<< std::endl;
    }
    m_decryptionKeys = m_encryptionKeys;
    std::reverse(m_decryptionKeys.begin(), m_decryptionKeys.end());
}


std::vector<unsigned char> FeistelCipher::encryptBlock(const std::vector<unsigned char>& block) {
    if (m_encryptionKeys.empty()) {
        std::cout << "Key is not set." << std::endl;
    }
    if (block.size() != m_blockSize) {
        std::cout << "Invalid block size." << std::endl;
    }

    size_t half_size = m_blockSize / 2;
    std::vector<unsigned char> L(block.begin(), block.begin() + half_size);
    std::vector<unsigned char> R( block.begin() + half_size, block.end());


    for (int i = 0; i < m_numRounds; ++i) {
        std::vector<unsigned char> old_L = L;
        L = R;
        std::vector<unsigned char> f_result = m_roundFunction->apply(R, m_encryptionKeys[i]);
        xor_bytes(f_result, old_L);
        R = f_result;
    }

    std::vector<unsigned char> result = R;
    result.insert(result.end(), L.begin(), L.end());
    return result;
}

std::vector<unsigned char> FeistelCipher::decryptBlock(const std::vector<unsigned char>& block) {
    if (m_encryptionKeys.empty()) {
        std::cout << "Key is not set." << std::endl;
    }
    if (block.size() != m_blockSize) {
        std::cout << "Invalid block size." << std::endl;
    }

    size_t half_size = m_blockSize / 2;
    std::vector<unsigned char> L(block.begin(), block.begin() + half_size);
    std::vector<unsigned char> R( block.begin() + half_size, block.end());

    for (int i = 0; i < m_numRounds; ++i) {
        std::vector<unsigned char> old_L = L;
        L = R;
        std::vector<unsigned char> f_result = m_roundFunction->apply(R, m_decryptionKeys[i]);
        xor_bytes(f_result, old_L);
        R = f_result;
    }

    std::vector<unsigned char> result = R;
    result.insert(result.end(), L.begin(), L.end());
    return result;
}

size_t FeistelCipher::getBlockSize() const {
    return m_blockSize;
}