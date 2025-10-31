//
// Created by Вероника on 17.10.2025.
//

#include "DEAL.h"
#include <algorithm>
#include <cstdint>
//https://www.schneier.com/wp-content/uploads/2016/02/paper-deal.pdf

using namespace DES_Implementation;

void adjust_des_parity_bits(byte_array& key) {
    if (key.size() != 8) {
        return;
    }

    for (size_t i = 0; i < 8; ++i) {
        int ones = 0;
        for (int bit = 1; bit <= 7; ++bit) {
            if ((key[i] >> bit) & 1) {
                ++ones;
            }
        }
        if (ones % 2 == 0) {
            key[i] |= 1;
        } else {
            key[i] &= 0xFE;
        }
    }
}

DES_Adapter::DES_Adapter() {
}

byte_array DES_Adapter::apply(const byte_array& half_block, const byte_array& roundKey) {
    if (half_block.size() != 8) {
        std::cout << "DEAL round function requires a 64-bit block." << std::endl;
    }
    byte_array adjusted_key = roundKey; // Создаем копию
    adjust_des_parity_bits(adjusted_key);
    auto it = m_des_cache.find(adjusted_key);
    if (it != m_des_cache.end()) {
        return it->second->encryptBlock(half_block);
    } else {
        std::lock_guard<std::mutex> lock(m_mutex);
        it = m_des_cache.find(adjusted_key);
        if (it == m_des_cache.end()) {
            auto des = std::make_unique<DES>();
            des->setKey(adjusted_key);
            m_des_cache[adjusted_key] = std::move(des);
            return m_des_cache[adjusted_key]->encryptBlock(half_block);
        } else {
            return it->second->encryptBlock(half_block);
        }
    }
}


DEALKeyExpander::DEALKeyExpander(DEAL_Variant variant) : m_variant(variant) {}

round_keys_array DEALKeyExpander::generateRoundKeys(const byte_array& masterKey) {
    size_t s_parts = 0;
    size_t r_rounds = 0;

    if (m_variant == DEAL_Variant::DEAL_128_6) {
        s_parts = 2; r_rounds = 6;
    } else if (m_variant == DEAL_Variant::DEAL_192_6) {
        s_parts = 3; r_rounds = 6;
    } else if (m_variant == DEAL_Variant::DEAL_256_8) {
        s_parts = 4; r_rounds = 8;
    } else {
        std::cout << "Unsupported DEAL variant." << std::endl;
    }

    if (masterKey.size() != s_parts * 8)
        std::cout << "Master key size does not match DEAL variant." << std::endl;

    std::vector<byte_array> K;
    for (size_t i = 0; i < s_parts; ++i)
        K.emplace_back(masterKey.begin() + i * 8, masterKey.begin() + (i + 1) * 8);

    round_keys_array R;
    R.reserve(r_rounds);

    DES des_const;
    byte_array const_key(8, 0x0F);
    adjust_des_parity_bits(const_key);
    des_const.setKey(const_key);

    for (size_t i = 0; i < s_parts; ++i) {
        if (i == 0) {
            R.push_back(des_const.encryptBlock(K[0]));
        } else {
            byte_array tmp = K[i];
            xor_bytes(tmp, R[i - 1]);
            R.push_back(des_const.encryptBlock(tmp));
        }
    }

    for (size_t i = s_parts; i < r_rounds; ++i) {
        byte_array tmp = K[i % s_parts];
        xor_bytes(tmp, R[i - 1]);

        uint64_t constant = 1ULL << (i - s_parts);
        for (int j = 0; j < 8; ++j)
            tmp[7 - j] ^= (constant >> (8 * j)) & 0xFF;

        R.push_back(des_const.encryptBlock(tmp));
    }

    return R;
}



DEAL::DEAL(DEAL_Variant variant) : m_variant(variant) {
    int num_rounds = (variant == DEAL_Variant::DEAL_128_6 || variant == DEAL_Variant::DEAL_192_6) ? 6 : 8;

    auto key_expander = std::make_unique<DEALKeyExpander>(variant);

    m_feistel_network = std::make_unique<FeistelCipher>(
            std::move(key_expander),
            std::make_unique<DES_Adapter>(),
            num_rounds,
            16
    );
}

void DEAL::setKey(const byte_array& key) {
    m_feistel_network->setKey(key);
}

byte_array DEAL::encryptBlock(const byte_array& block) {
    return m_feistel_network->encryptBlock(block);
}

byte_array DEAL::decryptBlock(const byte_array& block) {
    return m_feistel_network->decryptBlock(block);
}

size_t DEAL::getBlockSize() const {
    return m_feistel_network->getBlockSize();
}