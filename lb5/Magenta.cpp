//
// Created by Вероника Мельцова on 24.11.2025.
//

#include "Magenta.h"
#include <stdexcept>



namespace {
    const uint8_t s_block[256] = {
        1, 2, 4, 8, 16, 32, 64, 128, 101, 202, 241, 135, 107, 214, 201, 247,
        139, 115, 230, 169, 55, 110, 220, 221, 223, 219, 211, 195, 227, 163, 35, 70,
        140, 125, 250, 145, 71, 142, 121, 242, 129, 103, 206, 249, 151, 75, 150, 73,
        146, 65, 130, 97, 194, 225, 167, 43, 86, 172, 61, 122, 244, 141, 127, 254,
        153, 87, 174, 57, 114, 228, 173, 63, 126, 252, 157, 95, 190, 25, 50, 100,
        200, 245, 143, 123, 246, 137, 119, 238, 185, 23, 46, 92, 184, 21, 42, 84,
        168, 53, 106, 212, 205, 255, 155, 83, 166, 41, 82, 164, 45, 90, 180, 13,
        26, 52, 104, 208, 197, 239, 187, 19, 38, 76, 152, 85, 170, 49, 98, 196,
        237, 191, 27, 54, 108, 216, 213, 207, 251, 147, 67, 134, 105, 210, 193, 231,
        171, 51, 102, 204, 253, 159, 91, 182, 9, 18, 36, 72, 144, 69, 138, 113,
        226, 161, 39, 78, 156, 93, 186, 17, 34, 68, 136, 117, 234, 177, 7, 14,
        28, 56, 112, 224, 165, 47, 94, 188, 29, 58, 116, 232, 181, 15, 30, 60,
        120, 240, 133, 111, 222, 217, 215, 203, 243, 131, 99, 198, 233, 183, 11, 22,
        44, 88, 176, 5, 10, 20, 40, 80, 160, 37, 74, 148, 77, 154, 81, 162,
        33, 66, 132, 109, 218, 209, 199, 235, 179, 3, 6, 12, 24, 48, 96, 192,
        229, 175, 59, 118, 236, 189, 31, 62, 124, 248, 149, 79, 158, 89, 178, 0
    };

    uint8_t f(uint8_t x) {
        return s_block[x];
    }

    uint8_t A(uint8_t x, uint8_t y) {
        return f(x ^ f(y));
    }

    byte_array PE(uint8_t x, uint8_t y) {
        return { A(x, y), A(y, x) };
    }

    byte_array PI_func(const byte_array& X) {
        byte_array result;
        result.reserve(16);
        for (int i = 0; i < 8; ++i) {
            byte_array pe_res = PE(X[i], X[i + 8]);
            result.insert(result.end(), pe_res.begin(), pe_res.end());
        }
        return result;
    }

    byte_array T_func(byte_array X) {
        X = PI_func(X);
        X = PI_func(X);
        X = PI_func(X);
        X = PI_func(X);
        return X;
    }

    byte_array S_func(const byte_array& X) {
        byte_array result;
        result.reserve(16);
        for (int i = 0; i < 16; i += 2) {
            result.push_back(X[i]);
        }
        for (int i = 1; i < 16; i += 2) {
            result.push_back(X[i]);
        }
        return result;
    }

    byte_array C_func(int k, byte_array X) {
        if (k == 1) {
            return T_func(X);
        }
        byte_array c_prev = C_func(k - 1, X);
        byte_array s_c_prev = S_func(c_prev);
        for(size_t i = 0; i < X.size(); ++i) {
            X[i] ^= s_c_prev[i];
        }
        return T_func(X);
    }
}

byte_array MagentaRoundFunction::apply(const byte_array& half_block, const byte_array& roundKey) {
	byte_array input_128 = half_block;
	input_128.insert(input_128.end(), roundKey.begin(), roundKey.end());
	byte_array c_res = C_func(3, input_128);
	byte_array s_res = S_func(c_res);
	return byte_array(s_res.begin(), s_res.begin() + 8);
}

MagentaKeyExpander::MagentaKeyExpander(size_t key_size_bits) : m_key_size_bits(key_size_bits) {}

round_keys_array MagentaKeyExpander::generateRoundKeys(const byte_array& masterKey) {
    if (masterKey.size() * 8 != m_key_size_bits) {
        throw std::invalid_argument("MAGENTA masterKey size does not match configured key size.");
    }
    std::vector<byte_array> key_parts;
    for (size_t i = 0; i < masterKey.size(); i += 8) {
        key_parts.push_back(byte_array(masterKey.begin() + i, masterKey.begin() + i + 8));
    }
    round_keys_array round_keys;
    if (m_key_size_bits == 128) {
        round_keys = {key_parts[0], key_parts[0], key_parts[1], key_parts[1], key_parts[0], key_parts[0]};
    } else if (m_key_size_bits == 192) {
        round_keys = {key_parts[0], key_parts[1], key_parts[2], key_parts[2], key_parts[1], key_parts[0]};
    } else if (m_key_size_bits == 256) {
        round_keys = {key_parts[0], key_parts[1], key_parts[2], key_parts[3],
                      key_parts[3], key_parts[2], key_parts[1], key_parts[0]};
    }
    return round_keys;
}


Magenta::Magenta(size_t key_size_bits) {
    if (key_size_bits != 128 && key_size_bits != 192 && key_size_bits != 256) {
        throw std::invalid_argument("Unsupported MAGENTA key size.");
    }

    size_t num_rounds = (key_size_bits == 128 || key_size_bits == 192) ? 6 : 8;

    m_feistel_network = std::make_unique<FeistelCipher>(
        std::make_unique<MagentaKeyExpander>(key_size_bits),
        std::make_unique<MagentaRoundFunction>(),
        num_rounds,
        16
    );
}

void Magenta::setKey(const byte_array& key) {
    m_feistel_network->setKey(key);
}

byte_array Magenta::encryptBlock(const byte_array& block) {
    return m_feistel_network->encryptBlock(block);
}

byte_array Magenta::decryptBlock(const byte_array& block) {
    return m_feistel_network->decryptBlock(block);
}

size_t Magenta::getBlockSize() const {
    return m_feistel_network->getBlockSize();
}