//
// Created by Вероника on 13.10.2025.
//

#include "DES.h"
#include <algorithm>
#include <iostream>


namespace DES_Implementation {
    bool get_bit(const byte_array &data, size_t index) {
        return (data[index / 8] >> (7 - (index % 8))) & 1;
    }

    void set_bit(byte_array &data, size_t index, bool value) {
        if (value) {
            data[index / 8] |= (1 << (7 - (index % 8)));
        } else {
            data[index / 8] &= ~(1 << (7 - (index % 8)));
        }
    }

    void xor_bytes(std::vector<unsigned char>& a, const std::vector<unsigned char>& b) {
        if (a.size() != b.size()) {
            std::cout << "XOR vectors must have the same size." << std::endl;
        }
        for (size_t i = 0; i < a.size(); ++i) {
            a[i] ^= b[i];
        }
    }



    namespace DES_Tables {
        const std::vector<int> IP = {58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7};
        const std::vector<int> FP = {40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25};
        const std::vector<int> E = {32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1};
        const std::vector<int> P = {16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25};
        const std::vector<int> PC1 = {57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4};
        const std::vector<int> PC2 = {14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32};
        const int SHIFTS[] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};
        const int S_BOXES[8][4][16] = {{{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},{0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},{4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},{15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}},{{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},{3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},{0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},{13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}},{{10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},{13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},{13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},{1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}},{{7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},{13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},{10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},{3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}},{{2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},{14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},{4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},{11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}},{{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},{10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},{9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},{4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}},{{4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},{13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},{1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},{6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}},{{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},{1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},{7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},{2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}}};
    }

    bool check_des_parity_bits(const byte_array& key) {
        if (key.size() != 8) {
            return false;
        }

        for (size_t i = 0; i < 8; ++i) {
            unsigned char byte = key[i];
            int ones = 0;
            for (int bit = 0; bit < 7; ++bit) {
                if (byte & (1 << (7 - bit))){
                    ++ones;
                }
            }

            bool parity_bit = (byte & 1);
            bool should_be = !(ones % 2);

            if (parity_bit != should_be) {
                return false;
            }
        }
        return true;
    }


    std::vector<std::vector<unsigned char>> DESKeyExpander::generateRoundKeys(const byte_array &masterKey) {
        if (masterKey.size() != 8) {
            std::cout <<"The DES key must be 64-bit (8 bytes)." << std::endl;
        }

        if (!check_des_parity_bits(masterKey)) {
            std::cout << "Invalid DES key: parity bits are incorrect." << std::endl;
        }

        byte_array key_56 = permute(masterKey, DES_Tables::PC1, BitDir::BIG_END, BitBase::ONE_BASE);
        round_keys_array round_keys;
        for (int i = 0; i < 16; ++i) {
            uint32_t c_half = 0;
            uint32_t d_half = 0;
            for (int i = 0; i < 28; ++i) {
                if (get_bit(key_56, i)){
                    c_half |= (1 << (27 - i));
                }
                if (get_bit(key_56, i + 28)) {
                    d_half |= (1 << (27 - i));
                }
            }
            for (int s = 0; s < DES_Tables::SHIFTS[i]; ++s) {
                c_half = ((c_half << 1) | (c_half >> 27)) & 0x0FFFFFFF;
                d_half = ((d_half << 1) | (d_half >> 27)) & 0x0FFFFFFF;
            }

            byte_array combined_56(7, 0);
            for (int j = 0; j < 28; ++j) {
                if ((c_half >> (27 - j)) & 1){
                    set_bit(combined_56, j, true);
                }
                if ((d_half >> (27 - j)) & 1){
                    set_bit(combined_56, j + 28, true);
                }
            }

            byte_array round_key = permute(combined_56, DES_Tables::PC2, BitDir::BIG_END, BitBase::ONE_BASE);
            round_keys.push_back(round_key);
        }
        return round_keys;
    }

    byte_array DESRoundFunction::apply(const byte_array &half_block, const byte_array &roundKey) {
        if (half_block.size() != 4) {
            std::cout <<"DES F-function input must be 32 bits." << std::endl;
        }
        if (roundKey.size() != 6) {
            std::cout << "DES round key must be 48 bits." << std::endl;
        }
        byte_array expanded = permute(half_block, DES_Tables::E, BitDir::BIG_END, BitBase::ONE_BASE);
        xor_bytes(expanded, roundKey);

        byte_array s_output(4, 0);
        for (int i = 0; i < 8; ++i) {
            int six_bits = 0;
            for (int j = 0; j < 6; ++j) {
                if(get_bit(expanded,i*6 + j)){
                    six_bits|=(1 << (5 - j));//B^i блок
                }
            }
            int row = ((six_bits >> 5) & 1)*2 + (six_bits & 1);
            int col = (six_bits >> 1) & 0x0F;
            unsigned char s_val=DES_Tables::S_BOXES[i][row][col];//B'^i
            for(int j = 0; j < 4; ++j){
                if((s_val >> (3 - j)) & 1){
                    set_bit(s_output,i*4+j,true);
                }
            }
        }
        byte_array final_result = permute(s_output, DES_Tables::P, BitDir::BIG_END, BitBase::ONE_BASE);
        return final_result;
    }

    DES::DES() {
        auto key_expander = std::make_unique<DESKeyExpander>();
        auto round_function = std::make_unique<DESRoundFunction>();
        m_feistel_network = std::make_unique<FeistelCipher>(
                std::move(key_expander),
                std::move(round_function),
                16, 8
        );
    }

    void DES::setKey(const byte_array &key) {
        m_feistel_network->setKey(key);
    }

    byte_array DES::encryptBlock(const byte_array& block) {
        byte_array permuted = permute(block, DES_Tables::IP, BitDir::BIG_END, BitBase::ONE_BASE);
        byte_array feistel_out = m_feistel_network->encryptBlock(permuted);
        byte_array ciphertext = permute(feistel_out, DES_Tables::FP, BitDir::BIG_END, BitBase::ONE_BASE);
        return ciphertext;
    }

    byte_array DES::decryptBlock(const byte_array& block) {
        byte_array permuted = permute(block, DES_Tables::IP, BitDir::BIG_END, BitBase::ONE_BASE);
        byte_array feistel_out = m_feistel_network->decryptBlock(permuted);
        byte_array plaintext = permute(feistel_out, DES_Tables::FP, BitDir::BIG_END, BitBase::ONE_BASE);
        return plaintext;
    }

    size_t DES::getBlockSize() const {
        return 8;
    }
};