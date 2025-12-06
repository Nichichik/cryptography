//
// Created by Вероника Мельцова on 17.11.2025.
//

#include "Rijndael.h"
#include <algorithm>
#include <vector>


RijndaelKeyExpander::RijndaelKeyExpander(size_t block_size_bytes, size_t key_size_bytes, const byte_array& sbox)
    : m_sbox(sbox) {

    m_key_size_words = key_size_bytes / 4;
    m_block_size_words = block_size_bytes / 4;

    if (m_block_size_words == 4) {
        if (m_key_size_words == 4) m_num_rounds = 10;
        else if (m_key_size_words == 6) m_num_rounds = 12;
        else if (m_key_size_words == 8) m_num_rounds = 14;
    } else if (m_block_size_words == 6) {
        if (m_key_size_words == 4) m_num_rounds = 12;
        else if (m_key_size_words == 6) m_num_rounds = 12;
        else if (m_key_size_words == 8) m_num_rounds = 14;
    } else if (m_block_size_words == 8) {
        m_num_rounds = 14;
    }

    m_rcon.push_back(0x00);
    uint8_t val = 0x01;
    GaloisField::StatelessService gf;
    for (int i = 0; i < 30; ++i) { // Генерируем с запасом
        m_rcon.push_back(val);
        val = gf.multiply(val, 0x02);
    }
}

void RijndaelKeyExpander::rotWord(byte_array& word) const {
    std::rotate(word.begin(), word.begin() + 1, word.end());
}

void RijndaelKeyExpander::subWord(byte_array& word) const {
    for (size_t i = 0; i < word.size(); ++i) {
        word[i] = m_sbox[word[i]];
    }
}

round_keys_array RijndaelKeyExpander::generateRoundKeys(const byte_array& masterKey) {
    size_t Nk = m_key_size_words;
    size_t Nb = m_block_size_words;
    size_t total_words = Nb * (m_num_rounds + 1);

    std::vector<byte_array> words(total_words, byte_array(4));

    for (size_t i = 0; i < Nk; ++i) {
        words[i] = byte_array(masterKey.begin() + i * 4, masterKey.begin() + (i + 1) * 4);
    }
    for (size_t i = Nk; i < total_words; ++i) {
        byte_array temp = words[i - 1];
        if (i % Nk == 0) {
            rotWord(temp);
            subWord(temp);
            temp[0] ^= m_rcon[i / Nk];
        } else if (Nk > 6 && (i % Nk == 4)) {
            subWord(temp);
        }

        words[i] = words[i - Nk];
        xor_bytes(words[i], temp);
    }
    round_keys_array result_keys;
    for(size_t i = 0; i < total_words; i += Nb) {
        byte_array round_key;
        for(size_t j = 0; j < Nb; ++j) {
            round_key.insert(round_key.end(), words[i+j].begin(), words[i+j].end());
        }
        result_keys.push_back(round_key);
    }

    return result_keys;
}


Rijndael::Rijndael(size_t block_size_bits, size_t key_size_bits, uint16_t modulus)
    : m_sboxes_initialized(false), m_modulus(modulus) {

    m_block_size_bytes = block_size_bits / 8;
    m_key_size_bytes = key_size_bits / 8;

    size_t Nk = m_key_size_bytes / 4;
    size_t Nb = m_block_size_bytes / 4;
    if (Nb == 4) {
        if (Nk == 4) m_num_rounds = 10;
        else if (Nk == 6) m_num_rounds = 12;
        else if (Nk == 8) m_num_rounds = 14;
    } else if (Nb == 6) {
        if (Nk == 4) m_num_rounds = 12;
        else if (Nk == 6) m_num_rounds = 12;
        else if (Nk == 8) m_num_rounds = 14;
    } else if (Nb == 8) {
        m_num_rounds = 14;
    }
}

size_t Rijndael::getBlockSize() const { return m_block_size_bytes; }

void Rijndael::setKey(const byte_array& key) {
    if (key.size() != m_key_size_bytes) {
        throw std::invalid_argument("Invalid key size.");
    }

    ensureSBoxesInitialized();
    m_key_expander = std::make_unique<RijndaelKeyExpander>(m_block_size_bytes, m_key_size_bytes, m_sbox);
    m_round_keys = m_key_expander->generateRoundKeys(key);
}

byte_array Rijndael::encryptBlock(const byte_array& block) {
    if (block.size() != m_block_size_bytes) throw std::invalid_argument("Invalid block size.");
    if (m_round_keys.empty()) throw std::runtime_error("Key is not set.");

    byte_array state = block;
    addRoundKey(state, 0);
    for (size_t round = 1; round < m_num_rounds; ++round) {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, round);
    }
    subBytes(state);
    shiftRows(state);
    addRoundKey(state, m_num_rounds);

    return state;
}

byte_array Rijndael::decryptBlock(const byte_array& block) {
    if (block.size() != m_block_size_bytes) throw std::invalid_argument("Invalid block size.");
    if (m_round_keys.empty()) throw std::runtime_error("Key is not set.");

    byte_array state = block;

    addRoundKey(state, m_num_rounds);

    for (size_t round = m_num_rounds - 1; round > 0; --round) {
        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, round);
        invMixColumns(state);
    }

    invShiftRows(state);
    invSubBytes(state);
    addRoundKey(state, 0);

    return state;
}

void Rijndael::addRoundKey(byte_array& state, size_t round) {
    xor_bytes(state, m_round_keys[round]);
}

void Rijndael::subBytes(byte_array& state) {
    for(size_t i = 0; i < state.size(); ++i) state[i] = m_sbox[state[i]];
}

void Rijndael::invSubBytes(byte_array& state) {
    for(size_t i = 0; i < state.size(); ++i) state[i] = m_inv_sbox[state[i]];
}

void Rijndael::shiftRows(byte_array& state) {
    byte_array temp = state;
    size_t Nb = m_block_size_bytes / 4;
    // Сдвиги для разных Nb
    int shifts[4][3] = { {0,0,0}, {1,2,3}, {1,2,3}, {1,3,4} };
    int C1 = shifts[Nb/2-1][0];
    int C2 = shifts[Nb/2-1][1];
    int C3 = shifts[Nb/2-1][2];

    for(size_t r = 1; r < 4; ++r) {
        int shift = 0;
        if(r==1) shift=C1;
        if(r==2) shift=C2;
        if(r==3) shift=C3;
        for(size_t c = 0; c < Nb; ++c) {
            state[r + 4*c] = temp[r + 4*((c+shift)%Nb)];
        }
    }
}

void Rijndael::invShiftRows(byte_array& state) {
    byte_array temp = state;
    size_t Nb = m_block_size_bytes / 4;
    int shifts[4][3] = { {0,0,0}, {1,2,3}, {1,2,3}, {1,3,4} };
    int C1 = shifts[Nb/2-1][0];
    int C2 = shifts[Nb/2-1][1];
    int C3 = shifts[Nb/2-1][2];

    for(size_t r = 1; r < 4; ++r) {
        int shift = 0;
        if(r==1) shift=C1;
        if(r==2) shift=C2;
        if(r==3) shift=C3;
        for(size_t c = 0; c < Nb; ++c) {
            state[r + 4*c] = temp[r + 4*((c-shift+Nb)%Nb)];
        }
    }
}

void Rijndael::mixColumns(byte_array& state) {
    size_t Nb = m_block_size_bytes / 4;
    byte_array temp(m_block_size_bytes);
    for(size_t c = 0; c < Nb; ++c) {
        uint8_t* col = &state[c*4];
        temp[c*4 + 0] = m_gf_service.multiply(col[0], 0x02) ^ m_gf_service.multiply(col[1], 0x03) ^ col[2] ^ col[3];
        temp[c*4 + 1] = col[0] ^ m_gf_service.multiply(col[1], 0x02) ^ m_gf_service.multiply(col[2], 0x03) ^ col[3];
        temp[c*4 + 2] = col[0] ^ col[1] ^ m_gf_service.multiply(col[2], 0x02) ^ m_gf_service.multiply(col[3], 0x03);
        temp[c*4 + 3] = m_gf_service.multiply(col[0], 0x03) ^ col[1] ^ col[2] ^ m_gf_service.multiply(col[3], 0x02);
    }
    state = temp;
}

void Rijndael::invMixColumns(byte_array& state) {
    size_t Nb = m_block_size_bytes / 4;
    byte_array temp(m_block_size_bytes);
    for(size_t c = 0; c < Nb; ++c) {
        uint8_t* col = &state[c*4];
        temp[c*4 + 0] = m_gf_service.multiply(col[0], 0x0e) ^ m_gf_service.multiply(col[1], 0x0b) ^ m_gf_service.multiply(col[2], 0x0d) ^ m_gf_service.multiply(col[3], 0x09);
        temp[c*4 + 1] = m_gf_service.multiply(col[0], 0x09) ^ m_gf_service.multiply(col[1], 0x0e) ^ m_gf_service.multiply(col[2], 0x0b) ^ m_gf_service.multiply(col[3], 0x0d);
        temp[c*4 + 2] = m_gf_service.multiply(col[0], 0x0d) ^ m_gf_service.multiply(col[1], 0x09) ^ m_gf_service.multiply(col[2], 0x0e) ^ m_gf_service.multiply(col[3], 0x0b);
        temp[c*4 + 3] = m_gf_service.multiply(col[0], 0x0b) ^ m_gf_service.multiply(col[1], 0x0d) ^ m_gf_service.multiply(col[2], 0x09) ^ m_gf_service.multiply(col[3], 0x0e);
    }
    state = temp;
}

void Rijndael::ensureSBoxesInitialized() {
    if (!m_sboxes_initialized) {
        generateSBoxes();
        m_sboxes_initialized = true;
    }
}

void Rijndael::generateSBoxes() {
    m_sbox.resize(256);
    m_inv_sbox.resize(256);
    for (int i = 0; i < 256; ++i) {
        uint8_t val = static_cast<uint8_t>(i);
        uint8_t inv = (i == 0) ? 0 : m_gf_service.inverse(val, m_modulus);
        uint8_t s = inv ^ ((inv << 1) | (inv >> 7)) ^ ((inv << 2) | (inv >> 6)) ^
                    ((inv << 3) | (inv >> 5)) ^ ((inv << 4) | (inv >> 4)) ^ 0x63;
        m_sbox[i] = s;
        uint8_t inv_s_affine = ((val << 1) | (val >> 7)) ^ ((val << 3) | (val >> 5)) ^
                               ((val << 6) | (val >> 2)) ^ 0x05;
        m_inv_sbox[i] = (inv_s_affine == 0) ? 0 : m_gf_service.inverse(inv_s_affine, m_modulus);
    }
}