#pragma once

#include "../lb1/SymmetricInterfaces.h"
#include "StatelessService.h"
#include <vector>
#include <memory>
#include <stdexcept>

using byte_array = std::vector<unsigned char>;
using round_keys_array = std::vector<byte_array>;

class RijndaelKeyExpander : public IKeyExpander {
public:
    RijndaelKeyExpander(size_t block_size_bytes, size_t key_size_bytes, const byte_array& sbox);
    round_keys_array generateRoundKeys(const byte_array& masterKey) override;

private:
    void rotWord(byte_array& word) const;
    void subWord(byte_array& word) const;

    size_t m_key_size_words; // Nk
    size_t m_block_size_words; // Nb
    size_t m_num_rounds;     // Nr
    const byte_array& m_sbox;
    byte_array m_rcon;
};

class Rijndael : public ISymmetricCipher {
public:
    Rijndael(size_t block_size_bits = 128, 
             size_t key_size_bits = 128,
             uint16_t modulus = GaloisField::StatelessService::AES_MODULUS);

    void setKey(const byte_array& key) override;
    byte_array encryptBlock(const byte_array& block) override;
    byte_array decryptBlock(const byte_array& block) override;
    size_t getBlockSize() const override;

private:
    void subBytes(byte_array& state);
    void invSubBytes(byte_array& state);
    void shiftRows(byte_array& state);
    void invShiftRows(byte_array& state);
    void mixColumns(byte_array& state);
    void invMixColumns(byte_array& state);
    void addRoundKey(byte_array& state, size_t round);

    void ensureSBoxesInitialized();
    void generateSBoxes();

private:
    size_t m_block_size_bytes;
    size_t m_key_size_bytes;
    size_t m_num_rounds;

    uint16_t m_modulus;
    GaloisField::StatelessService m_gf_service;

    std::unique_ptr<IKeyExpander> m_key_expander;
    round_keys_array m_round_keys;

    byte_array m_sbox;
    byte_array m_inv_sbox;
    bool m_sboxes_initialized;
};