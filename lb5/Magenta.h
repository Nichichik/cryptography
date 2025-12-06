//
// Created by Вероника Мельцова on 24.11.2025.
//

#ifndef CRYPTOGRAPHY_MAGENTA_H
#define CRYPTOGRAPHY_MAGENTA_H

#include "../lb1/SymmetricInterfaces.h"
#include "../lb1/FeistelCipher.h"
#include <vector>
#include <memory>

using byte_array = std::vector<unsigned char>;
using round_keys_array = std::vector<byte_array>;

class MagentaRoundFunction : public IRoundFunction {
public:
    byte_array apply(const byte_array& half_block, const byte_array& roundKey) override;
};


class MagentaKeyExpander : public IKeyExpander {
public:
    MagentaKeyExpander(size_t key_size_bits);
    round_keys_array generateRoundKeys(const byte_array& masterKey) override;
private:
    size_t m_key_size_bits;
};

class Magenta : public ISymmetricCipher {
public:
    Magenta(size_t key_size_bits = 128);

    void setKey(const byte_array& key) override;
    byte_array encryptBlock(const byte_array& block) override;
    byte_array decryptBlock(const byte_array& block) override;
    size_t getBlockSize() const override;

private:
    std::unique_ptr<FeistelCipher> m_feistel_network;
};

#endif //CRYPTOGRAPHY_MAGENTA_H