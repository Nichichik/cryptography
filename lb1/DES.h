//
// Created by Вероника on 13.10.2025.
//
#include "bitPermute.h"
#include "FeistelCipher.h"

#ifndef CRYPTOGRAPHY_DES_H
#define CRYPTOGRAPHY_DES_H

namespace DES_Implementation {
    class DESKeyExpander : public IKeyExpander {
    public:
        std::vector<std::vector<unsigned char>> generateRoundKeys(const std::vector<unsigned char>& masterKey) override;
    };

    class DESRoundFunction : public IRoundFunction {
    public:
        std::vector<unsigned char> apply(const std::vector<unsigned char>& half_block, const std::vector<unsigned char>& roundKey) override;
    };

    class DES : public ISymmetricCipher {
    public:
        DES();
        void setKey(const std::vector<unsigned char>& key) override;
        std::vector<unsigned char> encryptBlock(const std::vector<unsigned char>& block) override;
        std::vector<unsigned char> decryptBlock(const std::vector<unsigned char>& block) override;
        size_t getBlockSize() const override;
    private:
        std::unique_ptr<FeistelCipher> m_feistel_network;
    };
}

#endif //CRYPTOGRAPHY_DES_H
