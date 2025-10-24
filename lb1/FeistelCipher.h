//
// Created by Вероника on 13.10.2025.
//

#ifndef CRYPTOGRAPHY_FEISTELCIPHER_H
#define CRYPTOGRAPHY_FEISTELCIPHER_H


#include "SymmetricInterfaces.h"
#include <memory>

class FeistelCipher : public ISymmetricCipher {
public:
    FeistelCipher(
            std::unique_ptr<IKeyExpander> keyExpander,
            std::unique_ptr<IRoundFunction> roundFunction,
            int numRounds,
            size_t blockSize
    );

    void setKey(const std::vector<unsigned char>& key) override;
    std::vector<unsigned char> encryptBlock(const std::vector<unsigned char>& block) override;
    std::vector<unsigned char> decryptBlock(const std::vector<unsigned char>& block) override;
    size_t getBlockSize() const override;

private:
    std::unique_ptr<IKeyExpander> m_keyExpander;
    std::unique_ptr<IRoundFunction> m_roundFunction;
    int m_numRounds;
    size_t m_blockSize;
    std::vector<std::vector<unsigned char>> m_encryptionKeys;
    std::vector<std::vector<unsigned char>> m_decryptionKeys;
};

#endif //CRYPTOGRAPHY_FEISTELCIPHER_H
