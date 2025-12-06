//
// Created by Вероника Мельцова on 24.11.2025.
//

#ifndef CRYPTOGRAPHY_RC4_H
#define CRYPTOGRAPHY_RC4_H

#include "../lb1/SymmetricInterfaces.h"
#include <vector>

using byte_array = std::vector<unsigned char>;

class RC4 : public ISymmetricCipher {
public:
    RC4();
    void setKey(const byte_array& key) override;
    byte_array encryptBlock(const byte_array& block) override;
    byte_array decryptBlock(const byte_array& block) override;
    size_t getBlockSize() const override;

private:
    uint8_t getNextKeystreamByte();

    byte_array S;
    uint8_t i, j;
};

#endif //CRYPTOGRAPHY_RC4_H