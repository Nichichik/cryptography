//
// Created by Вероника on 17.10.2025.
//

#ifndef CRYPTOGRAPHY_DEAL_H
#define CRYPTOGRAPHY_DEAL_H


#include "DES.h"
#include <memory>
#include <mutex>


enum class DEAL_Variant {
    DEAL_128_6,
    DEAL_192_6,
    DEAL_256_8
};


class DES_Adapter : public IRoundFunction {
public:
    DES_Adapter();
    byte_array apply(const byte_array& half_block, const byte_array& roundKey) override;

private:
    std::map<byte_array, std::unique_ptr<DES_Implementation::DES>> m_des_cache;
    std::mutex m_mutex;
};


class DEALKeyExpander : public IKeyExpander {
public:
    DEALKeyExpander(DEAL_Variant variant);
    round_keys_array generateRoundKeys(const byte_array& masterKey) override;

private:
    DEAL_Variant m_variant;
};


class DEAL : public ISymmetricCipher {
public:
    DEAL(DEAL_Variant variant = DEAL_Variant::DEAL_128_6);

    void setKey(const byte_array& key) override;
    byte_array encryptBlock(const byte_array& block) override;
    byte_array decryptBlock(const byte_array& block) override;
    size_t getBlockSize() const override;

private:
    std::unique_ptr<FeistelCipher> m_feistel_network;
    DEAL_Variant m_variant;
};

#endif //CRYPTOGRAPHY_DEAL_H
