// TripleDES.cpp
#include "TripleDES.h"
#include <stdexcept>

namespace TripleDES_Implementation {
    DES_Implementation::DES* DES_Cache_Adapter::get_des_instance(const byte_array& key) {
        auto it = m_des_cache.find(key);
        if (it != m_des_cache.end()) {
            return it->second.get();
        }

        std::lock_guard<std::mutex> lock(m_mutex);

        it = m_des_cache.find(key);
        if (it != m_des_cache.end()) {
            return it->second.get();
        }

        auto des = std::make_unique<DES_Implementation::DES>();
        des->setKey(key);
        auto* ptr = des.get();
        m_des_cache[key] = std::move(des);
        return ptr;
    }

    byte_array DES_Cache_Adapter::encrypt(const byte_array& block, const byte_array& key) {
        DES_Implementation::DES* des_instance = get_des_instance(key);
        return des_instance->encryptBlock(block);
    }

    byte_array DES_Cache_Adapter::decrypt(const byte_array& block, const byte_array& key) {
        DES_Implementation::DES* des_instance = get_des_instance(key);
        return des_instance->decryptBlock(block);
    }

    TripleDES::TripleDES() {}

    size_t TripleDES::getBlockSize() const {
        return 8;
    }

    void TripleDES::setKey(const byte_array& key) {
        if (key.size() != 16 && key.size() != 24) {
            throw std::invalid_argument("TripleDES key must be 16 or 24 bytes long.");
        }
        m_k1.assign(key.begin(), key.begin() + 8);
        m_k2.assign(key.begin() + 8, key.begin() + 16);
        if (key.size() == 24) {
            m_k3.assign(key.begin() + 16, key.end());
        } else {
            m_k3 = m_k1;
        }
    }

    byte_array TripleDES::encryptBlock(const byte_array& block) {
        if (m_k1.empty()) {
            throw std::runtime_error("Key is not set for TripleDES.");
        }
        byte_array temp_block = m_des_adapter.encrypt(block, m_k1);
        temp_block = m_des_adapter.decrypt(temp_block, m_k2);
        return m_des_adapter.encrypt(temp_block, m_k3);
    }

    byte_array TripleDES::decryptBlock(const byte_array& block) {
        if (m_k1.empty()) {
            throw std::runtime_error("Key is not set for TripleDES.");
        }

        byte_array temp_block = m_des_adapter.decrypt(block, m_k3);
        temp_block = m_des_adapter.encrypt(temp_block, m_k2);
        return m_des_adapter.decrypt(temp_block, m_k1);
    }

}