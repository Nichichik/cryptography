//
// Created by Вероника Мельцова on 17.11.2025.
//

#ifndef CRYPTOGRAPHY_TRIPLEDES_H
#define CRYPTOGRAPHY_TRIPLEDES_H

#include "DES.h"
#include <map>
#include <memory>
#include <mutex>

namespace TripleDES_Implementation {

    // Внутренний класс-помощник для потокобезопасного кэширования DES
    class DES_Cache_Adapter {
    public:
        // Метод, который возвращает результат шифрования/расшифрования
        // Он либо находит DES в кэше, либо создает новый
        byte_array encrypt(const byte_array& block, const byte_array& key);
        byte_array decrypt(const byte_array& block, const byte_array& key);

    private:
        // Кэш для хранения уже настроенных экземпляров DES
        std::map<byte_array, std::unique_ptr<DES_Implementation::DES>> m_des_cache;
        // Мьютекс для защиты кэша в многопоточной среде
        std::mutex m_mutex;

        // Внутренний метод для получения или создания экземпляра DES
        DES_Implementation::DES* get_des_instance(const byte_array& key);
    };


    class TripleDES : public ISymmetricCipher {
    public:
        TripleDES();

        void setKey(const byte_array& key) override;
        byte_array encryptBlock(const byte_array& block) override;
        byte_array decryptBlock(const byte_array& block) override;
        size_t getBlockSize() const override;

    private:
        // Используем наш новый потокобезопасный адаптер
        DES_Cache_Adapter m_des_adapter;

        // Ключи K1, K2, K3, как и раньше
        byte_array m_k1;
        byte_array m_k2;
        byte_array m_k3;
    };

} // namespace TripleDES_Implementation

#endif //CRYPTOGRAPHY_TRIPLEDES_H