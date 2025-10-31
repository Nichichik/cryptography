#ifndef RSA_SERVICE_H
#define RSA_SERVICE_H

#include "PrimalityTest.h"
#include <memory>
#include <utility>
#include <thread>
#include <atomic>
#include <mutex>
#include <vector>
#include <optional>
#include <tuple>
#include <future>
#include <boost/multiprecision/gmp.hpp>// <-- Добавляем для std::async и std::future
using big_int = boost::multiprecision::mpz_int;


struct RsaPublicKey {
    big_int n;
    big_int e;
};

struct RsaPrivateKey {
    big_int n;
    big_int d;
};

class RsaService {
public:
    void GenerateKeys(); // Генерирует сильный ключ
    void GenerateWeakKeys(); // Генерирует слабый ключ
    enum PrimalityTestType { FERMAT, SOLOVAY_STRASSEN, MILLER_RABIN };

private:
    class KeyGenerator {
    public:
        KeyGenerator(PrimalityTestType type, double probability, int bit_length);
        std::pair<RsaPublicKey, RsaPrivateKey> Generate();
        std::pair<RsaPublicKey, RsaPrivateKey> GenerateWeak(); // Новый метод


    private:
        big_int _prime_min_val;
        big_int _prime_max_val;
        // Методы, не меняющие состояние объекта, помечаем const
        std::tuple<big_int, big_int, big_int> _create_key_candidate() const;
        big_int GeneratePrime() const;

        void _search_worker();
        static big_int Sqrt(const big_int& n);

        // Члены класса
        std::unique_ptr<IPrimalityTest> _primality_test;
        double _probability;
        int _bit_length;

        mutable std::atomic<bool> _key_found_flag;
        std::mutex _result_mutex;
        std::optional<std::pair<RsaPublicKey, RsaPrivateKey>> _found_key_pair;
        mutable std::mutex _cout_mutex; // mutable для использования в const-методах
    };

public:
    RsaService(PrimalityTestType type, double probability, int bit_length);
    big_int Encrypt(const big_int& message) const;
    big_int Decrypt(const big_int& ciphertext) const;
    RsaPublicKey GetPublicKey() const { return _publicKey; }
    RsaPrivateKey GetPrivateKey() const { return _privateKey; }

private:
    KeyGenerator _keyGenerator;
    RsaPublicKey _publicKey;
    RsaPrivateKey _privateKey;
};

#endif //RSA_SERVICE_H