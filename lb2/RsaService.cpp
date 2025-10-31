#include "RsaService.h"
#include "StatelessService.h"
#include <iostream>
#include <stdexcept>
#include <tuple>
#include <vector>

namespace {
    std::mutex g_cout_mutex;
    std::vector<int> generate_small_primes(int limit) {
        std::vector<bool> is_prime(limit + 1, true);
        is_prime[0] = is_prime[1] = false;
        for (int p = 2; p * p <= limit; p++) {
            if (is_prime[p]) {
                for (int i = p * p; i <= limit; i += p)
                    is_prime[i] = false;
            }
        }
        std::vector<int> primes;
        for (int p = 2; p <= limit; p++) {
            if (is_prime[p]) {
                primes.push_back(p);
            }
        }
        return primes;
    }
}

RsaService::RsaService(PrimalityTestType type, double probability, int bit_length)
        : _keyGenerator(type, probability, bit_length) {
    GenerateKeys();
}

void RsaService::GenerateKeys() {
    auto key_pair = _keyGenerator.Generate();
    _publicKey = key_pair.first;
    _privateKey = key_pair.second;
}

big_int RsaService::Encrypt(const big_int& message) const {
    if (_publicKey.n.is_zero()) {
        throw std::runtime_error("Ключи не сгенерированы");
    }
    return CryptoService::ModPow(message, _publicKey.e, _publicKey.n);
}

big_int RsaService::Decrypt(const big_int& ciphertext) const {
    if (_privateKey.n.is_zero()) {
        throw std::runtime_error("Ключи не сгенерированы");
    }
    return CryptoService::ModPow(ciphertext, _privateKey.d, _privateKey.n);
}


RsaService::KeyGenerator::KeyGenerator(PrimalityTestType type, double probability, int bit_length)
        : _probability(probability), _bit_length(bit_length), _key_found_flag(false) {
    switch (type) {
        case FERMAT: _primality_test = std::make_unique<FermatTest>(); break;
        case SOLOVAY_STRASSEN: _primality_test = std::make_unique<SolovayStrassenTest>(); break;
        case MILLER_RABIN: _primality_test = std::make_unique<MillerRabinTest>(); break;
    }
    _prime_min_val = big_int(1) << (_bit_length - 1);
    _prime_max_val = (big_int(1) << _bit_length) - big_int(1);
}


std::pair<RsaPublicKey, RsaPrivateKey> RsaService::KeyGenerator::Generate() {
    while (true) {
        auto future_p = std::async(std::launch::async, &RsaService::KeyGenerator::GeneratePrime, this);
        big_int q = GeneratePrime();
        big_int p = future_p.get();
        while (p == q) q = GeneratePrime();

        std::cout << "p и q найдены. Проверяем безопасность" << std::endl;

        const big_int n = p * q;
        const big_int phi = (p - 1) * (q - 1);

        static const std::vector<big_int> exponents = {65537, 257, 17};
        big_int e;
        bool e_found = false;
        for (const auto& cand : exponents) {
            if (CryptoService::Gcd(cand, phi) == 1) { e = cand; e_found = true; break; }
        }
        if (!e_found) {
            do { e = PrimalityTest::GenerateRandomBigInt(3, phi - 1); }
            while (e % 2 == 0 || CryptoService::Gcd(e, phi) != 1);
        }

        big_int x, y;
        CryptoService::ExtendedGcd(e, phi, x, y);
        const big_int d = (x % phi + phi) % phi;

        if (boost::multiprecision::abs(p - q) < Sqrt(Sqrt(n))) {
            std::cout << "Ключ отвергнут: p и q слишком близки (уязвимость Ферма). Повторная попытка" << std::endl;
            continue;
        }

        if (d < (Sqrt(Sqrt(n)) / 3)) {
            std::cout << "Ключ отвергнут: d слишком мало (уязвимость Винера). Повторная попытка" << std::endl;
            continue;
        }

        std::cout << "Ключ прошел проверки безопасности." << std::endl;
        return {{n, e}, {n, d}};
    }
}

std::tuple<big_int, big_int, big_int> RsaService::KeyGenerator::_create_key_candidate() const {
    const big_int p = GeneratePrime();
    big_int q;
    do { q = GeneratePrime(); } while (p == q);
    const big_int n = p * q;
    const big_int phi = (p - big_int(1)) * (q - big_int(1));

    static const std::vector<big_int> exponents = {big_int(65537), big_int(257), big_int(17)};
    big_int e;
    bool e_found = false;

    for (const auto& exp_candidate : exponents) {
        if (CryptoService::Gcd(exp_candidate, phi) == big_int(1)) {
            e = exp_candidate;
            e_found = true;
            break;
        }
    }

    if (!e_found) {
        while (true) {
            e = PrimalityTest::GenerateRandomBigInt(big_int(3), phi - big_int(1));
            if (e % big_int(2) != big_int(0) && CryptoService::Gcd(e, phi) == big_int(1)) {
                break;
            }
        }
    }
    big_int x, y;
    CryptoService::ExtendedGcd(e, phi, x, y);
    const big_int d = (x % phi + phi) % phi;
    return {e, d, n};
}


big_int RsaService::KeyGenerator::GeneratePrime() const {
    static std::vector<int> small_primes = generate_small_primes(1000);

    big_int min_val = big_int(1) << (_bit_length - 1);
    big_int max_val = (big_int(1) << _bit_length) - 1;

    while (true) {
        big_int candidate = PrimalityTest::GenerateRandomBigInt(min_val, max_val);
        candidate |= (big_int(1) << (_bit_length - 1));
        candidate |= 1;

        bool composite_by_small = false;
        for (int p : small_primes) {
            big_int bp(p);
            if (candidate == bp) {
                composite_by_small = false;
                break;
            }
            if (candidate % bp == 0) {
                composite_by_small = true;
                break;
            }
        }
        if (composite_by_small) {
            continue;
        }
        if (_primality_test->IsPrime(candidate, _probability)) {
            return candidate;
        }
    }
}

big_int RsaService::KeyGenerator::Sqrt(const big_int& n) {
    if (n < big_int(0)) {
        throw std::invalid_argument("sqrt для отрицательного числа");
    }
    if (n.is_zero()) {
        return big_int(0);
    }
    big_int x = n;
    big_int y = (x + big_int(1)) / big_int(2);
    while (y < x) {
        x = y;
        y = (x + n / x) / big_int(2);
    }
    return x;
}

std::pair<RsaPublicKey, RsaPrivateKey> RsaService::KeyGenerator::GenerateWeak() {
    while (true) {
        const big_int p = GeneratePrime();
        big_int q;
        do { q = GeneratePrime(); } while (p == q);
        const big_int n = p * q;
        const big_int phi = (p - big_int(1)) * (q - big_int(1));

        big_int d_max = Sqrt(Sqrt(n)) / big_int(3);
        if (d_max < big_int(3)) {
            continue;
        }

        big_int d = PrimalityTest::GenerateRandomBigInt(big_int(3), d_max);
        if (d % big_int(2) == big_int(0)) d++;

        if (CryptoService::Gcd(d, phi) == big_int(1)) {
            big_int x, y;
            CryptoService::ExtendedGcd(d, phi, x, y);
            big_int e = (x % phi + phi) % phi;
            return {{n, e}, {n, d}};
        }
    }
}

void RsaService::GenerateWeakKeys() {
    auto key_pair = _keyGenerator.GenerateWeak();
    _publicKey = key_pair.first;
    _privateKey = key_pair.second;
}