//
// Created by Вероника on 27.10.2025.
//

#include "WienerAttackService.h"
#include "StatelessService.h"

static big_int integer_sqrt(const big_int& n) {
    if (n < 0) {
        return 0;
    }
    if (n == 0) {
        return 0;
    }
    big_int x = n, y = (x + 1) / 2;
    while (y < x) {
        x = y;
        y = (x + n / x) / 2;
    }
    return x;
}

std::vector<big_int> WienerAttackService::_calculate_continued_fraction(big_int e, big_int n) {
    std::vector<big_int> coefficients;
    while (e != 0) {
        coefficients.push_back(n / e);
        big_int remainder = n % e;
        n = e;
        e = remainder;
    }
    return coefficients;
}

std::optional<big_int> WienerAttackService::_test_candidate(const big_int& e, const big_int& n, const big_int& k, const big_int& d) {
    if (d == 0 || d % 2 == 0) {
        return std::nullopt;
    }

    if ((e * d - 1) % k != 0) {
        return std::nullopt;
    }

    big_int phi = (e * d - 1) / k;
    big_int b = n - phi + 1;

    big_int discriminant = b * b - 4 * n;

    if (discriminant < 0) {
        return std::nullopt;
    }

    big_int root_d = integer_sqrt(discriminant);
    if (root_d * root_d != discriminant) {
        return std::nullopt;
    }
    if ((b + root_d) % 2 != 0) {
        return std::nullopt;
    }
    return phi;
}

WienerAttackResult WienerAttackService::Attack(const RsaPublicKey& publicKey) {
    WienerAttackResult result;
    result.success = false;

    std::vector<big_int> cf = _calculate_continued_fraction(publicKey.e, publicKey.n);

    big_int pk_2 = 0, pk_1 = 1;
    big_int qk_2 = 1, qk_1 = 0;

    for (const auto& coeff : cf) {
        big_int pk = coeff * pk_1 + pk_2;
        big_int qk = coeff * qk_1 + qk_2;

        result.convergents.push_back({pk, qk});
        auto phi_opt1 = _test_candidate(publicKey.e, publicKey.n, pk, qk);
        if (phi_opt1.has_value()) {
            result.success = true;
            result.found_d = qk;
            result.found_phi = phi_opt1.value();
            return result;
        }

        auto phi_opt2 = _test_candidate(publicKey.e, publicKey.n, qk, pk);
        if (phi_opt2.has_value()) {
            result.success = true;
            result.found_d = pk;
            result.found_phi = phi_opt2.value();
            return result;
        }
        pk_2 = pk_1;
        qk_2 = qk_1;
        pk_1 = pk;
        qk_1 = qk;
    }

    return result;
}