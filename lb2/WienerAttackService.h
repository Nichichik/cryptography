//
// Created by Вероника on 27.10.2025.
//

#ifndef WIENER_ATTACK_SERVICE_H
#define WIENER_ATTACK_SERVICE_H

#include "RsaService.h"
#include <vector>
#include <optional>


struct WienerAttackResult {
    bool success;
    big_int found_d;
    big_int found_phi;
    std::vector<std::pair<big_int, big_int>> convergents;
};

class WienerAttackService {
public:
    WienerAttackService() = delete;
    static WienerAttackResult Attack(const RsaPublicKey& publicKey);

private:
    static std::vector<big_int> _calculate_continued_fraction(big_int e, big_int n);

    static std::optional<big_int> _test_candidate(const big_int& e, const big_int& n, const big_int& k, const big_int& d);
};

#endif //WIENER_ATTACK_SERVICE_H
