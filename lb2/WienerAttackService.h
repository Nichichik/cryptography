//
// Created by Вероника on 27.10.2025.
//

#ifndef WIENER_ATTACK_SERVICE_H
#define WIENER_ATTACK_SERVICE_H

#include "RsaService.h" // Нужен для RsaPublicKey
#include <vector>
#include <optional>

// Структура для хранения результатов атаки
struct WienerAttackResult {
    bool success;                   // Успешна ли была атака
    big_int found_d;                // Найденная секретная экспонента d
    big_int found_phi;              // Найденное значение функции Эйлера phi(n)
    std::vector<std::pair<big_int, big_int>> convergents; // Коллекция подходящих дробей (k/d)
};

class WienerAttackService {
public:
    WienerAttackService() = delete; // Stateless-сервис

    /**
     * @brief Выполняет атаку Винера на открытый ключ RSA.
     * @param publicKey Открытый ключ {e, n}.
     * @return Структура WienerAttackResult с результатами атаки.
     */
    static WienerAttackResult Attack(const RsaPublicKey& publicKey);

private:
    /**
     * @brief Вычисляет коэффициенты непрерывной дроби для e/n.
     * @param e Открытая экспонента.
     * @param n Модуль.
     * @return Вектор с коэффициентами.
     */
    static std::vector<big_int> _calculate_continued_fraction(big_int e, big_int n);

    /**
     * @brief Проверяет, является ли кандидат d правильной секретной экспонентой.
     * @param e Открытая экспонента.
     * @param n Модуль.
     * @param k Числитель подходящей дроби.
     * @param d Знаменатель подходящей дроби (кандидат на секретную экспоненту).
     * @return std::optional<big_int> со значением phi, если кандидат верен, иначе пустой.
     */
    static std::optional<big_int> _test_candidate(const big_int& e, const big_int& n, const big_int& k, const big_int& d);
};

#endif //WIENER_ATTACK_SERVICE_H
