//
// Created by Вероника on 26.10.2025.
//

#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include "PrimalityTest.h"

struct TestCase {
    std::string number_str;
    std::string description;
};

int main() {
    setlocale(LC_ALL, "Russian");

    FermatTest fermat_test;
    SolovayStrassenTest ss_test;
    MillerRabinTest mr_test;

    std::vector<TestCase> test_cases = {
            {"13", "Маленькое простое число"},
            {"15", "Маленькое составное число (3*5)"},
            {"999999937", "Большое простое число"},
            {"100160063", "Большое составное число (10007*10009)"},
            {"561", "Число Кармайкла (3*11*17) - должно обмануть тест Ферма"}
    };

    double probability = 0.9999;
    std::cout << "Тестирование будет проводиться для достижения вероятности > " << probability << std::endl << std::endl;

    for (const auto& tc : test_cases) {
        big_int n(tc.number_str);
        std::cout << "Тестируем число: " << n << " (" << tc.description << ") ---\n";

        try {
            bool fermat_result = fermat_test.IsPrime(n, probability);
            std::cout << std::left << std::setw(30) << "Тест Ферма:"
                      << (fermat_result ? "Вероятно простое" : "Составное") << std::endl;

            bool ss_result = ss_test.IsPrime(n, probability);
            std::cout << std::left << std::setw(30) << "Тест Соловея-Штрассена:"
                      << (ss_result ? "Вероятно простое" : "Составное") << std::endl;

            bool mr_result = mr_test.IsPrime(n, probability);
            std::cout << std::left << std::setw(30) << "Тест Миллера-Рабина:"
                      << (mr_result ? "Вероятно простое" : "Составное") << std::endl;

        } catch (const std::exception& e) {
            std::cerr << "Произошла ошибка: " << e.what() << std::endl;
        }
        std::cout << std::endl;
    }

    return 0;
}
