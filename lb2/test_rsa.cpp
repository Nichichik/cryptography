#include <iostream>
#include "RsaService.h"
#include "WienerAttackService.h" // <-- Подключаем наш новый сервис

int main() {
    setlocale(LC_ALL, "Russian");
    try {
        std::cout << "ТЕСТ 1: базовое шифрование/дешифрование (ключ 256 бит)" << std::endl;
        RsaService rsa_basic(RsaService::MILLER_RABIN, 0.999, 256);
        big_int data1("12345678901234567890");

        std::cout << "Исходные данные: " << data1 << std::endl;
        big_int encrypted1 = rsa_basic.Encrypt(data1);
        std::cout << "Шифротекст: " << encrypted1 << std::endl;
        big_int decrypted1 = rsa_basic.Decrypt(encrypted1);
        std::cout << "Расшифрованные данные: " << decrypted1 << std::endl;
        if (data1 == decrypted1) std::cout << "Успех: данные совпадают." << std::endl;
        else std::cout << "Ошибка: данные не совпадают." << std::endl;



        std::cout << "ТЕСТ 2: шифрование данных разного размера (ключ 512 бит)" << std::endl;
        RsaService rsa_multi(RsaService::MILLER_RABIN, 0.999, 512);
        std::vector<big_int> test_data = {
                big_int("100"),
                big_int("9876543210"),
                big_int("1111222233334444555566667777888899990000")
        };
        bool test2_ok = true;
        for (const auto& data : test_data) {
            big_int encrypted = rsa_multi.Encrypt(data);
            big_int decrypted = rsa_multi.Decrypt(encrypted);
            if (data != decrypted) test2_ok = false;
            std::cout << "Тест для data = " << data << " ... " << (data == decrypted ? "OK" : "FAIL") << std::endl;
        }
        if (test2_ok) std::cout << "Успех: все данные расшифрованы корректно." << std::endl;
        else std::cout << "Ошибка: есть ошибки в расшифровке." << std::endl;


        std::cout << "ТЕСТ 3: проверка ключа на уязвимость к атаке Винера" << std::endl;
        std::cout << "Атакуем сильный ключ" << std::endl;
        RsaPublicKey pubKey_safe = rsa_multi.GetPublicKey();
        WienerAttackResult attack_result_safe = WienerAttackService::Attack(pubKey_safe);

        if (!attack_result_safe.success) {
            std::cout << "Успех: атака на сильный ключ провалилась" << std::endl;
        } else {
            std::cout << "Ошибка: аильный ключ оказался уязвимым" << std::endl;
        }


        std::cout << "ТЕСТ 4: гененерация и атака на слабый ключ" << std::endl;
        rsa_multi.GenerateWeakKeys();

        RsaPublicKey pubKey_weak = rsa_multi.GetPublicKey();
        RsaPrivateKey privKey_weak = rsa_multi.GetPrivateKey();

        std::cout << "\nСгенерирован СЛАБЫЙ ключ:\n";
        std::cout << "  n = " << pubKey_weak.n << "\n";
        std::cout << "  e = " << pubKey_weak.e << "\n";
        std::cout << "  d (оригинальный) = " << privKey_weak.d << "\n\n";

        std::cout << "Атакуем слабый ключ..." << std::endl;
        WienerAttackResult attack_result_weak = WienerAttackService::Attack(pubKey_weak);

        if (attack_result_weak.success) {
            std::cout << "Успех: атака на слабый ключ прошла успешно\n";
            std::cout << "  Найденное d = " << attack_result_weak.found_d << "\n";
            if (attack_result_weak.found_d == privKey_weak.d) {
                std::cout << "Проверка: найденный 'd' совпадает с оригинальным\n";
            } else {
                std::cout << "Проверка: найденный 'd' не совпадает с оригинальным.\n";
            }
        } else {
            std::cout << "\nОшибка: атака на слабый ключ не удалась.\n";
        }

    } catch (const std::exception& e) {
        std::cerr << "Произошла критическая ошибка: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}