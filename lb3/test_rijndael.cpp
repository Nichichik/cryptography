//
// Created by Вероника Мельцова on 18.11.2025.
//

#include <iostream>
#include <filesystem>
#include <fstream>
#include <vector>
#include <memory>
#include <chrono>
#include <iomanip> // Для форматирования вывода

#include "Rijndael.h"
namespace fs = std::filesystem;

using byte_array = std::vector<unsigned char>;
using ExtraParams = std::map<std::string, std::any>;

byte_array read_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        std::cerr << "Cannot open file for reading: " << path << std::endl;
        return {};
    }
    return byte_array((std::istreambuf_iterator<char>(in)), {});
}

bool compare_buffers(const byte_array& a, const byte_array& b) {
    return a == b;
}


void test_rijndael_mode(
    const std::string& file,
    size_t block_size_bits,
    const byte_array& key,
    CipherMode mode,
    PaddingScheme padding,
    uint16_t modulus = GaloisField::StatelessService::AES_MODULUS,
    const ExtraParams& params = {}
) {
    size_t key_size_bits = key.size() * 8;

    std::cout << "[Rijndael] Testing file: " << file << "\n"
              << "  Config: Block=" << block_size_bits << " bits, Key=" << key_size_bits << " bits\n"
              << "  GF(2^8) Modulus: 0x" << std::hex << modulus << std::dec << "\n"
              << "  Mode: ";

    switch (mode) {
        case CipherMode::ECB: std::cout << "ECB"; break;
        case CipherMode::CBC: std::cout << "CBC"; break;
        case CipherMode::CFB: std::cout << "CFB"; break;
        case CipherMode::OFB: std::cout << "OFB"; break;
        case CipherMode::CTR: std::cout << "CTR"; break;
        case CipherMode::PCBC: std::cout << "PCBC"; break;
        case CipherMode::RANDOM_DELTA: std::cout << "RANDOM_DELTA"; break;
    }
    std::cout << std::endl;

    byte_array iv(block_size_bits / 8, 0xAA);

    byte_array original = read_file(file);
    if (original.empty()) {
        std::cout << "Skipped empty or unreadable file\n";
        return;
    }

    auto rijndael_algo = std::make_unique<Rijndael>(block_size_bits, key_size_bits, modulus);
    CipherContext ctx(std::move(rijndael_algo), key, mode, padding, iv, params);

    byte_array encrypted;
    ctx.encrypt(original, encrypted).get();

    byte_array decrypted;
    ctx.decrypt(encrypted, decrypted).get();

    if (compare_buffers(original, decrypted)) {
        std::cout << "  In-memory test: OK\n";
    } else {
        std::cout << "  In-memory test: FAILED\n";
    }

    std::string encrypted_file = file + ".enc";
    std::string decrypted_file = file + ".dec";

    auto start_time = std::chrono::high_resolution_clock::now();
    ctx.encrypt(file, encrypted_file).get();
    auto end_time = std::chrono::high_resolution_clock::now();
    auto encrypt_duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
    std::cout << "  File encrypt time: " << encrypt_duration << " ms" << std::endl;

    start_time = std::chrono::high_resolution_clock::now();
    ctx.decrypt(encrypted_file, decrypted_file).get();
    end_time = std::chrono::high_resolution_clock::now();
    auto decrypt_duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
    std::cout << "  File decrypt time: " << decrypt_duration << " ms" << std::endl;

    auto decrypted_from_file = read_file(decrypted_file);
    if (compare_buffers(original, decrypted_from_file)) {
        std::cout << "  File test: OK\n";
    } else {
        std::cout << "  File test: FAILED\n";
    }
}


int main() {
    try {
        fs::path test_dir = "../lb1/test_files";
        if (!fs::exists(test_dir)) {
            std::cerr << "test_files directory not found. Make sure it's next to lb1/lb2/lb3 folders.\n";
            return 1;
        }
        fs::current_path(test_dir);
        std::cout << "Current test directory: " << fs::current_path() << "\n";
        std::vector<std::string> files = { "Homework.docx", "flowers.jpg" };
        std::vector<CipherMode> modes = { CipherMode::ECB, CipherMode::CBC, CipherMode::CFB };

        struct Config { size_t block_bits; size_t key_bits; };
        std::vector<Config> configs = {
            {128, 128},
            {128, 256},
            {256, 256}
        };

        GaloisField::StatelessService gf_service;
        std::vector<uint16_t> moduli_to_test = {
            GaloisField::StatelessService::AES_MODULUS,
            0x11D
        };

        PaddingScheme padding = PaddingScheme::PKCS7;

        for (const auto& file : files) {
            for (const auto& config : configs) {
                byte_array key(config.key_bits / 8, 0xAB);
                for (auto modulus : moduli_to_test) {
                    for (auto mode : modes) {
                        try {
                            test_rijndael_mode(file, config.block_bits, key, mode, padding, modulus);
                        } catch (const std::exception& ex) {
                            std::cerr << "ERROR: " << ex.what() << std::endl;
                        }
                    }
                }
            }
        }
    } catch (const std::exception& ex) {
        std::cerr << "FATAL ERROR: " << ex.what() << std::endl;
        return 1;
    }

    return 0;
}