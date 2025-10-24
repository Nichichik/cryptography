//
// Created by Вероника on 15.10.2025.
//

#include "SymmetricInterfaces.h"
#include <stdexcept>
#include <fstream>
#include <algorithm>

#ifdef _OPENMP
#include <omp.h>
#endif


CipherContext::CipherContext(
        std::unique_ptr<ISymmetricCipher> algorithm,
        const byte_array& key,
        CipherMode mode,
        PaddingScheme padding,
        std::optional<byte_array> iv,
        ExtraParams params
)   : m_algorithm(std::move(algorithm)),
      m_mode(mode),
      m_padding(padding),
      m_params(std::move(params))
{
    bool iv_is_required;
    switch (m_mode) {
        case CipherMode::CBC:
        case CipherMode::PCBC:
        case CipherMode::CFB:
        case CipherMode::OFB:
        case CipherMode::CTR:
        case CipherMode::RANDOM_DELTA:
            iv_is_required = true;
            break;

        case CipherMode::ECB:
        default:
            iv_is_required = false;
            break;
    }

    if (iv_is_required) {
        if (!iv.has_value()) {
            std::cout << "This encryption mode requires an Initialization Vector (IV)." << std::endl;
        }
        if (iv->size() != m_algorithm->getBlockSize()) {
            std::cout << "IV size must be equal to the block size of the algorithm."<< std::endl;
        }

        m_iv = *iv;

    } else {
        if (iv.has_value()) {
            std::cout << "Warning: An IV was provided for a mode (like ECB) that does not use it. The IV will be ignored.\n";
        }

    }
    m_algorithm->setKey(key);
}


void CipherContext::applyPadding(std::vector<unsigned char>& data) {
    size_t block_size = getBlockSize();
    size_t padding_size = block_size - (data.size() % block_size);
    if (m_padding == PaddingScheme::PKCS7 && data.size() % block_size == 0) {
        padding_size = block_size;
    }
    if (padding_size == block_size && m_padding != PaddingScheme::PKCS7) {
        return;
    }

    switch (m_padding) {
        case PaddingScheme::Zeros:
            for (size_t i = 0; i < padding_size; ++i) {
                data.push_back(0x00);
            }
            break;
        case PaddingScheme::PKCS7:
            for (size_t i = 0; i < padding_size; ++i) {
                data.push_back(static_cast<unsigned char>(padding_size));
            }
            break;
        case PaddingScheme::ANSI_X923:
            for (size_t i = 0; i < padding_size - 1; ++i){
                data.push_back(0x00);
            }
            data.push_back(static_cast<unsigned char>(padding_size));
            break;
        case PaddingScheme::ISO_10126:
            for (size_t i = 0; i < padding_size - 1; ++i) {
                data.push_back(rand() % 256);
            }
            data.push_back(static_cast<unsigned char>(padding_size));
            break;
    }
}

void CipherContext::removePadding(std::vector<unsigned char>& data) {
    if (data.empty()) {
        return;
    }

    size_t padding_size = 0;
    switch (m_padding) {
        case PaddingScheme::PKCS7:
        case PaddingScheme::ANSI_X923:
        case PaddingScheme::ISO_10126:
            padding_size = data.back();
            if (padding_size > 0 && padding_size <= getBlockSize() && padding_size <= data.size()) {
                data.resize(data.size() - padding_size);
            }
            break;
        case PaddingScheme::Zeros:
            while (!data.empty() && data.back() == 0x00) {
                data.pop_back();
            }
            break;
    }
}

size_t CipherContext::getBlockSize() const {
    return m_algorithm->getBlockSize();
}

void CipherContext::setKey(const byte_array& key) {
    m_algorithm->setKey(key);
}

byte_array CipherContext::encryptBlock(const byte_array& block) {
    return m_algorithm->encryptBlock(block);
}

byte_array CipherContext::decryptBlock(const byte_array& block) {
    return m_algorithm->decryptBlock(block);
}

std::future<void> CipherContext::encrypt(const std::vector<unsigned char>& input, std::vector<unsigned char>& output) {
    return std::async(std::launch::async, [this, &input, &output]() {
        std::vector<unsigned char> data = input;
        applyPadding(data);
        const size_t block_size = getBlockSize();
        const size_t num_blocks = data.size() / block_size;
        output.resize(data.size());

        if (m_mode == CipherMode::ECB || m_mode == CipherMode::CTR) {
#pragma omp parallel for
            for (long long i = 0; i < num_blocks; ++i) {
                std::vector<unsigned char> block(data.begin() + i * block_size, data.begin() + (i + 1) * block_size);
                std::vector<unsigned char> encrypted_block;
                if (m_mode == CipherMode::ECB) {
                    encrypted_block = encryptBlock(block);
                }
                else {
                    std::vector<unsigned char> counter_block = m_iv;
                    for (long long j = 0; j < i; ++j) {
                        for (int k = counter_block.size() - 1; k >= 0; --k){
                            if (++counter_block[k] != 0)
                                break;
                        }
                    }
                    encrypted_block = encryptBlock(counter_block);
                    xor_bytes(encrypted_block, block);
                }
                std::copy(encrypted_block.begin(), encrypted_block.end(), output.begin() + i * block_size);
            }
        }
        else {
            std::vector<unsigned char> feedback = m_iv;
            for (size_t i = 0; i < num_blocks; ++i) {
                std::vector<unsigned char> block(data.begin() + i * block_size, data.begin() + (i + 1) * block_size);
                std::vector<unsigned char> encrypted_block;
                switch (m_mode) {
                    case CipherMode::CBC:
                        xor_bytes(block, feedback);
                        encrypted_block = encryptBlock(block);
                        feedback = encrypted_block;
                        break;
                    case CipherMode::PCBC: {
                        std::vector<unsigned char> plaintext_copy = block;
                        xor_bytes(block, feedback);
                        encrypted_block = encryptBlock(block);
                        feedback = encrypted_block;
                        xor_bytes(feedback, plaintext_copy);
                        break;
                    }
                    case CipherMode::CFB:
                        encrypted_block = encryptBlock(feedback);
                        xor_bytes(encrypted_block, block);
                        feedback = encrypted_block;
                        break;
                    case CipherMode::OFB:
                        feedback = encryptBlock(feedback);
                        encrypted_block = block;
                        xor_bytes(encrypted_block, feedback);
                        break;
                    case CipherMode::RANDOM_DELTA: {
                        const auto& delta = std::any_cast<std::vector<unsigned char>>(m_params.at("delta"));
                        xor_bytes(block, feedback);
                        encrypted_block = encryptBlock(block);
                        feedback = encrypted_block;
                        xor_bytes(feedback, delta);
                        break;
                    }
                    default:
                        break;
                }
                std::copy(encrypted_block.begin(), encrypted_block.end(), output.begin() + i * block_size);
            }
        }
    });
}

std::future<void> CipherContext::decrypt(const std::vector<unsigned char>& input, std::vector<unsigned char>& output) {
    return std::async(std::launch::async, [this, &input, &output]() {
        if (input.size() % getBlockSize() != 0){
            std::cout << "Invalid data size." << std::endl;
        }
        const size_t block_size = getBlockSize();
        const size_t num_blocks = input.size() / block_size;
        output.resize(input.size());

        if (m_mode == CipherMode::ECB || m_mode == CipherMode::CTR) {
#pragma omp parallel for
            for (long long i = 0; i < num_blocks; ++i) {
                std::vector<unsigned char> block(input.begin() + i * block_size, input.begin() + (i + 1) * block_size);
                std::vector<unsigned char> decrypted_block;
                if (m_mode == CipherMode::ECB) {
                    decrypted_block = decryptBlock(block);
                }
                else {
                    std::vector<unsigned char> counter_block = m_iv;
                    for (long long j = 0; j < i; ++j) {
                        for (int k = counter_block.size() - 1; k >= 0; --k) if (++counter_block[k] != 0) break; }
                    decrypted_block = encryptBlock(counter_block); // <-- ENCRYPT
                    xor_bytes(decrypted_block, block);
                }
                std::copy(decrypted_block.begin(), decrypted_block.end(), output.begin() + i * block_size);
            }
        }
        else {
            std::vector<unsigned char> feedback = m_iv;
            for (size_t i = 0; i < num_blocks; ++i) {
                std::vector<unsigned char> block(input.begin() + i * block_size, input.begin() + (i + 1) * block_size);
                std::vector<unsigned char> decrypted_block;
                switch (m_mode) {
                    case CipherMode::CBC:
                        decrypted_block = decryptBlock(block);
                        xor_bytes(decrypted_block, feedback);
                        feedback = block;
                        break;
                    case CipherMode::PCBC: {
                        std::vector<unsigned char> ciphertext_copy = block;
                        decrypted_block = decryptBlock(block);
                        xor_bytes(decrypted_block, feedback);
                        feedback = decrypted_block;
                        xor_bytes(feedback, ciphertext_copy);
                        break;
                    }
                    case CipherMode::CFB:
                        decrypted_block = encryptBlock(feedback);
                        xor_bytes(decrypted_block, block);
                        feedback = block;
                        break;
                    case CipherMode::OFB:
                        feedback = encryptBlock(feedback);
                        decrypted_block = block;
                        xor_bytes(decrypted_block, feedback);
                        break;
                    case CipherMode::RANDOM_DELTA: {
                        const auto& delta = std::any_cast<std::vector<unsigned char>>(m_params.at("delta"));
                        decrypted_block = decryptBlock(block);
                        xor_bytes(decrypted_block, feedback);
                        feedback = block;
                        xor_bytes(feedback, delta);
                        break;
                    }
                    default: break;
                }
                std::copy(decrypted_block.begin(), decrypted_block.end(), output.begin() + i * block_size);
            }
        }
        removePadding(output);
    });
}


std::future<void> CipherContext::encrypt(const std::string& inputFile, const std::string& outputFile) {
    return std::async(std::launch::async, [this, inputFile, outputFile]() {
        std::ifstream in(inputFile, std::ios::binary);
        if (!in) {
            std::cout << "Cannot open input file " + inputFile <<std::endl;
        }
        byte_array original_data((std::istreambuf_iterator<char>(in)), {});
        in.close();

        applyPadding(original_data);

        const int num_threads = std::max(1u, std::thread::hardware_concurrency());//количество ядер
        const size_t total_size = original_data.size();
        if (total_size == 0) {
            return;
        }

        const size_t block_size = getBlockSize();
        size_t chunk_size = (total_size / num_threads / block_size) * block_size;//чанки из целых блоков
        if (chunk_size == 0) {
            chunk_size = block_size; //маленькие файлы
        }

        std::vector<std::future<byte_array>> futures;
        size_t offset = 0;

        while (offset < total_size) {
            size_t current_chunk_size = std::min(chunk_size, total_size - offset);
            if (offset + chunk_size > total_size) {//последний чанк
                current_chunk_size = total_size - offset;
            }
            if (current_chunk_size == 0) {
                break;
            }

            byte_array chunk(original_data.begin() + offset, original_data.begin() + offset + current_chunk_size);

            futures.push_back(std::async(std::launch::async, [this, c = std::move(chunk)]() {
                byte_array encrypted_chunk;
                encrypt(c, encrypted_chunk).get();
                return encrypted_chunk;
            }));

            offset += current_chunk_size;
        }

        std::ofstream out(outputFile, std::ios::binary);
        if (!out) {
            std::cout <<"Cannot open output file: " + outputFile << std::endl;
        }

        for (auto& fut : futures) {
            byte_array encrypted_chunk = fut.get();
            out.write(reinterpret_cast<const char*>(encrypted_chunk.data()), encrypted_chunk.size());
        }
    });
}

std::future<void> CipherContext::decrypt(const std::string& inputFile, const std::string& outputFile) {
    return std::async(std::launch::async, [this, inputFile, outputFile]() {
        std::ifstream in(inputFile, std::ios::binary);
        if (!in) {
            std::cout << "Cannot open input file: " + inputFile << std::endl;
        }
        byte_array encrypted_data((std::istreambuf_iterator<char>(in)), {});
        in.close();

        if (encrypted_data.empty()) {
            return;
        }
        if (encrypted_data.size() % getBlockSize() != 0) {
            std::cout << "Encrypted file size is not a multiple of block size." << std::endl;
        }

        const int num_threads = std::max(1u, std::thread::hardware_concurrency());
        const size_t total_size = encrypted_data.size();
        size_t chunk_size = (total_size / num_threads / getBlockSize()) * getBlockSize();
        if (chunk_size == 0) {
            chunk_size = getBlockSize();
        }

        std::vector<std::future<byte_array>> futures;
        size_t offset = 0;

        while (offset < total_size) {
            size_t current_chunk_size = std::min(chunk_size, total_size - offset);
            if (offset + chunk_size > total_size) {
                current_chunk_size = total_size - offset;
            }
            if (current_chunk_size == 0) {
                break;
            }

            byte_array chunk(encrypted_data.begin() + offset, encrypted_data.begin() + offset + current_chunk_size);

            futures.push_back(std::async(std::launch::async, [this, c = std::move(chunk)]() {
                byte_array decrypted_chunk;
                decrypt(c, decrypted_chunk).get();
                return decrypted_chunk;
            }));

            offset += current_chunk_size;
        }

        byte_array decrypted_data;
        for (auto& fut : futures) {
            byte_array decrypted_chunk = fut.get();
            decrypted_data.insert(decrypted_data.end(), decrypted_chunk.begin(), decrypted_chunk.end());
        }

        removePadding(decrypted_data);

        std::ofstream out(outputFile, std::ios::binary);
        if (!out) {
            std::cout <<"Cannot open output file: " + outputFile << std::endl;
        }
        out.write(reinterpret_cast<const char*>(decrypted_data.data()), decrypted_data.size());
    });
}