//
// Created by Вероника on 02.10.2025.
//


#include<iostream>
#include <vector>
#include <string>
#include <memory>
#include <optional>
#include <future>
#include <map>
#include <any>
#include <fstream>

#ifdef _OPENMP
#include <omp.h>
#endif

using byte_array = std::vector<unsigned char>;
using round_keys_array = std::vector<byte_array>;
using ExtraParams = std::map<std::string, std::any>;

inline void xor_bytes(std::vector<unsigned char>& a, const std::vector<unsigned char>& b) {
    if (a.size() != b.size()) {
        throw std::invalid_argument("xor_bytes: vectors must have the same size: a=" + std::to_string(a.size()) + " b=" + std::to_string(b.size()));
    }
    for (size_t i = 0; i < a.size(); ++i) a[i] ^= b[i];
}


//2.1
class IKeyExpander{
public:
    virtual ~IKeyExpander() = default;
    virtual std::vector<std::vector<unsigned char>> generateRoundKeys (const std::vector<unsigned char>& masterKey) = 0;
};

//2.2
class IRoundFunction{
public:
    virtual ~IRoundFunction() = default;
    virtual std::vector<unsigned char> apply(const std::vector<unsigned char>& block, const std::vector<unsigned char>& roundKey) = 0;
};

//2.3
class ISymmetricCipher{
public:
    virtual ~ISymmetricCipher() = default;
    virtual void setKey(const std::vector<unsigned char>& key) = 0;
    virtual std::vector<unsigned char> encryptBlock(const std::vector<unsigned char>& block) = 0;
    virtual std::vector<unsigned char> decryptBlock(const std::vector<unsigned char>& block) = 0;
    virtual size_t getBlockSize() const = 0;
};

//2.4
enum class CipherMode{
    ECB,
    CBC,
    PCBC,
    CFB,
    OFB,
    CTR,
    RANDOM_DELTA
};

enum class PaddingScheme{
    Zeros,
    ANSI_X923,
    PKCS7,
    ISO_10126
};


class CipherContext : public ISymmetricCipher {
private:
    std::unique_ptr<ISymmetricCipher> m_algorithm;
    CipherMode m_mode;
    PaddingScheme m_padding;
    byte_array m_iv;
    ExtraParams m_params;

    void applyPadding(byte_array& data);
    void removePadding(byte_array& data);

public:
    CipherContext(
            std::unique_ptr<ISymmetricCipher> algorithm,
            const byte_array& key,
            CipherMode mode,
            PaddingScheme padding,
            std::optional<byte_array> iv = std::nullopt,
            ExtraParams params = {}
    );

    void setKey(const byte_array& key) override;
    byte_array encryptBlock(const byte_array& block) override;
    byte_array decryptBlock(const byte_array& block) override;
    size_t getBlockSize() const override;

    std::future<void> encrypt(const byte_array& input, byte_array& output);
    std::future<void> decrypt(const byte_array& input, byte_array& output);
    std::future<void> encrypt(const std::string& inputFile, const std::string& outputFile);
    std::future<void> decrypt(const std::string& inputFile, const std::string& outputFile);
};
