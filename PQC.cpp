#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <iomanip>
#include <algorithm>
#include <oqs/oqs.h>
#include <openssl/evp.h>

// Define file names for the input model, encrypted file, and decrypted file.
#define MODEL_FILE        "Model"         // Your downloaded AI model file
#define ENCRYPTED_FILE    "Model.enc"     // Encrypted output file
#define DECRYPTED_FILE    "Model.dec"     // Decrypted output file
#define SECRET_KEY_FILE   "kyber_sk.bin"  // File to store Kyber secret key

// --- Utility functions for file I/O (binary mode) ---

// Reads an entire binary file into a vector.
std::vector<uint8_t> readFile(const std::string &filename) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file) {
        std::cerr << "Error opening file: " << filename << std::endl;
        exit(1);
    }
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> buffer(size);
    if (!file.read(reinterpret_cast<char *>(buffer.data()), size)) {
        std::cerr << "Error reading file: " << filename << std::endl;
        exit(1);
    }
    return buffer;
}

// Writes binary data from a vector to a file.
void writeFile(const std::string &filename, const std::vector<uint8_t> &data) {
    std::ofstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Error writing file: " << filename << std::endl;
        exit(1);
    }
    file.write(reinterpret_cast<const char *>(data.data()), data.size());
}

// --- AES-256-GCM Encryption and Decryption functions (using OpenSSL) ---

// Encrypts plaintext using AES-256-GCM.
// The shared secret from Kyber is used as the 32-byte key.
// For demonstration, we use a fixed IV (NOT recommended for production).
std::vector<uint8_t> aesEncrypt(const std::vector<uint8_t> &plaintext,
                                const std::vector<uint8_t> &key,
                                std::vector<uint8_t> &iv_out,
                                std::vector<uint8_t> &tag_out) {
    const size_t KEY_SIZE = 32;
    const size_t IV_SIZE  = 12;
    const size_t TAG_SIZE = 16;

    if (key.size() < KEY_SIZE) {
        std::cerr << "Key size too small for AES-256-GCM." << std::endl;
        exit(1)
    }

    // For demo: use a fixed IV. In production, generate a random IV!
    iv_out.resize(IV_SIZE, 0x00);
    for (size_t i = 0; i < IV_SIZE; i++) {
        iv_out[i] = 0xAA;  // Example fixed IV (do not use in production)
    }

    std::vector<uint8_t> ciphertext(plaintext.size());
    tag_out.resize(TAG_SIZE);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Failed to create EVP_CIPHER_CTX." << std::endl;
        exit(1);
    }

    // Initialize encryption context for AES-256-GCM.
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        std::cerr << "EVP_EncryptInit_ex failed." << std::endl;
        exit(1);
    }

    // Set key and IV.
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key.data(), iv_out.data()) != 1) {
        std::cerr << "EVP_EncryptInit_ex (key/iv) failed." << std::endl;
        exit(1);
    }

    int len = 0;
    int ciphertext_len = 0;

    // Encrypt the plaintext.
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()) != 1) {
        std::cerr << "EVP_EncryptUpdate failed." << std::endl;
        exit(1);
    }
    ciphertext_len = len;

    // Finalize encryption.
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        std::cerr << "EVP_EncryptFinal_ex failed." << std::endl;
        exit(1);
    }
    ciphertext_len += len;
    ciphertext.resize(ciphertext_len);

    // Get the authentication tag.
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag_out.data()) != 1) {
        std::cerr << "EVP_CIPHER_CTX_ctrl failed." << std::endl;
        exit(1);
    }

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}

// Decrypts ciphertext using AES-256-GCM.
std::vector<uint8_t> aesDecrypt(const std::vector<uint8_t> &ciphertext,
                                const std::vector<uint8_t> &key,
                                const std::vector<uint8_t> &iv,
                                const std::vector<uint8_t> &tag) {
    const size_t KEY_SIZE = 32;
    if (key.size() < KEY_SIZE) {
        std::cerr << "Key size too small for AES-256-GCM." << std::endl;
        exit(1);
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Failed to create EVP_CIPHER_CTX." << std::endl;
        exit(1);
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        std::cerr << "EVP_DecryptInit_ex failed." << std::endl;
        exit(1);
    }

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key.data(), iv.data()) != 1) {
        std::cerr << "EVP_DecryptInit_ex (key/iv) failed." << std::endl;
        exit(1);
    }

    std::vector<uint8_t> plaintext(ciphertext.size());
    int len = 0;
    int plaintext_len = 0;

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()) != 1) {
        std::cerr << "EVP_DecryptUpdate failed." << std::endl;
        exit(1);
    }
    plaintext_len = len;

    // Set the expected authentication tag.
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(), (void*)tag.data()) != 1) {
        std::cerr << "EVP_CIPHER_CTX_ctrl (set tag) failed." << std::endl;
        exit(1);
    }

    // Finalize decryption.
    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    if (ret <= 0) {
        std::cerr << "EVP_DecryptFinal_ex: Authentication failed." << std::endl;
        exit(1);
    }
    plaintext_len += len;
    plaintext.resize(plaintext_len);

    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

// --- Hybrid Encryption: Protecting the AI Model File ---

// Encrypts the AI model file using Kyber KEM + AES-256-GCM.
void encryptModel() {
    // Initialize Kyber KEM from liboqs.
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_1024);
    if (!kem) {
        std::cerr << "Failed to initialize Kyber-1024." << std::endl;
        exit(1);
    }

    // Generate Kyber key pair.
    std::vector<uint8_t> public_key(kem->length_public_key);
    std::vector<uint8_t> secret_key(kem->length_secret_key);
    OQS_KEM_keypair(kem, public_key.data(), secret_key.data());

    // Save the secret key for decryption.
    writeFile(SECRET_KEY_FILE, secret_key);

    // Read the original AI model file (binary).
    std::vector<uint8_t> modelData = readFile(MODEL_FILE);

    // Encapsulate using Kyber to obtain a shared secret and ephemeral ciphertext.
    std::vector<uint8_t> kemCiphertext(kem->length_ciphertext);
    std::vector<uint8_t> sharedSecret(kem->length_shared_secret);
    OQS_KEM_encaps(kem, kemCiphertext.data(), sharedSecret.data(), public_key.data());

    // Use the shared secret as the AES key.
    // (Ensure that sharedSecret is at least 32 bytes; otherwise, derive a key from it.)
    std::vector<uint8_t> iv, tag;
    std::vector<uint8_t> aesCiphertext = aesEncrypt(modelData, sharedSecret, iv, tag);

    // Prepare a single output: [KEM ciphertext || IV || TAG || AES ciphertext]
    std::vector<uint8_t> output;
    output.insert(output.end(), kemCiphertext.begin(), kemCiphertext.end());
    output.insert(output.end(), iv.begin(), iv.end());
    output.insert(output.end(), tag.begin(), tag.end());
    output.insert(output.end(), aesCiphertext.begin(), aesCiphertext.end());

    // Write the encrypted data to file.
    writeFile(ENCRYPTED_FILE, output);

    std::cout << "Model encrypted and saved to " << ENCRYPTED_FILE << std::endl;
    OQS_KEM_free(kem);
}

// Decrypts the AI model file using the hybrid method.
void decryptModel() {
    // Initialize Kyber KEM.
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_1024);
    if (!kem) {
        std::cerr << "Failed to initialize Kyber-1024." << std::endl;
        exit(1);
    }

    // Load the secret key saved during encryption.
    std::vector<uint8_t> secret_key = readFile(SECRET_KEY_FILE);

    // Read the entire encrypted file.
    std::vector<uint8_t> encData = readFile(ENCRYPTED_FILE);
    size_t offset = 0;

    // Extract the KEM ciphertext.
    std::vector<uint8_t> kemCiphertext(encData.begin(), encData.begin() + kem->length_ciphertext);
    offset += kem->length_ciphertext;

    // For AES-256-GCM, we use a 12-byte IV and a 16-byte tag.
    const size_t IV_SIZE = 12;
    const size_t TAG_SIZE = 16;

    std::vector<uint8_t> iv(encData.begin() + offset, encData.begin() + offset + IV_SIZE);
    offset += IV_SIZE;
    std::vector<uint8_t> tag(encData.begin() + offset, encData.begin() + offset + TAG_SIZE);
    offset += TAG_SIZE;

    // The remainder is the AES ciphertext.
    std::vector<uint8_t> aesCiphertext(encData.begin() + offset, encData.end());

    // Decapsulate using Kyber to recover the shared secret.
    std::vector<uint8_t> sharedSecret(kem->length_shared_secret);
    OQS_KEM_decaps(kem, sharedSecret.data(), kemCiphertext.data(), secret_key.data());

    // Decrypt the AES ciphertext using the shared secret.
    std::vector<uint8_t> decryptedData = aesDecrypt(aesCiphertext, sharedSecret, iv, tag);

    // Write the decrypted data to file.
    writeFile(DECRYPTED_FILE, decryptedData);

    std::cout << "Model decrypted and saved to " << DECRYPTED_FILE << std::endl;
    OQS_KEM_free(kem);
}

int main() {
    // First, encrypt the AI model.
    encryptModel();

    // Then, decrypt the encrypted file.
    decryptModel();

    return 0;
}
