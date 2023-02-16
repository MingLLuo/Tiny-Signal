#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest/doctest.h"
#include "../include/pkg/client.hpp"
#include "../include/drivers/crypto_driver.hpp"
#include "../include-shared/util.hpp"

TEST_CASE("DH Test1") {
    CryptoDriver cd;
    DHParams_Message dh_params = cd.DH_generate_params();
    std::tuple<DH, SecByteBlock, SecByteBlock>
            dh1 = cd.DH_initialize(dh_params);
    std::tuple<DH, SecByteBlock, SecByteBlock>
            dh2 = cd.DH_initialize(dh_params);

    SecByteBlock dh1_shared_key = cd.DH_generate_shared_key(std::get<0>(dh1), std::get<1>(dh1), std::get<2>(dh2));
    SecByteBlock dh2_shared_key = cd.DH_generate_shared_key(std::get<0>(dh2), std::get<1>(dh2), std::get<2>(dh1));
    CHECK(byteblock_to_string(dh1_shared_key) == byteblock_to_string(dh2_shared_key));
}

TEST_CASE("AES TEST") {
    CryptoDriver cd;
    DHParams_Message dh_params = cd.DH_generate_params();
    std::tuple<DH, SecByteBlock, SecByteBlock>
            dh1 = cd.DH_initialize(dh_params);
    std::tuple<DH, SecByteBlock, SecByteBlock>
            dh2 = cd.DH_initialize(dh_params);

    SecByteBlock dh1_shared_key = cd.DH_generate_shared_key(std::get<0>(dh1), std::get<1>(dh1), std::get<2>(dh2));
    SecByteBlock dh2_shared_key = cd.DH_generate_shared_key(std::get<0>(dh2), std::get<1>(dh2), std::get<2>(dh1));

    SecByteBlock dh1_aes_key = cd.AES_generate_key(dh1_shared_key);
    SecByteBlock dh2_aes_key = cd.AES_generate_key(dh2_shared_key);

    std::string plaintext = "Hello World!";
    std::pair<std::string, SecByteBlock> dh1_encrypted = cd.AES_encrypt(dh1_aes_key, plaintext);
    std::string dh2_decrypted = cd.AES_decrypt(dh2_aes_key, std::get<1>(dh1_encrypted), std::get<0>(dh1_encrypted));

    CHECK(plaintext == dh2_decrypted);
}

TEST_CASE("HMAC TEST") {
    CryptoDriver cd;
    DHParams_Message dh_params = cd.DH_generate_params();
    std::tuple<DH, SecByteBlock, SecByteBlock>
            dh1 = cd.DH_initialize(dh_params);
    std::tuple<DH, SecByteBlock, SecByteBlock>
            dh2 = cd.DH_initialize(dh_params);

    SecByteBlock dh1_shared_key = cd.DH_generate_shared_key(std::get<0>(dh1), std::get<1>(dh1), std::get<2>(dh2));
    SecByteBlock dh2_shared_key = cd.DH_generate_shared_key(std::get<0>(dh2), std::get<1>(dh2), std::get<2>(dh1));

    SecByteBlock dh1_hmac_key = cd.HMAC_generate_key(dh1_shared_key);
    SecByteBlock dh2_hmac_key = cd.HMAC_generate_key(dh2_shared_key);

    std::string plaintext = "Hello World!";

    std::string dh1_hmac = cd.HMAC_generate(dh1_hmac_key, plaintext);
    auto dh2_hmac_verify = cd.HMAC_verify(dh2_hmac_key, plaintext, dh1_hmac);
    CHECK(dh2_hmac_verify);
}