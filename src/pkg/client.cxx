#include "../../include/pkg/client.hpp"

#include <sys/ioctl.h>

#include <boost/asio.hpp>
#include <boost/lexical_cast.hpp>
#include <cmath>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>

#include "../../include-shared/util.hpp"
#include "colors.hpp"

/**
 * Constructor. Sets up TCP socket and starts REPL
 * @param command One of "listen" or "connect"
 * @param address Address to listen on or connect to.q
 * @param port Port to listen on or connect to.
 */
Client::Client(std::shared_ptr<NetworkDriver> network_driver,
               std::shared_ptr<CryptoDriver> crypto_driver) {
  // Make shared variables.
  this->cli_driver = std::make_shared<CLIDriver>();
  this->crypto_driver = crypto_driver;
  this->network_driver = network_driver;
}

/**
 * Generates a new DH secret and replaces the keys. This function should:
 * 1) Call DH_generate_shared_key
 * 2) Use the resulting key in AES_generate_key and HMAC_generate_key
 * 3) Update private key variables
 */
void Client::prepare_keys(CryptoPP::DH DH_obj,
                          CryptoPP::SecByteBlock DH_private_value,
                          CryptoPP::SecByteBlock DH_other_public_value) {
  // TODO: implement me!
  CryptoDriver cd;
  SecByteBlock shared_key = cd.DH_generate_shared_key(DH_obj, DH_private_value, DH_other_public_value);
  this->AES_key = cd.AES_generate_key(shared_key);
  this->HMAC_key = cd.HMAC_generate_key(shared_key);
  this->DH_current_private_value = DH_private_value;
  this->DH_switched = false;
}

/**
 * Encrypts the given message and returns a Message struct. This function
 * should:
 * 1) Check if the DH Ratchet keys need to change; if so, update them.
 * 2) Encrypt and tag the message.
 */
Message_Message Client::send(std::string plaintext) {
  // Grab the lock to avoid race conditions between the receive and send threads
  // Lock will automatically release at the end of the function.
  std::unique_lock<std::mutex> lck(this->mtx);
  CryptoDriver cd;
  auto dhT = cd.DH_initialize(this->DH_params);
  if (this->DH_switched) {

      prepare_keys(std::get<0>(dhT), DH_current_private_value, DH_last_other_public_value);
  }
  auto p = cd.AES_encrypt(this->AES_key, plaintext);
  Message_Message ms;
  ms.ciphertext = p.first;
  ms.iv = p.second;
  ms.public_value = this->DH_current_public_value;
  ms.mac = cd.HMAC_generate(this->HMAC_key, concat_msg_fields(ms.iv, ms.public_value, ms.ciphertext));
  return ms;
}

/**
 * Decrypts the given Message into a tuple containing the plaintext and
 * an indicator if the MAC was valid (true if valid; false otherwise).
 * 1) Check if the DH Ratchet keys need to change; if so, update them.
 * 2) Decrypt and verify the message.
 */
std::pair<std::string, bool> Client::receive(Message_Message ciphertext) {
  // Grab the lock to avoid race conditions between the receive and send threads
  // Lock will automatically release at the end of the function.
  std::unique_lock<std::mutex> lck(this->mtx);
  CryptoDriver cd;
  auto dhT = cd.DH_initialize(this->DH_params);
  std::string plaintext;
  bool valid;
  try {
      plaintext = cd.AES_decrypt(this->AES_key,
                                 ciphertext.iv,
                                 ciphertext.ciphertext);
      valid = cd.HMAC_verify(this->HMAC_key,
                             concat_msg_fields(ciphertext.iv, ciphertext.public_value, ciphertext.ciphertext),
                             ciphertext.mac);
      this->DH_switched = true;
  } catch (std::runtime_error &e) {
      valid = false;
  }
  return std::make_pair(plaintext, valid);
}

/**
 * Run the client.
 */
void Client::run(std::string command) {
  // Initialize cli_driver.
  this->cli_driver->init();

  // Run key exchange.
  this->HandleKeyExchange(command);

  // Start msgListener thread.
  boost::thread msgListener =
      boost::thread(boost::bind(&Client::ReceiveThread, this));
  msgListener.detach();

  // Start sending thread.
  this->SendThread();
}

/**
 * Run key exchange. This function:
 * 1) Listen for or generate and send DHParams_Message depending on `command`
 * `command` can be either "listen" or "connect"; the listener should read()
 * for params, and the connector should generate and send params.
 * 2) Initialize DH object and keys
 * 3) Send your public value
 * 4) Listen for the other party's public value
 * 5) Generate DH, AES, and HMAC keys and set local variables
 */
void Client::HandleKeyExchange(std::string command) {
  // TODO: implement me!
  CryptoDriver cd;
  if (command == "listen") {
    // Listen for DHParams_Message
    // Initialize DH object and keys
    // Send your public value
    // Listen for the other party's public value
    // Generate DH, AES, and HMAC keys and set local variables
    std::vector<unsigned char> dpm_str = this->network_driver->read();
    DHParams_Message dpm;
    dpm.deserialize(dpm_str);

    auto tup = cd.DH_initialize(dpm);
    this->DH_params = dpm;
    SecByteBlock shared_val = cd.DH_generate_shared_key(std::get<0>(tup), std::get<1>(tup), std::get<2>(tup));
    this->DH_current_private_value = std::get<1>(tup);
    this->DH_current_public_value = std::get<2>(tup);

    // send public value
    std::vector<unsigned char> data1 = str2chvec(byteblock_to_string(this->DH_current_public_value));
    this->network_driver->send(data1);

    // get other's value
    std::vector<unsigned char> other_pub_val = this->network_driver->read();
    std::string str = chvec2str(other_pub_val);
    this->DH_last_other_public_value = string_to_byteblock(str);

    auto shared = cd.DH_generate_shared_key(std::get<0>(tup), std::get<1>(tup), this->DH_last_other_public_value);
    this->AES_key = cd.AES_generate_key(shared);
    this->HMAC_key = cd.HMAC_generate_key(shared);

  } else if (command == "connect") {
    // Generate and send DHParams_Message
    // Initialize DH object and keys
    // Send your public value
    // Listen for the other party's public value
    // Generate DH, AES, and HMAC keys and set local variables
    DHParams_Message dpm = cd.DH_generate_params();
    auto tup = cd.DH_initialize(dpm);
    this->DH_params = dpm;
    SecByteBlock shared_val = cd.DH_generate_shared_key(std::get<0>(tup), std::get<1>(tup), std::get<2>(tup));
    this->DH_current_private_value = std::get<1>(tup);
    this->DH_current_public_value = std::get<2>(tup);
    this->DH_switched = false;

    // send dhp
    std::vector<unsigned char> data0;
    dpm.serialize(data0);
    this->network_driver->send(data0);

    // send public value
    std::string public_value = byteblock_to_string(this->DH_current_public_value);
    std::vector<unsigned char> data1 = str2chvec(public_value);
    this->network_driver->send(data1);

    // get other's public
    std::vector<unsigned char> other_public_value_vec = this->network_driver->read();
    std::string other_public_value = chvec2str(other_public_value_vec);
    this->DH_last_other_public_value = string_to_byteblock(other_public_value);

    auto shared = cd.DH_generate_shared_key(std::get<0>(tup), std::get<1>(tup), this->DH_last_other_public_value);
    this->AES_key = cd.AES_generate_key(shared);
    this->HMAC_key = cd.HMAC_generate_key(shared);

  } else {
    throw std::runtime_error("Invalid command!");
  }
}

/**
 * Listen for messages and print to cli_driver.
 */
void Client::ReceiveThread() {
  while (true) {
    // Try reading data from the other user.
    std::vector<unsigned char> data;
    try {
      data = this->network_driver->read();
    } catch (std::runtime_error &_) {
      // Exit cleanly.
      this->cli_driver->print_left("Received EOF; closing connection");
      this->network_driver->disconnect();
      return;
    }

    // Deserialize, decrypt, and verify message.
    Message_Message msg;
    msg.deserialize(data);
    auto decrypted_data = this->receive(msg);
    if (!decrypted_data.second) {
      this->cli_driver->print_left("Received invalid HMAC; the following "
                                   "message may have been tampered with.");
      throw std::runtime_error("Received invalid MAC!");
    }
    this->cli_driver->print_left(std::get<0>(decrypted_data));
  }
}

/**
 * Listen for stdin and send to other party.
 */
void Client::SendThread() {
  std::string plaintext;
  while (true) {
    // Read from STDIN.
    std::getline(std::cin, plaintext);
    if (std::cin.eof()) {
      this->cli_driver->print_left("Received EOF; closing connection");
      this->network_driver->disconnect();
      return;
    }

    // Encrypt and send message.
    if (plaintext != "") {
      Message_Message msg = this->send(plaintext);
      std::vector<unsigned char> data;
      msg.serialize(data);
      this->network_driver->send(data);
    }
    this->cli_driver->print_right(plaintext);
  }
}
