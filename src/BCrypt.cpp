
/******************************************************************************
 * Copyright (c) 2024 Ross Gray
 *
 * This file is part of passGen2.
 *
 * passGen2 is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * passGen2 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with passGen2. If not, see <http://www.gnu.org/licenses/>.
 *
 *****************************************************************************/

#include "BCrypt.h"
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <regex>

std::string concatenateHash(int cost, uint8_t *salt, uint64_t *ciphers) {
  Converter converter;
  std::string alg = "$2a";
  std::string costString = "$" + std::to_string(cost);
  std::string saltString((char *)salt);
  std::string cipherString;

  for (int i = 0; i < 3; i++) {
    uint8_t *cipher = converter.bits_to_bytes(ciphers[i], 64);
    std::string str((char *)cipher);
    cipherString += str;
  }

  cipherString = cipherString.substr(0, 7);

  saltString = base64_encode(saltString);
  cipherString = base64_encode(cipherString);

  std::regex validChars("[^a-zA-Z0-9!@#$%^&*()]");

  saltString = saltString.substr(0, 4);

  std::string output = alg + cipherString + costString + saltString;

  output = std::regex_replace(output, validChars, "");

  return output;
}

uint8_t *appendRoundText(uint8_t **roundText, int numWords) {
  uint8_t *appended = (uint8_t *)malloc(sizeof(uint8_t) * (numWords * 8));

  for (int i = 0; i < 3; i++) {
    for (int n = 0; n < 8; n++) {
      appended[n + (8 * i)] = roundText[i][n];
    }
  }

  return appended;
}

int BCrypt(int cost, uint8_t *salt, uint8_t *password, int passwordLength) {
  uint32_t *P;
  uint32_t **S;
  uint8_t *saltBackup = (uint8_t *)malloc(sizeof(uint8_t) * 16);

  memcpy(saltBackup, salt, sizeof(uint8_t) * 16);

  // this text is used as the final cipher text as part of the bcrypt standard
  // there is an easter egg hidden here "Open BSD"
  uint8_t cipherText[24] = {'O', 'r', 'p', 'h', 'e', 'a', 'n', 'B',
                            'e', 'h', 'o', 'l', 'd', 'e', 'r', 'S',
                            'c', 'r', 'y', 'D', 'o', 'u', 'b', 't'};
  uint8_t **roundText;

  EksBlowfish eks(cost, passwordLength, salt, password);

  eks.generate_keys();

  // expensive key setup
  P = eks.getP();
  S = eks.getS();

  Blowfish blowfishInit(P, S, cipherText, 24);
  roundText = blowfishInit.Encrypt();

  for (int i = 0; i < 63; i++) {
    Blowfish blowfish(P, S, appendRoundText(roundText, 3), 24);
    roundText = blowfish.Encrypt();
  }

  Converter converter;
  uint64_t *ciphers = (uint64_t *)malloc(sizeof(uint64_t) * 3);
  for (int i = 0; i < 3; i++) {
    ciphers[i] = converter.bytes_to_64bit(roundText[i], 8);
  }

  std::string hash = concatenateHash(cost, saltBackup, ciphers);

  cout << std::hex << hash << endl;

  return 0;
}

uint8_t *pass_input(int *passwordLength) {
  bool passwordCorrect = false;
  std::string password;
  std::string passwordCheck;
  uint8_t *passwordReturn = nullptr;

  while (!passwordCorrect) {

    // fix the input hiding for windows here
    std::cout << "Enter Password: ";
    std::cin >> password;

    std::cout << "\n";

    std::cout << "Repeat Password: ";
    std::cin >> passwordCheck;

    std::cout << "\n";

    if (password.compare(passwordCheck) == 0) {
      *passwordLength = password.length();
      passwordReturn = new uint8_t[password.length()]();
      const char *passwordChars = password.c_str();

      for (long unsigned int i = 0; i < password.length(); i++) {
        passwordReturn[i] = passwordChars[i];
      }

      passwordCorrect = true;
    } else {
      std::cout << "<<< Passwords do not match! >>>";
    }
  }
  return passwordReturn;
}

uint8_t *gen_salt(uint8_t *salt, uint8_t *password, int passwordLength) {
  uint8_t *newSalt = new uint8_t[16]();

  for (int i = 0; i < 16; i++) {
    // modulo here to ensure we never overrun the password
    newSalt[i] = password[i % passwordLength] ^ salt[i];
  }

  return newSalt;
}

int main() {
  int cost = 4;
  int *passwordLength = new int(0);
  uint8_t defaultSalt[16] = {0x47, 0xD8, 0x7F, 0x70, 0x83, 0xF3, 0xD2, 0x08,
                             0xBE, 0x51, 0x13, 0x4D, 0x5F, 0x79, 0x21, 0xD8};
  uint8_t *salt;
  uint8_t *password = pass_input(passwordLength);

  salt = gen_salt(defaultSalt, password, *passwordLength);

  if (password != nullptr) {
    BCrypt(cost, salt, password, *passwordLength);
  } else {
    std::cerr << "Password read failed" << std::endl;
    exit(EXIT_FAILURE);
  }

  delete passwordLength;
  delete salt;
}
