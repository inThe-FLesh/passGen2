
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

#include "Blowfish.h"
#include <algorithm>
#include <cassert>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>

class EksBlowfish {
private:
  int cost;
  int passwordLength;
  int passwordLengthStorage;
  uint8_t *salt;
  uint8_t *password;
  uint8_t *saltStorage = new uint8_t[16]();
  uint8_t *passwordStorage;
  uint8_t *zeroSalt = new uint8_t[16]();
  uint32_t *P;
  uint32_t **S = new uint32_t *[4]();

public:
  EksBlowfish(int cost, int passwordLength, uint8_t *salt, uint8_t *password) {
    this->cost = cost;
    this->passwordLength = passwordLength;
    this->salt = salt;
    this->password = password;
    // creating backups of the password and salt values that will be needed
    // later

    passwordStorage = new uint8_t[passwordLength]();

    for (int i = 0; i < 16; i++) {
      saltStorage[i] = salt[i];
    }

    passwordStorage = new uint8_t[passwordLength]();

    for (int i = 0; i < passwordLength; i++) {
      passwordStorage[i] = password[i];
    }

    passwordLengthStorage = passwordLength;

    P = fill_with_pi(18);

    for (int i = 0; i < 4; i++) {
      S[i] = fill_with_pi(256);
    }
  }

  ~EksBlowfish() {
    delete[] saltStorage;
    delete[] passwordStorage;
    delete[] zeroSalt;
  }

  void generate_keys() {
    expand_key();

    salt = zeroSalt;

    // this is the expensive part of the algorithm
    // that improves its resistance to GPU acceleration
    for (int i = 0; i < pow(2, cost); i++) {

      for (int j = 0; j < passwordLength; j++) {
        password[j] = passwordStorage[j];
      }

      passwordLength = passwordLengthStorage;

      expand_key();

      for (int j = 0; j < 16; j++) {
        password[j] = saltStorage[j];
      }

      passwordLength = 16;

      expand_key();
    }
  }

  uint32_t *getP() { return P; }

  uint32_t **getS() { return S; }

private:
  // the P and S boxes are initialised with the fractional part of pi
  static uint32_t *fill_with_pi(int length) {
    uint32_t *piArray = (uint32_t *)malloc(sizeof(uint32_t) * length);
    double pi = M_PI;
    // removing the 3 to get the fractional part of pi

    pi -= 3;
    uint32_t pi32 = static_cast<uint32_t>(pi * pow(2, 32));

    for (int i = 0; i < length; i++) {
      piArray[i] = pi32;
    }

    return piArray;
  }

  // this is used to get 32 bits of password at a time
  // it is treated cylically
  uint32_t cyclePassword(int position) {
    int count = 0;
    uint32_t cycle = 0;

    while (count < 4) {
      cycle += password[position];
      if (count < 3) {
        cycle = cycle << 8;
      }

      count++;
      position++;

      if (position == passwordLength) {
        position = 0;
      }
    }

    return cycle;
  }

  // splits the 128 bit salt into two 64 bit numbers for use in the blowfish
  // algorithm
  uint64_t *generate_salt_halves(uint8_t *salt) {
    uint64_t *saltHalves = (uint64_t *)malloc(sizeof(uint64_t) * 2);

    uint64_t saltLeft = 0;
    uint64_t saltRight = 0;

    for (int i = 0; i < 7; i++) {
      saltLeft += salt[i];
      uint32_t **S = new uint32_t *[4]();
      saltLeft = saltLeft << 8;
    }

    saltLeft += salt[7];

    for (int i = 8; i < 15; i++) {
      saltRight += salt[i];
      saltRight = saltRight << 8;
    }

    saltRight += salt[15];

    saltHalves[0] = saltLeft;
    saltHalves[1] = saltRight;

    return saltHalves;
  }

  // this is the important hashing part that generates the new P and S values
  // from the passwords
  void expand_key() {
    uint8_t *block = new uint8_t[8]();
    Converter converter;

    // xoring the P boxes with 32 bits of the password at a time. Password is
    // cyclic
    for (int n = 0; n < 18; n++) {
      P[n] = P[n] ^ cyclePassword(4 * n % passwordLength);
    }

    // splitting the salt into two 64 bit halves as we need to xor each half
    // with the block in later steps

    uint64_t *saltHalves = generate_salt_halves(salt);

    for (int n = 0; n < 9; n++) {
      // this mess of conversion is necessary to ensure that the blowfish class
      // is compatible with later on in the algorithm. Saves writing 2 blowfish
      // implementations
      uint64_t buffer = converter.bytes_to_64bit(block, 0) ^ saltHalves[n % 2];
      block = converter.bits_to_bytes(buffer, 64);

      Blowfish blowfish(P, S, block, 8);

      uint8_t **blocks = blowfish.Encrypt();
      block = blocks[0];

      uint32_t *blockHalves =
          converter.split_64bit(converter.bytes_to_64bit(block, 8));
      P[2 * n] = blockHalves[0];
      P[(2 * n) + 1] = blockHalves[1];

      free(blockHalves);
    }

    for (int i = 0; i < 4; i++) {
      for (int n = 0; n < 127; n++) {
        uint64_t buffer = converter.bytes_to_64bit(block, 8) ^ salt[n % 2];
        block = converter.bits_to_bytes(buffer, 64);

        uint32_t *blockHalves =
            converter.split_64bit(converter.bytes_to_64bit(block, 8));
        S[i][2 * n] = blockHalves[0];
        S[i][2 * (n + 1)] = blockHalves[1];

        free(blockHalves);
      }
    }

    free(block);
    free(saltHalves);
  }
};
