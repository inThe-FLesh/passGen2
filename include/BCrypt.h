
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

#include "EksBlowfish.h"
#include "base64.h"
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <string>
#include <sys/time.h>
#include <sys/types.h>
#include <termios.h>

using std::cout;
using std::endl;

int BCrypt(int cost, const uint8_t *salt, uint8_t *password,
           int passwordLength);
