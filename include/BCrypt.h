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
