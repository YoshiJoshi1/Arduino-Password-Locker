#include <EEPROM.h>
#include <string.h>

// EEPROM layout
// [0]      : magic marker
// [1..4]   : 4-byte PIN (ASCII digits)
// [5..36]  : 32-byte symmetric key
static const uint8_t EEPROM_MAGIC_ADDR = 0;
static const uint8_t EEPROM_PIN_ADDR = 1;
static const uint8_t EEPROM_KEY_ADDR = 5;
static const uint8_t EEPROM_MAGIC_VALUE = 0xA5;

static const char DEFAULT_PIN[5] = "2356";

// Replace this key with your own random 32-byte value before flashing.
static const uint8_t DEFAULT_KEY[32] = {
  0xC7, 0x24, 0x11, 0x9E, 0x5A, 0xD3, 0x40, 0x7B,
  0xBE, 0x65, 0x2C, 0x18, 0xF1, 0x3D, 0x88, 0x4F,
  0x9B, 0xD6, 0xA0, 0x33, 0x72, 0xEC, 0x57, 0x14,
  0x68, 0xFA, 0x2D, 0x90, 0xCB, 0x45, 0x7E, 0x1A
};

static const unsigned long FAIL_DELAY_MS = 2000;
static const uint8_t MAX_LINE_LEN = 96;
static const unsigned long AUTH_WINDOW_MS = 15000;
static const char DERIVE_CTX[] = "VAULT_DERIVE_V1";

String lineBuffer = "";
bool authGranted = false;
unsigned long authGrantedAt = 0;

typedef struct {
  uint8_t data[64];
  uint32_t datalen;
  uint64_t bitlen;
  uint32_t state[8];
} SHA256_CTX;

static const uint32_t kSha256K[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

uint32_t rotr32(uint32_t x, uint8_t n) {
  return (x >> n) | (x << (32 - n));
}

void sha256Transform(SHA256_CTX* ctx, const uint8_t data[]) {
  uint32_t m[64];
  uint32_t a, b, c, d, e, f, g, h;
  uint32_t t1, t2;

  for (uint8_t i = 0, j = 0; i < 16; i++, j += 4) {
    m[i] = (static_cast<uint32_t>(data[j]) << 24) |
           (static_cast<uint32_t>(data[j + 1]) << 16) |
           (static_cast<uint32_t>(data[j + 2]) << 8) |
           static_cast<uint32_t>(data[j + 3]);
  }
  for (uint8_t i = 16; i < 64; i++) {
    uint32_t s0 = rotr32(m[i - 15], 7) ^ rotr32(m[i - 15], 18) ^ (m[i - 15] >> 3);
    uint32_t s1 = rotr32(m[i - 2], 17) ^ rotr32(m[i - 2], 19) ^ (m[i - 2] >> 10);
    m[i] = m[i - 16] + s0 + m[i - 7] + s1;
  }

  a = ctx->state[0];
  b = ctx->state[1];
  c = ctx->state[2];
  d = ctx->state[3];
  e = ctx->state[4];
  f = ctx->state[5];
  g = ctx->state[6];
  h = ctx->state[7];

  for (uint8_t i = 0; i < 64; i++) {
    uint32_t s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
    uint32_t ch = (e & f) ^ ((~e) & g);
    t1 = h + s1 + ch + kSha256K[i] + m[i];
    uint32_t s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
    uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    t2 = s0 + maj;

    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }

  ctx->state[0] += a;
  ctx->state[1] += b;
  ctx->state[2] += c;
  ctx->state[3] += d;
  ctx->state[4] += e;
  ctx->state[5] += f;
  ctx->state[6] += g;
  ctx->state[7] += h;
}

void sha256Init(SHA256_CTX* ctx) {
  ctx->datalen = 0;
  ctx->bitlen = 0;
  ctx->state[0] = 0x6a09e667;
  ctx->state[1] = 0xbb67ae85;
  ctx->state[2] = 0x3c6ef372;
  ctx->state[3] = 0xa54ff53a;
  ctx->state[4] = 0x510e527f;
  ctx->state[5] = 0x9b05688c;
  ctx->state[6] = 0x1f83d9ab;
  ctx->state[7] = 0x5be0cd19;
}

void sha256Update(SHA256_CTX* ctx, const uint8_t* data, size_t len) {
  for (size_t i = 0; i < len; i++) {
    ctx->data[ctx->datalen] = data[i];
    ctx->datalen++;
    if (ctx->datalen == 64) {
      sha256Transform(ctx, ctx->data);
      ctx->bitlen += 512;
      ctx->datalen = 0;
    }
  }
}

void sha256Final(SHA256_CTX* ctx, uint8_t hash[32]) {
  uint32_t i = ctx->datalen;

  if (ctx->datalen < 56) {
    ctx->data[i++] = 0x80;
    while (i < 56) {
      ctx->data[i++] = 0x00;
    }
  } else {
    ctx->data[i++] = 0x80;
    while (i < 64) {
      ctx->data[i++] = 0x00;
    }
    sha256Transform(ctx, ctx->data);
    memset(ctx->data, 0, 56);
  }

  ctx->bitlen += static_cast<uint64_t>(ctx->datalen) * 8;
  ctx->data[63] = static_cast<uint8_t>(ctx->bitlen);
  ctx->data[62] = static_cast<uint8_t>(ctx->bitlen >> 8);
  ctx->data[61] = static_cast<uint8_t>(ctx->bitlen >> 16);
  ctx->data[60] = static_cast<uint8_t>(ctx->bitlen >> 24);
  ctx->data[59] = static_cast<uint8_t>(ctx->bitlen >> 32);
  ctx->data[58] = static_cast<uint8_t>(ctx->bitlen >> 40);
  ctx->data[57] = static_cast<uint8_t>(ctx->bitlen >> 48);
  ctx->data[56] = static_cast<uint8_t>(ctx->bitlen >> 56);
  sha256Transform(ctx, ctx->data);

  for (i = 0; i < 4; i++) {
    hash[i] = static_cast<uint8_t>((ctx->state[0] >> (24 - i * 8)) & 0x000000ff);
    hash[i + 4] = static_cast<uint8_t>((ctx->state[1] >> (24 - i * 8)) & 0x000000ff);
    hash[i + 8] = static_cast<uint8_t>((ctx->state[2] >> (24 - i * 8)) & 0x000000ff);
    hash[i + 12] = static_cast<uint8_t>((ctx->state[3] >> (24 - i * 8)) & 0x000000ff);
    hash[i + 16] = static_cast<uint8_t>((ctx->state[4] >> (24 - i * 8)) & 0x000000ff);
    hash[i + 20] = static_cast<uint8_t>((ctx->state[5] >> (24 - i * 8)) & 0x000000ff);
    hash[i + 24] = static_cast<uint8_t>((ctx->state[6] >> (24 - i * 8)) & 0x000000ff);
    hash[i + 28] = static_cast<uint8_t>((ctx->state[7] >> (24 - i * 8)) & 0x000000ff);
  }
}

void readMasterKey(uint8_t outKey[32]) {
  for (uint8_t i = 0; i < 32; i++) {
    outKey[i] = EEPROM.read(EEPROM_KEY_ADDR + i);
  }
}

void hmacSha256(const uint8_t key[32], const uint8_t* msg, size_t msgLen, uint8_t out[32]) {
  uint8_t k0[64];
  uint8_t ipad[64];
  uint8_t opad[64];
  uint8_t innerHash[32];
  SHA256_CTX ctx;

  memset(k0, 0, sizeof(k0));
  for (uint8_t i = 0; i < 32; i++) {
    k0[i] = key[i];
  }
  for (uint8_t i = 0; i < 64; i++) {
    ipad[i] = static_cast<uint8_t>(k0[i] ^ 0x36);
    opad[i] = static_cast<uint8_t>(k0[i] ^ 0x5c);
  }

  sha256Init(&ctx);
  sha256Update(&ctx, ipad, sizeof(ipad));
  sha256Update(&ctx, msg, msgLen);
  sha256Final(&ctx, innerHash);

  sha256Init(&ctx);
  sha256Update(&ctx, opad, sizeof(opad));
  sha256Update(&ctx, innerHash, sizeof(innerHash));
  sha256Final(&ctx, out);

  memset(k0, 0, sizeof(k0));
  memset(ipad, 0, sizeof(ipad));
  memset(opad, 0, sizeof(opad));
  memset(innerHash, 0, sizeof(innerHash));
}

char nibbleToHex(uint8_t v) {
  if (v < 10) {
    return static_cast<char>('0' + v);
  }
  return static_cast<char>('A' + (v - 10));
}

void bytesToHex(const uint8_t* in, size_t len, char* outHex) {
  for (size_t i = 0; i < len; i++) {
    outHex[i * 2] = nibbleToHex((in[i] >> 4) & 0x0F);
    outHex[i * 2 + 1] = nibbleToHex(in[i] & 0x0F);
  }
  outHex[len * 2] = '\0';
}

int8_t hexToNibble(char c) {
  if (c >= '0' && c <= '9') {
    return static_cast<int8_t>(c - '0');
  }
  if (c >= 'A' && c <= 'F') {
    return static_cast<int8_t>(10 + (c - 'A'));
  }
  if (c >= 'a' && c <= 'f') {
    return static_cast<int8_t>(10 + (c - 'a'));
  }
  return -1;
}

bool hexToBytes(const String& hex, uint8_t* out, uint8_t expectedLen) {
  if (hex.length() != expectedLen * 2) {
    return false;
  }
  for (uint8_t i = 0; i < expectedLen; i++) {
    int8_t hi = hexToNibble(hex[i * 2]);
    int8_t lo = hexToNibble(hex[i * 2 + 1]);
    if (hi < 0 || lo < 0) {
      return false;
    }
    out[i] = static_cast<uint8_t>((hi << 4) | lo);
  }
  return true;
}

bool isValidPinFormat(const String& pin) {
  if (pin.length() != 4) {
    return false;
  }
  for (uint8_t i = 0; i < 4; i++) {
    if (pin[i] < '0' || pin[i] > '9') {
      return false;
    }
  }
  return true;
}

void writePinToEeprom(const String& newPin) {
  for (uint8_t i = 0; i < 4; i++) {
    EEPROM.update(EEPROM_PIN_ADDR + i, static_cast<uint8_t>(newPin[i]));
  }
}

void initializeIfNeeded() {
  if (EEPROM.read(EEPROM_MAGIC_ADDR) == EEPROM_MAGIC_VALUE) {
    return;
  }

  for (uint8_t i = 0; i < 4; i++) {
    EEPROM.update(EEPROM_PIN_ADDR + i, static_cast<uint8_t>(DEFAULT_PIN[i]));
  }

  for (uint8_t i = 0; i < 32; i++) {
    EEPROM.update(EEPROM_KEY_ADDR + i, DEFAULT_KEY[i]);
  }

  EEPROM.update(EEPROM_MAGIC_ADDR, EEPROM_MAGIC_VALUE);
}

bool pinMatches(const char* candidatePin) {
  for (uint8_t i = 0; i < 4; i++) {
    if (static_cast<uint8_t>(candidatePin[i]) != EEPROM.read(EEPROM_PIN_ADDR + i)) {
      return false;
    }
  }
  return true;
}

void expireAuthIfNeeded() {
  if (authGranted && (millis() - authGrantedAt > AUTH_WINDOW_MS)) {
    authGranted = false;
  }
}

void handleAuthCommand(const String& pin) {
  if (!isValidPinFormat(pin)) {
    Serial.println("INVALID PIN FORMAT");
    return;
  }

  char pinChars[5];
  pin.toCharArray(pinChars, sizeof(pinChars));
  if (pinMatches(pinChars)) {
    authGranted = true;
    authGrantedAt = millis();
    Serial.println("GRANTED");
  } else {
    authGranted = false;
    Serial.println("ACCESS DENIED");
    delay(FAIL_DELAY_MS);
  }
}

void handleChangePinCommand(const String& payload) {
  int separator = payload.indexOf(' ');
  if (separator <= 0 || separator >= payload.length() - 1) {
    Serial.println("INVALID COMMAND");
    return;
  }

  String oldPin = payload.substring(0, separator);
  String newPin = payload.substring(separator + 1);
  oldPin.trim();
  newPin.trim();

  if (!isValidPinFormat(oldPin) || !isValidPinFormat(newPin)) {
    Serial.println("INVALID PIN FORMAT");
    return;
  }

  char oldPinChars[5];
  oldPin.toCharArray(oldPinChars, sizeof(oldPinChars));
  if (!pinMatches(oldPinChars)) {
    authGranted = false;
    Serial.println("ACCESS DENIED");
    delay(FAIL_DELAY_MS);
    return;
  }

  writePinToEeprom(newPin);
  authGranted = false;
  Serial.println("PIN UPDATED");
}

void handleDeriveCommand(const String& saltHex) {
  expireAuthIfNeeded();
  if (!authGranted) {
    Serial.println("AUTH REQUIRED");
    return;
  }

  uint8_t salt[16];
  if (!hexToBytes(saltHex, salt, sizeof(salt))) {
    Serial.println("INVALID SALT");
    return;
  }

  uint8_t masterKey[32];
  uint8_t digest[32];
  uint8_t message[16 + sizeof(DERIVE_CTX) - 1];
  char digestHex[65];

  readMasterKey(masterKey);
  memcpy(message, salt, sizeof(salt));
  memcpy(message + sizeof(salt), DERIVE_CTX, sizeof(DERIVE_CTX) - 1);
  hmacSha256(masterKey, message, sizeof(message), digest);

  bytesToHex(digest, sizeof(digest), digestHex);
  Serial.print("DERIVED ");
  Serial.println(digestHex);

  // One-time authorization window; require PIN again after derivation.
  authGranted = false;

  memset(masterKey, 0, sizeof(masterKey));
  memset(digest, 0, sizeof(digest));
  memset(message, 0, sizeof(message));
  memset(salt, 0, sizeof(salt));
}

void handleCommand(const String& cmd) {
  if (cmd.startsWith("AUTH ")) {
    String pin = cmd.substring(5);
    pin.trim();
    handleAuthCommand(pin);
    return;
  }

  if (cmd.startsWith("DERIVE ")) {
    String saltHex = cmd.substring(7);
    saltHex.trim();
    handleDeriveCommand(saltHex);
    return;
  }

  if (cmd.startsWith("CHANGEPIN ")) {
    String payload = cmd.substring(10);
    payload.trim();
    handleChangePinCommand(payload);
    return;
  }

  Serial.println("INVALID COMMAND");
}

void setup() {
  Serial.begin(115200);
  while (!Serial) {
    // Keep for boards that need serial host handshake.
  }
  initializeIfNeeded();
  Serial.println("READY");
}

void loop() {
  while (Serial.available() > 0) {
    char incoming = static_cast<char>(Serial.read());

    if (incoming == '\r') {
      continue;
    }

    if (incoming == '\n') {
      if (lineBuffer.length() > 0) {
        handleCommand(lineBuffer);
        lineBuffer = "";
      }
    } else if (lineBuffer.length() < MAX_LINE_LEN) {
      lineBuffer += incoming;
    } else {
      // Drop oversized input to avoid memory growth and malformed commands.
      lineBuffer = "";
      Serial.println("INVALID COMMAND");
    }
  }
}
