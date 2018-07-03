#include <armnacl.h>
#include <MicroBit.h>
#include <CryptoUbirchProtocol.h>
#include <ubirch/ubirch_protocol_kex.h>

MicroBit uBit;
CryptoUbirchProtocol ubirch;
time_t startTime;

/* ==== ECC KEYS ================= */
unsigned char ed25519_public_key[crypto_sign_PUBLICKEYBYTES];
unsigned char ed25519_secret_key[crypto_sign_SECRETKEYBYTES];

void set_system_time(time_t t) {
    startTime = t - system_timer_current_time() / 1000;
}

time_t get_system_time() {
    return system_timer_current_time() / 1000 + startTime;
}

// a little helper function to print the resulting byte arrays
void hexprint(const uint8_t *b, size_t size) {
    for (unsigned int i = 0; i < size; i++) uBit.serial.printf("%02x", b[i]);
    uBit.serial.printf("\r\n");
}

/**                                  x
 * Save the last generated signature to Calliope mini flash.
 */
void saveSignature() {
    PacketBuffer signature = ubirch.getLastSignature();
    uBit.storage.put("s1", signature.getBytes(), 32);
    uBit.storage.put("s2", signature.getBytes() + 32, 32);
}

/**
 * Load the latest signature from flash (after reset).
 */
void loadSignature() {
    KeyValuePair *s1 = uBit.storage.get("s1");
    KeyValuePair *s2 = uBit.storage.get("s2");
    if (s1 && s2) {
        uint8_t s[64];
        memcpy(s, s1->value, 32);
        memcpy(s + 32, s2->value, 32);
        PacketBuffer signature(s, sizeof(s));
        ubirch.setLastSignature(signature);
    }
    // make sure to free memory
    delete s1;
    delete s2;
}

void loadOrGenerateKey() {
    KeyValuePair *kv_pk = uBit.storage.get("pk");
    KeyValuePair *kv_sk = uBit.storage.get("sk");
    if (kv_sk != NULL && kv_pk != NULL) {
        memcpy(ed25519_public_key, kv_pk->value, crypto_sign_PUBLICKEYBYTES);
        memcpy(ed25519_secret_key, kv_sk->value, crypto_sign_SECRETKEYBYTES);
    } else {
        crypto_sign_keypair(ed25519_public_key, ed25519_secret_key);
        uBit.storage.put("pk", ed25519_public_key, crypto_sign_PUBLICKEYBYTES);
        uBit.storage.put("sk", ed25519_secret_key, crypto_sign_SECRETKEYBYTES);
    }

    time_t t = get_system_time();
    PacketBuffer packet =
            ubirch.createKeyRegistration(ed25519_public_key, static_cast<unsigned int>(t + 1),
                                         static_cast<unsigned int>(t + 31536000));
    hexprint(packet.getBytes(), static_cast<size_t>(packet.length()));
}

int main() {
    time_t ts;

    uBit.init();
    uBit.serial.printf("ubirch protocol example v1.0\r\n");

    // we need to set the current time, simply enter what `date +%s` gives you
    uBit.serial.printf("TIME:\r\n");
    ManagedString input = uBit.serial.readUntil(ManagedString("\r\n"), SYNC_SPINWAIT);
    set_system_time(atoi(input.toCharArray()));
    ts = get_system_time();
    uBit.serial.printf(ctime(&ts));

    // try to load the key from flash storage, or create a new one and save it
    // ATTENTION: flashing new firmware will delete all keys
    loadOrGenerateKey();

    ubirch.reset(microbit_serial_number());
    // load the last generated signature
    loadSignature();

    const int temperature = uBit.thermometer.getTemperature();
    const int lightlevel = uBit.display.readLightLevel();

    // create 3 consecutive messages and chain them, pressing reset will continue the chain
    while(true) {
        ts = get_system_time();
        // structure: {"data": {1234: {"t":1234, "l":1234}}}
        ubirch.startMessage()
                .addMap(1)
                .addMap((int) ts, 2)
                .addInt("t", temperature)
                .addInt("l", lightlevel);
        PacketBuffer packet = ubirch.finishMessage();
        hexprint(packet.getBytes(), static_cast<size_t>(packet.length()));
        saveSignature();
    }
}
