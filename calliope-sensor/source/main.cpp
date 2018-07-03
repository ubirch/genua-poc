/**
 * Calliope Sensor Module
 * (c) 2018 ubirch GmbH
 * Author: Matthias L. Jugel (@thinkberg)
 *
 * Distance measurement taken from Seeed Grove Module (MIT License)
 * pulseIn() function adapted from Microsoft PXT (MIT License)
 */

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

/**
 * Load the key pair from flash or generate a new one and store it away.
 */
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

/**
 * Helper function that measures the length of a pulse on a pin.
 * @param pin the pin
 * @param value the value HIGH or LOW to measure
 * @param maxDuration the max duration of the pulse
 * @return the pulse time
 */
int pulseIn(MicroBitPin *pin, bool value, int maxDuration = 2000000) {
    if (!pin) return 0;

    int pulse = value ? 1 : 0;
    uint64_t tick = system_timer_current_time_us();
    uint64_t maxd = (uint64_t) maxDuration;
    while (pin->getDigitalValue() != pulse) {
        if (system_timer_current_time_us() - tick > maxd)
            return 0;
    }

    uint64_t start = system_timer_current_time_us();
    while (pin->getDigitalValue() == pulse) {
        if (system_timer_current_time_us() - tick > maxd)
            return 0;
    }
    uint64_t end = system_timer_current_time_us();
    return end - start;
}

static int distanceBackup;

/**
 * Measure the distance of an object.
 * @param pin use the pin to control the sensor
 * @return the distance in cm
 */
int measureInCentimeters(MicroBitPin *pin) {
    int duration = 0;
    int rangeInCentimeters = 0;

    pin->setDigitalValue(0);
    wait_us(2);
    pin->setDigitalValue(1);
    wait_us(20);
    pin->setDigitalValue(0);
    duration = pulseIn(pin, true, 50000); // Max duration 50 ms
    rangeInCentimeters = duration * 153 / 29.0 / 2.0 / 100;

    if (rangeInCentimeters > 0) distanceBackup = rangeInCentimeters;
    else rangeInCentimeters = distanceBackup;

    wait_ms(50);

    return rangeInCentimeters;
}

static int lastDetected = -99;
static int base = 0;

/**
 * Measure and detect the object size. Tries multiple times to avoid in-the-middle measurements.
 * @param pin the pin to control the sensor
 * @return the height in cm
 */
int detectAndMeasure(MicroBitPin *pin) {
    int detected = 0;
    uBit.display.clear();
    do {
        int range = -1;
        int measured = 0;
        int cnt = 0;
        while (cnt < 5) {
            int tmp = range;
            range = base - measureInCentimeters(pin);
            if (range == tmp) {
                measured = range;
                cnt++;
            } else {
                cnt = 0;
            }
            uBit.sleep(100);

            uBit.display.image.setPixelValue(4, 4, uBit.display.image.getPixelValue(4, 4) ^ 0xFF);
        }
        detected = measured;
    } while ((base != 0 && detected < 1) || lastDetected == detected);
    lastDetected = detected;
    return detected;
}

/**
 * Get an initial calibration measurement of the full available height.
 * @param pin the sensor pin
 */
void calibrate(MicroBitPin *pin) {
    int calib = detectAndMeasure(pin) * -1 - 1;
    uBit.serial.printf("calibrate: %d\r\n", calib);
    base = calib;
    lastDetected = -1;
}

int main() {
    time_t ts;

    uBit.init();
    uBit.serial.printf("ubirch protocol example v1.0\r\n");

    // we need to calibrate the distance sensor
    uBit.display.scroll("calibrate");
    calibrate(&uBit.io.P2);
    uBit.display.print(base);

    // we need to set the current time, simply enter what `date +%s` gives you
    uBit.serial.printf("TIME:\r\n");
    ManagedString input = uBit.serial.readUntil(ManagedString("\r\n"), SYNC_SPINWAIT);
    set_system_time(atoi(input.toCharArray()));
    ts = get_system_time();
    uBit.serial.printf(ctime(&ts));
    uBit.serial.printf("\r\n");

    // try to load the key from flash storage, or create a new one and save it
    // ATTENTION: flashing new firmware will delete all keys
    loadOrGenerateKey();

    ubirch.reset(microbit_serial_number());
    // load the last generated signature
    loadSignature();

    const int temperature = uBit.thermometer.getTemperature();
    const int lightlevel = uBit.display.readLightLevel();

    // create consecutive messages and chain them, pressing reset will continue the chain
    while (true) {
        ts = get_system_time();
        int size = 0;
        do {
            size = detectAndMeasure(&uBit.io.P2);
        } while (size < 1);

        uBit.serial.printf("%d\r\n", size);
        uBit.display.print(size);
        // structure: {"data": {1234: {"t":1234, "l":1234}}}
        ubirch.startMessage()
                .addMap(1)
                .addMap((int) ts, 3)
                .addMap("s", size)
                .addInt("t", temperature)
                .addInt("l", lightlevel);
        PacketBuffer packet = ubirch.finishMessage();
        hexprint(packet.getBytes(), static_cast<size_t>(packet.length()));
        saveSignature();
    }
}
