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
#include <ubirch/ubirch_ed25519.h>
#include "handshake.h"

MicroBitSerial serial(TGT_TX, TGT_RX);
MicroBitButton buttonA(MICROBIT_PIN_BUTTON_A, MICROBIT_ID_BUTTON_A);
MicroBitDisplay display;
MicroBitMessageBus messageBus;
MicroBitStorage storage;
MicroBitThermometer thermometer(storage);
MicroBitBLEManager bleManager(storage);
MicroBitPin P2(MICROBIT_ID_IO_P0, MICROBIT_PIN_P2, PIN_CAPABILITY_ALL);

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
    for (unsigned int i = 0; i < size; i++) serial.printf("%02x", b[i]);
    serial.printf("\r\n");
}

/**                                  x
 * Save the last generated signature to Calliope mini flash.
 */
void saveSignature() {
    PacketBuffer signature = ubirch.getLastSignature();
    storage.put("s1", signature.getBytes(), 32);
    storage.put("s2", signature.getBytes() + 32, 32);
}

/**
 * Load the latest signature from flash (after reset).
 */
void loadSignature() {
    KeyValuePair *s1 = storage.get("s1");
    KeyValuePair *s2 = storage.get("s2");
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
    KeyValuePair *kv_pk = storage.get("pk");
    KeyValuePair *kv_sk = storage.get("sk");
    if (kv_sk != NULL && kv_pk != NULL) {
        memcpy(ed25519_public_key, kv_pk->value, crypto_sign_PUBLICKEYBYTES);
        memcpy(ed25519_secret_key, kv_sk->value, crypto_sign_SECRETKEYBYTES);
        delete kv_pk;
        delete kv_sk;
    } else {
        crypto_sign_keypair(ed25519_public_key, ed25519_secret_key);
        storage.put("pk", ed25519_public_key, crypto_sign_PUBLICKEYBYTES);
        storage.put("sk", ed25519_secret_key, crypto_sign_SECRETKEYBYTES);
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
    return static_cast<int>(end - start);
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
    rangeInCentimeters = static_cast<int>(duration * 153 / 29.0 / 2.0 / 100);

    if (rangeInCentimeters > 0) distanceBackup = rangeInCentimeters;
    else rangeInCentimeters = distanceBackup;

    wait_ms(50);

    return rangeInCentimeters;
}

static int lastDetected = -99;
static int base = 0;
static bool buttonAPressed = false;

/**
 * Measure and detect the object size. Tries multiple times to avoid in-the-middle measurements.
 * @param pin the pin to control the sensor
 * @return the height in cm
 */
int detectAndMeasure(MicroBitPin *pin) {
    int detected = 0;
    display.clear();
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
            fiber_sleep(100);

            display.image.setPixelValue(4, 4, static_cast<uint8_t>(display.image.getPixelValue(4, 4) ^ 0xFF));
            if (buttonAPressed) return microbit_random(3) + 1;
        }
        detected = measured;
    } while (lastDetected == detected);
    lastDetected = detected;
    return detected;
}

/**
 * Get an initial calibration measurement of the full available height.
 * @param pin the sensor pin
 */
void calibrate(MicroBitPin *pin) {
    int calib = detectAndMeasure(pin) * -1;
    serial.printf("calibrate: %d\r\n", calib);
    base = calib;
    lastDetected = -1;
}

class CalliopeSensorHandshake : UbirchHandshake {
public:
    explicit CalliopeSensorHandshake(BLEDevice &_ble, unsigned char *publicKeyBytes, size_t publicKeySize)
            : UbirchHandshake(_ble, publicKeyBytes, publicKeySize) {
        serial.printf("enable BLE handshake");
    }

    void sign(uint8_t *buffer, size_t &size) override {
        unsigned char signature[crypto_sign_BYTES];
        serial.printf("signing %d bytes", size);
        ed25519_sign(buffer, size, signature);
        memcpy(buffer, signature, crypto_sign_BYTES);
        size = crypto_sign_BYTES;
        serial.printf("done\r\n");
    }
};

void onButtonA(MicroBitEvent) {
    buttonAPressed = true;
}

int main() {
    time_t ts;

    serial.printf("ubirch protocol example v1.1\r\n");

    // we need to calibrate the distance sensor
    display.scroll("calibrate");

    calibrate(&P2);
    display.print(base);

    // we need to set the current time, simply enter what `date +%s` gives you
//    serial.printf("TIME:\r\n");
//    ManagedString input = serial.readUntil(ManagedString("\r\n"), SYNC_SPINWAIT);
//    set_system_time(atoi(input.toCharArray()));

    ts = get_system_time();
    serial.printf(ctime(&ts));
    serial.printf("\r\n");

    // try to load the key from flash storage, or create a new one and save it
    // ATTENTION: flashing new firmware will delete all keys
    loadOrGenerateKey();

    bleManager.init(microbit_friendly_name(), "", messageBus, true);
    new CalliopeSensorHandshake(*bleManager.ble, ed25519_public_key, crypto_sign_PUBLICKEYBYTES);
    bleManager.advertise();
    serial.printf("BLE handshake started\r\n");

    ubirch.reset(microbit_serial_number());
    // load the last generated signature
    loadSignature();

    const int temperature = thermometer.getTemperature();
    const int lightlevel = display.readLightLevel();

    scheduler_init(messageBus);
    messageBus.listen(MICROBIT_ID_BUTTON_A, MICROBIT_BUTTON_EVT_CLICK, onButtonA);

    // create consecutive messages and chain them, pressing reset will continue the chain
    while (true) {
        ts = get_system_time();
        int size = 0;
        do {
            size = detectAndMeasure(&P2);
        } while (size < 1);
        buttonAPressed = false;

        serial.printf("%d\r\n", size);
        display.print(size);
        // structure: {"data": {1234: {"t":1234, "l":1234}}}
        ubirch.startMessage()
                .addMap(1)
                .addMap((int) ts, 3)
                .addInt("s", size)
                .addInt("t", temperature)
                .addInt("l", lightlevel);
        PacketBuffer packet = ubirch.finishMessage();
        hexprint(packet.getBytes(), static_cast<size_t>(packet.length()));
        saveSignature();
    }
}
