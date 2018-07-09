#include "MicroBitConfig.h"
#include "handshake.h"

UbirchHandshake::UbirchHandshake(BLEDevice &_ble, unsigned char *publicKeyBytes, size_t publicKeySize) : ble(_ble) {
    GattCharacteristic handshakeCharacteristic(HandshakeCharacteristicsUUID, (uint8_t *) handshakeBuffer, 0,
                                               sizeof(handshakeBuffer),
                                               GattCharacteristic::BLE_GATT_CHAR_PROPERTIES_READ |
                                               GattCharacteristic::BLE_GATT_CHAR_PROPERTIES_WRITE);
    memset(handshakeBuffer, 0, sizeof(handshakeBuffer));
    handshakeCharacteristic.requireSecurity(SecurityManager::MICROBIT_BLE_SECURITY_LEVEL);
    GattCharacteristic publicKeyCharacteristic(PublicKeyCharacteristicsUUID, (uint8_t *) publicKeyBytes, publicKeySize,
                                               publicKeySize, GattCharacteristic::BLE_GATT_CHAR_PROPERTIES_READ);

    GattCharacteristic *characteristics[] = {&handshakeCharacteristic, &publicKeyCharacteristic};
    GattService service(HandshakeServiceUUID, characteristics, sizeof(characteristics) / sizeof(GattCharacteristic *));
    ble.gattServer().addService(service);

    handshakeCharacteristicsHandle = handshakeCharacteristic.getValueHandle();

    ble.onDataWritten(this, &UbirchHandshake::onDataWritten);
}

void UbirchHandshake::onDataWritten(const GattWriteCallbackParams *params) {
    if (params->handle == handshakeCharacteristicsHandle && params->len > 0 && params->len <= sizeof(handshakeBuffer)) {
        size_t size = params->len;
        memset(handshakeBuffer, 0, sizeof(handshakeBuffer));
        memcpy(handshakeBuffer, params->data, params->len);

        sign(handshakeBuffer, size);
        ble.gattServer().write(handshakeCharacteristicsHandle,
                               (const uint8_t *) &handshakeBuffer, static_cast<uint16_t>(size));
    }
}

const uint8_t HandshakeServiceUUID[] = {
        0x80, 0xe4, 0x19, 0x6e, 0xe6, 0xa2, 0x4c, 0x5e, 0xbd, 0x8d, 0x09, 0x0c, 0x26, 0x60, 0xd8, 0x98,
};

const uint8_t HandshakeCharacteristicsUUID[] = {
        0x80, 0xe4, 0x00, 0x01, 0xe6, 0xa2, 0x4c, 0x5e, 0xbd, 0x8d, 0x09, 0x0c, 0x26, 0x60, 0xd8, 0x98,
};

const uint8_t PublicKeyCharacteristicsUUID[] = {
        0x80, 0xe4, 0xFE, 0x22, 0xe6, 0xa2, 0x4c, 0x5e, 0xbd, 0x8d, 0x09, 0x0c, 0x26, 0x60, 0xd8, 0x98,
};
