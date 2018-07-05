#ifndef CALLIOPE_SENSOR_HANDSHAKE_H
#define CALLIOPE_SENSOR_HANDSHAKE_H

#include "MicroBitConfig.h"
#include "ble/BLE.h"

// UUIDs for our service and characteristics
extern const uint8_t HandshakeServiceUUID[];
extern const uint8_t HandshakeCharacteristicsUUID[];

class UbirchHandshake {
public:
    explicit UbirchHandshake(BLEDevice &_ble);

    /**
     * Implement to sign the nonce sent to this device
     * for the handshake.
     *
     * @param buffer a 64 byte buffer
     */
    virtual void sign(uint8_t *buffer, size_t &size)= 0;


private:
    void onDataWritten(const GattWriteCallbackParams *params);

    // Bluetooth stack we're running on.
    BLEDevice &ble;
    uint8_t handshakeBuffer[64];
    GattAttribute::Handle_t handshakeCharacteristicsHandle;
};


#endif
