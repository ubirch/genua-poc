#! /usr/bin/env python3
import base64
import binascii
import configparser
import hashlib
import logging
import socket
from datetime import datetime
from time import sleep
from uuid import UUID

import msgpack

from ubirch import CSerial, UbirchAPI

logging.basicConfig(format='%(asctime)s %(name)20.20s %(levelname)-8.8s %(message)s', level=logging.DEBUG)

log = logging.getLogger(__name__)
log.info('ubirch Genua PoC (sensor)')

class FactorySensor(CSerial):
    TYPE_REG_PACKET = 0x01

    def __init__(self, port="/dev/ttyACM0", baud=115200, fwbox=("192.168.2.65", 8080),
                 ubirch_groups=list(), ubirch_auth=None, ubirch_env=None) -> None:
        super().__init__(port, baud)
        self.__fwbox = fwbox
        self._ubirch_groups = ubirch_groups
        self._ubirch_auth = ubirch_auth
        self._ubirch_api = UbirchAPI(ubirch_auth, ubirch_env)

    def line(self, data: bytes):
        unpacked = msgpack.unpackb(data)
        if len(unpacked) == 5 and unpacked[2] == self.TYPE_REG_PACKET:
            uuid = str(UUID(bytes=unpacked[1]))
            if not self._ubirch_api.is_identity_registered(uuid):
                log.info("ubirch: identity registration: {}".format(uuid))
                r = self._ubirch_api.register_identity(data)
                if r.status_code >= 200 and r.status_code < 300:
                    log.info("ubirch: identity registered: {}".format(uuid))

            log.info("ubirch: device registration")
            if not self._ubirch_api.device_exists(uuid):
                r = self._ubirch_api.create_device({
                    "deviceId": uuid,
                    "deviceName": uuid,
                    "hwDeviceId": uuid,
                    "hashedHwDeviceId": bytes.decode(
                        base64.b64encode(hashlib.sha512(str.encode(uuid)).digest())),
                    "groups": self._ubirch_groups,
                    "created": "{}Z".format(datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3])
                })
                if r.status_code >= 200 and r.status_code < 300:
                    log.info("ubirch: new device registered")
                else:
                    log.error("ubirch: device registration failed")
            self.handle_data_packet(data, None)

        elif len(unpacked) == 6:
            # anchor message in blockchain
            anchor_id = self._ubirch_api.anchor(data)
            if anchor_id is not None:
                log.info("anchored msg {} in blockchain".format(anchor_id))
            self.handle_data_packet(data, anchor_id)
        else:
            log.warning("unknown packet received")

    def handle_data_packet(self, data: bytes, anchor_id: None):
        # send to firewall box
        try:
            log.info("sending to {}".format(self.__fwbox))
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(self.__fwbox)
            log.info("{}|{}".format(anchor_id, binascii.hexlify(data)))
            s.send(str.encode("{}|{}".format(anchor_id, bytes.decode(binascii.hexlify(data)))))
            s.close()
            log.info("sent")
        except Exception as e:
            log.error("data could not be send to fwbox: {}".format(e))


config = configparser.ConfigParser()
config.read('sensor.ini')

fw_box = config.get("device", "fwbox", fallback="192.168.5.65:8080").split(":")
ubirch_groups = list(filter(None, config.get("ubirch", "groups", fallback="").split(",")))
ubirch_auth = config.get("ubirch", "auth", fallback=None)
ubirch_env = config.get("ubirch", "env", fallback=None)
sensor_port = config.get("sensor", "port", fallback="/dev/ttyACM0")
sensor_baud = int(config.get("sensor", "baud", fallback="115200"))

sensor = FactorySensor(
    port=sensor_port,
    baud=sensor_baud,
    fwbox=(fw_box[0], int(fw_box[1])),
    ubirch_groups=ubirch_groups,
    ubirch_auth=ubirch_auth,
    ubirch_env=ubirch_env
)

while True:
    sleep(1)
