import time
from datetime import datetime
from logging import getLogger
from threading import Thread

import serial

log = getLogger(__name__)


class CSerial():
    """Create a serial proxy that reads data from Calliope mini (sensor) to act on."""

    def __init__(self, port="/dev/ttyACM0", baudrate=115200) -> None:
        super().__init__()
        self._message = 0
        self._port = port
        self._baud = baudrate

        self._thread = Thread(target=self.run, daemon=True)
        self._thread.start()

    def line(self, line: bytearray):
        """Implement this function to act on msgpack messages."""
        pass

    def run(self):
        while True:
            log.info("starting serial logger")
            try:
                with serial.Serial(port=self._port, baudrate=self._baud) as ser:
                    while ser.readable():
                        line = bytes.decode(ser.readline()).replace('\r', '').replace('\n', '')
                        if not len(line):
                            continue

                        log.info("RCV: {}".format(line))
                        if line.startswith('TIME:'):
                            ser.write(str.encode(str(int(datetime.now().timestamp()))))
                            ser.write(b'\r\n')
                        elif line.startswith('9'):
                            try:
                                self.line(bytearray.fromhex(line))
                            except Exception as e:
                                log.warning("decoding error: {}".format(e))
                        else:
                            continue

            except Exception as e:
                log.error(e, exc_info=True)
                log.error("trying again to use serial device in 60s")
                time.sleep(60)
