# Genua geek week PoC

### Sensor Code

The sensor code is found in [calliope-sensor](calliope-sensor) and need to be
compiled and programmed on the [Calliope mini](https://calliope.cc) that is built into
the demonstrator box.

- install [yotta](http://docs.yottabuild.org/)
- run `yt update` to download the dependencies
- run `yt build` to build the binary
- copy the resulting `calliope-sensor-combines.hex` to the `MINI` drive

### RevPi Controller Code

The [RevolutionPi](https://revolution.kunbus.de/) acts as a proxy that collects the sensor
data and forwards it to the firewall box. The code handles time setup and
registration of keys from the microcontroller.

- checkout this repository: `git checkout git@github.com:ubirch/genua-poc.git`
- create a config file `genua-poc/controller/sensor.ini`:

```ini
[device]
fwbox=192.168.2.65:8080
[ubirch]
groups=<get a group id or remove this line>
auth=<get an authentication token>
env=dev
[sensor]
port=/dev/ttyACM0
baud=115200
``` 

- install the services if needed: `install-service-sensor.sh`
 

#### Debugging

- decode hex encoded packages on command line:
```bash
cat - | xxd -r -ps | msgpack2json -d
```