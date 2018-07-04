#! /bin/sh
sudo cp poc-sensor.service /lib/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable poc-sensor.service