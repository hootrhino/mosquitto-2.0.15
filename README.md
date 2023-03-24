Eclipse Mosquitto
=================
## About
这是mosquitto-2.0.15的fork版本，主要用来适配i4de体系下的本地化Broker网关, 不对Mosquitto做任何修改，仅仅增加一些插件。

## 环境搭建
Mosquitto 依赖了两个外部库：
```sh
sudo apt-get install -y \
    libssl-dev \
    libcjson1 \
    libjson-c-dev \
    libmosquitto-dev
```