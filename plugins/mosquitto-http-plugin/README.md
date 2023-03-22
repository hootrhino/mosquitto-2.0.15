mosquitto http 插件
==========================
## 编译
```sh
make
```

## 配置
```conf
listener 1883
allow_anonymous true
plugin  ../plugins/mosquitto-http-plugin/mosquitto_http_plugin.so
plugin_opt_mosquitto_http_plugin_url http://127.0.0.1:8899
```

## HTTP 认证
可通过HTTP POST方法认证，当 `HTTP返回码==200` 的时候表示认证成功，当 `HTTP返回码==400` 的时候表示认证失败。下面是认证请求body。
### Auth
```json
{
    "username": "u1",
    "password": "pwd",
    "clientID": "id1",
    "ip": "127.0.0.2",
    "certificate": "123123123456"
}
```
### ACL
```json
{
    "username": "u1",
    "clientID": "id1",
    "topic": "d/0",
    "access": 1,
    "ip": "127.0.0.2"
}
```
Access枚举：
```sh
NONE  ->    0
SUB   ->    1
PUB   ->    2
SUB   ->    4
UNSUB ->    8
```
## 消息转发
当mosquitto收到发布的消息的时候，直接转发到目标HTTP接口
### 上线
```json
{
    "action":"client_connected",
    "clientid":"C",
    "username":"C",
    "keepalive": 60,
    "ipaddress": "127.0.0.1",
    "proto_ver": 4,
    "connected_at": 1556176748,
    "conn_ack":0
}
```
### 下线
```json
{
    "action":"client_disconnected",
    "clientid":"C",
    "username":"C",
    "reason":"normal"
}
```
### 转发消息
同时消息会通过HTTP接口转发到目标地址，消息体格式:
```json
{
    "action":"message_publish",
    "from_client_id":"C",
    "from_username":"C",
    "topic":"world",
    "qos":0,
    "retain":true,
    "payload":"Hello world!",
    "ts":1492412774
}
```