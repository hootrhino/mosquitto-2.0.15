mosquitto-http-plugin
==========================
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
    "access": "sub",
    "ip": "127.0.0.2"
}
```
## 上线
```json
{
    "action":"client_connected",
    "clientid":"C_1492410235117",
    "username":"C_1492410235117",
    "keepalive": 60,
    "ipaddress": "127.0.0.1",
    "proto_ver": 4,
    "connected_at": 1556176748,
    "conn_ack":0
}
```
## 下线
```json
{
    "action":"client_disconnected",
    "clientid":"C_1492410235117",
    "username":"C_1492410235117",
    "reason":"normal"
}
```
## 转发消息
同时消息会通过HTTP接口转发到目标地址，消息体格式:
```json
{
    "action":"message_publish",
    "from_client_id":"C_1492410235117",
    "from_username":"C_1492410235117",
    "topic":"world",
    "qos":0,
    "retain":true,
    "payload":"Hello world!",
    "ts":1492412774
}
```