mosquitto http 插件
==========================
## 编译
依赖: cjson,  mosquitto, curl
```sh
make
```

## 配置
```conf
listener 1883
allow_anonymous true
plugin  ../plugins/mosquitto-http-plugin/mosquitto_http_plugin.so
plugin_opt_mosquitto_http_plugin_url http://127.0.0.1:8899
plugin_opt_mosquitto_http_plugin_topic $plugin/http/redirect

```

## HTTP 认证
可通过HTTP POST方法认证，当 `HTTP返回码==200` 的时候表示认证成功，当 `HTTP返回码==400` 的时候表示认证失败。下面是认证请求body。
### Auth
```json
{
    "username":"u1",
    "password":"pwd",
    "clientID":"id1",
    "ip":"127.0.0.2",
    "certificate":"123123123456"
}
```
### ACL
```json
{
    "username":"u1",
    "clientID":"id1",
    "topic":"d/0",
    "access":"pub",
    "ip":"127.0.0.2"
}
```

## 消息转发
当mosquitto收到上线的消息的时候，直接转发到目标HTTP接口, 同时会转发到`$SYS/brokers/clients/connected` Topic.
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
当mosquitto收到下线消息的时候，直接转发到目标HTTP接口, 同时会转发到`$SYS/brokers/clients/disconnected` Topic.

```json
{
    "action":"client_disconnected",
    "clientid":"C",
    "username":"C",
    "reason":"normal"
}
```
### 转发消息
当mosquitto 特定 Topic 收到消息的时候，消息会通过HTTP接口转发到目标地址，消息体格式:
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

## 消息桥接
Mosquitto 支持桥接，一次可以实现消息转发到另一个MQTT Server。
```
cleansession true
connection another-broker
remote_clientid test1
remote_username test1
remote_password test1
address 127.0.0.1:1883
topic $message/redirect/another both 1 mosquitto1/redirect
```