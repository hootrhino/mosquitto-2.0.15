#include <stdio.h>
#include <string.h>

#include "mosquitto_broker.h"
#include "mosquitto_plugin.h"
#include "mosquitto.h"
#include "mqtt_protocol.h"
#include <cjson/cJSON.h>

#define UNUSED(A) (void)(A)

typedef struct
{
  mosquitto_plugin_id_t *plugin_identifier; // 插件ID
  char product_id[64];                      // 网关所属的产品
  char device_name[64];                     // 网关名称
} mosquitto_plugin_config;
static mosquitto_plugin_config main_config;
// -------------------------------------------------------------------------------------------------
// 设备上线: $gateway/operation/${product-id}/${device-name}
// -------------------------------------------------------------------------------------------------
// {
//   "type": "online",
//   "payload": {
//     "devices": [
//       {
//         "key": "一个在服务器端可以解析出来的KEY"
//       }
//     ]
//   }
// }

static proxy_connected()
{
  cJSON *connectJson = cJSON_CreateObject();
  cJSON_AddStringToObject(connectJson, "type", "online");
  cJSON *payloadJson = cJSON_CreateObject();
  cJSON *devices = cJSON_CreateArray();
}
// -------------------------------------------------------------------------------------------------
// 代理下线: $gateway/operation/${product-id}/${device-name}
// -------------------------------------------------------------------------------------------------
// {
//   "type": "offline",
//   "payload": {
//     "devices": [
//       {
//         "product_id": "CFC******AG7",
//         "device_name": sub-device
//       }
//     ]
//   }
// }

static proxy_disconnected()
{
}
/// @brief 消息回调
/// @param event
/// @param event_data
/// @param userdata
/// @return
static int on_message(int event, void *event_data, void *userdata)
{
  struct mosquitto_evt_message *message = event_data;
  return MOSQ_ERR_SUCCESS;
}

int mosquitto_plugin_version(int supported_version_count, const int *supported_versions)
{
  UNUSED(supported_version_count);
  UNUSED(supported_versions);
  return 5;
}

int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier, void **user_data, struct mosquitto_opt *opts, int opt_count)
{
  UNUSED(user_data);
  UNUSED(opts);
  UNUSED(opt_count);

  main_config.plugin_identifier = identifier;
  return mosquitto_callback_register(main_config.plugin_identifier, MOSQ_EVT_MESSAGE, on_message, NULL, NULL);
}

int mosquitto_plugin_cleanup(void *user_data, struct mosquitto_opt *opts, int opt_count)
{
  UNUSED(user_data);
  UNUSED(opts);
  UNUSED(opt_count);

  return mosquitto_callback_unregister(main_config.plugin_identifier, MOSQ_EVT_MESSAGE, on_message, NULL);
}
