#include <stdio.h>
#include <string.h>

#include "mosquitto_broker.h"
#include "mosquitto_plugin.h"
#include "mosquitto.h"
#include "mqtt_protocol.h"
#include <cjson/cJSON.h>

#define UNUSED(A) (void)(A)
#define DEBUG
//
#define MOSQ_ACL_NONE 0x00
#define MOSQ_ACL_READ 0x01
#define MOSQ_ACL_WRITE 0x02
#define MOSQ_ACL_SUBSCRIBE 0x04
#define MOSQ_ACL_UNSUBSCRIBE 0x08

typedef struct
{
  mosquitto_plugin_id_t *plugin_identifier; // 插件ID
} mosquitto_plugin_config;
static mosquitto_plugin_config main_config;
char *sum_key(char *clientid, char *username)
{
  UNUSED(clientid);
  UNUSED(username);
  // 这里暂时留空, 具体网关具体实现加密逻辑
  return "5D41402ABC4B2A76B9719D911017C592";
}
/// @brief 拼接JSON
/// @param msgtype
/// @param clientid
/// @param username
/// @param password
/// @return
cJSON *msg_to_json(char *msgtype, const char *ip,
                   const char *clientid, const char *username)
{
  cJSON *data = cJSON_CreateObject();
  cJSON_AddStringToObject(data, "type", (msgtype));
  cJSON *payloadJson = cJSON_CreateObject();
  cJSON_AddItemToObject(data, "payload", payloadJson);
  cJSON *devices = cJSON_CreateArray();
  cJSON *device = cJSON_CreateObject();
  char *key = sum_key((char *)clientid, (char *)username);
  cJSON_AddStringToObject(device, "key", key);
  cJSON_AddStringToObject(device, "ip", ip);
  cJSON_AddItemToArray(devices, device);
  cJSON_AddItemToObject(payloadJson, "devices", devices);
  return data;
}
// -------------------------------------------------------------------------------------------------
// 设备下线: $gateway/operation
// -------------------------------------------------------------------------------------------------
static int on_disconnect_callback(int event, void *event_data, void *userdata)
{
  UNUSED(event);
  UNUSED(userdata);
  struct mosquitto_evt_disconnect *disconnect_message = event_data;
  const char *ip_address = mosquitto_client_address(disconnect_message->client);
  const char *clientid = mosquitto_client_id(disconnect_message->client);
  const char *username = mosquitto_client_username(disconnect_message->client);
  cJSON *msg_body = msg_to_json("offline", ip_address, clientid, username);
  char *jsonString = cJSON_Print(msg_body);
  cJSON_Minify(jsonString);
#ifdef DEBUG
  mosquitto_log_printf(MOSQ_LOG_INFO, "[on_disconnect_callback] :%s\n", jsonString);
#endif
  if (strcmp(ip_address, "127.0.0.1") == 0)
  {
    return MOSQ_ERR_SUCCESS;
  }

  mosquitto_broker_publish(NULL, "$gateway/redirect/another/up",
                           (int)strlen(jsonString), jsonString, 1, 0, NULL);
  cJSON_Delete(msg_body);
  return MOSQ_ERR_SUCCESS;
}
// -------------------------------------------------------------------------------------------------
// 代理上线: $gateway/operation
// -------------------------------------------------------------------------------------------------
static int on_acl_check_callback(int event, void *event_data, void *userdata)
{
  UNUSED(event);
  UNUSED(userdata);
  struct mosquitto_evt_acl_check *acl_check_message = event_data;
  const char *ip_address = mosquitto_client_address(acl_check_message->client);
  const char *clientid = mosquitto_client_id(acl_check_message->client);
  const char *username = mosquitto_client_username(acl_check_message->client);
  cJSON *msg_body = msg_to_json("online", ip_address, clientid, username);
  char *jsonString = cJSON_Print(msg_body);
  cJSON_Minify(jsonString);
#ifdef DEBUG
  mosquitto_log_printf(MOSQ_LOG_INFO, "[on_acl_check_callback] :%s\n", jsonString);
#endif
  if (acl_check_message->access == MOSQ_ACL_SUBSCRIBE)
  {
    char topic_buf[29] = {0};
    strncpy(topic_buf, acl_check_message->topic, 28);
    // 特殊Topic不能订阅
    if (strcmp(topic_buf, "$gateway/redirect/another/up") == 0)
    {
      mosquitto_log_printf(MOSQ_LOG_ERR, "[on_acl_check_callback] topic no permission: %s\n",
                           acl_check_message->topic);
      return MOSQ_ERR_ACL_DENIED;
    }
  }
  // 本地连接不转发
  if (strcmp(ip_address, "127.0.0.1") == 0)
  {
    return MOSQ_ERR_SUCCESS;
  }

  mosquitto_broker_publish(NULL, "$gateway/redirect/another/up",
                           (int)strlen(jsonString), jsonString, 1, 0, NULL);
  cJSON_Delete(msg_body);
  return MOSQ_ERR_SUCCESS;
}
/// @brief 消息回调
/// @param event
/// @param event_data
/// @param userdata
/// @return
static int on_message(int event, void *event_data, void *userdata)
{
  // struct mosquitto_evt_message *message = event_data;
  UNUSED(event);
  UNUSED(event_data);
  UNUSED(userdata);
  return MOSQ_ERR_SUCCESS;
}

int mosquitto_plugin_version(int supported_version_count, const int *supported_versions)
{
  UNUSED(supported_version_count);
  UNUSED(supported_versions);
  return 5;
}
void print_banner()
{
  printf("------------------------------------------------\n");
  printf("| Welcome To Mosquitto Edge Gateway World<'v'> |\n");
  printf("------------------------------------------------\n");
}
int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier, void **user_data, struct mosquitto_opt *opts, int opt_count)
{
  print_banner();
  UNUSED(user_data);
  UNUSED(opts);
  UNUSED(opt_count);
  main_config.plugin_identifier = identifier;
  mosquitto_callback_register(main_config.plugin_identifier, MOSQ_EVT_ACL_CHECK,
                              on_acl_check_callback, NULL, NULL);
  mosquitto_callback_register(main_config.plugin_identifier, MOSQ_EVT_DISCONNECT,
                              on_disconnect_callback, NULL, NULL);
  mosquitto_callback_register(main_config.plugin_identifier, MOSQ_EVT_MESSAGE,
                              on_message, NULL, NULL);
  return MOSQ_ERR_SUCCESS;
}

int mosquitto_plugin_cleanup(void *user_data, struct mosquitto_opt *opts, int opt_count)
{
  UNUSED(user_data);
  UNUSED(opts);
  UNUSED(opt_count);

  mosquitto_callback_unregister(main_config.plugin_identifier,
                                MOSQ_EVT_MESSAGE, on_message, NULL);
  mosquitto_callback_unregister(main_config.plugin_identifier,
                                MOSQ_EVT_DISCONNECT, on_disconnect_callback, NULL);
  mosquitto_callback_unregister(main_config.plugin_identifier,
                                MOSQ_EVT_ACL_CHECK, on_acl_check_callback, NULL);
  return MOSQ_ERR_SUCCESS;
}
