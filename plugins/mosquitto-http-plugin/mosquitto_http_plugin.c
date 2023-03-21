#include <stdio.h>
#include <string.h>

#include <mosquitto_broker.h>
#include <mosquitto_plugin.h>
#include <cjson/cJSON.h>
#include <mosquitto.h>
#include <sys/time.h>
#include <string.h>
#include <curl/curl.h>
#include <stdio.h>

#define UNUSED(A) (void)(A)

#define MOSQ_ACL_NONE 0x00
#define MOSQ_ACL_READ 0x01
#define MOSQ_ACL_WRITE 0x02
#define MOSQ_ACL_SUBSCRIBE 0x04
#define MOSQ_ACL_UNSUBSCRIBE 0x08

/// @brief
static mosquitto_plugin_id_t *plugin_identifier = NULL;
static CURL *curl_client = NULL;
static struct curl_slist *curl_http_headers = NULL;
static const char *target_url = "http://127.0.0.1:8899";
//--------------------------------------------------------------------------------------------------
// User Functions
//--------------------------------------------------------------------------------------------------

/// @brief
/// @param jsonString
/// @param url
/// @return
int http_post(char *jsonString, const char *url)
{
  if (curl_client)
  {
    curl_easy_setopt(curl_client, CURLOPT_URL, url);
    curl_easy_setopt(curl_client, CURLOPT_HTTPHEADER, curl_http_headers);
    curl_easy_setopt(curl_client, CURLOPT_POSTFIELDS, jsonString);
    printf("no error\n");
    CURLcode res = curl_easy_perform(curl_client);

    printf("error:%d\n", res);
    return res;
  }
  printf("error\n");
  return 400;
}
/// @brief
/// @param event
/// @param event_data
/// @param userdata
/// @return
static int on_disconnect_callback(int event, void *event_data, void *userdata)
{
  UNUSED(event);
  UNUSED(userdata);
  struct mosquitto_evt_disconnect *disconnect_message = event_data;
  const char *ip_address = mosquitto_client_address(disconnect_message->client);
  const char *clientid = mosquitto_client_id(disconnect_message->client);
  const char *username = mosquitto_client_username(disconnect_message->client);
  cJSON *disconnectJson = cJSON_CreateObject();
  cJSON_AddStringToObject(disconnectJson, "action", "client_disconnected");
  cJSON_AddStringToObject(disconnectJson, "clientid", clientid);
  cJSON_AddStringToObject(disconnectJson, "username", username);
  cJSON_AddNumberToObject(disconnectJson, "reason", disconnect_message->reason);
  cJSON_AddStringToObject(disconnectJson, "ip", ip_address);
  struct timeval tv;
  gettimeofday(&tv, NULL);
  char *tsbuf = (char *)cJSON_malloc(16);
  long ts = tv.tv_sec * 1000000 + tv.tv_usec;
  sprintf(tsbuf, "%ld", ts);
  cJSON_AddStringToObject(disconnectJson, "ts", tsbuf);
  char *jsonString = cJSON_Print(disconnectJson);
  cJSON_Minify(jsonString);
  mosquitto_log_printf(MOSQ_LOG_INFO, "[on_disconnect_callback] :%s\n", jsonString);
  http_post(jsonString, target_url);
  cJSON_free(disconnectJson);
  return MOSQ_ERR_SUCCESS;
}

/// @brief
/// @param event
/// @param event_data
/// @param userdata
/// @return
static int on_acl_check_callback(int event, void *event_data, void *userdata)
{
  UNUSED(event);
  UNUSED(userdata);
  struct mosquitto_evt_acl_check *acl_check_message = event_data;

  const char *ip_address = mosquitto_client_address(acl_check_message->client);
  const char *clientid = mosquitto_client_id(acl_check_message->client);
  const char *username = mosquitto_client_username(acl_check_message->client);

  cJSON *aclJson = cJSON_CreateObject();
  cJSON_AddStringToObject(aclJson, "action", "acl_check");
  cJSON_AddStringToObject(aclJson, "ip", ip_address);
  cJSON_AddStringToObject(aclJson, "clientid", clientid);
  cJSON_AddStringToObject(aclJson, "username", username);
  cJSON_AddNumberToObject(aclJson, "qos", acl_check_message->qos);
  cJSON_AddStringToObject(aclJson, "topic", acl_check_message->topic);
  cJSON_AddNumberToObject(aclJson, "access", acl_check_message->access);
  char *jsonString = cJSON_Print(aclJson);
  cJSON_Minify(jsonString);
  mosquitto_log_printf(MOSQ_LOG_INFO, "[on_acl_check_callback] :%s\n", jsonString);
  http_post(jsonString, target_url);
  cJSON_free(aclJson);
  return MOSQ_ERR_SUCCESS;
}
/// @brief
/// @param event
/// @param event_data
/// @param userdata
/// @return
static int on_message_callback(int event, void *event_data, void *userdata)
{
  UNUSED(event);
  UNUSED(userdata);
  struct mosquitto_evt_message *message = event_data;

  unsigned char buffer[1024];
  memcpy(buffer, message->payload, message->payloadlen);
  cJSON *msgJson = cJSON_CreateObject();
  cJSON_AddStringToObject(msgJson, "action", "message_publish");
  const char *ip_address = mosquitto_client_address(message->client);
  const char *clientid = mosquitto_client_id(message->client);
  const char *username = mosquitto_client_username(message->client);
  cJSON_AddStringToObject(msgJson, "ip", ip_address);
  cJSON_AddStringToObject(msgJson, "from_client_id", clientid);
  cJSON_AddStringToObject(msgJson, "from_username", username);
  cJSON_AddStringToObject(msgJson, "topic", message->topic);
  cJSON_AddStringToObject(msgJson, "payload", message->payload);
  cJSON_AddNumberToObject(msgJson, "qos", message->qos);
  cJSON_AddBoolToObject(msgJson, "retain", message->retain);
  struct timeval tv;
  gettimeofday(&tv, NULL);
  char *tsbuf = (char *)cJSON_malloc(16);
  long ts = tv.tv_sec * 1000000 + tv.tv_usec;
  sprintf(tsbuf, "%ld", ts);
  cJSON_AddStringToObject(msgJson, "ts", tsbuf);
  char *jsonString = cJSON_Print(msgJson);
  cJSON_Minify(jsonString);
  mosquitto_log_printf(MOSQ_LOG_INFO, "[on_message] :%s\n", jsonString);
  http_post(jsonString, target_url);

  cJSON_free(msgJson);
  return MOSQ_ERR_SUCCESS;
}
/// @brief
/// @param event
/// @param event_data
/// @param userdata
/// @return
static int on_auth_callback(int event, void *event_data, void *userdata)
{

  UNUSED(event);
  UNUSED(userdata);
  struct mosquitto_evt_basic_auth *auth_data = event_data;
  const char *ip_address = mosquitto_client_address(auth_data->client);
  const char *clientid = mosquitto_client_id(auth_data->client);
  const char *username = auth_data->username;
  const char *password = auth_data->password;

  cJSON *authJson = cJSON_CreateObject();
  cJSON_AddStringToObject(authJson, "action", "auth_check");
  cJSON_AddStringToObject(authJson, "ip", ip_address);
  cJSON_AddStringToObject(authJson, "clientid", clientid);
  cJSON_AddStringToObject(authJson, "username", username);
  cJSON_AddStringToObject(authJson, "password", password);
  char *jsonString = cJSON_Print(authJson);
  cJSON_Minify(jsonString);
  mosquitto_log_printf(MOSQ_LOG_INFO, "[on_auth_callback] => %s\n", jsonString);
  http_post(jsonString, target_url);
  cJSON_free(authJson);
  return MOSQ_ERR_SUCCESS;
}
//--------------------------------------------------------------------------------------------------
// Mosquitto Interface
//--------------------------------------------------------------------------------------------------
/// @brief
/// @param supported_version_count
/// @param supported_versions
/// @return
int mosquitto_plugin_version(int supported_version_count, const int *supported_versions)

{
  int i;

  for (i = 0; i < supported_version_count; i++)
  {
    if (supported_versions[i] == 5)
    {
      return 5;
    }
  }
  return -1;
}
/// @brief
/// @param identifier
/// @param userdata
/// @param options
/// @param option_count
/// @return
int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier,
                          void **userdata,
                          struct mosquitto_opt *options,
                          int option_count)

{
  UNUSED(userdata);
  UNUSED(options);
  UNUSED(option_count);
  plugin_identifier = identifier;
  curl_global_init(CURL_GLOBAL_DEFAULT);
  curl_client = curl_easy_init();
  curl_http_headers = curl_slist_append(curl_http_headers, "Content-Type: application/json");
  mosquitto_callback_register(plugin_identifier, MOSQ_EVT_BASIC_AUTH,
                              on_auth_callback, NULL, NULL);
  mosquitto_callback_register(plugin_identifier, MOSQ_EVT_MESSAGE,
                              on_message_callback, NULL, NULL);
  mosquitto_callback_register(plugin_identifier, MOSQ_EVT_ACL_CHECK,
                              on_acl_check_callback, NULL, NULL);
  mosquitto_callback_register(plugin_identifier, MOSQ_EVT_DISCONNECT,
                              on_disconnect_callback, NULL, NULL);
  return MOSQ_ERR_SUCCESS;
}
/// @brief
/// @param userdata
/// @param options
/// @param option_count
/// @return
int mosquitto_plugin_cleanup(void *userdata, struct mosquitto_opt *options, int option_count)
{
  UNUSED(userdata);
  UNUSED(options);
  UNUSED(option_count);
  curl_global_cleanup();
  curl_easy_cleanup(curl_client);
  mosquitto_callback_unregister(plugin_identifier, MOSQ_EVT_DISCONNECT, on_auth_callback, NULL);
  mosquitto_callback_unregister(plugin_identifier, MOSQ_EVT_ACL_CHECK, on_auth_callback, NULL);
  mosquitto_callback_unregister(plugin_identifier, MOSQ_EVT_MESSAGE, on_auth_callback, NULL);
  mosquitto_callback_unregister(plugin_identifier, MOSQ_EVT_BASIC_AUTH, on_message_callback, NULL);
  return MOSQ_ERR_SUCCESS;
}