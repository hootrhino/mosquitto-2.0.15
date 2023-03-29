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
#include <stdlib.h>
#define DEBUG
#define UNUSED(A) (void)(A)
#define NEW_T(__T) (__T *)malloc(sizeof(__T))

//--------------------------------------------------------------------------------------------------
// Superuser 配置
//--------------------------------------------------------------------------------------------------
typedef struct
{
  char *username;
  char *ip;
} superuser;
typedef struct node
{
  superuser *user;
  struct node *next;
} superuser_linknode;

void print_list(superuser_linknode *head)
{
  superuser_linknode *current = head;

  while (current != NULL)
  {
    printf("Username: %s, IP: %s\n", current->user->username, current->user->ip);
    current = current->next;
  }
}

superuser_linknode *find_list(superuser_linknode *head, char *username)
{
  superuser_linknode *current = head;

  while (current != NULL)
  {
    if (strcmp(current->user->username, username) == 0)
    {
      return current;
    }
    current = current->next;
  }
  return NULL;
}

void insert_superuser_linknode(superuser_linknode **head, superuser *user)
{
  superuser_linknode *new_node = NEW_T(superuser_linknode);
  new_node->user = user;
  new_node->next = *head;
  *head = new_node;
}

void free_superuser_linklist(superuser_linknode **head)
{
  superuser_linknode *current = *head;

  while (current != NULL)
  {
    superuser_linknode *next = current->next;
    free(current);
    current = next;
  }

  *head = NULL;
}
//--------------------------------------------------------------------------------------------------
// 辅助类函数
//--------------------------------------------------------------------------------------------------

/// @brief 清除字符串里的空格
/// @param s
void trim(char *s)
{
  char *s_c = s;
  int i, j = 0;
  for (i = 0; s[i] != '\0'; i++)
  {
    if (s[i] != ' ')
      s_c[j++] = s[i];
  }
  s_c[j] = '\0';
  s = s_c;
}

//--------------------------------------------------------------------------------------------------
// Plugin config
//--------------------------------------------------------------------------------------------------

typedef struct
{
  mosquitto_plugin_id_t *plugin_identifier;
  CURL *curl_client;
  struct curl_slist *curl_http_headers;
  char target_url[2048]; // 2048 is max URL length
  superuser_linknode *head;
} mosquitto_http_plugin_config;
// 全局配置

static mosquitto_http_plugin_config main_config = {
    .plugin_identifier = NULL,
    .curl_client = NULL,
    .curl_http_headers = NULL,
    .target_url = "http://127.0.0.1:8899",
    .head = NULL,
};
//--------------------------------------------------------------------------------------------------
// User Functions
//--------------------------------------------------------------------------------------------------
// #define MOSQ_ACL_NONE 0x00
// #define MOSQ_ACL_READ 0x01
// #define MOSQ_ACL_WRITE 0x02
// #define MOSQ_ACL_SUBSCRIBE 0x04
// #define MOSQ_ACL_UNSUBSCRIBE 0x08

static void get_access_type(int code, char *access_type)
{
  switch (code)
  {
  case 0:
    strcpy(access_type, "none");
    break;
  case 2:
    strcpy(access_type, "pub");
    break;
  case 1:
  case 4:
    strcpy(access_type, "sub");
    break;
  case 8:
    strcpy(access_type, "unsub");
    break;
  default:
    strcpy(access_type, "none");
    break;
  }
}
static size_t http_receive_data(void *dataptr, size_t size, size_t nmemb, void *userptr)
{
  UNUSED(dataptr);
  UNUSED(userptr);
  return nmemb * size;
}

/// @brief HTTP 请求函数
/// @param jsonString
/// @param url
/// @return
static long http_post(char *jsonString)
{
  curl_easy_setopt(main_config.curl_client, CURLOPT_POSTFIELDS, jsonString);
  long code = curl_easy_perform(main_config.curl_client);

  if (code != CURLE_OK)
  {
    mosquitto_log_printf(MOSQ_LOG_ERR, "http post error: %s, %s",
                         curl_easy_strerror(code), main_config.target_url);
    return code;
  }
  long http_code = 0;
  curl_easy_getinfo(main_config.curl_client, CURLINFO_RESPONSE_CODE, &http_code);
  return http_code;
}
/// @brief 当客户端离线的时候调用
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
  char *ts_buf = (char *)cJSON_malloc(16);
  long ts = tv.tv_sec * 1000000 + tv.tv_usec;
  sprintf(ts_buf, "%ld", ts);
  cJSON_AddStringToObject(disconnectJson, "ts", ts_buf);
  char *jsonString = cJSON_Print(disconnectJson);
  cJSON_Minify(jsonString);
#ifdef DEBUG
  mosquitto_log_printf(MOSQ_LOG_INFO, "[on_disconnect_callback] :%s\n", jsonString);
#endif
  http_post(jsonString);
  cJSON_free(disconnectJson);
  mosquitto_broker_publish(NULL, "$SYS/brokers/clients/disconnected",
                           (int)strlen(jsonString), jsonString, 1, 0, NULL);
  return MOSQ_ERR_SUCCESS;
}

/// @brief 当认证ACL的时候调用
/// @param event
/// @param event_data
/// @param userdata
/// @return
static int on_acl_check_callback(int event, void *event_data, void *userdata)
{
  printf("[flag] 0\n");
  UNUSED(event);
  UNUSED(userdata);
  struct mosquitto_evt_acl_check *acl_check_message = event_data;

  const char *ip_address = mosquitto_client_address(acl_check_message->client);
  const char *clientid = mosquitto_client_id(acl_check_message->client);
  const char *username = mosquitto_client_username(acl_check_message->client);
  superuser_linknode *node = find_list(main_config.head, (char *)username);
  if (node != NULL)
  {
#ifdef DEBUG
    mosquitto_log_printf(MOSQ_LOG_INFO, "[on_acl_superuser] :%s\n", username);
#endif
    if (strcmp(username, node->user->username) == 0)
    {
      // Success if superuser check passed
      return MOSQ_ERR_SUCCESS;
    }
  }

  cJSON *aclJson = cJSON_CreateObject();
  cJSON_AddStringToObject(aclJson, "action", "acl_check");
  cJSON_AddStringToObject(aclJson, "ip", ip_address);
  cJSON_AddStringToObject(aclJson, "clientid", clientid);
  cJSON_AddStringToObject(aclJson, "username", username);
  cJSON_AddNumberToObject(aclJson, "qos", acl_check_message->qos);
  cJSON_AddStringToObject(aclJson, "topic", acl_check_message->topic);
  char access_type[6];
  get_access_type(acl_check_message->access, access_type);
  cJSON_AddStringToObject(aclJson, "access", access_type);
  char *jsonString = cJSON_Print(aclJson);
  cJSON_Minify(jsonString);
#ifdef DEBUG
  mosquitto_log_printf(MOSQ_LOG_INFO, "[on_acl_check_callback] :%s\n", jsonString);
#endif
  long code = http_post(jsonString);
  cJSON_free(aclJson);
  if (code != 200)
  {
    return MOSQ_ERR_ACL_DENIED;
  }
  return MOSQ_ERR_SUCCESS;
}
/// @brief 当消息转发的时候调用
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
  char *ts_buf = (char *)cJSON_malloc(16);
  long ts = tv.tv_sec * 1000000 + tv.tv_usec;
  sprintf(ts_buf, "%ld", ts);
  cJSON_AddStringToObject(msgJson, "ts", ts_buf);
  char *jsonString = cJSON_Print(msgJson);
  cJSON_Minify(jsonString);
#ifdef DEBUG
  mosquitto_log_printf(MOSQ_LOG_INFO, "[on_message] :%s\n", jsonString);
#endif
  http_post(jsonString);

  cJSON_free(msgJson);
  return MOSQ_ERR_SUCCESS;
}
/// @brief 当登录的时候调用
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
  superuser_linknode *node = find_list(main_config.head, (char *)username);
  if (node != NULL)
  {
#ifdef DEBUG
    mosquitto_log_printf(MOSQ_LOG_INFO, "[on_auth_superuser] :%s\n", username);
#endif
    if (strcmp(username, node->user->username) == 0)
    {
      // Success if superuser check passed
      return MOSQ_ERR_SUCCESS;
    }
  }

  cJSON *authJson = cJSON_CreateObject();
  cJSON_AddStringToObject(authJson, "action", "auth_check");
  cJSON_AddStringToObject(authJson, "ip", ip_address);
  cJSON_AddStringToObject(authJson, "clientid", clientid);
  cJSON_AddStringToObject(authJson, "username", username);
  cJSON_AddStringToObject(authJson, "password", password);
  char *jsonString = cJSON_Print(authJson);
  cJSON_Minify(jsonString);
#ifdef DEBUG
  mosquitto_log_printf(MOSQ_LOG_INFO, "[on_auth_callback] => %s\n", jsonString);
#endif
  long code = http_post(jsonString);
  cJSON_free(authJson);
  if (code != 200)
  {
    return MOSQ_ERR_AUTH;
  }
  mosquitto_broker_publish(NULL, "$SYS/brokers/clients/connected",
                           (int)strlen(jsonString), jsonString, 1, 0, NULL);
  return MOSQ_ERR_SUCCESS;
}
//--------------------------------------------------------------------------------------------------
// Mosquitto Interface
//--------------------------------------------------------------------------------------------------
/// @brief mosquitto的支持版本号检查
/// @param supported_version_count
/// @param supported_versions
/// @return
int mosquitto_plugin_version(int supported_version_count, const int *supported_versions)

{
  UNUSED(supported_version_count);
  UNUSED(supported_versions);
  // V5版本的插件
  return 5;
}
/// @brief 初始化函数
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
  main_config.plugin_identifier = identifier;
  main_config.head = NULL;
  UNUSED(userdata);
  //------------------------------------------------------------------------------------------------
  // init config options
  //------------------------------------------------------------------------------------------------
  for (int i = 0; i < option_count; i++)
  {
    if (strcmp("mosquitto_http_plugin_url", (options + i)->key) == 0)
    {
      strcpy(main_config.target_url, (options + i)->value);
    }
    if (strcmp("mosquitto_http_plugin_super", (options + i)->key) == 0)
    {
      char *super = (options + i)->value;
      trim(super);
      char *super_name = strtok(super, ", ");
      if (strlen(super_name) == 0)
      {
        exit(0);
      }
      char *super_net = strtok(NULL, ", ");
      if (strlen(super_net) == 0)
      {
        exit(0);
      }
      superuser *new_user = (superuser *)malloc(sizeof(superuser));
      new_user->ip = super_net;
      new_user->username = super_name;
      insert_superuser_linknode(&main_config.head, new_user);
    }
  }
  //------------------------------------------------------------------------------------------------
  // init config options end
  //------------------------------------------------------------------------------------------------

  //------------------------------------------------------------------------------------------------
  // init curl
  //------------------------------------------------------------------------------------------------
  curl_global_init(CURL_GLOBAL_DEFAULT);
  main_config.curl_client = curl_easy_init();
  main_config.curl_http_headers = curl_slist_append(main_config.curl_http_headers,
                                                    "Content-Type: application/json");
  curl_easy_setopt(main_config.curl_client, CURLOPT_HTTPHEADER,
                   main_config.curl_http_headers);
  curl_easy_setopt(main_config.curl_client, CURLOPT_TIMEOUT, 5000);
  curl_easy_setopt(main_config.curl_client, CURLOPT_WRITEFUNCTION, http_receive_data);
  curl_easy_setopt(main_config.curl_client, CURLOPT_URL,
                   main_config.target_url);
  //------------------------------------------------------------------------------------------------
  // init curl end
  //------------------------------------------------------------------------------------------------

  mosquitto_callback_register(main_config.plugin_identifier, MOSQ_EVT_BASIC_AUTH,
                              on_auth_callback, NULL, NULL);
  mosquitto_callback_register(main_config.plugin_identifier, MOSQ_EVT_MESSAGE,
                              on_message_callback, NULL, NULL);
  mosquitto_callback_register(main_config.plugin_identifier, MOSQ_EVT_ACL_CHECK,
                              on_acl_check_callback, NULL, NULL);
  mosquitto_callback_register(main_config.plugin_identifier, MOSQ_EVT_DISCONNECT,
                              on_disconnect_callback, NULL, NULL);
  return MOSQ_ERR_SUCCESS;
}
/// @brief 释放资源
/// @param userdata
/// @param options
/// @param option_count
/// @return
int mosquitto_plugin_cleanup(void *userdata, struct mosquitto_opt *options, int option_count)
{
  UNUSED(userdata);
  UNUSED(options);
  UNUSED(option_count);
  curl_easy_cleanup(main_config.curl_client);
  curl_global_cleanup();
  free_superuser_linklist(&main_config.head);
  mosquitto_callback_unregister(main_config.plugin_identifier,
                                MOSQ_EVT_DISCONNECT, on_auth_callback, NULL);
  mosquitto_callback_unregister(main_config.plugin_identifier,
                                MOSQ_EVT_ACL_CHECK, on_acl_check_callback, NULL);
  mosquitto_callback_unregister(main_config.plugin_identifier,
                                MOSQ_EVT_MESSAGE, on_auth_callback, NULL);
  mosquitto_callback_unregister(main_config.plugin_identifier,
                                MOSQ_EVT_BASIC_AUTH, on_message_callback, NULL);
  return MOSQ_ERR_SUCCESS;
}