#include <stdio.h>
#include <string.h>

#include "mosquitto_broker.h"
#include "mosquitto_plugin.h"
#include "mosquitto.h"
#include "mqtt_protocol.h"

#define UNUSED(A) (void)(A)

//
static mosquitto_plugin_id_t *plugin_identifier = NULL;
static int on_message(int event, void *event_data, void *userdata)
{
  UNUSED(event);
  UNUSED(userdata);
  struct mosquitto_evt_message *message = event_data;
  unsigned char buffer[1024];
  memcpy(buffer, message->payload, message->payloadlen);
  mosquitto_log_printf(MOSQ_LOG_INFO, "[on_message] QOS: %d; Topic:%s; Payload:%s\n", message->qos, message->topic, buffer);
  return MOSQ_ERR_SUCCESS;
}
//
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

int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier,
                          void **userdata,
                          struct mosquitto_opt *options,
                          int option_count)

{
  UNUSED(userdata);
  UNUSED(options);
  UNUSED(option_count);
  plugin_identifier = identifier;
  return mosquitto_callback_register(plugin_identifier, MOSQ_EVT_MESSAGE, on_message, NULL, NULL);
}

int mosquitto_plugin_cleanup(void *userdata, struct mosquitto_opt *options, int option_count)
{
  UNUSED(userdata);
  UNUSED(options);
  UNUSED(option_count);
  return mosquitto_callback_unregister(plugin_identifier, MOSQ_EVT_MESSAGE, on_message, NULL);
}