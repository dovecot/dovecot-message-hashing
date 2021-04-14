#ifndef MESSAGE_HASHING_PLUGIN_H
#define MESSAGE_HASHING_PLUGIN_H

extern const char *message_hashing_plugin_dependencies[];

void message_hashing_plugin_init(struct module *module);
void message_hashing_plugin_deinit(void);

#endif
