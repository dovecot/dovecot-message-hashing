/* Copyright (c) Michael Slusarz <slusarz@curecanti.org>,
 * see the included COPYING file */

#include "lib.h"
#include "hash-format.h"
#include "hash-method.h"
#include "hex-binary.h"
#include "istream.h"
#include "istream-attachment-extractor.h"
#include "istream-hash.h"
#include "mail-storage-private.h"
#include "message-hashing-plugin.h"
#include "notify-plugin.h"
#include "ostream.h"
#include "ostream-null.h"
#include "safe-mkstemp.h"
#include "str.h"

#define MESSAGE_HASHING_DEFAULT_HASH_METHOD "md5"
#define MESSAGE_HASHING_DEFAULT_MIN_ATC_SIZE 1
#define MESSAGE_HASHING_PLUGIN_NAME "message_hashing"
#define MESSAGE_HASHING_PLUGIN_LOG_LABEL MESSAGE_HASHING_PLUGIN_NAME ": "

struct message_hashing_settings {
	const char *hash_method;
	unsigned int min_atc_size;
};

struct message_hashing_user {
	union mail_user_module_context module_ctx;
	struct notify_context *message_hashing_ctx;
	struct message_hashing_settings set;
};

struct message_hashing_mail_txn_context {
	unsigned int atc_count;
	struct event *event;
	const struct hash_method *hash;
	unsigned char *hash_ctx;
	const char *hash_format_variable;
	struct istream *hinput;
	struct mail_user *muser;

	pool_t pool;
};

#define MESSAGE_HASHING_USER_CONTEXT(obj) \
        MODULE_CONTEXT_REQUIRE(obj, message_hashing_user_module)
static MODULE_CONTEXT_DEFINE_INIT(message_hashing_user_module,
				  &mail_user_module_register);


static void
message_hashing_init_full_message(struct message_hashing_mail_txn_context *ctx,
				  struct istream *input)
{
	ctx->atc_count = 0;
	ctx->hash->init(ctx->hash_ctx);
	ctx->hinput = i_stream_create_hash(input, ctx->hash, ctx->hash_ctx);
}

static void
message_hashing_deinit_full_message(struct message_hashing_mail_txn_context *ctx,
				    struct istream *input)
{
	unsigned char *digest;
	const char *hash;

	digest = p_malloc(ctx->pool, ctx->hash->digest_size);
	ctx->hash->result(ctx->hash_ctx, digest);

	hash = binary_to_hex(digest, ctx->hash->digest_size);

	e_debug(event_create_passthrough(ctx->event)->
		set_name("message_hashing_msg_full")->
		add_int("attachments", ctx->atc_count)->
		add_str("hash", hash)->
		add_int("size", input->v_offset)->
		event(), "full message (%s, %zu)", hash, input->v_offset);

	i_stream_destroy(&ctx->hinput);
}

static int message_hashing_attachment_open_temp_fd(void *context)
{
	struct message_hashing_mail_txn_context *ctx = context;
	int fd;
	string_t *temp_path;

	temp_path = t_str_new(256);
	mail_user_set_get_temp_prefix(temp_path, ctx->muser->set);
	fd = safe_mkstemp_hostpid(temp_path, 0600, (uid_t)-1, (gid_t)-1);

        if (fd == -1)
		return -1;
	if (unlink(str_c(temp_path)) < 0) {
		i_close_fd(&fd);
		return -1;
	}

	return fd;
}

static int
message_hashing_attachment_open_ostream(struct istream_attachment_info *info,
					struct ostream **output_r,
					const char **error_r ATTR_UNUSED,
					void *context)
{
	struct message_hashing_mail_txn_context *ctx = context;

	e_debug(event_create_passthrough(ctx->event)->
		set_name("message_hashing_msg_part")->
		add_str("hash", info->hash)->
		add_int("size", info->encoded_size)->
		event(), "message part (%s, %zu)", info->hash,
		info->encoded_size);

	*output_r = o_stream_create_null();

	++ctx->atc_count;

	return 0;
}

static int
message_hashing_attachment_close_ostream(struct ostream *output,
					 bool success ATTR_UNUSED,
					 const char **error ATTR_UNUSED,
					 void *context ATTR_UNUSED)
{
	o_stream_unref(&output);

	return 0;
}

static void
message_hashing_parse_message(struct message_hashing_mail_txn_context *ctx)
{
	const unsigned char *data;
	const char *error;
	struct istream *input;
	struct istream_attachment_settings set;
	size_t size;
	struct message_hashing_user *user;

	i_zero(&set);

	(void)hash_format_init(ctx->hash_format_variable, &set.hash_format,
			       &error);

	user = MESSAGE_HASHING_USER_CONTEXT(ctx->muser);
	set.min_size = user->set.min_atc_size;
	set.drain_parent_input = TRUE;
	set.want_attachment = NULL;
	set.open_temp_fd = message_hashing_attachment_open_temp_fd;
	set.open_attachment_ostream = message_hashing_attachment_open_ostream;
	set.close_attachment_ostream = message_hashing_attachment_close_ostream;

	input = i_stream_create_attachment_extractor(ctx->hinput, &set, ctx);

	while (i_stream_read_more(input, &data, &size) > 0)
		i_stream_skip(input, size);

	i_stream_unref(&input);
}

static void message_hashing_mail_save(void *txn, struct mail *mail)
{
	struct message_hashing_mail_txn_context *ctx =
		(struct message_hashing_mail_txn_context *)txn;
	struct istream *input;

	if (mail_get_stream_because(mail, NULL, NULL, "message hashing", &input) < 0)
		return;

	message_hashing_init_full_message(ctx, input);
	message_hashing_parse_message(ctx);
	message_hashing_deinit_full_message(ctx, input);
}

static void *
message_hashing_mail_transaction_begin(struct mailbox_transaction_context *t)
{
	struct mailbox *box;
	struct message_hashing_mail_txn_context *ctx;
	struct message_hashing_user *muser;
	pool_t pool;
	struct mail_storage *storage;
	struct mail_user *user;

	pool = pool_alloconly_create("message hashing transaction", 2048);

	box = mailbox_transaction_get_mailbox(t);
	storage = mailbox_get_storage(box);
	user = mail_storage_get_user(storage);
	muser = MESSAGE_HASHING_USER_CONTEXT(user);

	ctx = p_new(pool, struct message_hashing_mail_txn_context, 1);
	ctx->event = event_create(user->event);
	ctx->muser = user;
	ctx->pool = pool;

	ctx->hash = hash_method_lookup(muser->set.hash_method);
	ctx->hash_ctx = p_malloc(pool, ctx->hash->context_size);
	ctx->hash_format_variable = p_strdup_printf(pool, "%%{%s}",
						    muser->set.hash_method);

	event_set_append_log_prefix(ctx->event,
				    MESSAGE_HASHING_PLUGIN_LOG_LABEL);

	return ctx;
}

static void
message_hashing_mail_transaction_commit(void *txn,
					struct mail_transaction_commit_changes *changes ATTR_UNUSED)
{
	struct message_hashing_mail_txn_context *ctx =
		(struct message_hashing_mail_txn_context *)txn;

	event_unref(&ctx->event);
	pool_unref(&ctx->pool);
}

static void
message_hashing_mail_transaction_rollback(void *txn)
{
	message_hashing_mail_transaction_commit(txn, NULL);
}

static int
message_hashing_plugin_init_settings(struct mail_user *user,
				     struct message_hashing_settings *set,
				     const char *str)
{
	const char *const *tmp;
	unsigned int val;

	set->hash_method = MESSAGE_HASHING_DEFAULT_HASH_METHOD;
	set->min_atc_size = MESSAGE_HASHING_DEFAULT_MIN_ATC_SIZE;

	for (tmp = t_strsplit_spaces(str, " "); *tmp != NULL; tmp++) {
		if (str_begins(*tmp, "hash_method=")) {
			set->hash_method = p_strdup(user->pool, *tmp + 12);
			if (hash_method_lookup(set->hash_method) == NULL) {
				i_error(MESSAGE_HASHING_PLUGIN_LOG_LABEL
					"Invalid hash_method setting: %s",
					set->hash_method);
				return -1;
			}
		} else if (str_begins(*tmp, "min_atc_size=")) {
			if (str_to_uint(*tmp + 13, &val) < 0) {
				i_error(MESSAGE_HASHING_PLUGIN_LOG_LABEL
					"Invalid min_atc_size setting: %s",
					*tmp + 13);
				return -1;
			}
			set->min_atc_size = I_MAX(MESSAGE_HASHING_DEFAULT_MIN_ATC_SIZE,
						  val);
		} else {
			i_error(MESSAGE_HASHING_PLUGIN_LOG_LABEL
				"Invalid setting: %s", *tmp);
			return -1;
		}
	}

	return 0;
}

static const struct notify_vfuncs message_hashing_vfuncs = {
	.mail_save = message_hashing_mail_save,
	.mail_transaction_begin = message_hashing_mail_transaction_begin,
	.mail_transaction_commit = message_hashing_mail_transaction_commit,
	.mail_transaction_rollback = message_hashing_mail_transaction_rollback
};

static void message_hashing_mail_user_deinit(struct mail_user *user)
{
	struct message_hashing_user *muser = MESSAGE_HASHING_USER_CONTEXT(user);

	notify_unregister(muser->message_hashing_ctx);

	muser->module_ctx.super.deinit(user);
}

static void message_hashing_mail_user_created(struct mail_user *user)
{
	const char *env;
	struct message_hashing_user *muser;
	struct mail_user_vfuncs *v = user->vlast;

	muser = p_new(user->pool, struct message_hashing_user, 1);
	env = mail_user_plugin_getenv(user, MESSAGE_HASHING_PLUGIN_NAME);
	if (env == NULL)
		env = "";

	if (message_hashing_plugin_init_settings(user, &muser->set, env) < 0) {
		/* Invalid settings; disable plugin. Error messages have
		 * already been sent to logs. */
		return;
	}

	muser->module_ctx.super = *v;
	user->vlast = &muser->module_ctx.super;
	v->deinit = message_hashing_mail_user_deinit;
	MODULE_CONTEXT_SET(user, message_hashing_user_module, muser);

	muser->message_hashing_ctx = notify_register(&message_hashing_vfuncs);
}

/* Plugin Initialization. */

static struct mail_storage_hooks message_hashing_mail_storage_hooks = {
	.mail_user_created = message_hashing_mail_user_created
};

void message_hashing_plugin_init(struct module *module)
{
	mail_storage_hooks_add(module, &message_hashing_mail_storage_hooks);
}

void message_hashing_plugin_deinit(void)
{
	mail_storage_hooks_remove(&message_hashing_mail_storage_hooks);
}

const char *message_hashing_plugin_dependencies[] = { "notify", NULL };
