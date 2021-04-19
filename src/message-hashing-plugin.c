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


// TODO: Is this needed?
struct message_hashing_user {
	union mail_user_module_context module_ctx;
};

struct message_hashing_mail_txn_context {
	struct event *event;
	const struct hash_method *hash;
	unsigned char *hash_ctx;
	struct istream *hinput;
	struct mail_user *muser;

	pool_t pool;
};

static MODULE_CONTEXT_DEFINE_INIT(message_hashing_user_module,
				  &mail_user_module_register);


static void
message_hashing_init_full_message(struct message_hashing_mail_txn_context *ctx,
				  struct istream *input)
{
	ctx->hash = hash_method_lookup("md5");
	ctx->hash_ctx = p_malloc(ctx->pool, ctx->hash->context_size);
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

	i_zero(&set);

  	(void)hash_format_init("%{md5}", &set.hash_format, &error);
	set.min_size = 1;
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
	struct mail_user *muser;
	struct mail_storage *storage;
	pool_t pool;

	pool = pool_alloconly_create("message hashing transaction", 2048);

	box = mailbox_transaction_get_mailbox(t);
	storage = mailbox_get_storage(box);
	muser = mail_storage_get_user(storage);

	ctx = p_new(pool, struct message_hashing_mail_txn_context, 1);
	ctx->event = event_create(muser->event);
	ctx->muser = muser;
	ctx->pool = pool;

	event_set_append_log_prefix(ctx->event, "message-hashing: ");

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

static void message_hashing_mail_user_created(struct mail_user *user)
{
	struct message_hashing_user *muser;

	muser = p_new(user->pool, struct message_hashing_user, 1);
	MODULE_CONTEXT_SET(user, message_hashing_user_module, muser);
}

/* Plugin Initialization. */

static const struct notify_vfuncs message_hashing_vfuncs = {
	.mail_save = message_hashing_mail_save,
	.mail_transaction_begin = message_hashing_mail_transaction_begin,
	.mail_transaction_commit = message_hashing_mail_transaction_commit
};

static struct notify_context *message_hashing_ctx;

static struct mail_storage_hooks message_hashing_mail_storage_hooks = {
	.mail_user_created = message_hashing_mail_user_created
};

void message_hashing_plugin_init(struct module *module)
{
	message_hashing_ctx = notify_register(&message_hashing_vfuncs);
	mail_storage_hooks_add(module, &message_hashing_mail_storage_hooks);
}

void message_hashing_plugin_deinit(void)
{
	mail_storage_hooks_remove(&message_hashing_mail_storage_hooks);
	notify_unregister(message_hashing_ctx);
}

const char *message_hashing_plugin_dependencies[] = { "notify", NULL };
