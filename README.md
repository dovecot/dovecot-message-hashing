Message Hashing plugin for Dovecot
==================================

What?
-----

This plugin calculates a hash for every attachment in a message (attachment
determination done via istream-attachment-extractor code) and a hash for the
entire message. This data is emitted via named events, which can be collected
and analyzed as needed.

This plugin captures message saving via any method (LMTP/LDA, doveadm, IMAP
APPEND). To restrict to a certain protocol, load the plugin in a protocol
block instead of globally.

Requirements
------------

* Dovecot 2.3+ (tested on Dovecot CE 2.3.14)

Compilation
-----------

If you downloaded this package using Git, you will first need to run
`autogen.sh` to generate the configure script and some other files:

```
./autogen.sh
```

The following compilation software/packages must be installed:

 - autoconf
 - automake
 - libtool
 - GNU make

After this script is executed successfully, `configure` needs to be executed
with the following parameters:

 - `--with-dovecot=<path>`

   Path to the dovecot-config file. This can either be a compiled dovecot
   source tree or point to the location where the dovecot-config file is
   installed on your system (typically in the $prefix/lib/dovecot directory).

When these paremeters are omitted, the configure script will try to find thex
local Dovecot installation implicitly.

For example, when compiling against compiled Dovecot sources:

```
./configure --with-dovecot=../dovecot-src
```

Or when compiling against a Dovecot installation:

```
./configure --with-dovecot=/path/to/dovecot
```

As usual, to compile and install, execute the following:

```
make
sudo make install
```

Configuration
-------------

Message Hashing plugin provies a single plugin option for configuration:
`message_hashing`.

Options for the `message_hashing` plugin setting:

 - `hash_method` - The hashing method to use. Must be a recognized Dovecot
                   hash method (see
                   https://doc.dovecot.org/settings/core/#setting-auth-policy-hash-mech)
                   or else the plugin will log a warning and be disabled.
                   (string; DEFAULT: "md5")
 - `min_atc_size` - The minimum size of an attachment (in bytes) to be
                    processed; attachments smaller than this will be skipped.
                    (integer; DEFAULT: 1)

Example configuration:

```
mail_plugins = $mail_plugins message_hashing

plugin {
  message_hashing = hash_method=md5
}
```

Logging/Events
--------------

The following named events are emitted:

## message_hashing_msg_full

Emitted for every message saved.

+-------------+-----------------------------------------------------+
| Field       | Description                                         |
+=============+=====================================================+
| attachments | The number of attachments processed in this message |
|             | (attachments with size > min_atc_size)              |
+-------------+-----------------------------------------------------+
| hash        | The hash of the entire message                      |
+-------------+-----------------------------------------------------+
| size        | The size (in bytes) of the entire message           |
+-------------+-----------------------------------------------------+

## message_hashing_msg_part

Emitted for every attachment found.

+---------+---------------------------------------+
| Field   | Description                           |
+=========+=======================================+
| hash    | The hash of the attachment            |
+---------+---------------------------------------+
| size    | The size (in bytes) of the attachment |
+---------+---------------------------------------+
