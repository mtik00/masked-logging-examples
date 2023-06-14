# Masking sensitive information from logs

## Info

You should normally keep sensitive information (passwords, access tokens, PII, etc)
from your log files.  This is especially true if you use a log aggregator (e.g
New Relic, DataDog, etc).  Setting up appropriate RBAC to allow developers to
debug with production logs but _not_ see sensitive data is complex and error prone.

The easiest thing to do is to not log that information in the first place.  However,
it can come in handy.  If you can't keep the information out of logs, the next
best thing is to mask the information to give users/devs just enough information
to debug the problem.  For example, the first and last characters of an API token
might be enough to prove it's expired, or the first characters of a base64 digest
might be enough to prove the `username:password` is wrong, etc.

When masking information, you want to be sure you don't leak metadata.  The main
example here is the length of the thing you are masking.  This isn't very useful
for API tokens, however, it's very important for passwords.  You don't want to
use a masking function that simply replaces the characters in a string.

## Methodology

The examples configure and use the built-in `logging` module.  This has the
benefit of affecting all 1st and 3rd party modules that also use the `logging`
module.  This means that logs from a package like `requests` will also use this
masking method.

The one caveat is that your application/script must set up logging as soon as
possible (which is expected anyway).

How you initialize your logger is up to you.  The example presented here use
`basicConfig` that is executed on imported.  You might need to do something much
more complex.  The only constant is that you should use the `Formatter` given in
the examples, and more sure the _root_ logger is using it.  That's the special
sauce that keep your sensitive data masked.

## Examples

There are two example modules presented in this repo.

The first example, `logger_basic.py`, can be used when the amount of sensitive
information is: a) known; b) not "too" large.  This is perfect for small
applications/scripts that are not long running.

The second example, `logger_advanced.py`, is much more complex.  This is example
adds regular expressions in an attempt to make the solution more generic.  The 
downside, is, well, regex.  They're hard to get right.  The good news is that
this example is much more scalable in theory.

### logger_basic.py

This example uses a `list` to keep track of any information that should be kept
from logs.  During log formatting, each item in the list is used to replace the
substring in the text with a masked value.

If you know the thing you are using, add it to the `SENSITIVE` list as soon as
you know it.  For example:
```
password = getpass("Enter your Gmail password:")
SENSITIVE.append(password)
log.info("You can't see the full password: %s", password)
```

or maybe something is stored as an environment variable:
```
import os
basic_auth = os.getenv("BASIC_AUTH)
SENSITIVE.append(basic_auth)

basic_auth_header = {"Authorization": f"Basic {basic_auth}"}
log.info("request headers: %s", basic_auth_header)
```

Just remember that the algorithm executes `str.replace` on each item in the list,
every time a log is emitted.  Having billions of items in that list might slow
down logging (YMMV, of course).

### logger_advanced.py

This module builds on the previous one.  This module adds regular expressions.
Some common expressions are presented, but of course you can (and should) tailor
these to your use case.

The `Masker` class is used to test each expression and call a custom method to
determine exactly how to mask the item.  For example, for an email, only the
`username` portion is masked.  Is that ok?  I have no clue.  That depends on your
use case.  It's just an example.

Add the appropriate `Mask` object to `Masker.__init__()` function.  Like above,
this list will be iterated every time a log is emitted.  You might want to limit
how large this list is.  Although with regex's, you probably won't be adding
more than dozens, which should be fine.

You also might need a special masking function.  Make sure to add new `@staticmethod`s
as appropriate and reference them when creating new `Mask` objects.

The challenge is coming up with regex's that work for you.  Good luck.

Crafting regular expressions is hard.  Here's a couple of places to look for
inspiration:
 - https://github.com/sdushantha/dora/blob/main/dora/db/data.json
 - https://github.com/System00-Security/API-Key-regex

Always test your regex's as thoroughly as you can.

You can also mix the above method (`SENSITIVE`) with this one.

This example also introduces an `init_logger` function that needs to be called
after importing the module.  That's a pattern that I find works for me, so I can
do more complex things that `basicConfig` can't handle (not shown in this example).

# WARNING

These modules do not mask structured logging!  These example will not keep sensitive
data out of structures logs (e.g. `json`).  That's left up to the reader.

Obviously, these examples don't affect `print()` statements.  One not-so-obvious
problem is with `sys.stdout`/`sys.stderr` in general.  For example, Exceptions
are not handled appropriately.  You might still leak sensitive information if
you push these streams to a file (or API endpoint).

# Final words

This is just one way of doing things (including setting up the logger).  YMMV.
Feel free to take this code and hack away for your specific needs.
