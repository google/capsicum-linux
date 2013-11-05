# Part of a Linux implementation of Capsicum, a capability API for UNIX.
#
# Copyright (C) 2012 The Chromium OS Authors <chromium-os-dev@chromium.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2, as
# published by the Free Software Foundation.
kt: kt.c
	gcc -g -static -Wall -Werror -DDEBUGFS_MOUNT='"/debug"' -o $@ $<

clean:
	rm kt
