/* Local namespaces defs
 *
 * Copyright (C) 2017 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

extern struct nsproxy *create_new_namespaces(unsigned long flags,
					     struct nsproxy *nsproxy,
					     struct user_namespace *user_ns,
					     struct fs_struct *new_fs);
