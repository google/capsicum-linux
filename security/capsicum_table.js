#!/usr/bin/env js

/*
 * System call permission table for Capsicum, a capability API for UNIX.
 *
 * Copyright (C) 2012 The Chromium OS Authors <chromium-os-dev@chromium.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */


/*
   A few words about testing:

   Ideally we would test that every permitted system call only allows
   operations that match the permissions of the capability with which it is
   invoked. However, this would require coverage of every code path in every
   system call we allow. While this would be a great thing to have, in
   practice this is an infeasibly large task (especially for Meredydd’s
   internship).

   Instead, we aim to have tests which give us confidence that each system
   call is permitted only if the capability it consumes has the rights listed
   in this table. We rely on human analysis to verify that allowing these
   system calls under these conditions will not break our security model.

   This approach leaves open the possibility that upstream extensions to the
   system call API open new holes. The primary defence is to be conservative
   about what we permit - for example, by whitelisting rather than blacklisting
   bitfields, which are a likely route for new functionality to be added.
   Unfortunately, this is not foolproof, and leaves us having to check
   changelogs carefully for new system call semantics as we merge.
*/


/* Provisional format:

   Standard:
	{fn: <function_name>, rights: [ "arg1right1|arg1right2", "arg2right1", ...],
	 flags_ok: [ "arg1flag1|arg1flag2", "arg2flag1", ...]}
	eg:
	{fn: "sys_write", rights: ["WRITE|SEEK"]}

   A "rights" definition can depend on flags present in another argument:
	rights: [{always: "right1|right2",
		  flags: [{FLAG1:"rightX|rightY",_FLAG2:"rightZ", ok: "FLAG1|FLAG2|..."},
			  ...] },
		 ...]
	(An underscore in front of a flag name means "require this right if this flag
	 is *not* set. If the syscall is called with a flag not mentioned in the flags: or ok: section,
         -ECAPMODE will be returned.)
	eg:
	{fn: "sys_openat", rights: [{always: "LOOKUP", flags: [null, null, {_O_WRONLY:"READ", O_WRONLY:"WRITE", ..., ok: "O_APPEND|..."}]}]}

	Also, adding {notnull: [null, "CONNECT|BIND"]} to rights: will
	require CAP_CONNECT and CAP_BIND when args[1] is non-NULL.
*/

/* Awkward cases as-yet unhandled:
	- select() and poll() might require a rethink of how we do TOCTOU
	  protection. (crosbug.com/30900)
	- fpathconf() is apparently different in Linux. (crosbug.com/53902)
	- mkfifo() goes via mknod(), which itself needs a decision.
	  (crosbug.com/30903)
	- Enforce CAP_BIND on the other ways a socket can be bound
	  implicitly (manpage mentions "as a result of connect() or send(),
	  and [] socket options set with setsockopt() may also affect
	  binding behaviour"). (crosbug.com/30904)
	- old_mmap(); anonymous mmap2(). (crosbug.com/90306)
	- Allow munmap()?  (crosbug.com/90307)
	- aio_*() (read, write, etc). (crosbug.com/30908)
	- recvmsg() - passing FDs over sockets. (crosbug.com/90309)

	- FreeBSD's cap_new() manpage is confusing on the subject of
	  CAP_LOOKUP - it seems to say that openat(), linkat() and unlinkat()
	  "are not available in capability mode as they manipulate a global
	  name space". Which...sounds wrong. I am allowing them in cap mode.

   Security audit TODO: (crosbug.com/30910)
	- Do the permissions for FreeBSD xattrs correspond directly to Linux's?
	- Do we need to require something else for faccessat()?
	- What permissions should we have for linkat/unlinkat/mkdirat/etc?
	- Case study: sctp_peeloff. What does it do?

   Places Linux just differs from FreeBSD: (crosbug.com/30910)
	- the sem_ stuff doesn't rely on FDs - it maps stuff into memory,
	  like a sensible creature. However, this means libc does literal
	  lookups of /dev/shm, then checks /proc/mounts, and all that jazz.
	  None of this is OK in capability mode.
*/

syscall_table = [
	{fn: "sys_accept", rights: ["ACCEPT"]},
	{fn: "sys_accept4", rights: ["ACCEPT"]},
	/* TODO(meredydd): ACL maintenance and checking. */
	{fn: "sys_bind", rights: ["BIND"]},
	{fn: "sys_connect", rights: ["CONNECT"]},
	{fn: "sys_sendto", rights: [{always: "WRITE", notnull: [null, null, null, null, "CONNECT"]}]},
	/* TODO(meredydd): select(), poll(), kevent() */
	/* TODO(meredydd): fexecve() */
	{fn: "sys_fremovexattr", rights: ["EXTATTR_DELETE"]},
	{fn: "sys_fgetxattr", rights: ["EXTATTR_GET"]},
	{fn: "sys_flistxattr", rights: ["EXTATTR_LIST"]},
	{fn: "sys_fsetxattr", rights: ["EXTATTR_SET"]},
	{fn: "sys_fchdir", rights: ["FCHDIR"]},
	/* TODO(meredydd): What's the equivalent of FreeBSD's fchflags()? */
	{fn: "sys_fchmod", rights: ["FCHMOD"]},
	{fn: "sys_fchown", rights: ["FCHOWN"]},
	{fn: "sys_fcntl", rights: ["FCNTL"]},
	{fn: "sys_flock", rights: ["FLOCK"]},
	/* TODO(meredydd): fpathconf() needs a closer look
	   {fn: "sys_fpathconf", rights: ["FPATHCONF"]},
	*/
	/* TODO(meredydd): What's the equivalent of FreeBSD's CAP_FSCK? */
	{fn: "sys_fstat", rights: ["FSTAT"]},
	/* TODO(meredydd): Do we need special support for aio_fsync? */
	{fn: "sys_fsync", rights: ["FSYNC"]},
	{fn: "sys_fdatasync", rights: ["FSYNC"]},
	{fn: "sys_ftruncate", rights: ["FTRUNCATE"]},
	/* glibc turns futimes() into utimensat() */
	{fn: "sys_utimensat", rights: [{always: "FUTIMES", notnull: [null, "LOOKUP"]}]},
	{fn: "sys_getpeername", rights: ["GETPEERNAME"]},
	{fn: "sys_getsockname", rights: ["GETSOCKNAME"]},
	{fn: "sys_getsockopt", rights: ["GETSOCKOPT"]},
	{fn: "sys_ioctl", rights: ["IOCTL"]},
	/* TODO(meredydd): What's the equivalent of FreeBSD's kevent()? */
	{fn: "sys_listen", rights: ["LISTEN"]},
	{fn: "sys_openat", rights:
		[{always: "LOOKUP",
			flags: [null,null, {_O_WRONLY:"READ",O_WRONLY:"WRITE",O_RDWR:"READ|WRITE",O_CREAT:"WRITE",
						O_EXCL:"WRITE",O_TRUNC:"WRITE",
						ok: "O_APPEND|FASYNC|O_CLOEXEC|O_DIRECT|O_DIRECTORY|O_LARGEFILE|O_NOATIME|O_NOCTTY|O_NOFOLLOW|O_NONBLOCK|O_SYNC",
						}]}]},
	{fn: "sys_faccessat", rights: ["LOOKUP"]},
	{fn: "sys_fchmodat", rights: ["LOOKUP|FCHMOD"]},
	{fn: "sys_fchownat", rights: ["LOOKUP|FCHOWN"]},
	{fn: "sys_newfstatat", rights: ["LOOKUP|FSTAT"]},
	{fn: "sys_futimesat", rights: ["LOOKUP|FUTIMES"]},
	{fn: "sys_linkat", rights: ["LOOKUP", null, "LOOKUP|CREATE"]},
	{fn: "sys_mkdirat", rights: ["LOOKUP|MKDIR"]},
	/*{fn: "sys_mknodat", rights: ["LOOKUP|CREATE"]},*/  /* This needs a security audit! */
	{fn: "sys_readlinkat", rights: ["LOOKUP|READ"]},
	{fn: "sys_renameat", rights: ["LOOKUP|DELETE", null, "LOOKUP|CREATE"]},
	{fn: "sys_symlinkat", rights: [null, "LOOKUP|CREATE"]},
	{fn: "sys_unlinkat", rights: ["LOOKUP|DELETE"]},
	/* UML relies on mmap_old */
	{fn: "sys_mmap_pgoff", rights:
		[null, null, null, null,
		 {always: "MMAP",
		  flags: [null, null, null,
			  {PROT_READ: "READ", PROT_WRITE: "WRITE", PROT_EXEC: "MAPEXEC",
			   ok: "MAP_SHARED|MAP_PRIVATE|MAP_32BIT|MAP_FIXED|MAP_HUGETLB|MAP_NONBLOCK|MAP_NORESERVE|MAP_POPULATE|MAP_STACK"
			  }]}]},
	/* Omit all the PD* capabilities, because we don't have PDs yet. */
	/* Omit aio_*() for now */
	{fn: "sys_pread64", rights: ["READ"]},
	{fn: "sys_read", rights: ["READ|SEEK"]},
	{fn: "sys_recv", rights: ["READ"]},
	{fn: "sys_recvfrom", rights: ["READ"]},
	/* Omit recvmsg() until we have a good story on how to transfer fds. */
	/* frevoke() does not exist on Linux */
	{fn: "sys_lseek", rights: ["SEEK"]},
	{fn: "sys_setsockopt", rights: ["SETSOCKOPT"]},
	{fn: "sys_shutdown", rights: ["SHUTDOWN"]},
	{fn: "sys_write", rights: ["WRITE|SEEK"]},
	{fn: "sys_pwrite64", rights: ["WRITE"]},
	{fn: "sys_send", rights: ["WRITE"]},

	{fn: "sys_pdfork", flags_ok: [null, "0"]},
	{fn: "sys_pdkill"},

	/* Unconditionally OK. */
	{fn: "sys_close"},
	{fn: "sys_cap_new"},
	{fn: "sys_exit"},
];


// Generate the table!

out = "/*\n\
 * System call permission table for Capsicum, a capability API for UNIX.\n\
 *\n\
 * Copyright (C) 2012 The Chromium OS Authors <chromium-os-dev@chromium.org>\n\
 *\n\
 * This program is free software; you can redistribute it and/or modify\n\
 * it under the terms of the GNU General Public License version 2, as\n\
 * published by the Free Software Foundation.\n\
 *\n\
 * This file is generated by capsicum_table.js. It should not live in the\n\
 * repository in the long term: eventually, capsicum_table.js will be\n\
 * rewritten in Perl, and will be invoked automatically by the build system,\n\
 * and this file will be removed from the repository.\n\
 */\n\
#include <linux/mman.h>\n\
\n\
static int run_syscall_table(void *call, unsigned long *args)\n\
{\n\n";

function cap_bits(rstr) {
	if (!rstr) { return "0"; }

	var r = rstr.split("|");

	for (var k in r) {
		r[k] = "CAP_" + r[k];
	}
	return r.join("|");
}

for(var i in syscall_table) {

	var spec = syscall_table[i];
	var first = true;
	var handled_flags = [];

	out += "\tif (call == (void *)"+spec.fn+")\n\t\treturn ";

	for (var j in spec.rights) {
		var rspec = spec.rights[j];
		if (!rspec) { continue; }

		out += (first?"":"\n\t\t\t?: ");
		first = false;

		if (!(rspec.flags || rspec.notnull)) {
			out += "require_rights(args["+j+"], " + cap_bits(rspec)+")";
		} else {
			var ffirst = true;
			out += "require_rights(args["+j+"], ";
			if (rspec.always) {
				out += cap_bits(rspec.always);
				ffirst = false;
			}
			for (var fn in rspec.flags) {
				var flags = rspec.flags[fn];
				if (!flags) { continue; }
				handled_flags[fn] = [];

				for (var flag in flags) {
					if (flag == "ok") {
						handled_flags[fn] = handled_flags[fn].concat(flags[flag]);
						continue;
					}

					var inv = "";
					var caps = cap_bits(flags[flag]);
					var invcaps = cap_bits(flags["_"+flag]);

					if (flag.charAt(0) == "_" && flags[flag.substring(1)]) {
						continue;
					}
					if (!ffirst) {
						out += "\n\t\t\t\t\t| ";
					}
					out += "(args["+fn+"] & "+flag+" ? " + caps + " : " + invcaps +")";
					handled_flags[fn].push(flag);
					ffirst = false;
				}
			}
			for (var nn in rspec.notnull) {
				var notnull = rspec.notnull[nn];

				if (!notnull) { continue; }
				var caps = cap_bits(notnull);
				if (!ffirst) {
					out += "\n\t\t\t\t\t| ";
				}
				ffirst = false;
				out += "(((void *)args["+nn+"] != NULL) ? " + caps + " : 0)";
			}
			out += ")";
		}
	}

	for (var j in spec.flags_ok) {
		var handled = handled_flags[j];
		var flags = spec.flags_ok[j];

		if (flags) {
			if (!handled)
				handled = [];
			handled_flags[j] = handled.concat(flags);
		}
	}

	for (var fn in handled_flags) {
		if (handled_flags[fn]) {
			if (!first) {
				out += "\n\t\t\t?: ";
			}
			first = false;
			out += "(args["+fn+"] & ~("+handled_flags[fn].join("|")+") ? -ECAPMODE : 0)";
		}
	}

	if (first) {
		out += "0";
	}

	out += ";\n\n";

}

out += "\treturn -ECAPMODE;\n";

out += "}\n";

f = new java.io.FileOutputStream("capsicum_syscall_table.h");
f.write(new java.lang.String(out).getBytes());
f.close();

