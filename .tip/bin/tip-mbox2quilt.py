#!/usr/bin/env python
#
# Convert mbox to quilt series
#
# (C) 2007-2009 Thomas Gleixner <tglx@linutronix.de>
# (C) 2009 Ingo Molnar <mingo@elte.hu>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#

import os
import re
import sys
import getopt
import email
import mailbox
import string
import commands
import urllib

# Print the usage information
def usage():
	print "USAGE:"
	print "mbox2quilt.py <-h -v mbox>"
	print "  -v        verbose"
	return

def subject_to_fname(mailsubject):

	fn = mailsubject.lower()
	fname = ""
	i = 0
	while i < len(fn):
		c = fn[i]
		if c in string.digits or c in string.lowercase or c in "_":
			fname = fname + c
		else:
			if len(fname) > 0 and not fname.endswith("-"):
				fname = fname + "-"
		i += 1

	if fname.endswith("-"):
		fname = fname[:len(fname)-1]
	return fname + ".patch"

def parse_msg(body, fdp, mailcc, messageid):

	sobfound = 0
	lkml_posting = 0
	lines = body.split("\n")

	acks = ""
	for line in lines:
		if line.strip().startswith("Signed-off-by: "):
			acks = acks + line + "\n"
		if line.strip().startswith("Acked-by: "):
			acks = acks + line + "\n"
		if line.strip().startswith("Reviewed-by: "):
			acks = acks + line + "\n"
		if line.strip().startswith("Reported-by: "):
			acks = acks + line + "\n"
		if line.strip().startswith("Tested-by: "):
			acks = acks + line + "\n"
	acks = acks.split("\n")

	align_buf = ""
	align_tail_once = 1

	for line in lines:
		if sobfound == 0:
			if line.strip().startswith("Signed-off-by"):
				sobfound = 1
		elif sobfound == 1:
			if line.strip().startswith("Signed-off-by"):
				pass
			elif line.strip().startswith("Acked-by"):
				pass
			elif line.strip().startswith("Reviewed-by"):
				pass
			else:
				for cc in mailcc:
					cc = cc.strip()
					cc = cc.replace("\"", "")
					#
					# Skip maintainers and lkml:
					#
					if cc.find("tglx") >= 0:
						continue
					if cc.find("hpa@zytor") >= 0:
						continue
					if cc.find("mingo") >= 0:
						continue
					if cc.find("akpm") >= 0:
						continue
					if cc.find("x86@kernel.org") >= 0:
						continue
					if cc.find("vger.kernel.org") >= 0:
						lkml_posting = 1
						continue

					ack_match = 0
					for ack in acks:
						if ack.find(cc) >= 0:
							ack_match = 1
							break

					if ack_match == 0:
						fdp.write("Cc: " + cc + "\n")

				if lkml_posting == 1:
					fdp.write("Link: http://lkml.kernel.org/r/" + messageid + "\n")
				fdp.write("Signed-off-by: " + mailaddr + "\n")
				sobfound = 3

		cols = 65

		if cols and sobfound == 0:
			if align_buf != "":
				if line != "":
					align_buf += " " + line
			else:
				align_buf = line

			if len(align_buf) >= 65 and line != "" and not line[0].isspace():

				space_idx = -1
				for i in range(65):
					if align_buf[i] == " ":
						space_idx = i

				if space_idx == -1:
					fdp.write(align_buf + "\n")
					align_buf = ""
				else:
					fdp.write(align_buf[0:space_idx] + "\n")
					align_buf = align_buf[space_idx+1:]
			else:
				fdp.write(align_buf + "\n")
				if align_buf != "" and line == "":
					fdp.write("\n")
				align_buf = ""
		else:
			if align_buf != "":
				fdp.write(align_buf + "\n")
				align_buf = ""

			fdp.write(line + "\n")


# Verbose output
verbose = 1

# Here we go
# Parse the commandline
try:
	(options, arguments) = getopt.getopt(sys.argv[1:],'hv')
except getopt.GetoptError, ex:
	print
	print "ERROR:"
	print ex.msg
	usage()
	sys.exit(1)
	pass

for option, value in options:
	if option == '-v':
		verbose = 1
	elif option == '-h':
		usage()
		sys.exit(0)
		pass
	pass

if len(arguments) != 1:
    usage()
    sys.exit(1)


patchdir = "patches"

if len(arguments) > 1:
    patchdir = patchdir %(arguments[1])

cmd = "mkdir " + patchdir + " 2>/dev/null"
os.system(cmd)

cmd = "echo $(git config --get user.name)' <'$(git config --get user.email)'>'"
mailaddr = commands.getoutput(cmd)

print mailaddr
exit

fd = open(arguments[0], "r")
mbx = mailbox.PortableUnixMailbox(fd, email.message_from_file)

rmpatch = re.compile("\[[^\]]*[Pp][Aa][Tt][Cc][Hh][^\]]*\]")

fds = open(patchdir + "/series", "a")

while 1:

	mbxmsg = mbx.next()
	if not mbxmsg:
		break

	msg = email.message_from_string(mbxmsg.as_string())

	try:
		mailto = msg.get("To").split(",")
	except:
		mailto = "".split()

	try:
		mailcc = msg.get("Cc").split(",")
	except:
		mailcc = "".split()
	mailcc.extend(mailto)

	mailsubject = msg.get("Subject")
	mailfrom = msg.get("From")
	maildate = msg.get("Date")

	#
	# Get the raw Message-ID header field from the mail:
	#
	messageid = msg.get("Message-ID")

	#
	# First strip the <> from the Message-ID:
	#
	messageid = messageid[+1:-1]

	#
	# Message-ID is used for Link: tag URL generation,
	# it is untrusted external data, so escape script-unsafe
	# characters.
	#
	# Note, we make a special exception for '@' which is
	# technically not URL-safe - but it's script-safe and
	# makes for more human-readable commit logs:
	#
	messageid = urllib.quote(messageid, "@")

	mailsubject = mailsubject.replace("\n", "")
	mailsubject = mailsubject.replace("\t", " ")

	subject = str(rmpatch.sub("", mailsubject)).strip().rstrip(".")
	subject = urllib.quote(subject, " :[](),/")
	fname = subject_to_fname(subject)

	idx = subject.find(":")
	if idx >= 0:
		idx += 2
		if idx < len(subject):
			subject = subject[0:idx] + subject[idx].capitalize() + subject[idx+1:]

	# Add it to series file
	fds.write(fname + "\n")

	fdp = open(patchdir + "/" + fname, "w")
	fdp.write("Subject: " + subject + "\n")
	fdp.write("From: " + mailfrom + "\n")
	fdp.write("Date: " + maildate + "\n")
	fdp.write("\n")

	for part in msg.walk():
		if part.get_content_type().find("multipart") >= 0:
			continue

		body = part.get_payload(decode=True)
		if body:
			parse_msg(body, fdp, mailcc, messageid)

	fdp.close()

fds.close()
