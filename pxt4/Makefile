# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the linux ext4-filesystem routines.
#

obj-m += jbd3/ pxt4.o

pxt4-y	:= balloc.o bitmap.o block_validity.o dir.o pxt4_jbd3.o extents.o \
		extents_status.o file.o fsmap.o fsync.o hash.o ialloc.o \
		indirect.o inline.o inode.o ioctl.o mballoc.o migrate.o \
		mmp.o move_extent.o namei.o page-io.o readpage.o resize.o \
		super.o symlink.o sysfs.o xattr.o xattr_hurd.o xattr_trusted.o \
		xattr_user.o fast_commit.o orphan.o

pxt4-m	+= acl.o
pxt4-m		+= xattr_security.o
pxt4-inode-test-objs			+= inode-test.o
obj-$(CONFIG_PXT4_KUNIT_TESTS)		+= pxt4-inode-test.o
pxt4-m		+= verity.o
pxt4-m		+= crypto.o


KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	rm *.mod.*
	rm *.ko
	rm *.o
