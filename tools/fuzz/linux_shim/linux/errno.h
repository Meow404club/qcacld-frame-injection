/* SPDX-License-Identifier: ISC */
/*
 * Kernel errno values for the host harness. The host libc's errno.h is not
 * relied upon: the parser's return contract and the frozen manifest record
 * these exact kernel numbers.
 */
#ifndef HOST_FUZZ_SHIM_LINUX_ERRNO_H
#define HOST_FUZZ_SHIM_LINUX_ERRNO_H

#define EPERM 1
#define ENOENT 2
#define EIO 5
#define ENOMEM 12
#define EBUSY 16
#define EEXIST 17
#define EINVAL 22
#define EMSGSIZE 90
#define EOPNOTSUPP 95
#define ENOTSUP EOPNOTSUPP
#define EADDRINUSE 98
#define ENETDOWN 100
#define ENODEV 19
#define EUCLEAN 117
#define ENODATA 61
#define ERANGE 34
#define EBADMSG 74
#define ESHUTDOWN 103
#define ETIMEDOUT 110
#define EAGAIN 11
#define ECANCELED 125
#define EPROTONOSUPPORT 93

#endif /* HOST_FUZZ_SHIM_LINUX_ERRNO_H */
