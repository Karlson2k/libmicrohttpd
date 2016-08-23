/*
  This file is part of libmicrohttpd
  Copyright (C) 2014-2016 Karlson2k (Evgeny Grin)

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

*/

/**
 * @file microhttpd/mhd_sockets.c
 * @brief  Implementation for sockets functions
 * @author Karlson2k (Evgeny Grin)
 */

#include "mhd_sockets.h"
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /* HAVE_UNISTD_H */
#include <fcntl.h>

#ifdef MHD_WINSOCK_SOCKETS

/**
 * Return pointer to string description of specified WinSock error
 * @param err the WinSock error code.
 * @return pointer to string description of specified WinSock error.
 */
const char* MHD_W32_strerror_winsock_(int err)
{
  switch (err)
    {
  case 0:
    return "No error";
  case WSA_INVALID_HANDLE:
    return "Specified event object handle is invalid";
  case WSA_NOT_ENOUGH_MEMORY:
    return "Insufficient memory available";
  case WSA_INVALID_PARAMETER:
    return "One or more parameters are invalid";
  case WSA_OPERATION_ABORTED:
    return "Overlapped operation aborted";
  case WSA_IO_INCOMPLETE:
    return "Overlapped I/O event object not in signaled state";
  case WSA_IO_PENDING:
    return "Overlapped operations will complete later";
  case WSAEINTR:
    return "Interrupted function call";
  case WSAEBADF:
    return "File handle is not valid";
  case WSAEACCES:
    return "Permission denied";
  case WSAEFAULT:
    return "Bad address";
  case WSAEINVAL:
    return "Invalid argument";
  case WSAEMFILE:
    return "Too many open files";
  case WSAEWOULDBLOCK:
    return "Resource temporarily unavailable";
  case WSAEINPROGRESS:
    return "Operation now in progress";
  case WSAEALREADY:
    return "Operation already in progress";
  case WSAENOTSOCK:
    return "Socket operation on nonsocket";
  case WSAEDESTADDRREQ:
    return "Destination address required";
  case WSAEMSGSIZE:
    return "Message too long";
  case WSAEPROTOTYPE:
    return "Protocol wrong type for socket";
  case WSAENOPROTOOPT:
    return "Bad protocol option";
  case WSAEPROTONOSUPPORT:
    return "Protocol not supported";
  case WSAESOCKTNOSUPPORT:
    return "Socket type not supported";
  case WSAEOPNOTSUPP:
    return "Operation not supported";
  case WSAEPFNOSUPPORT:
    return "Protocol family not supported";
  case WSAEAFNOSUPPORT:
    return "Address family not supported by protocol family";
  case WSAEADDRINUSE:
    return "Address already in use";
  case WSAEADDRNOTAVAIL:
    return "Cannot assign requested address";
  case WSAENETDOWN:
    return "Network is down";
  case WSAENETUNREACH:
    return "Network is unreachable";
  case WSAENETRESET:
    return "Network dropped connection on reset";
  case WSAECONNABORTED:
    return "Software caused connection abort";
  case WSAECONNRESET:
    return "Connection reset by peer";
  case WSAENOBUFS:
    return "No buffer space available";
  case WSAEISCONN:
    return "Socket is already connected";
  case WSAENOTCONN:
    return "Socket is not connected";
  case WSAESHUTDOWN:
    return "Cannot send after socket shutdown";
  case WSAETOOMANYREFS:
    return "Too many references";
  case WSAETIMEDOUT:
    return "Connection timed out";
  case WSAECONNREFUSED:
    return "Connection refused";
  case WSAELOOP:
    return "Cannot translate name";
  case WSAENAMETOOLONG:
    return "Name too long";
  case WSAEHOSTDOWN:
    return "Host is down";
  case WSAEHOSTUNREACH:
    return "No route to host";
  case WSAENOTEMPTY:
    return "Directory not empty";
  case WSAEPROCLIM:
    return "Too many processes";
  case WSAEUSERS:
    return "User quota exceeded";
  case WSAEDQUOT:
    return "Disk quota exceeded";
  case WSAESTALE:
    return "Stale file handle reference";
  case WSAEREMOTE:
    return "Item is remote";
  case WSASYSNOTREADY:
    return "Network subsystem is unavailable";
  case WSAVERNOTSUPPORTED:
    return "Winsock.dll version out of range";
  case WSANOTINITIALISED:
    return "Successful WSAStartup not yet performed";
  case WSAEDISCON:
    return "Graceful shutdown in progress";
  case WSAENOMORE:
    return "No more results";
  case WSAECANCELLED:
    return "Call has been canceled";
  case WSAEINVALIDPROCTABLE:
    return "Procedure call table is invalid";
  case WSAEINVALIDPROVIDER:
    return "Service provider is invalid";
  case WSAEPROVIDERFAILEDINIT:
    return "Service provider failed to initialize";
  case WSASYSCALLFAILURE:
    return "System call failure";
  case WSASERVICE_NOT_FOUND:
    return "Service not found";
  case WSATYPE_NOT_FOUND:
    return "Class type not found";
  case WSA_E_NO_MORE:
    return "No more results";
  case WSA_E_CANCELLED:
    return "Call was canceled";
  case WSAEREFUSED:
    return "Database query was refused";
  case WSAHOST_NOT_FOUND:
    return "Host not found";
  case WSATRY_AGAIN:
    return "Nonauthoritative host not found";
  case WSANO_RECOVERY:
    return "This is a nonrecoverable error";
  case WSANO_DATA:
    return "Valid name, no data record of requested type";
  case WSA_QOS_RECEIVERS:
    return "QoS receivers";
  case WSA_QOS_SENDERS:
    return "QoS senders";
  case WSA_QOS_NO_SENDERS:
    return "No QoS senders";
  case WSA_QOS_NO_RECEIVERS:
    return "QoS no receivers";
  case WSA_QOS_REQUEST_CONFIRMED:
    return "QoS request confirmed";
  case WSA_QOS_ADMISSION_FAILURE:
    return "QoS admission error";
  case WSA_QOS_POLICY_FAILURE:
    return "QoS policy failure";
  case WSA_QOS_BAD_STYLE:
    return "QoS bad style";
  case WSA_QOS_BAD_OBJECT:
    return "QoS bad object";
  case WSA_QOS_TRAFFIC_CTRL_ERROR:
    return "QoS traffic control error";
  case WSA_QOS_GENERIC_ERROR:
    return "QoS generic error";
  case WSA_QOS_ESERVICETYPE:
    return "QoS service type error";
  case WSA_QOS_EFLOWSPEC:
    return "QoS flowspec error";
  case WSA_QOS_EPROVSPECBUF:
    return "Invalid QoS provider buffer";
  case WSA_QOS_EFILTERSTYLE:
    return "Invalid QoS filter style";
  case WSA_QOS_EFILTERTYPE:
    return "Invalid QoS filter type";
  case WSA_QOS_EFILTERCOUNT:
    return "Incorrect QoS filter count";
  case WSA_QOS_EOBJLENGTH:
    return "Invalid QoS object length";
  case WSA_QOS_EFLOWCOUNT:
    return "Incorrect QoS flow count";
  case WSA_QOS_EUNKOWNPSOBJ:
    return "Unrecognized QoS object";
  case WSA_QOS_EPOLICYOBJ:
    return "Invalid QoS policy object";
  case WSA_QOS_EFLOWDESC:
    return "Invalid QoS flow descriptor";
  case WSA_QOS_EPSFLOWSPEC:
    return "Invalid QoS provider-specific flowspec";
  case WSA_QOS_EPSFILTERSPEC:
    return "Invalid QoS provider-specific filterspec";
  case WSA_QOS_ESDMODEOBJ:
    return "Invalid QoS shape discard mode object";
  case WSA_QOS_ESHAPERATEOBJ:
    return "Invalid QoS shaping rate object";
  case WSA_QOS_RESERVED_PETYPE:
    return "Reserved policy QoS element type";
    }
  return "Unknown winsock error";
}


#endif /* MHD_WINSOCK_SOCKETS */


/**
 * Add @a fd to the @a set.  If @a fd is
 * greater than @a max_fd, set @a max_fd to @a fd.
 *
 * @param fd file descriptor to add to the @a set
 * @param set set to modify
 * @param max_fd maximum value to potentially update
 * @param fd_setsize value of FD_SETSIZE
 * @return non-zero if succeeded, zero otherwise
 */
int
MHD_add_to_fd_set_ (MHD_socket fd,
                    fd_set *set,
                    MHD_socket *max_fd,
                    unsigned int fd_setsize)
{
  if (NULL == set || MHD_INVALID_SOCKET == fd)
    return 0;
  if (!MHD_SCKT_FD_FITS_FDSET_SETSIZE_(fd, set, fd_setsize))
    return 0;
  MHD_SCKT_ADD_FD_TO_FDSET_SETSIZE_(fd, set, fd_setsize);
  if ( (NULL != max_fd) &&
       ((fd > *max_fd) || (MHD_INVALID_SOCKET == *max_fd)) )
    *max_fd = fd;

  return !0;
}


/**
 * Change socket options to be non-blocking.
 *
 * @param sock socket to manipulate
 * @return non-zero if succeeded, zero otherwise
 */
int
MHD_socket_nonblocking_ (MHD_socket sock)
{
#if defined(MHD_POSIX_SOCKETS)
  int flags;

  flags = fcntl (sock, F_GETFL);
  if (-1 == flags)
    return 0;

  if ( ((flags | O_NONBLOCK) != flags) &&
       (0 != fcntl (sock, F_SETFL, flags | O_NONBLOCK)) )
    return 0;
#elif defined(MHD_WINSOCK_SOCKETS)
  unsigned long flags = 1;

  if (0 != ioctlsocket (sock, FIONBIO, &flags))
    return 0;
#endif /* MHD_WINSOCK_SOCKETS */
  return !0;
}
