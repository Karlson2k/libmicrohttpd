/*
     This file is part of libmicrohttpd
     (C) 2010 Daniel Pittman and Christian Grothoff

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
 * @file digestauth.c
 * @brief Implements HTTP/1.1 Digest Auth according to RFC2617
 * @author Amr Ali
 */

#include "internal.h"
#include "md5.h"

#define HASH_MD5_HEX_LEN (2 * MD5_DIGEST_SIZE)

/**
 * Beginning string for any valid Digest authentication header.
 */
#define _BASE		"Digest "

/**
 * Maximum length of a username for digest authentication.
 */
#define MAX_USERNAME_LENGTH 128

/**
 * Maximum length of a realm for digest authentication.
 */
#define MAX_REALM_LENGTH 256

/**
 * Maximum length of a nonce in digest authentication.
 */
#define MAX_NONCE_LENGTH 128

/**
 * Maximum length of the response in digest authentication.
 */
#define MAX_AUTH_RESPONSE_LENGTH 128

/**
 * convert bin to hex 
 *
 * @param bin binary data
 * @param len number of bytes in bin
 * @param hex pointer to len*2+1 bytes
 */
static void
cvthex(const unsigned char *bin,
       size_t len,
       char *hex)
{
  size_t i;
  unsigned int j;
  
  for (i = 0; i < len; ++i) 
    {
      j = (bin[i] >> 4) & 0x0f;      
      hex[i * 2] = j <= 9 ? (j + '0') : (j + 'a' - 10);    
      j = bin[i] & 0x0f;    
      hex[i * 2 + 1] = j <= 9 ? (j + '0') : (j + 'a' - 10);
    }
  hex[len * 2] = '\0';
}

/**
 * calculate H(A1) as per RFC2617 spec and store the
 * result in 'sessionkey'.
 *
 * @param alg FIXME: document
 * @param username FIXME: document
 * @param realm FIXME: document
 * @param password FIXME: document
 * @param nonce FIXME: document
 * @param cnonce FIXME: document
 * @param sessionkey pointer to buffer of HASH_MD5_HEX_LEN+1 bytes
 */
static void
digest_calc_ha1(const char *alg,
		const char *username,
		const char *realm,
		const char *password,
		const char *nonce,
		const char *cnonce,
		char *sessionkey)
{
  struct MD5Context md5;
  unsigned char ha1[MD5_DIGEST_SIZE];
  
  MD5Init (&md5);
  MD5Update (&md5, username, strlen (username));
  MD5Update (&md5, ":", 1);
  MD5Update (&md5, realm, strlen (realm));
  MD5Update (&md5, ":", 1);
  MD5Update (&md5, password, strlen (password));
  MD5Final (ha1, &md5);
  if (0 == strcasecmp(alg, "md5-sess")) 
    {
      MD5Init (&md5);
      MD5Update (&md5, ha1, sizeof (ha1));
      MD5Update (&md5, ":", 1);
      MD5Update (&md5, nonce, strlen (nonce));
      MD5Update (&md5, ":", 1);
      MD5Update (&md5, cnonce, strlen (cnonce));
      MD5Final (ha1, &md5);
    }
  cvthex(ha1, sizeof (ha1), sessionkey);
}


/**
 * calculate request-digest/response-digest as per RFC2617 spec 
 * 
 * @param ha1 H(A1)
 * @param nonce nonce from server
 * @param noncecount 8 hex digits
 * @param cnonce client nonce
 * @param qop qop-value: "", "auth" or "auth-int"
 * @param method method from request
 * @param uri requested URL
 * @param hentity H(entity body) if qop="auth-int"
 * @param response request-digest or response-digest
 */
static void
digest_calc_response(const char *ha1,
		     const char *nonce,
		     const char *noncecount,
		     const char *cnonce,
		     const char *qop,
		     const char *method,
		     const char *uri,
		     const char *hentity,
		     char *response)
{
  struct MD5Context md5;
  unsigned char ha2[MD5_DIGEST_SIZE];
  unsigned char resphash[MD5_DIGEST_SIZE];
  char ha2hex[HASH_MD5_HEX_LEN + 1];
  
  MD5Init (&md5);
  MD5Update (&md5, method, strlen(method));
  MD5Update (&md5, ":", 1);
  MD5Update (&md5, uri, strlen(uri));  
  if (strcasecmp(qop, "auth-int") == 0) 
    {
      MD5Update (&md5, ":", 1);
      MD5Update (&md5, hentity, strlen(hentity));
    }  
  MD5Final (ha2, &md5);
  cvthex(ha2, MD5_DIGEST_SIZE, ha2hex);
  MD5Init (&md5);  
  /* calculate response */  
  MD5Update (&md5, ha1, HASH_MD5_HEX_LEN);
  MD5Update (&md5, ":", 1);
  MD5Update (&md5, nonce, strlen(nonce));
  MD5Update (&md5, ":", 1);  
  if ('\0' != *qop)
    {
      MD5Update (&md5, noncecount, strlen(noncecount));
      MD5Update (&md5, ":", 1);
      MD5Update (&md5, cnonce, strlen(cnonce));
      MD5Update (&md5, ":", 1);
      MD5Update (&md5, qop, strlen(qop));
      MD5Update (&md5, ":", 1);
    }  
  MD5Update (&md5, ha2hex, HASH_MD5_HEX_LEN);
  MD5Final (resphash, &md5);
  cvthex(resphash, sizeof (resphash), response);
}


/**
 * Lookup subvalue off of the HTTP Authorization header.
 *
 * A description of the input format for 'data' is at
 * http://en.wikipedia.org/wiki/Digest_access_authentication
 *
 *
 * @param dest where to store the result (possibly truncated if
 *             the buffer is not big enough).
 * @param size size of dest
 * @param data pointer to the Authorization header
 * @param key key to look up in data
 * @return size of the located value, 0 if otherwise
 */
static int
lookup_sub_value(char *dest,
		 size_t size,
		 const char *data,
		 const char *key)
{
  size_t keylen = strlen(key);
  size_t len;
  const char *ptr = data;
  const char *eq;
  const char *q1;
  const char *q2;
  const char *qn;

  if (0 == size)
    return 0;
  while ('\0' != *ptr)
    {
      if (NULL == (eq = strstr (ptr, "=")))
	return 0;
      q1 = eq + 1;
      while (' ' == *q1)
	q1++;      
      if ('\"' != *q1)
	{
	  q2 = strstr (q1, ",");
	  qn = q2;
	}
      else
	{
	  q1++;
	  q2 = strstr (q1, "\"");
	  if (NULL == q2)
	    return 0; /* end quote not found */
	  qn = q2 + 1;
	}      
      if ( (0 == strncasecmp (ptr,
			      key,
			      keylen)) &&
	   (eq == &ptr[keylen]) )
	{
	  if (q2 == NULL)
	    {
	      len = strlen (q1) + 1;
	      if (size > len)
		size = len;
	      size--;
	      strncpy (dest,
		       q1,
		       size);
	      dest[size] = '\0';
	      return size;
	    }
	  else
	    {
	      if (size > (q2 - q1) + 1)
		size = (q2 - q1) + 1;
	      size--;
	      memcpy (dest, 
		      q1,
		      size);
	      dest[size] = '\0';
	      return size;
	    }
	}
      if (NULL == qn)
	return 0;
      ptr = strstr (qn, ",");
      if (NULL == ptr)
	return 0;
      ptr++;
      while (' ' == *ptr)
	ptr++;
    }
  return 0;
}


/**
 * Get the username from the authorization header sent by the client
 *
 * @param connection The MHD connection structure
 * @return NULL if no username could be found, a pointer
 * 			to the username if found
 */
char *
MHD_digest_auth_get_username(struct MHD_Connection *connection)
{
  size_t len;
  char user[MAX_USERNAME_LENGTH];
  const char *header;
  
  header = MHD_lookup_connection_value(connection,
				       MHD_HEADER_KIND, 
				       MHD_HTTP_HEADER_AUTHORIZATION); 
  if (header == NULL)
    return NULL;
  if (strncmp(header, _BASE, strlen(_BASE)) != 0)
    return NULL;
  header += strlen (_BASE);
  len = lookup_sub_value(user,
			 sizeof (user),
			 header, 
			 "username");
  if (!len)
    return NULL;
  return strdup(user);
}


/**
 * FIXME: document
 *
 * @param nonce_time  FIXME: document
 * @param method  FIXME: document
 * @param rnd  FIXME: document
 * @param uri  FIXME: document
 * @param realm  FIXME: document
 * @param nonce  FIXME: document
 */
static void
calculate_nonce (uint32_t nonce_time,
		 const char *method,
		 const char *rnd,
		 const char *uri,
		 const char *realm,
		 char *nonce)
{
  struct MD5Context md5;
  unsigned char timestamp[4];
  unsigned char tmpnonce[MD5_DIGEST_SIZE];
  char timestamphex[sizeof(timestamp)*2+1];

  MD5Init (&md5);
  timestamp[0] = (nonce_time & 0xff000000) >> 0x18;
  timestamp[1] = (nonce_time & 0x00ff0000) >> 0x10;
  timestamp[2] = (nonce_time & 0x0000ff00) >> 0x08;
  timestamp[3] = (nonce_time & 0x000000ff);    
  MD5Update(&md5, timestamp, 4);
  MD5Update(&md5, ":", 1);
  MD5Update(&md5, method, strlen(method));
  MD5Update(&md5, ":", 1);
  MD5Update(&md5, rnd, strlen(rnd));
  MD5Update(&md5, ":", 1);
  MD5Update(&md5, uri, strlen(uri));
  MD5Update(&md5, ":", 1);
  MD5Update(&md5, realm, strlen(realm));
  MD5Final (tmpnonce, &md5);  
  cvthex(tmpnonce, sizeof (tmpnonce), nonce);  
  cvthex(timestamp, 4, timestamphex);
  strncat(nonce, timestamphex, 8);
}


/**
 * Authenticates the authorization header sent by the client
 *
 * @param connection The MHD connection structure
 * @param realm The realm presented to the client
 * @param username The username needs to be authenticated
 * @param password The password used in the authentication
 * @param nonce_timeout The amount of time for a nonce to be
 * 			invalid in seconds
 * @return MHD_YES if authenticated, MHD_NO if not,
 * 			MHD_INVALID_NONCE if nonce is invalid
 */
int
MHD_digest_auth_check(struct MHD_Connection *connection,
		      const char *realm,
		      const char *username,
		      const char *password,
		      unsigned int nonce_timeout)
{
  size_t len;
  const char *header;
  char nonce[MAX_NONCE_LENGTH];
  char cnonce[MAX_NONCE_LENGTH];
  /* char qop[15]; // Uncomment when supporting "auth-int" */  
  const char * qop = "auth"; /* "auth-int" is not supported */
  char nc[20];
  char response[MAX_AUTH_RESPONSE_LENGTH];
  const char *hentity = NULL; /* "auth-int" is not supported */
  char ha1[HASH_MD5_HEX_LEN + 1];
  char respexp[HASH_MD5_HEX_LEN + 1];
  char noncehashexp[HASH_MD5_HEX_LEN + 9];
  uint32_t nonce_time;
  uint32_t t;
  size_t left; /* number of characters left in 'header' for 'uri' */

  header = MHD_lookup_connection_value(connection,
				       MHD_HEADER_KIND,
				       MHD_HTTP_HEADER_AUTHORIZATION);  
  if (header == NULL) 
    return MHD_NO;
  if (strncmp(header, _BASE, strlen(_BASE)) != 0) 
    return MHD_NO;
  header += strlen (_BASE);
  left = strlen (header);

  {
    char un[MAX_USERNAME_LENGTH];
    len = lookup_sub_value(un,
			   sizeof (un),
			   header, "username");
    if ( (!len) ||
	 (strcmp(username, un) != 0) ) 
      return MHD_NO;
    left -= strlen ("username") + len;
  }

  {
    char r[MAX_REALM_LENGTH];
    len = lookup_sub_value(r, 
			   sizeof (r),
			   header, "realm");  
    if ( (!len) || 
	 (strcmp(realm, r) != 0) )
      return MHD_NO;
    left -= strlen ("realm") + len;
  }

  if (0 == (len = lookup_sub_value(nonce, 
				   sizeof (nonce),
				   header, "nonce")))
    return MHD_NO;
  left -= strlen ("nonce") + len;

  {
    char uri[left];  
  
    if (0 == lookup_sub_value(uri,
			      sizeof (uri),
			      header, "uri")) 
      return MHD_NO;
      
    /* 8 = 4 hexadecimal numbers for the timestamp */  
    nonce_time = strtoul(nonce + len - 8, 0, 16);  
    t = (uint32_t) time(NULL);    
    /*
     * First level vetting for the nonce validity
     * if the timestamp attached to the nonce
     * exceeds `nonce_timeout' then the nonce is
     * invalid.
     */
    if (t > nonce_time + nonce_timeout) 
      return MHD_INVALID_NONCE;    
    calculate_nonce (nonce_time,
		     connection->method,
		     connection->daemon->digest_auth_random,
		     uri,
		     realm,
		     noncehashexp);
    /*
     * Second level vetting for the nonce validity
     * if the timestamp attached to the nonce is valid
     * and possibility fabricated (in case of an attack)
     * the attacker must also know the password to be
     * able to generate a "sane" nonce, which if he does
     * not, the nonce fabrication process going to be
     * very hard to achieve.
     */
    
    if (0 != strcmp(nonce, noncehashexp))
      return MHD_INVALID_NONCE;
    if ( (0 == lookup_sub_value(cnonce,
				sizeof (cnonce), 
				header, "cnonce")) ||
	 /*	 (0 == lookup_sub_value(qop, sizeof (qop), header, "qop")) || // Uncomment when supporting "auth-int" */
	 (0 == lookup_sub_value(nc, sizeof (nc), header, "nc"))  ||
	 (0 == lookup_sub_value(response, sizeof (response), header, "response")) )
      return MHD_NO;
    
    digest_calc_ha1("md5",
		    username,
		    realm,
		    password,
		    nonce,
		    cnonce,
		    ha1);
    digest_calc_response(ha1,
			 nonce,
			 nc,
			 cnonce,
			 qop,
			 connection->method,
			 uri,
			 hentity,
			 respexp);  
    return strcmp(response, respexp) == 0 ? MHD_YES : MHD_NO;
  }
}


/**
 * Queues a response to request authentication from the client
 *
 * @param connection The MHD connection structure
 * @param realm the realm presented to the client
 * @param opaque string to user for opaque value
 * @param signal_stale MHD_YES if the nonce is invalid to add
 * 			'stale=true' to the authentication header
 * @return MHD_YES on success, MHD_NO otherwise
 */
int
MHD_queue_auth_fail_response(struct MHD_Connection *connection,
			     const char *realm,
			     const char *opaque,
			     struct MHD_Response *response,
			     int signal_stale)
{
  int ret;
  size_t hlen;
  char nonce[HASH_MD5_HEX_LEN + 9];

  
  /* Generating the server nonce */  
  calculate_nonce ((uint32_t) time(NULL),
		   connection->method,
		   connection->daemon->digest_auth_random,
		   connection->url,
		   realm,
		   nonce);
  
  /* Building the authentication header */
  hlen = snprintf(NULL,
		  0,
		  "Digest realm=\"%s\",qop=\"auth\",nonce=\"%s\",opaque=\"%s\"%s",
		  realm, 
		  nonce,
		  opaque,
		  signal_stale ? ",stale=\"true\"" : "");
  {
    char header[hlen + 1];
    snprintf(header,
	     sizeof(header),
	     "Digest realm=\"%s\",qop=\"auth\",nonce=\"%s\",opaque=\"%s\"%s",
	     realm, 
	     nonce,
	     opaque,
	     signal_stale ? ",stale=\"true\"" : "");
    ret = MHD_add_response_header(response,
				  MHD_HTTP_HEADER_WWW_AUTHENTICATE, 
				  header);
  }
  if (MHD_YES == ret) 
    ret = MHD_queue_response(connection, 
			     MHD_HTTP_UNAUTHORIZED, 
			     response);  
  return ret;
}

/* end of digestauth.c */
