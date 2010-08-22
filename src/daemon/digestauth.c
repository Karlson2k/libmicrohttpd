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
#include "sha1.h"

#define HASH_MD5_LEN 16
#define HASH_SHA1_LEN 20
#define HASH_MD5_HEX_LEN 32
#define HASH_SHA1_HEX_LEN 40

#define _BASE		"Digest "

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
  
  for (i = 0; i < len; ++i) {
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
 * @param sessionkey pointer to buffer of 2*MD5_DIGEST_SIZE+1 bytes
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
 * @return ???
 */
static int
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
  char ha2hex[MD5_DIGEST_SIZE * 2 + 1];
  
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
  cvthex(ha2, HASH_MD5_LEN, ha2hex);
  MD5Init (&md5);
  
  /* calculate response */
  
  MD5Update (&md5, ha1, HASH_MD5_HEX_LEN);
  MD5Update (&md5, ":", 1);
  MD5Update (&md5, nonce, strlen(nonce));
  MD5Update (&md5, ":", 1);
  
  if (*qop) 
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
  return 0;
}

static const char *
lookup_sub_value(char *data, 
		 size_t len,
		 const char *key)
{
  char *tmp = data;
  char *value = NULL;
  size_t keylen;
  size_t i;
  
  keylen = strlen(key);
  for (i = 0; i < len; ++i) {
    if (strncmp(tmp, key, keylen) == 0 &&
	strncmp(tmp + keylen, "=", 1) == 0) 
      {
	tmp += keylen;
	break;
      }
    else 
      {
	tmp++;
      }    
    if ((i + 1) == len) 
      return NULL;
  }  
  while (1) 
    {
      tmp++;
      
      if (*tmp == '"' && *(tmp + 1) == ',') 
	{
	  *tmp = '\0';
	  break;
	}      
      if (*tmp == '"' && *(tmp + 1) == '\0') 
	{
	  *tmp = '\0';
	  break;
	}      
      if (*tmp == ',' || *tmp == '\0') 
	{
	  *tmp = '\0';
	  break;
	}      
      if (*tmp == '"')
	continue;      
      if (value == NULL)
	value = tmp;
    }
  
  return value;
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
  size_t userlen;
  char *buffer;
  char *username;
  const char *user;
  const char *header;
  
  header = MHD_lookup_connection_value(connection,
				       MHD_HEADER_KIND, 
				       MHD_HTTP_HEADER_AUTHORIZATION); 
  if (header == NULL)
    return NULL;
  if (strncmp(header, _BASE, strlen(_BASE)) != 0)
    return NULL;  
  len = strlen(header) - strlen(_BASE) + 1;
  buffer = malloc(len);  
  if (buffer == NULL)
    return NULL;
  
  strncpy(buffer, header + strlen(_BASE), len);
  
  user = lookup_sub_value(buffer, len, "username");
  
  if (user) 
    {
      userlen = strlen(user) + 1;
      username = malloc(userlen);
      
      if (username != NULL) 
	{
	  strncpy(username, user, userlen);
	  free(buffer);
	  return username;
	}
    }
  
  free(buffer);
  return NULL;
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
  int auth;
  size_t len;
  char *buffer;
  const char *header;
  const char *ret;
  const char *nonce;
  const char *cnonce;
  const char *uri;
  const char *qop;
  const char *nc;
  const char *response;
  unsigned char tmpnonce[SHA1_DIGEST_SIZE];
  char *hentity = NULL; /* "auth-int" is not supported */
  char timestamp[5];
  char ha1[HASH_MD5_HEX_LEN + 1];
  char respexp[HASH_MD5_HEX_LEN + 1];
  char noncehashexp[HASH_SHA1_HEX_LEN + 9];
  unsigned int nonce_time;
  time_t t;
  struct SHA1Context sha1;
  
  header = MHD_lookup_connection_value(connection,
				       MHD_HEADER_KIND,
				       MHD_HTTP_HEADER_AUTHORIZATION);  
  if (header == NULL) 
    return MHD_NO;
  if (strncmp(header, _BASE, strlen(_BASE)) != 0) 
    return MHD_NO;  
  len = strlen(header) - strlen(_BASE) + 1;  
  buffer = malloc(len);
  
  if (buffer == NULL) 
    return MHD_NO;
  strncpy(buffer, 
	  header + strlen(_BASE), 
	  len);
  
  ret = lookup_sub_value(buffer, len, "username");
  
  if ( (ret == NULL) || (strcmp(username, ret) != 0) ) 
    {
      free(buffer);
      return MHD_NO;
    }  
  ret = lookup_sub_value(buffer, len, "realm");
  
  if (ret == NULL || strcmp(realm, ret) != 0) 
    {
      free(buffer);
      return MHD_NO;
    }  
  if ((uri = lookup_sub_value(buffer, len, "uri")) == NULL) 
    {
      free(buffer);
      return MHD_NO;
    }
  if ((nonce = lookup_sub_value(buffer, len, "nonce")) == NULL) 
    {
      free(buffer);
      return MHD_NO;
    }
  
  /*
   * 8 = 4 hexadecimal numbers for the timestamp
   */
  
  nonce_time = strtoul(nonce + strlen(nonce) - 8, 0, 16);  
  time(&t);
  
  /*
   * First level vetting for the nonce validity
   * if the timestamp attached to the nonce
   * exceeds `nonce_timeout' then the nonce is
   * invalid.
   */
  
  if (t - nonce_time > nonce_timeout) 
    {
      free(buffer);
      return MHD_INVALID_NONCE;
    }
  SHA1Init (&sha1);
  timestamp[0] = (nonce_time & 0xff000000) >> 0x18;
  timestamp[1] = (nonce_time & 0x00ff0000) >> 0x10;
  timestamp[2] = (nonce_time & 0x0000ff00) >> 0x08;
  timestamp[3] = nonce_time & 0x000000ff;
  timestamp[4] = '\0';
  
  SHA1Update(&sha1, timestamp, 4);
  SHA1Update(&sha1, ":", 1);
  SHA1Update(&sha1, connection->method, strlen(connection->method));
  SHA1Update(&sha1, ":", 1);
  SHA1Update(&sha1, password, strlen(password));
  SHA1Update(&sha1, ":", 1);
  SHA1Update(&sha1, uri, strlen(uri));
  SHA1Update(&sha1, ":", 1);
  SHA1Update(&sha1, realm, strlen(realm));
  SHA1Final (tmpnonce, &sha1);
  
  cvthex(tmpnonce, sizeof (tmpnonce), noncehashexp);
  
  strncat(noncehashexp, nonce + strlen(nonce) - 8, 8);
  
  /*
   * Second level vetting for the nonce validity
   * if the timestamp attached to the nonce is valid
   * and possibility fabricated (in case of an attack)
   * the attacker must also know the password to be
   * able to generate a "sane" nonce, which if he does
   * not, the nonce fabrication process going to be
   * very hard to achieve.
   */
  
  if (strncmp(nonce, noncehashexp, strlen(nonce)) != 0) 
    {
      free(buffer);
      return MHD_INVALID_NONCE;
    }
  
  if ((cnonce = lookup_sub_value(buffer, len, "cnonce")) == NULL) 
    {
      free(buffer);
      return MHD_NO;
    }
  
  if ((qop = lookup_sub_value(buffer, len, "qop")) == NULL) 
    {
      free(buffer);
      return MHD_NO;
    }
  
  if ((nc = lookup_sub_value(buffer, len, "nc")) == NULL) 
    {
      free(buffer);
      return MHD_NO;
    }
  
  if ((response = lookup_sub_value(buffer, len, "response")) == NULL) 
    {
      free(buffer);
      return MHD_NO;
    }
  
  digest_calc_ha1("md5",
		  username,
		  realm,
		  password,
		  nonce,
		  cnonce,
		  ha1);
  auth = digest_calc_response(ha1,
			      nonce,
			      nc,
			      cnonce,
			      qop,
			      connection->method,
			      uri,
			      hentity,
			      respexp);
  
  if (auth) 
    {
      free(buffer);
      return MHD_NO;
    }
  
  auth = strcmp(response, respexp) == 0 ? MHD_YES : MHD_NO;
  
  free(buffer);
  
  return auth;
}


/**
 * Queues a response to request authentication from the client
 *
 * @param connection The MHD connection structure
 * @param realm The realm presented to the client
 * @param password The password used in authentication
 * @param signal_stale MHD_YES if the nonce is invalid to add
 * 			'stale=true' to the authentication header
 * @return MHD_YES on success, MHD_NO otherwise
 */
int
MHD_queue_auth_fail_response(struct MHD_Connection *connection,
			     const char *realm,
			     const char *password,
			     const char *opaque,
			     int signal_stale)
{
  int ret;
  size_t hlen;
  unsigned char tmpnonce[SHA1_DIGEST_SIZE];
  unsigned char timestamp[5];
  char timestamphex[9];
  char nonce[HASH_SHA1_HEX_LEN + 9];
  time_t t;
  struct MHD_Response *response;
  struct SHA1Context sha1;
  
  response = MHD_create_response_from_data(0, NULL, MHD_NO, MHD_NO);  
  if (!response) 
    return MHD_NO;
  
  /*
   * Generating the server nonce
   */
  
  SHA1Init (&sha1);
  time(&t);
  
  timestamp[0] = (t & 0xff000000) >> 0x18;
  timestamp[1] = (t & 0x00ff0000) >> 0x10;
  timestamp[2] = (t & 0x0000ff00) >> 0x08;
  timestamp[3] = t & 0x000000ff;
  timestamp[4] = '\0';
  
  SHA1Update(&sha1, timestamp, 4);
  SHA1Update(&sha1, ":", 1);
  SHA1Update(&sha1, connection->method, strlen(connection->method));
  SHA1Update(&sha1, ":", 1);
  SHA1Update(&sha1, password, strlen(password));
  SHA1Update(&sha1, ":", 1);
  SHA1Update(&sha1, connection->url, strlen(connection->url));
  SHA1Update(&sha1, ":", 1);
  SHA1Update(&sha1, realm, strlen(realm));
  SHA1Final (tmpnonce, &sha1);
  
  cvthex(timestamp, 4, timestamphex);
  cvthex(tmpnonce, sizeof (tmpnonce), nonce);
  strncat(nonce, timestamphex, 8);
  
  /*
   * Building the authentication header
   */
  hlen = snprintf(NULL,
		  0,
		  "Digest realm=\"%s\",qop=\"auth\",nonce=\"%s\",opaque=\"%s\"%s",
		  realm, 
		  nonce,
		  opaque,
		  signal_stale ? ",stale=true" : "");
  {
    char header[hlen + 1];
    snprintf(header,
	     sizeof(header),
	     "Digest realm=\"%s\",qop=\"auth\",nonce=\"%s\",opaque=\"%s\"%s",
	     realm, 
	     nonce,
	     opaque,
	     signal_stale ? ",stale=true" : "");
    ret = MHD_add_response_header(response,
				  MHD_HTTP_HEADER_WWW_AUTHENTICATE, 
				  header);
  }
  if(!ret) 
    {
      MHD_destroy_response(response);
      return MHD_NO;
    }
  
  ret = MHD_queue_response(connection, MHD_HTTP_UNAUTHORIZED, response);
  
  MHD_destroy_response(response);
  
  return ret;
}

/* end of digestauth.c */
