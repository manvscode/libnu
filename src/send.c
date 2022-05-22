/* Copyright (C) 2013 by Joseph A. Marrero, https://joemarrero.com/
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include "netutils.h"

bool nu_send( int socket, const uint8_t* data, size_t size )
{
    size_t count = 0;

    while( size > 0 )
    {
		/* send the data. */
		int sentBytes = send( socket, data + count, size, 0 );

		if( sentBytes <= 0 )
		{
			return false;
		}

		size -= sentBytes;
		count += sentBytes;
    }

    return true;
}

nu_result_t nu_send_async( int socket, const void* data, size_t size )
{
    if( !nu_send( socket, data, size ) )
    {
		switch( errno )
		{
			case EINTR: // interrupted by signal...
			case EAGAIN: // EWOULDBLOCK
				return NU_TRYAGAIN;
			case ENOTSOCK: // client socket is not a socket.
			case ENOTCONN: // not connected yet.
			case EINVAL: // invalid argument passed.
			case EFAULT: // an argument is outside process's address space
			case EBADF:  // bad socket/file descriptor
			case EOPNOTSUPP: // some socket flag is inappropriate for this socket type.
				assert( false ); // these are programming errors
			case ECONNRESET: // connection reset by peer
			case ENOMEM: // no memory available
			default:
				return NU_FAILED;
		}
    }

    return NU_SUCCESS;
}

