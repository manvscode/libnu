/* Copyright (C) 2013 by Joseph A. Marrero, http://www.manvscode.com/
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

bool nu_recv( int socket, void* data, size_t size )
{
	ssize_t rv = 0;

	/* receive the data... */
	for( size_t recv_bytes = 0; recv_bytes < size; recv_bytes += rv )
	{
		rv = recv( socket, data + recv_bytes, size - recv_bytes, 0 );

		if( rv < 0 )
		{
			//if( errno == EINTR || errno == EAGAIN ) continue;
			return false;
		}
		else if( rv == 0 )
		{
			/* connection closed by peer */
			return false;
		}
	}

    return true;
}

nu_result_t nu_recv_async( int socket, void* data, size_t size )
{
    if( !nu_recv( socket, data, size ) )
    {
		switch( errno )
		{
			case EINTR: // interrupted by signal...
			case EAGAIN: // EWOULDBLOCK
				return NETUTILS_TRYAGAIN;
			case ENOTSOCK: // client socket is not a socket.
			case ENOTCONN: // not connected yet.
			case EINVAL: // invalid argument passed.
			case EFAULT: // the receive buffer is outside process's address space
			case EBADF:  // bad socket/file descriptor
				assert( false ); // these are programming errors
			case ECONNREFUSED:
			default:
				return NETUTILS_FAILED;
		}
    }

    return NETUTILS_SUCCESS;
}
