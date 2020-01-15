/*
 * Copyright (c) 2009-2012 Niels Provos, Nick Mathewson
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "event2/event-config.h"
#include "evconfig-private.h"

#include <sys/types.h>

#ifdef _WIN32
#ifndef _WIN32_WINNT
/* Minimum required for InitializeCriticalSectionAndSpinCount */
#define _WIN32_WINNT 0x0403
#endif
#include <winsock2.h>
#include <winerror.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#endif
#ifdef EVENT__HAVE_AFUNIX_H
#include <afunix.h>
#endif
#include <errno.h>
#ifdef EVENT__HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef EVENT__HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef EVENT__HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "event2/listener.h"
#include "event2/util.h"
#include "event2/event.h"
#include "event2/event_struct.h"
#include "mm-internal.h"
#include "util-internal.h"
#include "log-internal.h"
#include "evthread-internal.h"
#ifdef _WIN32
#include "iocp-internal.h"
#include "defer-internal.h"
#include "event-internal.h"
#endif

struct evconnlistener_ops {
	int (*enable)(struct evconnlistener *);
	int (*disable)(struct evconnlistener *);
	void (*destroy)(struct evconnlistener *);
	void (*shutdown)(struct evconnlistener *);
	evutil_socket_t (*getfd)(struct evconnlistener *);
	struct event_base *(*getbase)(struct evconnlistener *);
};

/* 作为服务端 socket 倾听者重要的抽象 */
struct evconnlistener {
	const struct evconnlistener_ops *ops;
	void *lock;
	evconnlistener_cb cb;
	evconnlistener_errorcb errorcb;
	void *user_data;
	unsigned flags;
	short refcnt;
	int accept4_flags;
	unsigned enabled : 1;
};

struct evconnlistener_event {
	/* 服务端 socket 专有成员 */
	struct evconnlistener base;
	/* event 基本成员 */
	struct event listener;
};

#ifdef _WIN32
struct evconnlistener_iocp {
	struct evconnlistener base;
	evutil_socket_t fd;
	struct event_base *event_base;
	struct event_iocp_port *port;
	short n_accepting;
	unsigned shutting_down : 1;
	unsigned event_added : 1;
	struct accepting_socket **accepting;
};
#endif

#define LOCK(listener) EVLOCK_LOCK((listener)->lock, 0)
#define UNLOCK(listener) EVLOCK_UNLOCK((listener)->lock, 0)

struct evconnlistener *
evconnlistener_new_async(struct event_base *base,
    evconnlistener_cb cb, void *ptr, unsigned flags, int backlog,
    evutil_socket_t fd); /* XXXX export this? */

static int event_listener_enable(struct evconnlistener *);
static int event_listener_disable(struct evconnlistener *);
static void event_listener_destroy(struct evconnlistener *);
static evutil_socket_t event_listener_getfd(struct evconnlistener *);
static struct event_base *event_listener_getbase(struct evconnlistener *);

#if 0
static void
listener_incref_and_lock(struct evconnlistener *listener)
{
	LOCK(listener);
	++listener->refcnt;
}
#endif

static int
listener_decref_and_unlock(struct evconnlistener *listener)
{
	int refcnt = --listener->refcnt;
	if (refcnt == 0) {
		listener->ops->destroy(listener);
		UNLOCK(listener);
		EVTHREAD_FREE_LOCK(listener->lock, EVTHREAD_LOCKTYPE_RECURSIVE);
		mm_free(listener);
		return 1;
	} else {
		UNLOCK(listener);
		return 0;
	}
}

/* socket 服务端统默认的处理倾听事件的函数集合 */
static const struct evconnlistener_ops evconnlistener_event_ops = {
	event_listener_enable,
	event_listener_disable,
	event_listener_destroy,
	NULL, /* shutdown */
	event_listener_getfd,
	event_listener_getbase
};

static void listener_read_cb(evutil_socket_t, short, void *);

struct evconnlistener *
evconnlistener_new(struct event_base *base,
    evconnlistener_cb cb, void *ptr, unsigned flags, int backlog,
    evutil_socket_t fd)
{
	struct evconnlistener_event *lev;

#ifdef _WIN32
	if (base && event_base_get_iocp_(base)) {
		const struct win32_extension_fns *ext =
			event_get_win32_extension_fns_();
		if (ext->AcceptEx && ext->GetAcceptExSockaddrs)
			return evconnlistener_new_async(base, cb, ptr, flags,
				backlog, fd);
	}
#endif

	if (backlog > 0) {
		/* 倾听指定端口的套接字的连接
		 * backlog：指定未完成连接的最大长度，如果一个连接请求到达时
		 * 未完成连接并且队列已满，那么客户端将收到错误信息
		 * ECONNREFUSED
		 * */
		if (listen(fd, backlog) < 0)
			return NULL;
	} else if (backlog < 0) {
		/* 默认最大长度时 128 */
		if (listen(fd, 128) < 0)
			return NULL;
	}

	/* 申请一个 struct evconnlistener_event 实例 */
	lev = mm_calloc(1, sizeof(struct evconnlistener_event));
	if (!lev)
		return NULL;

	/* 初始化这个 evconnlistener_event 结构体实例
	 * 该结构体实例的 base 是一个 evconnlistenner 实例
	 * 使用默认的 socket 作为服务端时候的函数集合
	 * 初始化这个 evconnlistener 实例的 ops 成员，函数集合
	 * */
	lev->base.ops = &evconnlistener_event_ops;
	/* 关联用户自定义的回调函数 */
	lev->base.cb = cb;
	/* 初始化用户传递给回调函数的参数 */
	lev->base.user_data = ptr;
	/* 记录初始化时的 socket 的 flags
	 * sample/hello-world.c flags=LEV_OPT_REUSEABLE|LEV_OPT_CLOSE_ON_FREE
	 * */
	lev->base.flags = flags;
	lev->base.refcnt = 1;

	/* 根据传递的 flags 标志初始化 struct evconnlistener 的
	 * 相关标志 sample/hello-world
	 * flags = LEV_OPT_REUSEABLE|LEV_OPT_CLOSE_ON_FREE
	 * */
	lev->base.accept4_flags = 0;
	if (!(flags & LEV_OPT_LEAVE_SOCKETS_BLOCKING))
		/* 置位该标志 */
		lev->base.accept4_flags |= EVUTIL_SOCK_NONBLOCK;
	if (flags & LEV_OPT_CLOSE_ON_EXEC)
		lev->base.accept4_flags |= EVUTIL_SOCK_CLOEXEC;

	/* 如果有额外的线程安全的要求 */
	if (flags & LEV_OPT_THREADSAFE) {
		EVTHREAD_ALLOC_LOCK(lev->base.lock, EVTHREAD_LOCKTYPE_RECURSIVE);
	}

	/* event_assign 函数定义在 event.c 文件
	 * 这个函数十分重要，关联了 event_base 到 listener （这是一个 struct event 实例）
	 * 重点是初始化一个 event 实例
	 * */
	event_assign(&lev->listener, base, fd, EV_READ|EV_PERSIST,
	    listener_read_cb, lev);

	/* 一般都不会置位这个标志位，所以会直接使能这个 socket
	 * 默认作为服务端倾听 socket 的函数处理集合：evconnlistener_event_ops
	 * 传递的参数是 evconnlistenner 实例
	 * */
	if (!(flags & LEV_OPT_DISABLED))
	    evconnlistener_enable(&lev->base);

	return &lev->base;
}

struct evconnlistener *
evconnlistener_new_bind(struct event_base *base, evconnlistener_cb cb,
    void *ptr, unsigned flags, int backlog, const struct sockaddr *sa,
    int socklen)
{
	struct evconnlistener *listener;
	evutil_socket_t fd;
	int on = 1;
	int family = sa ? sa->sa_family : AF_UNSPEC;
	int socktype = SOCK_STREAM | EVUTIL_SOCK_NONBLOCK;
	int support_keepalive = 1;

	if (backlog == 0)
		return NULL;

	if (flags & LEV_OPT_CLOSE_ON_EXEC)
		socktype |= EVUTIL_SOCK_CLOEXEC;

	/* 创建一个 socket */
	fd = evutil_socket_(family, socktype, 0);
	if (fd == -1)
		return NULL;

#if defined(_WIN32) && defined(EVENT__HAVE_AFUNIX_H)
	if (family == AF_UNIX && evutil_check_working_afunix_()) {
		/* AF_UNIX socket can't set SO_KEEPALIVE option on Win10.
		 * Avoid 10042 error.  */
		support_keepalive = 0;
	}
#endif
	if (support_keepalive) {
		/* 配置 socket 的保活机制 */
		if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (void*)&on, sizeof(on))<0)
			goto err;
	}

	if (flags & LEV_OPT_REUSEABLE) {
		if (evutil_make_listen_socket_reuseable(fd) < 0)
			goto err;
	}

	if (flags & LEV_OPT_REUSEABLE_PORT) {
		if (evutil_make_listen_socket_reuseable_port(fd) < 0)
			goto err;
	}

	if (flags & LEV_OPT_DEFERRED_ACCEPT) {
		if (evutil_make_tcp_listen_socket_deferred(fd) < 0)
			goto err;
	}

	if (flags & LEV_OPT_BIND_IPV6ONLY) {
		if (evutil_make_listen_socket_ipv6only(fd) < 0)
			goto err;
	}

	/* 如果指定了端口信息 */
	if (sa) {
		/* 作为服务端：绑定 socket 和指定的端口 */
		if (bind(fd, sa, socklen)<0)
			goto err;
	}

	/* sample/hello-world：flags == LEV_OPT_REUSEABLE|LEV_OPT_CLOSE_ON_FREE */
	listener = evconnlistener_new(base, cb, ptr, flags, backlog, fd);
	if (!listener)
		goto err;

	return listener;
err:
	evutil_closesocket(fd);
	return NULL;
}

void
evconnlistener_free(struct evconnlistener *lev)
{
	LOCK(lev);
	lev->cb = NULL;
	lev->errorcb = NULL;
	if (lev->ops->shutdown)
		lev->ops->shutdown(lev);
	listener_decref_and_unlock(lev);
}

static void
event_listener_destroy(struct evconnlistener *lev)
{
	struct evconnlistener_event *lev_e =
	    EVUTIL_UPCAST(lev, struct evconnlistener_event, base);

	event_del(&lev_e->listener);
	if (lev->flags & LEV_OPT_CLOSE_ON_FREE)
		evutil_closesocket(event_get_fd(&lev_e->listener));
	event_debug_unassign(&lev_e->listener);
}

/* 使能作为服务端倾听的 socket */
int
evconnlistener_enable(struct evconnlistener *lev)
{
	int r;
	LOCK(lev);
	lev->enabled = 1;
	/* 如果有关联到用户定义的回调函数 */
	if (lev->cb)
		/* ops 关联的是 evconnlistener_event_ops
		 * 执行 evconnlistener_event_ops 的 enable 回调函数 
		 * event_listener_enable 函数，传递的参数是 evconnlistener 实例
		 * 实际就是添加这个 event
		 * */
		r = lev->ops->enable(lev);
	else
		r = 0;
	UNLOCK(lev);
	return r;
}

int
evconnlistener_disable(struct evconnlistener *lev)
{
	int r;
	LOCK(lev);
	lev->enabled = 0;
	r = lev->ops->disable(lev);
	UNLOCK(lev);
	return r;
}

static int
event_listener_enable(struct evconnlistener *lev)
{
	/* 倒推出 evconnlistener_event 地址
	 * 目的是获取关联这个 evconnlistener 的 event 成员 */
	struct evconnlistener_event *lev_e =
	    EVUTIL_UPCAST(lev, struct evconnlistener_event, base);
	/* 添加这个 event 实例 */
	return event_add(&lev_e->listener, NULL);
}

static int
event_listener_disable(struct evconnlistener *lev)
{
	struct evconnlistener_event *lev_e =
	    EVUTIL_UPCAST(lev, struct evconnlistener_event, base);
	return event_del(&lev_e->listener);
}

evutil_socket_t
evconnlistener_get_fd(struct evconnlistener *lev)
{
	evutil_socket_t fd;
	LOCK(lev);
	fd = lev->ops->getfd(lev);
	UNLOCK(lev);
	return fd;
}

static evutil_socket_t
event_listener_getfd(struct evconnlistener *lev)
{
	struct evconnlistener_event *lev_e =
	    EVUTIL_UPCAST(lev, struct evconnlistener_event, base);
	return event_get_fd(&lev_e->listener);
}

struct event_base *
evconnlistener_get_base(struct evconnlistener *lev)
{
	struct event_base *base;
	LOCK(lev);
	base = lev->ops->getbase(lev);
	UNLOCK(lev);
	return base;
}

static struct event_base *
event_listener_getbase(struct evconnlistener *lev)
{
	struct evconnlistener_event *lev_e =
	    EVUTIL_UPCAST(lev, struct evconnlistener_event, base);
	return event_get_base(&lev_e->listener);
}

void
evconnlistener_set_cb(struct evconnlistener *lev,
    evconnlistener_cb cb, void *arg)
{
	int enable = 0;
	LOCK(lev);
	if (lev->enabled && !lev->cb)
		enable = 1;
	lev->cb = cb;
	lev->user_data = arg;
	if (enable)
		evconnlistener_enable(lev);
	UNLOCK(lev);
}

void
evconnlistener_set_error_cb(struct evconnlistener *lev,
    evconnlistener_errorcb errorcb)
{
	LOCK(lev);
	lev->errorcb = errorcb;
	UNLOCK(lev);
}

/* 服务端 socket 倾听者读取数据的回调函数 */
static void
listener_read_cb(evutil_socket_t fd, short what, void *p)
{
	struct evconnlistener *lev = p;
	int err;
	evconnlistener_cb cb;
	evconnlistener_errorcb errorcb;
	void *user_data;
	LOCK(lev);
	while (1) {
		struct sockaddr_storage ss;
		ev_socklen_t socklen = sizeof(ss);
		evutil_socket_t new_fd = evutil_accept4_(fd, (struct sockaddr*)&ss, &socklen, lev->accept4_flags);
		if (new_fd < 0)
			break;
		if (socklen == 0) {
			/* This can happen with some older linux kernels in
			 * response to nmap. */
			evutil_closesocket(new_fd);
			continue;
		}

		if (lev->cb == NULL) {
			evutil_closesocket(new_fd);
			UNLOCK(lev);
			return;
		}
		++lev->refcnt;
		cb = lev->cb;
		user_data = lev->user_data;
		UNLOCK(lev);
		cb(lev, new_fd, (struct sockaddr*)&ss, (int)socklen,
		    user_data);
		LOCK(lev);
		if (lev->refcnt == 1) {
			int freed = listener_decref_and_unlock(lev);
			EVUTIL_ASSERT(freed);
			return;
		}
		--lev->refcnt;
		if (!lev->enabled) {
			/* the callback could have disabled the listener */
			UNLOCK(lev);
			return;
		}
	}
	err = evutil_socket_geterror(fd);
	if (EVUTIL_ERR_ACCEPT_RETRIABLE(err)) {
		UNLOCK(lev);
		return;
	}
	if (lev->errorcb != NULL) {
		++lev->refcnt;
		errorcb = lev->errorcb;
		user_data = lev->user_data;
		UNLOCK(lev);
		errorcb(lev, user_data);
		LOCK(lev);
		listener_decref_and_unlock(lev);
	} else {
		event_sock_warn(fd, "Error from accept() call");
		UNLOCK(lev);
	}
}

#ifdef _WIN32
struct accepting_socket {
	CRITICAL_SECTION lock;
	struct event_overlapped overlapped;
	SOCKET s;
	int error;
	struct event_callback deferred;
	struct evconnlistener_iocp *lev;
	ev_uint8_t buflen;
	ev_uint8_t family;
	unsigned free_on_cb:1;
	char addrbuf[1];
};

static void accepted_socket_cb(struct event_overlapped *o, ev_uintptr_t key,
    ev_ssize_t n, int ok);
static void accepted_socket_invoke_user_cb(struct event_callback *cb, void *arg);

static void
iocp_listener_event_add(struct evconnlistener_iocp *lev)
{
	if (lev->event_added)
		return;

	lev->event_added = 1;
	event_base_add_virtual_(lev->event_base);
}

static void
iocp_listener_event_del(struct evconnlistener_iocp *lev)
{
	if (!lev->event_added)
		return;

	lev->event_added = 0;
	event_base_del_virtual_(lev->event_base);
}

static struct accepting_socket *
new_accepting_socket(struct evconnlistener_iocp *lev, int family)
{
	struct accepting_socket *res;
	int addrlen;
	int buflen;

	if (family == AF_INET)
		addrlen = sizeof(struct sockaddr_in);
	else if (family == AF_INET6)
		addrlen = sizeof(struct sockaddr_in6);
#ifdef EVENT__HAVE_AFUNIX_H
	else if (family == AF_UNIX && evutil_check_working_afunix_())
		addrlen = sizeof(struct sockaddr_un);
#endif
	else
		return NULL;
	buflen = (addrlen+16)*2;

	res = mm_calloc(1,sizeof(struct accepting_socket)-1+buflen);
	if (!res)
		return NULL;

	event_overlapped_init_(&res->overlapped, accepted_socket_cb);
	res->s = EVUTIL_INVALID_SOCKET;
	res->lev = lev;
	res->buflen = buflen;
	res->family = family;

	event_deferred_cb_init_(&res->deferred,
	    event_base_get_npriorities(lev->event_base) / 2,
	    accepted_socket_invoke_user_cb, res);

	InitializeCriticalSectionAndSpinCount(&res->lock, 1000);

	return res;
}

static void
free_and_unlock_accepting_socket(struct accepting_socket *as)
{
	/* requires lock. */
	if (as->s != EVUTIL_INVALID_SOCKET)
		closesocket(as->s);

	LeaveCriticalSection(&as->lock);
	DeleteCriticalSection(&as->lock);
	mm_free(as);
}

static int
start_accepting(struct accepting_socket *as)
{
	/* requires lock */
	const struct win32_extension_fns *ext = event_get_win32_extension_fns_();
	DWORD pending = 0;
	SOCKET s = socket(as->family, SOCK_STREAM, 0);
	int error = 0;

	if (!as->lev->base.enabled)
		return 0;

	if (s == EVUTIL_INVALID_SOCKET) {
		error = WSAGetLastError();
		goto report_err;
	}

	/* XXXX It turns out we need to do this again later.  Does this call
	 * have any effect? */
	setsockopt(s, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT,
	    (char *)&as->lev->fd, sizeof(&as->lev->fd));

	if (!(as->lev->base.flags & LEV_OPT_LEAVE_SOCKETS_BLOCKING))
		evutil_make_socket_nonblocking(s);

	if (event_iocp_port_associate_(as->lev->port, s, 1) < 0) {
		closesocket(s);
		return -1;
	}

	as->s = s;

	if (ext->AcceptEx(as->lev->fd, s, as->addrbuf, 0,
		as->buflen/2, as->buflen/2, &pending, &as->overlapped.overlapped))
	{
		/* Immediate success! */
		accepted_socket_cb(&as->overlapped, 1, 0, 1);
	} else {
		error = WSAGetLastError();
		if (error != ERROR_IO_PENDING) {
			goto report_err;
		}
	}

	return 0;

report_err:
	as->error = error;
	event_deferred_cb_schedule_(
		as->lev->event_base,
		&as->deferred);
	return 0;
}

static void
stop_accepting(struct accepting_socket *as)
{
	/* requires lock. */
	SOCKET s = as->s;
	as->s = EVUTIL_INVALID_SOCKET;
	closesocket(s);
}

static void
accepted_socket_invoke_user_cb(struct event_callback *dcb, void *arg)
{
	struct accepting_socket *as = arg;

	struct sockaddr *sa_local=NULL, *sa_remote=NULL;
	int socklen_local=0, socklen_remote=0;
	const struct win32_extension_fns *ext = event_get_win32_extension_fns_();
	struct evconnlistener *lev = &as->lev->base;
	evutil_socket_t sock=-1;
	void *data;
	evconnlistener_cb cb=NULL;
	evconnlistener_errorcb errorcb=NULL;
	int error;

	EVUTIL_ASSERT(ext->GetAcceptExSockaddrs);

	LOCK(lev);
	EnterCriticalSection(&as->lock);
	if (as->free_on_cb) {
		free_and_unlock_accepting_socket(as);
		listener_decref_and_unlock(lev);
		return;
	}

	++lev->refcnt;

	error = as->error;
	if (error) {
		as->error = 0;
		errorcb = lev->errorcb;
	} else {
		ext->GetAcceptExSockaddrs(
			as->addrbuf, 0, as->buflen/2, as->buflen/2,
			&sa_local, &socklen_local, &sa_remote,
			&socklen_remote);
		sock = as->s;
		cb = lev->cb;
		as->s = EVUTIL_INVALID_SOCKET;

		/* We need to call this so getsockname, getpeername, and
		 * shutdown work correctly on the accepted socket. */
		/* XXXX handle error? */
		setsockopt(sock, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT,
		    (char *)&as->lev->fd, sizeof(&as->lev->fd));
	}
	data = lev->user_data;

	LeaveCriticalSection(&as->lock);
	UNLOCK(lev);

	if (errorcb) {
		WSASetLastError(error);
		errorcb(lev, data);
	} else if (cb) {
		cb(lev, sock, sa_remote, socklen_remote, data);
	}

	LOCK(lev);
	if (listener_decref_and_unlock(lev))
		return;

	EnterCriticalSection(&as->lock);
	start_accepting(as);
	LeaveCriticalSection(&as->lock);
}

static void
accepted_socket_cb(struct event_overlapped *o, ev_uintptr_t key, ev_ssize_t n, int ok)
{
	struct accepting_socket *as =
	    EVUTIL_UPCAST(o, struct accepting_socket, overlapped);

	LOCK(&as->lev->base);
	EnterCriticalSection(&as->lock);
	if (ok) {
		/* XXXX Don't do this if some EV_MT flag is set. */
		event_deferred_cb_schedule_(
			as->lev->event_base,
			&as->deferred);
		LeaveCriticalSection(&as->lock);
	} else if (as->free_on_cb) {
		struct evconnlistener *lev = &as->lev->base;
		free_and_unlock_accepting_socket(as);
		listener_decref_and_unlock(lev);
		return;
	} else if (as->s == EVUTIL_INVALID_SOCKET) {
		/* This is okay; we were disabled by iocp_listener_disable. */
		LeaveCriticalSection(&as->lock);
	} else {
		/* Some error on accept that we couldn't actually handle. */
		BOOL ok;
		DWORD transfer = 0, flags=0;
		event_sock_warn(as->s, "Unexpected error on AcceptEx");
		ok = WSAGetOverlappedResult(as->s, &o->overlapped,
		    &transfer, FALSE, &flags);
		if (ok) {
			/* well, that was confusing! */
			as->error = 1;
		} else {
			as->error = WSAGetLastError();
		}
		event_deferred_cb_schedule_(
			as->lev->event_base,
			&as->deferred);
		LeaveCriticalSection(&as->lock);
	}
	UNLOCK(&as->lev->base);
}

static int
iocp_listener_enable(struct evconnlistener *lev)
{
	int i;
	struct evconnlistener_iocp *lev_iocp =
	    EVUTIL_UPCAST(lev, struct evconnlistener_iocp, base);

	LOCK(lev);
	iocp_listener_event_add(lev_iocp);
	for (i = 0; i < lev_iocp->n_accepting; ++i) {
		struct accepting_socket *as = lev_iocp->accepting[i];
		if (!as)
			continue;
		EnterCriticalSection(&as->lock);
		if (!as->free_on_cb && as->s == EVUTIL_INVALID_SOCKET)
			start_accepting(as);
		LeaveCriticalSection(&as->lock);
	}
	UNLOCK(lev);
	return 0;
}

static int
iocp_listener_disable_impl(struct evconnlistener *lev, int shutdown)
{
	int i;
	struct evconnlistener_iocp *lev_iocp =
	    EVUTIL_UPCAST(lev, struct evconnlistener_iocp, base);

	LOCK(lev);
	iocp_listener_event_del(lev_iocp);
	for (i = 0; i < lev_iocp->n_accepting; ++i) {
		struct accepting_socket *as = lev_iocp->accepting[i];
		if (!as)
			continue;
		EnterCriticalSection(&as->lock);
		if (!as->free_on_cb && as->s != EVUTIL_INVALID_SOCKET) {
			if (shutdown)
				as->free_on_cb = 1;
			stop_accepting(as);
		}
		LeaveCriticalSection(&as->lock);
	}

	if (shutdown && lev->flags & LEV_OPT_CLOSE_ON_FREE)
		evutil_closesocket(lev_iocp->fd);

	UNLOCK(lev);
	return 0;
}

static int
iocp_listener_disable(struct evconnlistener *lev)
{
	return iocp_listener_disable_impl(lev,0);
}

static void
iocp_listener_destroy(struct evconnlistener *lev)
{
	struct evconnlistener_iocp *lev_iocp =
	    EVUTIL_UPCAST(lev, struct evconnlistener_iocp, base);

	if (! lev_iocp->shutting_down) {
		lev_iocp->shutting_down = 1;
		iocp_listener_disable_impl(lev,1);
	}

}

static evutil_socket_t
iocp_listener_getfd(struct evconnlistener *lev)
{
	struct evconnlistener_iocp *lev_iocp =
	    EVUTIL_UPCAST(lev, struct evconnlistener_iocp, base);
	return lev_iocp->fd;
}
static struct event_base *
iocp_listener_getbase(struct evconnlistener *lev)
{
	struct evconnlistener_iocp *lev_iocp =
	    EVUTIL_UPCAST(lev, struct evconnlistener_iocp, base);
	return lev_iocp->event_base;
}

static const struct evconnlistener_ops evconnlistener_iocp_ops = {
	iocp_listener_enable,
	iocp_listener_disable,
	iocp_listener_destroy,
	iocp_listener_destroy, /* shutdown */
	iocp_listener_getfd,
	iocp_listener_getbase
};

/* XXX define some way to override this. */
#define N_SOCKETS_PER_LISTENER 4

struct evconnlistener *
evconnlistener_new_async(struct event_base *base,
    evconnlistener_cb cb, void *ptr, unsigned flags, int backlog,
    evutil_socket_t fd)
{
	struct sockaddr_storage ss;
	int socklen = sizeof(ss);
	struct evconnlistener_iocp *lev;
	int i;

	flags |= LEV_OPT_THREADSAFE;

	if (!base || !event_base_get_iocp_(base))
		goto err;

	/* XXXX duplicate code */
	if (backlog > 0) {
		if (listen(fd, backlog) < 0)
			goto err;
	} else if (backlog < 0) {
		if (listen(fd, 128) < 0)
			goto err;
	}
	if (getsockname(fd, (struct sockaddr*)&ss, &socklen)) {
		event_sock_warn(fd, "getsockname");
		goto err;
	}
	lev = mm_calloc(1, sizeof(struct evconnlistener_iocp));
	if (!lev) {
		event_warn("calloc");
		goto err;
	}
	lev->base.ops = &evconnlistener_iocp_ops;
	lev->base.cb = cb;
	lev->base.user_data = ptr;
	lev->base.flags = flags;
	lev->base.refcnt = 1;
	lev->base.enabled = 1;

	lev->port = event_base_get_iocp_(base);
	lev->fd = fd;
	lev->event_base = base;


	if (event_iocp_port_associate_(lev->port, fd, 1) < 0)
		goto err_free_lev;

	EVTHREAD_ALLOC_LOCK(lev->base.lock, EVTHREAD_LOCKTYPE_RECURSIVE);

	lev->n_accepting = N_SOCKETS_PER_LISTENER;
	lev->accepting = mm_calloc(lev->n_accepting,
	    sizeof(struct accepting_socket *));
	if (!lev->accepting) {
		event_warn("calloc");
		goto err_delete_lock;
	}
	for (i = 0; i < lev->n_accepting; ++i) {
		lev->accepting[i] = new_accepting_socket(lev, ss.ss_family);
		if (!lev->accepting[i]) {
			event_warnx("Couldn't create accepting socket");
			goto err_free_accepting;
		}
		if (cb && start_accepting(lev->accepting[i]) < 0) {
			event_warnx("Couldn't start accepting on socket");
			EnterCriticalSection(&lev->accepting[i]->lock);
			free_and_unlock_accepting_socket(lev->accepting[i]);
			goto err_free_accepting;
		}
		++lev->base.refcnt;
	}

	iocp_listener_event_add(lev);

	return &lev->base;

err_free_accepting:
	mm_free(lev->accepting);
	/* XXXX free the other elements. */
err_delete_lock:
	EVTHREAD_FREE_LOCK(lev->base.lock, EVTHREAD_LOCKTYPE_RECURSIVE);
err_free_lev:
	mm_free(lev);
err:
	/* Don't close the fd, it is caller's responsibility. */
	return NULL;
}

#endif
