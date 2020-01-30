/*
 * Copyright (c) 2000-2007 Niels Provos <provos@citi.umich.edu>
 * Copyright (c) 2007-2012 Niels Provos and Nick Mathewson
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
#ifndef EVENT2_EVENT_STRUCT_H_INCLUDED_
#define EVENT2_EVENT_STRUCT_H_INCLUDED_

/** @file event2/event_struct.h

  Structures used by event.h.  Using these structures directly WILL harm
  forward compatibility: be careful.

  No field declared in this file should be used directly in user code.  Except
  for historical reasons, these fields would not be exposed at all.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <event2/event-config.h>
#ifdef EVENT__HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef EVENT__HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

/* For int types. */
#include <event2/util.h>

/* For evkeyvalq */
#include <event2/keyvalq_struct.h>

#define EVLIST_TIMEOUT	    0x01
#define EVLIST_INSERTED	    0x02
#define EVLIST_SIGNAL	    0x04
#define EVLIST_ACTIVE	    0x08
#define EVLIST_INTERNAL	    0x10
#define EVLIST_ACTIVE_LATER 0x20
#define EVLIST_FINALIZING   0x40
/* event 初始化时的标志就是 0x80 */
#define EVLIST_INIT	    0x80

#define EVLIST_ALL          0xff

/* Fix so that people don't have to run with <sys/queue.h> */
#ifndef TAILQ_ENTRY
#define EVENT_DEFINED_TQENTRY_
#define TAILQ_ENTRY(type)						\
struct {								\
	struct type *tqe_next;	/* next element */			\
	struct type **tqe_prev;	/* address of previous next element */	\
}
#endif /* !TAILQ_ENTRY */

#ifndef TAILQ_HEAD
#define EVENT_DEFINED_TQHEAD_
#define TAILQ_HEAD(name, type)			\
struct name {					\
	struct type *tqh_first;			\
	struct type **tqh_last;			\
}
#endif

/* Fix so that people don't have to run with <sys/queue.h> */
#ifndef LIST_ENTRY
#define EVENT_DEFINED_LISTENTRY_
#define LIST_ENTRY(type)						\
struct {								\
	struct type *le_next;	/* next element */			\
	struct type **le_prev;	/* address of previous next element */	\
}
#endif /* !LIST_ENTRY */

#ifndef LIST_HEAD
#define EVENT_DEFINED_LISTHEAD_
#define LIST_HEAD(name, type)						\
struct name {								\
	struct type *lh_first;  /* first element */			\
	}
#endif /* !LIST_HEAD */

struct event;

struct event_callback {
	/* tailq 管理已经激活的事件 */
	TAILQ_ENTRY(event_callback) evcb_active_next;
	/* event 的标志，考虑是标记当前整个 event 的阶段 */
	short evcb_flags;
	/* event 回调抽象的优先级，数值越小，优先级越高 */
	ev_uint8_t evcb_pri;	/* smaller numbers are higher priority */
	/* 在处理激活的 event 的时候，根据这个
	 * 值执行 event_callback 不同的回调函数成员（一个 union）  */
	ev_uint8_t evcb_closure;
	/* allows us to adopt for different types of events */
	/* 这个联合需要注意！！！ */
        union {
		/* event 的回调函数，参数关联的是 socket 类 ？？？ */
		void (*evcb_callback)(evutil_socket_t, short, void *);
		void (*evcb_selfcb)(struct event_callback *, void *);
		void (*evcb_evfinalize)(struct event *, void *);
		void (*evcb_cbfinalize)(struct event_callback *, void *);
	} evcb_cb_union;
	/* evcb_cb_union 联合的函数指针对应的参数 */
	void *evcb_arg;
};

struct event_base;
struct event {
	struct event_callback ev_evcallback;

	/* for managing timeouts */
	/* 管理事件超时相关的内容？？？ */
	union {
		TAILQ_ENTRY(event) ev_next_with_common_timeout;
		size_t min_heap_idx;
	} ev_timeout_pos;
	/* 事件倾听的句柄 */
	evutil_socket_t ev_fd;

	/* 倾听的事件类型 */
	short ev_events;
	/* 要传递给事件回调函数具体是
	 * 的倾听事件类型（eg:EV_TIMEOUT、EV_READ、EV_WRITE、EV_SIGNAL） */
	short ev_res;		/* result passed to event callback */

	/* 指向关联的 event_base 实例 */
	struct event_base *ev_base;

	union {
		/* used for io events */
		struct {
			LIST_ENTRY (event) ev_io_next;
			struct timeval ev_timeout;
		} ev_io;

		/* used by signal events */
		struct {
			LIST_ENTRY (event) ev_signal_next;
			/* 接收到的信号次数？？？ */
			short ev_ncalls;
			/* Allows deletes in callback */
			/* 允许在回调删除，什么意思？？？ */
			short *ev_pncalls;
		} ev_signal;
	} ev_;


	/* 倾听事件的超时时间？？？ */
	struct timeval ev_timeout;
};

TAILQ_HEAD (event_list, event);

#ifdef EVENT_DEFINED_TQENTRY_
#undef TAILQ_ENTRY
#endif

#ifdef EVENT_DEFINED_TQHEAD_
#undef TAILQ_HEAD
#endif

/* 这个链表头可以链接 event */
LIST_HEAD (event_dlist, event);

/* LIST_HEAD 宏展开
 * struct event_dlist {
 *     struct event *lh_first; 指向 struct event 实例，串联 struct event 的链表头
 * }
 */

#ifdef EVENT_DEFINED_LISTENTRY_
#undef LIST_ENTRY
#endif

#ifdef EVENT_DEFINED_LISTHEAD_
#undef LIST_HEAD
#endif

#ifdef __cplusplus
}
#endif

#endif /* EVENT2_EVENT_STRUCT_H_INCLUDED_ */
