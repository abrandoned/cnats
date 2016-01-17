// Copyright 2015 Apcera Inc. All rights reserved.

#ifndef NATSP_H_
#define NATSP_H_

#if defined(_WIN32)
# include "include/n-win.h"
#else
# include "include/n-unix.h"
#endif

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "err.h"
#include "nats.h"
#include "buf.h"
#include "parser.h"
#include "timer.h"
#include "url.h"
#include "srvpool.h"
#include "msg.h"
#include "asynccb.h"
#include "hash.h"
#include "stats.h"
#include "natstime.h"

// Comment/uncomment to replace some function calls with direct structure
// access
//#define DEV_MODE    (1)

#define LIB_NATS_VERSION_STRING             NATS_VERSION_STRING
#define LIB_NATS_VERSION_NUMBER             NATS_VERSION_NUMBER
#define LIB_NATS_VERSION_REQUIRED_NUMBER    NATS_VERSION_REQUIRED_NUMBER

#define CString     "C"

#define _OK_OP_     "+OK"
#define _ERR_OP_    "-ERR"
#define _MSG_OP_    "MSG"
#define _PING_OP_   "PING"
#define _PONG_OP_   "PONG"
#define _INFO_OP_   "INFO"

#define _CRLF_      "\r\n"
#define _SPC_       " "
#define _PUB_P_     "PUB "

#define _PING_PROTO_         "PING\r\n"
#define _PONG_PROTO_         "PONG\r\n"
#define _PUB_PROTO_          "PUB %s %s %d\r\n"
#define _SUB_PROTO_          "SUB %s %s %d\r\n"
#define _UNSUB_PROTO_        "UNSUB %" PRId64 " %d\r\n"
#define _UNSUB_NO_MAX_PROTO_ "UNSUB %" PRId64 " \r\n"

#define STALE_CONNECTION     "Stale Connection"
#define STATE_CONNECTION_LEN (16)

#define _CRLF_LEN_          (2)
#define _SPC_LEN_           (1)
#define _PUB_P_LEN_         (4)
#define _PING_OP_LEN_       (4)
#define _PONG_OP_LEN_       (4)
#define _PING_PROTO_LEN_    (6)
#define _PONG_PROTO_LEN_    (6)
#define _OK_OP_LEN_         (3)

extern int64_t gLockSpinCount;

typedef void (*natsInitOnceCb)(void);

typedef struct __natsControl
{
    char    *op;
    char    *args;

} natsControl;

typedef struct __natsServerInfo
{
    char        *id;
    char        *host;
    int         port;
    char        *version;
    bool        authRequired;
    bool        tlsRequired;
    int64_t     maxPayload;

} natsServerInfo;

typedef struct __natsSSLCtx
{
    natsMutex   *lock;
    int         refs;
    SSL_CTX     *ctx;
    char        *expectedHostname;

} natsSSLCtx;

#define natsSSLCtx_getExpectedHostname(ctx) ((ctx)->expectedHostname)

struct __natsOptions
{
    // This field must be the first (see natsOptions_clone, same if you add
    // allocated fields such as strings).
    natsMutex               *mu;

    char                    *url;
    char                    **servers;
    int                     serversCount;
    bool                    noRandomize;
    int64_t                 timeout;
    char                    *name;
    bool                    verbose;
    bool                    pedantic;
    bool                    allowReconnect;
    bool                    secure;
    int                     maxReconnect;
    int64_t                 reconnectWait;

    natsConnectionHandler   closedCb;
    void                    *closedCbClosure;

    natsConnectionHandler   disconnectedCb;
    void                    *disconnectedCbClosure;

    natsConnectionHandler   reconnectedCb;
    void                    *reconnectedCbClosure;

    natsErrHandler          asyncErrCb;
    void                    *asyncErrCbClosure;

    int64_t                 pingInterval;
    int                     maxPingsOut;
    int                     maxPendingMsgs;

    natsSSLCtx              *sslCtx;

};

typedef struct __natsMsgList
{
    natsMsg     *head;
    natsMsg     *tail;
    int         count;

} natsMsgList;

struct __natsSubscription
{
    natsMutex                   *mu;

    int                         refs;

    // These two are updated by the connection in natsConn_processMsg.
    // 'msgs' is used to determine if we have reached the max (if > 0).
    uint64_t                    msgs;
    uint64_t                    bytes;

    // This is non-zero when auto-unsubscribe is used.
    uint64_t                    max;

    // This is updated in the delivery thread (or NextMsg) and indicates
    // how many message have been presented to the callback (or returned
    // from NextMsg). Like 'msgs', this is also used to determine if we
    // have reached the max number of messages.
    uint64_t                    delivered;

    // The list of messages waiting to be delivered to the callback (or
    // returned from NextMsg).
    natsMsgList                 msgList;

    // The max number of messages that should go in msgList.
    int                         pendingMax;

    // True if msgList.count is over pendingMax
    bool                        slowConsumer;

    // If 'true', the connection will notify the deliveryThread when a
    // message arrives (if the delivery thread is in wait).
    bool                        noDelay;

    // Condition variable used to wait for message delivery.
    natsCondition               *cond;

    // When 'noDelay' is false, a timer is used to check for the need
    // to notify the deliveryMsg thread.
    natsTimer                   *signalTimer;

    // Interval of the above timer.
    int64_t                     signalTimerInterval;

    // Indicates the number of time the signal timer failed to try to
    // acquire the lock (after which it will call Lock()).
    int                         signalFailCount;

    // Temporarily voids the use of the signalTimer when the message list
    // count reaches a certain threshold.
    int                         signalLimit;

    // This is > 0 when the delivery thread (or NextMsg) goes into a
    // condition wait.
    int                         inWait;

    // The subscriber is closed (or closing).
    bool                        closed;

    // If true, the subscription is closed, but because the connection
    // was closed, not because of subscription (auto-)unsubscribe.
    bool                        connClosed;

    // Subscriber id. Assigned during the creation, does not change after that.
    int64_t                     sid;

    // Subject that represents this subscription. This can be different
    // than the received subject inside a Msg if this is a wildcard.
    char                        *subject;

    // Optional queue group name. If present, all subscriptions with the
    // same name will form a distributed queue, and each message will
    // only be processed by one member of the group.
    char                        *queue;

    // Reference to the connection that created this subscription.
    struct __natsConnection     *conn;

    // Delivery thread (for async subscription).
    natsThread                  *deliverMsgsThread;

    // Message callback and closure (for async subscription).
    natsMsgHandler              msgCb;
    void                        *msgCbClosure;

};

typedef struct __natsPong
{
    int64_t             id;

    struct __natsPong   *prev;
    struct __natsPong   *next;

} natsPong;

typedef struct __natsPongList
{
    natsPong            *head;
    natsPong            *tail;

    int64_t             incoming;
    int64_t             outgoingPings;

    natsPong            cached;

    natsCondition       *cond;

} natsPongList;

typedef struct __natsSockCtx
{
    natsSock        fd;
    bool            fdActive;

    // We switch to blocking socket after receiving the PONG to the first PING
    // during the connect process. Should we make all read/writes non blocking,
    // then we will use two different fd sets, and also probably pass deadlines
    // individually as opposed to use one at the connection level.
    fd_set          *fdSet;
    natsDeadline    deadline;

    SSL             *ssl;

} natsSockCtx;

struct __natsConnection
{
    natsMutex           *mu;
    natsOptions         *opts;
    const natsUrl       *url;

    int                 refs;

    natsSockCtx         sockCtx;

    natsSrvPool         *srvPool;

    natsBuffer          *pending;
    bool                usePending;

    natsBuffer          *bw;
    natsBuffer          *scratch;

    natsServerInfo      info;

    int64_t             ssid;
    natsHash            *subs;

    natsConnStatus      status;
    natsStatus          err;
    char                errStr[256];

    natsParser          *ps;
    natsTimer           *ptmr;
    int                 pout;

    natsPongList        pongs;

    natsThread          *readLoopThread;

    natsThread          *flusherThread;
    natsCondition       *flusherCond;
    bool                flusherSignaled;
    bool                flusherStop;

    natsThread          *reconnectThread;

    natsStatistics      stats;
};

//
// Library
//
void
natsSys_Init(void);

void
natsLib_Retain(void);

void
natsLib_Release(void);

void
nats_resetTimer(natsTimer *t, int64_t newInterval);

void
nats_stopTimer(natsTimer *t);

// Returns the number of timers that have been created and not stopped.
int
nats_getTimersCount(void);

// Returns the number of timers actually in the list. This should be
// equal to nats_getTimersCount() or nats_getTimersCount() - 1 when a
// timer thread is invoking a timer's callback.
int
nats_getTimersCountInList(void);

natsStatus
nats_postAsyncCbInfo(natsAsyncCbInfo *info);

void
nats_sslRegisterThreadForCleanup(void);

natsStatus
nats_sslInit(void);

//
// Threads
//
typedef void (*natsThreadCb)(void *arg);

natsStatus
natsThread_Create(natsThread **t, natsThreadCb cb, void *arg);

bool
natsThread_IsCurrent(natsThread *t);

void
natsThread_Join(natsThread *t);

void
natsThread_Detach(natsThread *t);

void
natsThread_Destroy(natsThread *t);

natsStatus
natsThreadLocal_CreateKey(natsThreadLocal *tl, void (*destructor)(void*));

void*
natsThreadLocal_Get(natsThreadLocal tl);

#define natsThreadLocal_Set(k, v) natsThreadLocal_SetEx((k), (v), true)

natsStatus
natsThreadLocal_SetEx(natsThreadLocal tl, const void *value, bool setErr);

void
natsThreadLocal_DestroyKey(natsThreadLocal tl);

bool
nats_InitOnce(natsInitOnceType *control, natsInitOnceCb cb);


//
// Conditions
//
natsStatus
natsCondition_Create(natsCondition **cond);

void
natsCondition_Wait(natsCondition *cond, natsMutex *mutex);

natsStatus
natsCondition_TimedWait(natsCondition *cond, natsMutex *mutex, int64_t timeout);

natsStatus
natsCondition_AbsoluteTimedWait(natsCondition *cond, natsMutex *mutex,
                                int64_t absoluteTime);

void
natsCondition_Signal(natsCondition *cond);

void
natsCondition_Broadcast(natsCondition *cond);

void
natsCondition_Destroy(natsCondition *cond);

//
// Mutexes
//
natsStatus
natsMutex_Create(natsMutex **newMutex);

void
natsMutex_Lock(natsMutex *m);

bool
natsMutex_TryLock(natsMutex *m);

void
natsMutex_Unlock(natsMutex *m);

void
natsMutex_Destroy(natsMutex *m);


#endif /* NATSP_H_ */
