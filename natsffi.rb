require 'rubygems'
require 'ffi'
require 'thread'
require 'securerandom'

trap(:TRAP) do
  ::Thread.list.each do |thread|
    $stdout << <<-THREAD_TRACE
    #{thread.inspect}:
    #{thread.backtrace && thread.backtrace.join($INPUT_RECORD_SEPARATOR)}"
    THREAD_TRACE
  end
end

module NATSFFI
  extend FFI::Library
  ffi_lib_flags :now, :global
  ffi_lib File.expand_path("./libnats.so", File.dirname(__FILE__))

  enum :NATS_STATUS, [
    :NATS_OK, 0,                     #< Success
    :NATS_ERR,                       #< Generic error
    :NATS_PROTOCOL_ERROR,            #< Error when parsing a protocol message, or not getting the expected message.
    :NATS_IO_ERROR,                  #< IO Error (network communication).
    :NATS_LINE_TOO_LONG,             #< The protocol message read from the socket does not fit in the read buffer.
    :NATS_CONNECTION_CLOSED,         #< Operation on this connection failed because the connection is closed.
    :NATS_NO_SERVER,                 #< Unable to connect, the server could not be reached or is not running.
    :NATS_STALE_CONNECTION,          #< The server closed our connection because it did not receive PINGs at the expected interval.
    :NATS_SECURE_CONNECTION_WANTED,  #< The client is configured to use TLS, but the server is not.
    :NATS_SECURE_CONNECTION_REQUIRED,#< The server expects a TLS connection.
    :NATS_CONNECTION_DISCONNECTED,   #< The connection was disconnected. Depending on the configuration, the connection may reconnect.
    :NATS_CONNECTION_AUTH_FAILED,    #< The connection failed due to authentication error.
    :NATS_NOT_PERMITTED,             #< The action is not permitted.
    :NATS_NOT_FOUND,                 #< An action could not complete because something was not found. So far, this is an internal error.
    :NATS_ADDRESS_MISSING,           #< Incorrect URL. For instance no host specified in the URL.
    :NATS_INVALID_SUBJECT,           #< Invalid subject, for instance NULL or empty string.
    :NATS_INVALID_ARG,               #< An invalid argument is passed to a function. For instance passing NULL to an API that does not accept this value.
    :NATS_INVALID_SUBSCRIPTION,      #< The call to a subscription function fails because the subscription has previously been closed.
    :NATS_INVALID_TIMEOUT,           #< Timeout must be positive numbers.
    :NATS_ILLEGAL_STATE,             #< An unexpected state, for instance calling #natsSubscription_NextMsg() on an asynchronous subscriber.
    :NATS_SLOW_CONSUMER,             #< The maximum number of messages waiting to be delivered has been reached. Messages are dropped.
    :NATS_MAX_PAYLOAD,               #< Attempt to send a payload larger than the maximum allowed by the NATS Server.
    :NATS_MAX_DELIVERED_MSGS,        #< Attempt to receive more messages than allowed, for instance because of #natsSubscription_AutoUnsubscribe().
    :NATS_INSUFFICIENT_BUFFER,       #< A buffer is not large enough to accommodate the data.
    :NATS_NO_MEMORY,                 #< An operation could not complete because of insufficient memory.
    :NATS_SYS_ERROR,                 #< Some system function returned an error.
    :NATS_TIMEOUT,                   #< An operation timed-out. For instance #natsSubscription_NextMsg().
    :NATS_FAILED_TO_INITIALIZE,      #< The library failed to initialize.
    :NATS_NOT_INITIALIZED,           #< The library is not yet initialized.
    :NATS_SSL_ERROR                  #< An SSL error occurred when trying to establish a connection.
  ]

  # message handler callback definition
  callback :on_message_function, [:pointer, :pointer, :pointer, :pointer], :void

  # nats
  attach_function :nats_Close, [], :void
  attach_function :nats_GetLastError, [:pointer], :strptr
  attach_function :nats_GetLastErrorStack, [:buffer_out, :size_t], :int
  attach_function :nats_GetVersion, [], :strptr
  attach_function :nats_GetVersionNumber, [], :uint32
  attach_function :nats_Now, [], :int64
  attach_function :nats_NowInNanoSeconds, [], :int64
  attach_function :nats_Open, [:int64], :int
  # attach_function :nats_PrintLastErrorStack, [:pointer], :void
  attach_function :nats_SetMessageDeliveryPoolSize, [:int], :int
  attach_function :nats_Sleep, [:int64], :void

  # natsConnection
  attach_function :natsConnection_Buffered, [:pointer], :int
  attach_function :natsConnection_Close, [:pointer], :void
  attach_function :natsConnection_Connect, [:pointer, :pointer], :int
  attach_function :natsConnection_ConnectTo, [:pointer, :string], :int
  attach_function :natsConnection_Destroy, [:pointer], :void
  attach_function :natsConnection_Flush, [:pointer], :int
  attach_function :natsConnection_IsClosed, [:pointer], :bool
  attach_function :natsConnection_IsReconnecting, [:pointer], :bool
  attach_function :natsConnection_PublishString, [:pointer, :string, :string], :void
  attach_function :natsConnection_Request, [:pointer, :pointer, :string, :string, :int, :int64], :void
  attach_function :natsConnection_RequestString, [:pointer, :pointer, :string, :string, :int64], :void
  attach_function :natsConnection_Subscribe, [:pointer, :pointer, :string, :on_message_function, :pointer], :void

  # natsMsg
  attach_function :natsMsg_Destroy, [:pointer], :void
  attach_function :natsMsg_GetSubject, [:pointer], :strptr
  attach_function :natsMsg_GetReply, [:pointer], :strptr
  attach_function :natsMsg_GetData, [:pointer], :strptr
  attach_function :natsMsg_GetDataLength, [:pointer], :int

  # natsNUID
  attach_function :natsNUID_free, [], :void
  attach_function :natsNUID_init, [], :void
  attach_function :natsNUID_Next, [:string, :int], :void

  # natsOptions
  attach_function :natsOptions_Create, [:pointer], :int
  attach_function :natsOptions_Destroy, [:pointer], :void
  attach_function :natsOptions_IPResolutionOrder, [:pointer, :int], :int
  attach_function :natsOptions_SetAllowReconnect, [:pointer, :bool], :int
  attach_function :natsOptions_SetCiphers, [:pointer, :string], :int
  attach_function :natsOptions_SetExpectedHostname, [:pointer, :string], :int
  attach_function :natsOptions_SetMaxPingsOut, [:pointer, :int64], :int
  attach_function :natsOptions_SetMaxPendingMsgs, [:pointer, :int], :int
  attach_function :natsOptions_SetMaxReconnect, [:pointer, :int], :int
  attach_function :natsOptions_SetReconnectBufSize, [:pointer, :int], :int
  attach_function :natsOptions_SetReconnectWait, [:pointer, :int64], :int
  attach_function :natsOptions_SetName, [:pointer, :string], :int
  attach_function :natsOptions_SetNoRandomize, [:pointer, :bool], :int
  attach_function :natsOptions_SetPedantic, [:pointer, :bool], :int
  attach_function :natsOptions_SetPingInterval, [:pointer, :int64], :int
  attach_function :natsOptions_SetSecure, [:pointer, :bool], :int
  attach_function :natsOptions_SetServers, [:pointer, :pointer], :int
  attach_function :natsOptions_SetTimeout, [:pointer, :int64], :int
  attach_function :natsOptions_SetToken, [:pointer, :string], :int
  attach_function :natsOptions_SetURL, [:pointer, :string], :int
  attach_function :natsOptions_SetUserInfo, [:pointer, :string, :string], :int
  attach_function :natsOptions_SetVerbose, [:pointer, :bool], :int
  attach_function :natsOptions_UseGlobalMessageDelivery, [:pointer, :bool], :void

  # natsSubscription
  attach_function :natsSubscription_AutoUnsubscribe, [:pointer, :int], :void
  attach_function :natsSubscription_Destroy, [:pointer], :void
  attach_function :natsSubscription_IsValid, [:pointer], :bool
  attach_function :natsSubscription_Unsubscribe, [:pointer], :void

  # natsStatistics
  attach_function :natsStatistics_Create, [:pointer], :int
  attach_function :natsStatistics_Destroy, [:pointer], :void
  attach_function :natsStatistics_GetCounts, [:pointer, :pointer, :pointer, :pointer, :pointer, :pointer], :int

  # natsStatus
  attach_function :natsStatus_GetText, [:NATS_STATUS], :strptr


  SubscribeCallback = FFI::Function.new(:void, [:pointer, :pointer, :pointer, :pointer]) do |conn, sub, msg, closure|
    #queue_name = closure.read_string
    #queue_name = NATSFFI.natsMsg_GetSubject(msg)
    #queue_for_and_remove(queue_name) << NATSFFI.natsMsg_GetData(msg)

    #print "+"
    reply_to, _ = NATSFFI.natsMsg_GetReply(msg)
    NATSFFI.natsConnection_PublishString(conn, reply_to, "thanks")
    NATSFFI.natsConnection_Flush(conn)
    NATSFFI.natsMsg_Destroy(msg)
  end

  def self.subscribe(connection, subscription, subject, &blk)
    if blk.arity == 4
      puts "subscribing to => #{subject}"
      NATSFFI.natsConnection_Subscribe(subscription, connection, subject, blk, nil)
    else
      raise "subscribe block arity must be 4 ... ish"
    end
  end

  Q_MUTEX = Mutex.new

  def self.queue_for_and_remove(queue_name)
    Q_MUTEX.synchronize do
      @queues.delete(queue_name)
    end
  end

  def self.queue_for(queue_name)
    Q_MUTEX.synchronize do
      @queues ||= {}
      @queues[queue_name] ||= Queue.new
    end
  end

  def self.run_subscribe(connection)
    subscription = FFI::MemoryPointer.new :pointer
    uuid = SecureRandom.uuid
    q = Queue.new
    #q = queue_for(uuid)

    #NATSFFI.natsConnection_Subscribe(subscription, connection, uuid, NATSFFI::SubscribeCallback, nil)
    subscribe(connection, subscription, uuid) do |conn, sub, msg, closure|
      print "+"
      data, _ = NATSFFI.natsMsg_GetData(msg)
      subject, _ = NATSFFI.natsMsg_GetSubject(msg)
      puts subject
      q << data
      NATSFFI.natsMsg_Destroy(msg)
      NATSFFI.natsSubscription_Unsubscribe(sub)
    end

    #NATSFFI.natsSubscription_AutoUnsubscribe(subscription.get_pointer(0), 1)
    sub = subscription.get_pointer(0)
    #NATSFFI.natsSubscription_AutoUnsubscribe(sub, 1)
    NATSFFI.natsConnection_PublishString(connection, uuid, "hello from the other side")
    #NATSFFI.natsConnection_Flush(connection)

    q.pop
    NATSFFI.natsSubscription_Destroy(sub)
  end

  def self.test_subscribe
    threads = []

    1.times do
      threads << Thread.new do
        connection_pointer = FFI::MemoryPointer.new :pointer
        NATSFFI.natsConnection_ConnectTo(connection_pointer, "nats://localhost:4222")
        connection = connection_pointer.get_pointer(0)

        1_000.times do
          run_subscribe(connection)
        end

        NATSFFI.natsConnection_Flush(connection)
        NATSFFI.natsConnection_Close(connection)
        NATSFFI.natsConnection_Destroy(connection)
      end
    end

    threads.map(&:join)
  end

  def self.test_request_reply
    start = Time.now
    num_threads = 1
    publish_per_thread = 10
    threads = []
    subject = "hello"
    message = "world"
    reply = "thanks"
    message_size = message.size

    subscription = FFI::MemoryPointer.new :pointer
    conn = FFI::MemoryPointer.new :pointer
    NATSFFI.natsConnection_ConnectTo(conn, "nats://localhost:4222")
    conn_t = conn.get_pointer(0)
    NATSFFI.natsConnection_Subscribe(subscription, conn_t, subject, NATSFFI::SubscribeCallback, nil)
    NATSFFI.natsConnection_Flush(conn_t)

    num_threads.times do
      threads << Thread.new do
        options_pointer = FFI::MemoryPointer.new :pointer
        connection_pointer = FFI::MemoryPointer.new :pointer

        NATSFFI.natsOptions_Create(options_pointer)
        options_pointer = options_pointer.get_pointer(0)
        NATSFFI.natsOptions_SetURL(options_pointer, "nats://localhost:4222")

        NATSFFI.natsConnection_Connect(connection_pointer, options_pointer)
        connection_pointer = connection_pointer.get_pointer(0)

        publish_per_thread.times do
          FFI::MemoryPointer.new(:pointer) do |message_pointer|
            NATSFFI.natsConnection_RequestString(message_pointer, connection_pointer, subject, message, 1000)
            NATSFFI.natsMsg_Destroy(message_pointer.get_pointer(0))
          end
        end
      end
    end

    threads.map(&:join)

    NATSFFI.natsSubscription_Unsubscribe(subscription.get_pointer(0))
    NATSFFI.natsSubscription_Destroy(subscription.get_pointer(0))

    finish = Time.now
    time_diff = finish.to_i - start.to_i
    throughput = (num_threads * publish_per_thread)
    puts <<-FINISH
    THREADS: #{num_threads}
    PUBLISH PER THREAD: #{publish_per_thread}
    START: #{start}
    FINISH: #{finish}
    PER SECOND: #{time_diff == 0 ? throughput : throughput/time_diff}
    FINISH
  end

  def self.test_threaded
    start = Time.now
    num_threads = 16
    publish_per_thread = 10_000_000
    threads = []
    subject = "hello"
    message = "world"
    message_size = message.size

    num_threads.times do
      threads << Thread.new do
        connection_pointer = nil

        if false
          connection_pointer = FFI::MemoryPointer.new :pointer
          NATSFFI.natsConnection_ConnectTo(connection_pointer, "nats://localhost:4222")
          connection_pointer = connection_pointer.get_pointer(0)
        else
          options_pointer = FFI::MemoryPointer.new :pointer
          connection_pointer = FFI::MemoryPointer.new :pointer

          NATSFFI.natsOptions_Create(options_pointer)
          options_pointer = options_pointer.get_pointer(0)
          NATSFFI.natsOptions_SetURL(options_pointer, "nats://localhost:4222")

          NATSFFI.natsConnection_Connect(connection_pointer, options_pointer)
          connection_pointer = connection_pointer.get_pointer(0)
        end

        publish_per_thread.times do
          NATSFFI.natsConnection_PublishString(connection_pointer, subject, message)
        end
      end
    end

    threads.map(&:join)
    finish = Time.now
    puts <<-FINISH
    THREADS: #{num_threads}
    PUBLISH PER THREAD: #{publish_per_thread}
    START: #{start}
    FINISH: #{finish}
    PER SECOND: #{(num_threads * publish_per_thread)/(finish.to_i - start.to_i)}
    FINISH
  end
end
