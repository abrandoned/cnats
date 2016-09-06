require 'rubygems'
require 'ffi'
require 'thread'
require 'securerandom'

module NATSFFI
  extend FFI::Library
  ffi_lib_flags :now, :global
  ffi_lib File.expand_path("./libnats.so", File.dirname(__FILE__))

  # message handler callback definition
  callback :on_message_function, [:pointer, :pointer, :pointer, :pointer], :void

  # natsConnection
  attach_function :natsConnection_Close, [:pointer], :void
  attach_function :natsConnection_Connect, [:pointer, :pointer], :void
  attach_function :natsConnection_ConnectTo, [:pointer, :string], :void
  attach_function :natsConnection_Destroy, [:pointer], :void
  attach_function :natsConnection_Flush, [:pointer], :void
  attach_function :natsConnection_PublishString, [:pointer, :string, :string], :void
  attach_function :natsConnection_Subscribe, [:pointer, :pointer, :string, :on_message_function, :pointer], :void

  # natsMsg
  attach_function :natsMsg_Destroy, [:pointer], :void
  attach_function :natsMsg_GetSubject, [:pointer], :string
  attach_function :natsMsg_GetReply, [:pointer], :string
  attach_function :natsMsg_GetData, [:pointer], :string
  attach_function :natsMsg_GetDataLength, [:pointer], :int

  # natsNUID
  attach_function :natsNUID_free, [], :void
  attach_function :natsNUID_init, [], :void
  attach_function :natsNUID_Next, [:string, :int], :void

  # natsOptions
  attach_function :natsOptions_Create, [:pointer], :void
  attach_function :natsOptions_SetCiphers, [:pointer, :string], :void
  attach_function :natsOptions_SetExpectedHostname, [:pointer, :string], :void
  attach_function :natsOptions_SetSecure, [:pointer, :bool], :void
  attach_function :natsOptions_SetServers, [:pointer, :pointer], :void
  attach_function :natsOptions_SetURL, [:pointer, :string], :void

  # natsSubscription
  attach_function :natsSubscription_AutoUnsubscribe, [:pointer, :int], :void
  attach_function :natsSubscription_Destroy, [:pointer], :void
  attach_function :natsSubscription_IsValid, [:pointer], :bool
  attach_function :natsSubscription_Unsubscribe, [:pointer], :void

  def self.subscribe(connection, subscription, subject, &blk)
    if blk.arity == 4
      NATSFFI.natsConnection_Subscribe(subscription, connection, subject, blk, nil)
      return subscription.get_pointer(0) # return the subscription_pointer that was created
    else
      raise "subscribe block arity must be 4 ... ish"
    end
  end

  def self.run_subscribe(connection, subscription)
    q = Queue.new
    uuid = SecureRandom.uuid

    new_sub = subscribe(connection, subscription, uuid) do |conn, sub, msg, closure|
      print "+"
      q << NATSFFI.natsMsg_GetData(msg)
      NATSFFI.natsMsg_Destroy(msg)
      NATSFFI.natsSubscription_Destroy(sub)
    end

    NATSFFI.natsSubscription_AutoUnsubscribe(new_sub, 1)
    NATSFFI.natsConnection_PublishString(connection, uuid, "hello from the other side")
    NATSFFI.natsConnection_Flush(connection)

    while q.empty?
      puts "waiting"
      sleep 0.1
    end
  end

  def self.test_subscribe
    threads = []

    1.times do
      threads << Thread.new do
        connection_pointer = FFI::MemoryPointer.new :pointer
        NATSFFI.natsConnection_ConnectTo(connection_pointer, "nats://localhost:4222")
        connection_pointer = connection_pointer.get_pointer(0)

        10_000.times do
          subscription_pointer = FFI::MemoryPointer.new :pointer
          run_subscribe(connection_pointer, subscription_pointer)
        end

        NATSFFI.natsConnection_Flush(connection_pointer)
        NATSFFI.natsConnection_Close(connection_pointer)
        NATSFFI.natsConnection_Destroy(connection_pointer)
      end
    end

    threads.map(&:join)
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
