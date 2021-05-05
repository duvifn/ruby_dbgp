#!/usr/share/rvm/rubies/ruby-2.7.3/bin/ruby -w

# Copyright (c) 2016 ActiveState Software Inc.
# DBGP client for debugging Ruby 2.x.
#
# This client is a stand-alone Ruby application that directly debugs client code
# via the Byebug debugger while communicating with an IDE. There are two ways
# the IDE (or user) can use this client:
#   (1) Envoke this script with the name of the file to debug as its only
#       argument. Any options like host and port must be specified as
#       `key=value`, space-separated strings in a `RUBYDB_OPTS` environment
#       variable. See the end of this script for more details.
#   (2) `require` this script from the file to debug and call
#           Byebug::DBGP.start()
#       above the line to start debugging on. Keyword arguments for setting the
#       host and port (especially for remote debugging) and other options are
#       available. See that method's documentation for more details.
#
# This client listens for incoming IDE commands in a separate thread. As
# commands come in, they are queued up in a thread-safe Queue. While the
# debugger is paused, Byebug reads any queued up commands and runs them in the
# main thread. When execution resumes (i.e. the debugger is in the 'run' state),
# a new thread is started that processes any incoming asynchronous commands in
# that thread. When the debugger is paused again, the async thread is killed and
# subsequent commands are processed by Byebug in the main thread as usual.
#
# In order to interface with Byebug, this client has two main components: the
# DBGPInterface and the DBGPCommandProcessor. Each is a subclass of a
# corresponding Byebug component. The DBGPInterface is responsible for
# communicating with the IDE: retrieving debugging commands to run and sending
# XML responses. The DBGPCommandProcessor is responsible for executing the
# debugging commands received. Byebug handles the communication between
# DBGPInterface and DBGPCommandProcessor by itself.
#
# For more information on the DBGP protocol, see:
#    http://xdebug.org/docs-dbgp.php
#    
# This DBGP client was developed against v1.0 of the DBGP protocol.

require 'base64'
require 'logger'
require 'optparse'
require 'rexml/document'
require 'shellwords'
require 'socket'
require 'uri'

begin
  require 'byebug/core'
rescue LoadError
  # This should only happen when running unit tests on a development machine.
  # Add the development machine's Byebug lib path to the Ruby path.
  $LOAD_PATH << '../../../../contrib/ruby-debug-base/byebug-8.2.1/lib'
  begin
    require 'byebug/core'
  rescue LoadError => e
    $stderr.puts(e.message)
    $stderr.puts("The Komodo Ruby debugger couldn't load the Byebug component.")
    $stderr.puts("  Please install it by running `gem install byebug`")
    exit(1)
  end
end
require 'byebug/helpers/eval'

# Patch Byebug helper method since Byebug is not being used as a RubyGem.
require 'byebug/helpers/path'
module Byebug
  module Helpers
    module PathHelper
      def lib_files() @lib_files ||= [__FILE__] end
    end
  end
end

# Top-level Ruby 2.x debugger module.
module Byebug
  # Module that houses DBGP protocol constants and start method.
  module DBGP
    # Status types.
    STATUS_STARTING = 0
    STATUS_STOPPING = 1
    STATUS_STOPPED = 2
    STATUS_RUNNING = 3
    STATUS_BREAK = 4
    STATUS_INTERACT = 5
    STATUS_NAMES = %w(starting stopping stopped running break interactive)
    # Reason types.
    REASON_OK = 0
    REASON_ERROR = 1
    REASON_ABORTED = 2
    REASON_EXCEPTION = 3
    REASON_NAMES = %w(ok error aborted exception)
    # Breakpoint types.
    BREAKPOINT_TYPE_LINE = 0
    BREAKPOINT_TYPE_CONDITIONAL = 1
    BREAKPOINT_TYPE_NAMES = %w(line conditional)
    # Breakpoint states.
    BREAKPOINT_STATE_DISABLED = 0
    BREAKPOINT_STATE_ENABLED = 1
    BREAKPOINT_STATE_NAMES = %w(disabled enabled)
    # Context types.
    CONTEXT_LOCALS = 0
    CONTEXT_SELF = 1
    CONTEXT_GLOBALS = 2
    CONTEXT_BUILTINS = 3
    CONTEXT_SPECIAL = 4
    CONTEXT_NAMES = %w(Locals Self Globals Builtins Special)
    # Type map.
    TYPEMAP = {
      'NilClass' => 'null',
      'Array' => 'array',
      'Hash' => 'hash',
      'Bignum' => 'int',
      'Fixnum' => 'int',
      'Integer' => 'int',
      'Numeric' => 'int',
      'Float' => 'float',
      'TrueClass' => 'bool',
      'FalseClass' => 'bool',
      'String' => 'string',
      'Symbol' => 'symbol',
      'Binding' => 'resource',
      'Class' =>  'resource',
      'Continuation' =>  'resource',
      'Exception' => 'resource',
      'Method' => 'resource',
      'Module' => 'resource',
      'Proc' => 'resource',
      'Thread' => 'resource',
      'Fiber' => 'resource',
    }
    # Stdout/Stderr stream options.
    STREAM_DISABLE = 0
    STREAM_COPY = 1
    STREAM_REDIRECT = 2
    
    # Replacement IO stream for $stdout and $stderr in order for the IDE to be
    # notified of output.
    class OutputStream
      # IDE state: STREAM_DISABLE, STREAM_COPY, or STREAM_REDIRECT.
      attr_accessor :state
      
      # Creates a replacement IO stream for $stdout or $stderr.
      # origin:: Either STDOUT or STDERR.
      # ide:: The DBGPInterface to send output to.
      def initialize(origin, ide)
        @origin = origin
        @type = origin == STDOUT ? 'stdout' : 'stderr'
        @state = STREAM_DISABLE
        @ide = ide
      end
      
      # Copies the given output to the IDE if it is listening for it.
      # string:: Output to copy.
      def copy(string)
        $LOG.debug(self.class.name) do
          "Attempting to send #{@type} to IDE: '#{string}'..."
        end
        stream = REXML::Element.new('stream')
        stream.add_attribute('type', @type)
        stream.text = Base64.encode64(string)
        @ide.puts stream if @ide.connected?
        $LOG.debug(self.class.name) do
          @ide.connected? ? "Sent." : "IDE is no longer listening."
        end
      end
      
      # Replacement for +puts+.
      def puts(*args)
        @origin.puts *args unless @state == STREAM_REDIRECT
        copy("#{args.join('\n')}\n") unless @state == STREAM_DISABLE
      end
      
      # Replacement for +print+.
      def print(*args)
        @origin.print *args unless @state == STREAM_REDIRECT
        copy(args.join) unless @state == STREAM_DISABLE
      end
      
      # Replacement for +printf+.
      def printf(*args)
        @origin.printf *args unless @state == STREAM_REDIRECT
        copy(sprintf(*args)) unless @state == STREAM_DISABLE
      end
      
      # Replacement for +write+.
      def write(arg)
        @origin.write(arg) unless @state == STREAM_REDIRECT
        copy(arg) unless @state == STREAM_DISABLE
      end
      
      # Empty implementation for +close+ in order to better simulate a stream
      # object.
      # In particular, this is needed for Ruby's stdlib Logger.
      def close
        # empty
      end
      
      # Forward any other methods to STDOUT or STDERR directly.
      # That way errors are not raised when a debugee uses $stdout or $stderr in
      # an unexpected way.
      def method_missing(name, *args, &block)
        @origin.__send__(name, *args, &block)
        $LOG.debug(self.class.name) { "Unknown #{@type} method: '#{name}'" }
      end
    end
    
    # Represents a Ruby variable as a DBGP property for sending to the IDE.
    class Property
      include Byebug::Helpers::EvalHelper
      @@options = {} # needs to be a mirror of DBGPInterface's @options hash
      attr_reader :name, :value
      
      # Creates a new DBGP property from the Ruby variable with the given name
      # and value or binding.
      # name:: The Ruby variable's name.
      # full_name:: Optional full variable's name, which includes any object
      #             names the variable belongs to. The default value is the
      #             value of 'name'.
      # value:: Optional variable value (the Ruby object itself). If not given,
      #         'binding' must be specified.
      # binding:: Optional binding to evaluate the variable name in in order to
      #           fetch the variable's value (as a Ruby object). If not given,
      #           'value' must be specified.
      def initialize(name, full_name = nil, value: nil, binding: nil)
        @name = name.to_s
        @full_name = full_name || @name
        @value = binding ? safe_inspect(silent_eval(name.to_s, binding)) : value
      end
      
      # Returns the property's XML representation, suitable for sending to the
      # IDE (after adding it to a proper response tag).
      # depth:: The current depth when fetching child properties. This is used
      #         for internal purposes and should not be set externally.
      # max_data:: Optional size to limit property value text to. The default
      #            value is +@@options['max_data']+.
      # page:: Optional current page when fetching child properties. The default
      #        value is 0, the first page.
      def to_xml(depth = 1, max_data = nil, page: 0)
        property = REXML::Element.new('property')
        
        # Property attributes.
        property.add_attributes({
          'name' => @name,
          'fullname' => @full_name,
          'classname' => @value.class.name,
          'type' => DBGP::TYPEMAP.fetch(@value.class.name, 'object'),
          'size' => @value.to_s.length,
          'key' => @value.object_id
        })
        children = []
        if depth <= @@options['max_depth'].to_i &&
           @@options['max_children'].to_i > 0
          # Fetch children.
          case property.attributes['type']
          when 'array'
            @value.each_with_index do |v, i|
              children << Property.new(i, "#{@full_name}[#{i}]", value: v)
            end
          when 'hash'
            @value.keys.sort.each do |k|
              children << Property.new("#{safe_inspect(k)}",
                                       "#{@full_name}[#{safe_inspect(k)}]",
                                       value: @value[k])
            end
          when 'object'
            vars = []
            @value.instance_variables.each do |v|
              vars << Property.new("#{v.to_s}", "#{@full_name}.#{v.to_s}",
                                       value: @value.instance_variable_get(v))
            end
            @value.class.class_variables.each do |v|
              vars << Property.new("#{v.to_s}",
                                   "#{@value.class.name}.#{v.to_s}",
                                   value: @value.class.class_variable_get(v))
            end
            children.push(*vars.sort_by { |v| v.name.match(/^@@?(.+)$/)[1] })
          end
        end
        property.add_attribute('children', children.empty? ? '0' : '1')
        unless children.empty?
          property.add_attributes({
            'page' => page,
            'pagesize' => @@options['max_children'],
            'numchildren' => children.length
          })
        end
        # Property value data (trimmed, if necessary).
        value = REXML::Element.new('value')
        value.add_attribute('encoding', 'base64')
        text = !@value.nil? ? @value.to_s : 'nil'
        value.text = Base64.encode64((len = (max_data ||
                                             @@options['max_data'].to_i)) > 0 ?
                                     text[0..len] : text)
        property.add_element(value)
        # Add paged children XML properties.
        unless children.empty?
          max_children = @@options['max_children'].to_i
          range = (page * max_children)...(page * max_children + max_children)
          children[range].each do |child|
            property.add_element(child.to_xml(depth + 1, max_data))
          end
        end
        
        property
      end
    end
    
    # An error raised when executing a command issued by the IDE.
    class CommandError < Exception
      NONE                      = 0   # no error
      COMMAND_PARSE             = 1   # parse error
      DUPLICATE_ARGS            = 2   # duplicate arguments in command
      INVALID_ARGS              = 3   # invalid options
      COMMAND_NOT_SUPPORTED     = 4   # unimplemented command
      COMMAND_NOT_AVAILABLE     = 5   # command not available
      FILE_ACCESS               = 100 # can not open file
      STREAM_REDIRECT_FAILED    = 101 # stream redirect failed
      BREAKPOINT_INVALID        = 200 # breakpoint could not be set
      BREAKPOINT_TYPE           = 201 # breakpoint type not supported
      BREAKPOINT_INVALID_LINE   = 202 # invalid breakpoint
      BREAKPOINT_NOT_REACHABLE  = 203 # no code on breakpoint line
      BREAKPOINT_STATE          = 204 # invalid breakpoint state
      BREAKPOINT_DOES_NOT_EXIST = 205 # no such breakpoint
      EVAL_FAILED               = 206 # error evaluating code
      INVALID_EXPRESSION        = 207 # invalid expression
      PROPERTY_DOES_NOT_EXIST   = 300 # cannot get property
      STACK_DEPTH               = 301 # stack depth invalid
      CONTEXT_INVALID           = 302 # context invalid
      ENCODING                  = 900 # encoding not supported
      EXCEPTION                 = 998 # internal exception occurred
      UNKNOWN                   = 999 # unknown error
      
      # Creates a new error object for a command issued by the IDE.
      # command:: The string name of the command issued.
      # transaction_id:: The transaction ID of the command issued.
      # error_code:: The DBGP error code for the error that occurred.
      # message:: The error text to send back to the IDE.
      def initialize(command, transaction_id, error_code, error_message)
        @xml = REXML::Element.new('response')
        @xml.add_attributes({'command' => command,
                             'transaction_id' => transaction_id})
        error = REXML::Element.new('error')
        error.add_attribute('code', error_code)
        message = REXML::Element.new('message')
        message.text = "<![CDATA[#{error_message}]]>"
        error.add_element(message)
        @xml.add_element(error)
      end

      # Returns this error object in the XML format required by the DBGP
      # protocol. It can be sent directly to the IDE as a command response.
      def to_xml
        @xml
      end
    end
    
    # Returns the filename associated with the given URI.
    # uri:: The URI to extract the filename from.
    def DBGP.uri_to_filename(uri)
      URI.unescape(URI.parse(uri).path)
    end
    
    # Returns the URI associated with the given filename.
    # filename:: The filename to compose a URI with. Will be converted to an
    #            absolute path.
    def DBGP.filename_to_uri(filename)
      filename = File.absolute_path(filename)
      filename.gsub!(/\\/, '/') # replace Windows '\' with '/'
      filename.gsub!(/^(\w):/, '\\1') # replace Windows leading 'c:' with 'c'
      "file://#{URI.escape(filename)}"
    end
    
    # Starts a Ruby 2.x debug session.
    # opts:: Option hash of debug settings provided by the IDE or callee. Valid
    #        keys are:
    #        * filename - The path of the Ruby file to debug. If +nil+, Byebug
    #          will break on the next executable line.
    #        * host - The hostname the IDE is running on. The default value is
    #          'localhost'.
    #        * port - The port number the IDE is listening on. The default value
    #          is 9000.
    #        * verbose - Log level from 0 (minimal) to 4 (verbose). The default
    #          value is 0.
    #        * logfile - File or stream to log to: +stdout+ and +stderr+ for
    #          STDOUT and STDERR streams, respectively, and a filename
    #          otherwise.
    #        * interactive - Whether or not this debug session is really just an
    #          interactive shell session, and nothing is being debugged.
    #          (The DBGP protocol allows for this.)
    def DBGP.start(opts)
      # Initialize defaults.
      opts[:host] ||= 'localhost'
      opts[:port] ||= 9000
      opts[:verbose] ||= 0
      opts[:logfile] ||= 'stderr'
      
      # Initialize logging.
      $LOG = Logger.new(case opts[:logfile]
                        when 'stdout'
                          $stdout
                        when 'stderr'
                          $stderr
                        else
                          File.open(opts[:logfile], 'w') rescue $stderr
                        end)
      $LOG.level = [Logger::FATAL, Logger::ERROR, Logger::WARN, Logger::INFO,
                    Logger::DEBUG].fetch(opts[:verbose].to_i, Logger::FATAL)
      $LOG.datetime_format = "%H:%M:%S"

      # Start debugging.
      $LOG.info(self.class.name) do
        debuggee = opts[:filename] ||
                   (opts[:interactive] ? "<interactive>" : "<callee>")
        %Q[Debugging '#{debuggee}' with Ruby #{RUBY_VERSION}]
      end
      Byebug::Setting.settings[:autosave].value = false # no ./.byebug_history
      Byebug::Context.interface = Byebug::DBGPInterface.new(opts[:host],
                                                            opts[:port],
                                                            opts[:timeout])
      Byebug::Context.processor = Byebug::DBGPCommandProcessor
      if opts[:filename]
        # Debug the given file.
        Byebug.mode = :dbgp_standalone
        if (error = Byebug.debug_load(opts[:filename], true))
          $LOG.error(self.class.name) do
            "Debugging error: #{error}\n#{error.backtrace}"
          end
          # Extract the part of the backtrace prior to this script before
          # potentially sending the error to the IDE.
          pertinent_lines = error.backtrace.take_while do |line|
            line !~ %r{[/\\]support[/\\]dbgp[/\\]rubylib[/\\]}
          end
          $stderr.puts(%Q[#{error}\n#{pertinent_lines.join("\n")}])
        end
      else
        # Debug starting after the call to `Byebug::DBGP.start` or this is only
        # an interactive shell session.
        Byebug.mode = !opts[:interactive] ? :dbgp_attached : :dbgp_interactive
        Byebug.start
        Byebug.current_context.step_into(1)
      end
    end
  end

  # DBGP communication interface for Byebug.
  # Receives input from the IDE per the DBGP protocol and sends back XML output.
  class DBGPInterface < Interface
    # Initializes the DBGP communication interface and connects to the IDE.
    # host:: The hostname the IDE is running on.
    # port:: The port the IDE is listening on.
    # timeout:: Optional socket timeout. This should only be set in testing.
    #           Normally when asked to retrieve messages from the IDE, the
    #           client waits indefinately for a message. When that message is
    #           received, the client will wait for any other queued messages,
    #           but up until this timeout, before passing control back to the
    #           caller.
    def initialize(host, port, timeout)
      super()
      @timeout = timeout || 0.05
      
      # Connect to the IDE.
      $LOG.debug(self.class.name) { "Connecting to IDE." }
      @socket = TCPSocket.new(host, port)
      $LOG.info(self.class.name) { "Connection to IDE established." }
      
      # Reconfigure output streams.
      $stdout = DBGP::OutputStream.new(STDOUT, self)
      $stderr = DBGP::OutputStream.new(STDERR, self)
      
      # Start the IDE command reader thread, but use a thread-safe array for
      # Byebug::Interface's @command_queue.
      @command_queue = Queue.new
      @ide_connection_thread = DebugThread.new do
        loop do
          $LOG.debug(self.class.name) { "Waiting for commands from IDE..." }
          data = ''
          loop do
            begin
              data += @socket.recv_nonblock(1024)
              if data.empty?
                $LOG.info(self.class.name) { "IDE hung up." }
                @socket.close
                command_queue.push(nil)
                Thread.exit
              end
              break unless IO.select([@socket], nil, nil, @timeout)
            rescue IO::WaitReadable
              IO.select([@socket]) # wait
              retry
            rescue SocketError => e
              $LOG.error(self.class.name) do
                "Unable to read commands from IDE: #{e}"
              end
              break unless data.empty?
              @socket.close
              command_queue.push(nil)
              Thread.exit
            end
          end
          $LOG.debug(self.class.name) { "Received data from IDE: '#{data}'" }
          command_queue.push(*data.split("\0"))
        end
      end
      Thread.abort_on_exception = true
    rescue => e
      $LOG.error(self.class.name) { "Failed to connect: #{e}" }
      exit false
    end
    
    # Returns whether or not this interface is connected to the IDE.
    # This is used by DBGP::OutputStream prior to sending stdout or stderr.
    def connected?
      return @ide_connection_thread.alive?
    end
    
    # Interface method for reading input commands for the Ruby debugger.
    # In this case, commands are read from the IDE over a socket. This method
    # blocks until data is read.
    # Commands are delimited by NUL bytes ('\0').
    # Multiple commands can be read and queued, but this method only returns one
    # at a time for processing by Byebug.
    def read_input(*)
      command_queue.shift # Queue#shift is blocking
    end
    
    # Byebug interface method for printing command output.
    # This is unused since this client does not use Byebug's stock commands, but
    # defines its own, non-print-using ones.
    def print(*)
    
    end
    
    # Sends an XML response to the IDE.
    # Note: the response is encoded in UTF-8 since Ruby's REXML library requires
    # UTF-8-encoded strings.
    # xml_element:: The XML element to send, formatted according to the DBGP
    #               protocol. The header and xmlns will be added automatically.
    def puts(xml_element)
      xml = REXML::Document.new
      xml << REXML::XMLDecl.new(1.0, 'UTF-8')
      xml << xml_element
      xml_element.add_namespace('urn:debugger_protocol_v1')
      s = "#{xml.to_s.length}\0#{xml}\0"
      #$LOG.debug(self.class.name) { "Sending response to IDE: '#{xml}'" }
      @socket.send(s, 0)
    rescue SocketError => e
      $LOG.error(self.class.name) { "Failed to send response to IDE: #{e}" }
    end
    
    # Byebug interface method for reporting errors safely.
    # This really should not happen.
    # message:: The message for the error that occurred.
    def errmsg(message)
      $LOG.error(self.class.name) { "Unexpected error: #{message}" }
    end
  end
  
  # DBGP command processing interface for Byebug.
  # Processes DBGP commands from the IDE.
  class DBGPCommandProcessor < CommandProcessor
    # Initializes the DBGP command processor.
    # context:: The debugger context given by Byebug.
    def initialize(context)
      @context = context
      
      @status = DBGP::STATUS_STARTING
      @reason = DBGP::REASON_OK
      
      # Initialize read-only features.
      @features = {
        # The following features MUST be available.
        'language_supports_threads' => '1',
        'language_name' => 'Ruby',
        'language_version' => RUBY_VERSION.to_s,
        'encoding' => 'UTF-8',
        'protocol_version' => '1',
        'supports_async' => '1',
        'data_encoding' => 'base64',
        'breakpoint_languages' => '0',
        'breakpoint_types' => 'line conditional',
        'multiple_sessions' => '0', # read-only instead of read-write
        'extended_properties' => '0', # read-only instead of read-write
        # The following features MAY be available.
        'supports_postmortem' => '0',
        'show_hidden' => '0',
        'notify_ok' => '1',
      }
      # Initialize configurable options.
      @options = {
        # The following options MUST be available.
        'max_children' => '10',
        'max_data' => '256',
        'max_depth' => '1',
      }
      DBGP::Property.class_variable_set(:@@options, @options) # mirror
      @breakpoints = {}
      @next_breakpoint_id = 0
      @last_continuation_command = nil
      @async_command_thread = DebugThread.new {}
      @interact_buffer = ''
      
      # Notify the IDE when the script has finished running.
      at_exit do
        if @last_continuation_command &&
           ['run', 'step_into', 'step_over',
            'step_out'].include?(@last_continuation_command[:name])
          @status = DBGP::STATUS_STOPPED
          response = REXML::Element.new('response')
          response.add_attribute('command', @last_continuation_command[:name])
          response.add_attribute('transaction_id',
                                 @last_continuation_command[:transaction_id])
          response.add_attribute('status', DBGP::STATUS_NAMES[@status])
          response.add_attribute('reason', DBGP::REASON_NAMES[DBGP::REASON_OK])
          puts response
        end
      end
    end
    
    # Specifies that none of Byebug's built-in commands are available. All
    # commands will be handled directly by the client per the DBGP protocol.
    def commands
      []
    end
    
    #
    def at_line
      $LOG.debug(self.class.name) { "at_line: #{frame.file}:#{frame.line}" }
      
      if @status == DBGP::STATUS_STARTING
        # Ready to debug. Send initialization packet to IDE.
        $LOG.debug(self.class.name) { "Sending initialization packet..." }
        init = REXML::Element.new('init')
        init.add_attributes(
          'xmlns' => 'urn:debugger_protocol_v1',
          'appid' => $$,
          'idekey' => ENV['DBGP_IDEKEY'] || ENV['USER'] || ENV['USERNAME'] || '',
          'session' => ENV['DBGP_COOKIE'] || '',
          'thread' => Thread.current.object_id,
          'parent' => ENV['DEBUGGER_APPID'] || '',
          'language' => 'ruby',
          'protocol_version' => '1.0',
        )
        if Byebug.mode != :dbgp_interactive
          init.add_attribute('fileuri', DBGP.filename_to_uri(frame.file))
        else
          # Note: this is not documented in the DBGP protocol, but is handled
          # by Komodo's dbgp server code.
          init.add_attribute('interactive', '>')
        end
        puts init
        
        @status = DBGP::STATUS_BREAK if Byebug.mode == :dbgp_attached
        @status = DBGP::STATUS_INTERACT if Byebug.mode == :dbgp_interactive
      elsif @status == DBGP::STATUS_STOPPING
        return # detached
      else
        @async_command_thread.exit if @async_command_thread.alive?
        @status = DBGP::STATUS_BREAK
      end
      
      if @last_continuation_command
        # Send IDE a response for the last continuation command ('run',
        # 'step_over', etc.).
        response = REXML::Element.new('response')
        response.add_attribute('command', @last_continuation_command[:name])
        response.add_attribute('transaction_id',
                               @last_continuation_command[:transaction_id])
        response.add_attribute('status', DBGP::STATUS_NAMES[@status])
        response.add_attribute('reason', DBGP::REASON_NAMES[DBGP::REASON_OK])
        puts response
        @last_continuation_command = nil
      end
      
      process_commands
      return if @status == DBGP::STATUS_STOPPING # detached
      
      # Sometimes a breakpoint will be set on the first line of the file.
      # Since Byebug breaks on the first executable line by default before
      # sending the IDE an initialization packet, the IDE may unwittingly send
      # a 'run' command, expecting a break on the first line. This special
      # case needs to be handled now.
      if @status == DBGP::STATUS_STARTING && @breakpoints.values.find do |bp|
           DBGP.uri_to_filename(bp[:filename]) == frame.file &&
             bp[:lineno] == frame.line
         end
        @status = DBGP::STATUS_BREAK
        at_line
      end
      
      @status = DBGP::STATUS_RUNNING
      @async_command_thread = DebugThread.new { process_commands }
    end
    
    # Byebug interface method for notifying the debugger at a tracepoint.
    # This is unused since the client has no need for tracing.
    def at_tracing
      $LOG.debug(self.class.name) { "at_tracing: #{context.full_location}" }
    end
    
    # Byebug interface method for notifying the debugger at a breakpoint.
    # This is unused since the `at_line` method is still called, and that is
    # more useful.
    def at_breakpoint(breakpoint)
      $LOG.debug(self.class.name) do
        num = Byebug.breakpoints.index(breakpoint) + 1
        "at_breakpoint #{num}: #{frame.file}:#{frame.line}"
      end
    end
    
    # Byebug interface method for notifying the debugger at a catchpoint.
    # This is unused since the client does not make use of catchpoints.
    def at_catchpoint(exception)
      $LOG.debug(self.class.name) do
        "at_catchpoint: #{context.location}: #{exception}"
      end
    end
    
    # Byebug interface method for notifying the debugger upon the return of a
    # method for inspection of its value.
    def at_return(return_value)
      $LOG.debug(self.class.name) { "at_return: #{return_value}" }
      
      return if @status == DBGP::STATUS_STOPPING # detached
      
      @async_command_thread.exit if @async_command_thread.alive?
      @status = DBGP::STATUS_BREAK
      
      process_commands
      return if @status == DBGP::STATUS_STOPPING # detached
      
      @status = DBGP::STATUS_RUNNING
      @async_command_thread = DebugThread.new { process_commands }
    end
    
    # Byebug interface method for notifying the debugger at the end of
    # debugging.
    def at_end
      $LOG.debug(self.class.name) { "at_end" }
      
      @async_command_thread.exit if @async_command_thread.alive?
      @status = DBGP::STATUS_STOPPED
    end
    
    private
    
    # Processes a command from the IDE.
    # The syntax of a command is:
    #     command [args] -- data
    # For each command, the corresponding `self.on_x` method is called, where
    # 'x' is the command's name.
    # input:: The IDE command to process.
    def run_cmd(input)
      input.chomp!("\0")
      $LOG.debug(self.class.name) { "Processing command '#{input}'" }
      safely do
        args, data = input.include?(' -- ') ? input.split(' -- ') : [input, '']
        command, *argv = Shellwords::shellwords(args)
        
        # If the debugger is in the 'run' state, only asynchronous commands
        # (e.g. 'break' or 'status') are available.
        if (@status == DBGP::STATUS_RUNNING &&
            !['break', 'stop', 'status'].include?(command)) ||
           (Byebug.mode == :dbgp_interactive &&
            ['run', 'step_into', 'step_over', 'step_out', 'stop', 'detach',
               'break'].include?(command))
          $LOG.debug(self.class.name) { "Command '#{command}' not available." }
          puts DBGP::CommandError.new(command, argv[argv.index('-i') + 1],
                                      DBGP::CommandError::COMMAND_NOT_AVAILABLE,
                                      "Command '#{command}' not available").to_xml
          return
        end
        
        handler = "on_#{command}"
        if respond_to?(handler, true)
          begin
            __send__(handler, argv, data)
          rescue OptionParser::ParseError => e
            $LOG.error(self.class.name) do
              "Bad argument list for '#{command}': #{e}"
            end
            puts DBGP::CommandError.new(command, argv[argv.index('-i') + 1],
                                        DBGP::CommandError::INVALID_ARGS,
                                        e.message).to_xml
          rescue DBGP::CommandError => error
            puts error.to_xml
          rescue => e
            puts DBGP::CommandError.new(command, argv[argv.index('-i') + 1],
                                        DBGP::CommandError::EXCEPTION,
                                        "#{e}\n#{e.backtrace}").to_xml
          end
        else
          $LOG.error(self.class.name) { "Unknown command '#{command}'" }
          puts DBGP::CommandError.new(command, argv[argv.index('-i') + 1],
                                      DBGP::CommandError::COMMAND_NOT_SUPPORTED,
                                      "Unknown command '#{command}'").to_xml
        end
      end
    end
    
    # DBGP callbacks.
    
    # Responds to the IDE 'status' command.
    # Provides a way for the IDE to find out whether execution may be continued
    # or not.
    # argv:: The argument string for 'status', according to the DBGP protocol.
    def on_status(argv, *)
      response = REXML::Element.new('response')
      response.add_attribute('command', 'status')
      
      args = {}
      OptionParser.new do |parser|
        parser.on('-i transaction_id', Integer) { |i| args[:i] = i }
      end.parse(*argv)
      raise OptionParser::MissingArgument unless [:i].all? { |o| args[o] }
      
      response.add_attribute('transaction_id', args[:i])
      response.add_attribute('status', DBGP::STATUS_NAMES[@status])
      response.add_attribute('reason', DBGP::REASON_NAMES[@reason])
      
      puts response
    end
    
    # Responds to the IDE 'feature_get' command.
    # Used to request feature support and discover values for various features,
    # such as the language version or name.
    # Note: 'supported' does not mean the feature is supported, just that the
    # feature is recognized by 'feature_get'.
    # argv:: The argument string for 'feature_get', according to the DBGP
    #        protocol.
    def on_feature_get(argv, *)
      response = REXML::Element.new('response')
      response.add_attribute('command', 'feature_get')
      
      args = {}
      OptionParser.new do |parser|
        parser.on('-i transaction_id', Integer) { |i| args[:i] = i }
        parser.on('-n feature_name') { |n| args[:n] = n }
      end.parse(*argv)
      raise OptionParser::MissingArgument unless [:i, :n].all? { |o| args[o] }
      
      response.add_attribute('transaction_id', args[:i])
      response.add_attribute('feature_name', args[:n])
      response.add_attribute('supported',
                             @features.include?(args[:n]) ||
                             @options.include?(args[:n]) ||
                             respond_to?("on_#{args[:n]}", true) ? 1 : 0)
      response.text =
        if @features.include?(args[:n])
          $LOG.debug(self.class.name) { "'#{args[:n]}' is a read-only feature" }
          @features[args[:n]]
        elsif @options.include?(args[:n])
          $LOG.debug(self.class.name) do
            "'#{args[:n]}' is a configurable feature"
          end
          @options[args[:n]]
        else
          if respond_to?("on_#{args[:n]}", true)
            $LOG.debug(self.class.name) { "'#{args[:n]}' is a command" }
          else
            $LOG.debug(self.class.name) { "'#{args[:n]}' is unknown" }
          end
          nil
        end
      
      puts response
    end
    
    # Responds to the IDE 'feature_set' command.
    # Allows the IDE to indicate what additional capabilities it has. The
    # response issued to the IDE indicates whether or not that feature has been
    # enabled.
    # This can be called at any time during a debug session.
    # argv:: The argument string for 'feature_set', according to the DBGP
    #        protocol.
    def on_feature_set(argv, *)
      response = REXML::Element.new('response')
      response.add_attribute('command', 'feature_set')
      
      args = {}
      OptionParser.new do |options|
        options.on('-i transaction_id', Integer) { |i| args[:i] = i }
        options.on('-n feature_name') { |n| args[:n] = n }
        options.on('-v value') { |v| args[:v] = v }
      end.parse(*argv)
      raise OptionParser::MissingArgument unless [:i, :n, :v].all? do |o|
        args[o]
      end
      
      response.add_attribute('transaction_id', args[:i])
      response.add_attribute('feature_name', args[:n])
      response.add_attribute('success',
        if @options.include?(args[:n])
          $LOG.debug(self.class.name) do
            "'#{args[:n]}' is configurable; setting to #{args[:v]}"
          end
          @options[args[:n]] = args[:v]
          1
        else
          $LOG.debug(self.class.name) do
            "'#{args[:n]}' is not configurable; ignoring."
          end
          0
        end
      )
      
      puts response
    end
    
    # Responds to the IDE 'run' command.
    # Starts or resumes the script until a new breakpoint is reached, or the end
    # of the script is reached.
    # argv:: The argument string for 'run', according to the DBGP protocol.
    def on_run(argv, *)
      args = {}
      OptionParser.new do |parser|
        parser.on('-i transaction_id', Integer) { |i| args[:i] = i }
      end.parse(*argv)
      raise OptionParser::MissingArgument unless [:i].all? { |o| args[o] }
      
      if @status != DBGP::STATUS_STARTING && @status != DBGP::STATUS_BREAK
        $LOG.warn(self.class.name) do
          "Inconsistent state: #{DBGP::STATUS_NAMES[@status]}"
        end
        response = REXML::Element.new('response')
        response.add_attribute('command', 'run')
        response.add_attribute('transaction_id', args[:i])
        response.add_attribute('status', DBGP::STATUS_NAMES[@status])
        response.add_attribute('reason', DBGP::REASON_NAMES[DBGP::REASON_OK])
        puts response
        return
      end
      
      if @status == DBGP::STATUS_STARTING
        $LOG.info(self.class.name) { "Debugging started." }
      else
        $LOG.debug(self.class.name) { "Resuming from breakpoint." }
      end
      @last_continuation_command = {name: 'run', transaction_id: args[:i]}
      proceed!
      #Byebug.stop if Byebug.stoppable?
    end
    
    # Responds to the IDE 'step_into' command.
    # Steps into the next statement. If there is a function call involved,
    # breaks on the first statement of that function.
    # argv:: The argument string for 'step_into', according to the DBGP
    #        protocol.
    def on_step_into(argv, *)
      args = {}
      OptionParser.new do |parser|
        parser.on('-i transaction_id', Integer) { |i| args[:i] = i }
      end.parse(*argv)
      raise OptionParser::MissingArgument unless [:i].all? { |o| args[o] }
      
      @last_continuation_command = {name: 'step_into', transaction_id: args[:i]}
      context.step_into(1, context.frame.pos)
      proceed!
    end
    
    # Responds to the IDE 'step_over' command.
    # Steps to the next statement. If there is a function call on the line from
    # which 'step_over' is issued, breaks at the next statement after the
    # function call in the same scope as from where that command was issued.
    # argv:: The argument string for 'step_over', according to the DBGP
    #        protocol.
    def on_step_over(argv, *)
      args = {}
      OptionParser.new do |parser|
        parser.on('-i transaction_id', Integer) { |i| args[:i] = i }
      end.parse(*argv)
      raise OptionParser::MissingArgument unless [:i].all? { |o| args[o] }
      
      @last_continuation_command = {name: 'step_over', transaction_id: args[:i]}
      context.step_over(1, context.frame.pos)
      proceed!
    end
    
    # Responds to the IDE 'step_out' command.
    # Steps out of the current scope and breaks on the statement after returning
    # from the current function.
    # argv:: The argument string for 'step_out', according to the DBGP
    #        protocol.
    def on_step_out(argv, *)
      args = {}
      OptionParser.new do |parser|
        parser.on('-i transaction_id', Integer) { |i| args[:i] = i }
      end.parse(*argv)
      raise OptionParser::MissingArgument unless [:i].all? { |o| args[o] }
      
      @last_continuation_command = {name: 'step_out', transaction_id: args[:i]}
      context.step_out(context.frame.pos + 1, false)
      context.frame = 0
      proceed!
    end
    
    # Responds to the IDE 'stop' command.
    # Kills all running threads, terminating the debug process.
    # argv:: The argument string for 'stop', according to the DBGP protocol.
    def on_stop(argv, *)
      response = REXML::Element.new('response')
      response.add_attribute('command', 'stop')
      
      args = {}
      OptionParser.new do |parser|
        parser.on('-i transaction_id', Integer) { |i| args[:i] = i }
      end.parse(*argv)
      raise OptionParser::MissingArgument unless [:i].all? { |o| args[o] }
      
      response.add_attribute('transaction_id', args[:i])
      response.add_attribute('status', DBGP::STATUS_NAMES[DBGP::STATUS_STOPPED])
      response.add_attribute('reason', DBGP::REASON_NAMES[DBGP::REASON_OK])
      #Byebug.thread_context(Thread.main).interrupt
      #Byebug.stop if Byebug.stoppable?
      
      puts response
      
      if Thread.current == Thread.main
        # Byebug is in the 'break' state with only one running thread (main).
        exit!(true)
      else
        # Byebug is in the 'running' state. Kill all other threads before this
        # one, which is @async_command_thread.
        # TODO: should this be done differently?
        Thread.list.each { |t| t.exit unless t == Thread.current }
        exit
      end
    end
    
    # Responds to the IDE 'detach' command.
    # Stops interaction with the debugger. This does not end execution of the
    # script, but detaches from debugging.
    # argv:: The argument string for 'detach', according to the DBGP protocol.
    def on_detach(argv, *)
      response = REXML::Element.new('response')
      response.add_attribute('command', 'detach')
      
      args = {}
      OptionParser.new do |parser|
        parser.on('-i transaction_id', Integer) { |i| args[:i] = i }
      end.parse(*argv)
      raise OptionParser::MissingArgument unless [:i].all? { |o| args[o] }
      
      response.add_attribute('transaction_id', args[:i])
      @status = DBGP::STATUS_STOPPING
      $stdout.state = DBGP::STREAM_DISABLE
      $stderr.state = DBGP::STREAM_DISABLE
      # TODO: clear breakpoints?
      proceed!
      response.add_attribute('status', DBGP::STATUS_NAMES[@status])
      response.add_attribute('reason', DBGP::REASON_NAMES[DBGP::REASON_OK])
      
      puts response
    end
    
    # Responds to the IDE 'breakpoint_set' command.
    # Sets a breakpoint, where the executation is paused, the IDE is notified,
    # and further instructions from the IDE are processed.
    # argv:: The argument string for 'breakpoint_set', according to the DBGP
    #        protocol.
    # data:: Optional conditional expression for 'conditional' type breakpoints
    #        (encoded in base64).
    def on_breakpoint_set(argv, data)
      response = REXML::Element.new('response')
      response.add_attribute('command', 'breakpoint_set')
      
      args = {s: DBGP::BREAKPOINT_STATE_ENABLED, h: 0, o: '>=', r: 0}
      OptionParser.new do |parser|
        parser.on('-i transaction_id', Integer) { |i| args[:i] = i }
        parser.on('-t type', DBGP::BREAKPOINT_TYPE_NAMES) do |t|
          args[:t] = DBGP::BREAKPOINT_TYPE_NAMES.index(t)
        end
        parser.on('-s state', DBGP::BREAKPOINT_STATE_NAMES) do |s|
          args[:s] = DBGP::BREAKPOINT_STATE_NAMES.index(s)
        end
        parser.on('-f uri') { |f| args[:f] = f }
        parser.on('-n lineno', Integer) { |n| args[:n] = n }
        parser.on('-m function') { |m| args[:m] = m }
        parser.on('-x exception') { |x| args[:x] = x }
        parser.on('-h hit_value', Integer) { |h| args[:h] = h }
        parser.on('-o hit_condition', %w(>= == %)) { |o| args[:o] = o }
        parser.on('-r temporary', %w(0 1), Integer) { |r| args[:r] = r }
      end.parse(*argv)
      raise OptionParser::MissingArgument unless [:i, :t, :f, :n].all? do |o|
        args[o]
      end
      
      response.add_attribute('transaction_id', args[:i])
      response.add_attribute('state', DBGP::BREAKPOINT_STATE_NAMES[args[:s]])
      expression = args[:t] == DBGP::BREAKPOINT_TYPE_CONDITIONAL ? Base64.decode64(data) : nil
      breakpoint = {
        id: @next_breakpoint_id,
        type: args[:t],
        state: args[:s],
        filename: args[:f],
        lineno: args[:n],
        temporary: args[:r],
        expression: expression,
        byebug_obj: nil, # will be updated later
      }
      @breakpoints[breakpoint[:id]] = breakpoint
      @next_breakpoint_id += 1
      $LOG.debug(self.class.name) do
        "Attempting to add breakpoint on '#{args[:f]}:#{args[:n]}'"
      end
      if breakpoint[:state] == DBGP::BREAKPOINT_STATE_ENABLED
        breakpoint[:byebug_obj] = Breakpoint.add(DBGP.uri_to_filename(args[:f]),
                                                 args[:n], expression)
      end
      $LOG.debug(self.class.name) { "Breakpoint added." }
      response.add_attribute('id', breakpoint[:id])
      
      puts response
    end
    
    # Responds to the IDE 'breakpoint_get' command.
    # Retrieves a particular breakpoint's information.
    # argv:: The argument string for 'breakpoint_get', according to the DBGP
    #        protocol.
    def on_breakpoint_get(argv, *)
      response = REXML::Element.new('response')
      response.add_attribute('command', 'breakpoint_get')
      breakpoint = REXML::Element.new('breakpoint')
      expression = REXML::Element.new('expression')
      
      args = {}
      OptionParser.new do |parser|
        parser.on('-i transaction_id', Integer) { |i| args[:i] = i }
        parser.on('-d breakpoint_id', @breakpoints.keys.map(&:to_s),
                  Integer) { |d| args[:d] = d }
      end.parse(*argv)
      raise OptionParser::MissingArgument unless [:i, :d].all? { |o| args[o] }
      
      response.add_attribute('transaction_id', args[:i])
      bp = @breakpoints[args[:d]]
      $LOG.debug(self.class.name) { "Retrieved breakpoint '#{args[:d]}'" }
      breakpoint.add_attributes({
        'id' => bp[:id],
        'type' => DBGP::BREAKPOINT_TYPE_NAMES[bp[:type]],
        'state' => DBGP::BREAKPOINT_STATE_NAMES[bp[:state]],
        'filename' => bp[:filename], 'lineno' => bp[:lineno],
        'temporary' => bp[:temporary]
      })
      if bp[:expression]
        expression.text = Base64.encode64(bp[:expression])
        breakpoint.add_element(expression)
      end
      response.add_element(breakpoint)
      
      puts response
    end

    # Responds to the IDE 'breakpoint_update' command.
    # Updates one or more attributes of a breakpoint that has already been set
    # via the 'breakpoint_set' command.
    # argv:: The argument string for 'breakpoint_update', according to the DBGP
    #        protocol.
    def on_breakpoint_update(argv, *)
      response = REXML::Element.new('response')
      response.add_attribute('command', 'breakpoint_update')
      
      args = {}
      OptionParser.new do |parser|
        parser.on('-i transaction_id', Integer) { |i| args[:i] = i }
        parser.on('-d breakpoint_id', @breakpoints.keys.map(&:to_s),
                  Integer) { |d| args[:d] = d }
        parser.on('-s state', DBGP::BREAKPOINT_STATE_NAMES) do |s|
          args[:s] = DBGP::BREAKPOINT_STATE_NAMES.index(s)
        end
        parser.on('-n lineno', Integer) { |n| args[:n] = n }
        parser.on('-h hit_value', Integer) { |h| args[:h] = h }
        parser.on('-o hit_condition', %w(>= == %)) { |o| args[:o] = o }
      end.parse(*argv)
      raise OptionParser::MissingArgument unless [:i, :d].all? { |o| args[o] }
      
      response.add_attribute('transaction_id', args[:i])
      bp = @breakpoints[args[:d]]
      $LOG.debug(self.class.name) do
        "Retrieved breakpoint '#{args[:d]}'; updating it."
      end
      bp[:state] = args[:s] if args[:s]
      if args[:n]
        Breakpoint.remove(bp[:byebug_obj].id) if bp[:byebug_obj]
        bp[:lineno] = args[:n]
        if bp[:state] == DBGP::BREAKPOINT_STATE_ENABLED
          Breakpoint.add(DBGP.uri_to_filename(bp[:filename]), bp[:lineno],
                         bp[:expression])
        end
      end
      $LOG.debug(self.class.name) { "Breakpoint updated." }
      
      puts response
    end

    # Responds to the IDE 'breakpoint_remove' command.
    # Removes a breakpoint.
    # argv:: The argument string for 'breakpoint_remove', according to the DBGP
    #        protocol.
    def on_breakpoint_remove(argv, *)
      response = REXML::Element.new('response')
      response.add_attribute('command', 'breakpoint_remove')
      
      args = {}
      OptionParser.new do |parser|
        parser.on('-i transaction_id', Integer) { |i| args[:i] = i }
        parser.on('-d breakpoint_id', @breakpoints.keys.map(&:to_s),
                  Integer) { |d| args[:d] = d }
      end.parse(*argv)
      raise OptionParser::MissingArgument unless [:i, :d].all? { |o| args[o] }
      
      response.add_attribute('transaction_id', args[:i])
      byebug_obj = @breakpoints[args[:d]][:byebug_obj]
      Breakpoint.remove(byebug_obj.id) if byebug_obj
      @breakpoints.delete(args[:d])
      
      puts response
    end

    # Responds to the IDE 'breakpoint_list' command.
    # Retrieves breakpoint information for all known breakpoints.
    # argv:: The argument string for 'breakpoint_list', according to the DBGP
    #        protocol.
    def on_breakpoint_list(argv, *)
      response = REXML::Element.new('response')
      response.add_attribute('command', 'breakpoint_list')
      
      args = {}
      OptionParser.new do |parser|
        parser.on('-i transaction_id', Integer) { |i| args[:i] = i }
      end.parse(*argv)
      raise OptionParser::MissingArgument unless [:i].all? { |o| args[o] }
      
      response.add_attribute('transaction_id', args[:i])
      @breakpoints.each_value do |bp|
        breakpoint = REXML::Element.new('breakpoint')
        breakpoint.add_attributes({
          'id' => bp[:id],
          'type' => DBGP::BREAKPOINT_TYPE_NAMES[bp[:type]],
          'state' => DBGP::BREAKPOINT_STATE_NAMES[bp[:state]],
          'filename' => bp[:filename], 'lineno' => bp[:lineno],
          'temporary' => bp[:temporary]
        })
        if bp[:expression]
          expression = REXML::Element.new('expression')
          expression.text = Base64.encode64(bp[:expression])
          breakpoint.add_element(expression)
        end
        response.add_element(breakpoint)
      end
      
      puts response
    end

    # Responds to the IDE 'stack_depth' command.
    # Returns the maximum stack depth that is available.
    # argv:: The argument string for 'stack_depth', according to the DBGP
    #        protocol.
    def on_stack_depth(argv, *)
      response = REXML::Element.new('response')
      response.add_attribute('command', 'stack_depth')
      
      args = {}
      OptionParser.new do |parser|
        parser.on('-i transaction_id', Integer) { |i| args[:i] = i }
      end.parse(*argv)
      raise OptionParser::MissingArgument unless [:i].all? { |o| args[o] }
      
      response.add_attribute('transaction_id', args[:i])
      response.add_attribute('depth', context.stack_size)
      
      puts response
    end

    # Responds to the IDE 'stack_get' command.
    # Returns stack information for a given stack depth or for the entire stack.
    # argv:: The argument string for 'stack_get', according to the DBGP
    #        protocol.
    def on_stack_get(argv, *)
      response = REXML::Element.new('response')
      response.add_attribute('command', 'stack_get')
      
      args = {}
      OptionParser.new do |parser|
        parser.on('-i transaction_id', Integer) { |i| args[:i] = i }
        parser.on('-d depth', (0...context.stack_size).map(&:to_s),
                  Integer) { |d| args[:d] = d }
      end.parse(*argv)
      raise OptionParser::MissingArgument unless [:i].all? { |o| args[o] }
      
      response.add_attribute('transaction_id', args[:i])
      response.add_attribute('depth', context.stack_size)
      (args[:d] ? [args[:d]] : 0...context.stack_size).each do |level|
        stack = REXML::Element.new('stack')
        stack.add_attribute('level', level)
        stack.add_attribute('type', 'file')
        stack.add_attribute('filename', DBGP.filename_to_uri(
                                          context.frame_file(level)))
        stack.add_attribute('lineno', context.frame_line(level))
        where = "#{context.frame_class(level)}.#{context.frame_method(level)}"
        stack.add_attribute('where', where.sub(/^\./, ''))
        response.add_element(stack)
      end
      
      puts response
    end

    # Responds to the IDE 'context_names' command.
    # Returns a list of the names of currently available contexts variables can
    # belong to (e.g. "Locals" and "Globals").
    # argv:: The argument string for 'context_names', according to the DBGP
    #        protocol.
    def on_context_names(argv, *)
      response = REXML::Element.new('response')
      response.add_attribute('command', 'context_names')
      
      args = {}
      OptionParser.new do |parser|
        parser.on('-i transaction_id', Integer) { |i| args[:i] = i }
        parser.on('-d stack_depth', Integer) { |d| args[:d] = d }
      end.parse(*argv)
      raise OptionParser::MissingArgument unless [:i].all? { |o| args[o] }
      
      response.add_attribute('transaction_id', args[:i])
      DBGP::CONTEXT_NAMES.each_with_index do |name, id|
        context = REXML::Element.new('context')
        context.add_attribute('name', name)
        context.add_attribute('id', id)
        response.add_element(context)
      end
      
      puts response
    end

    # Returns a list of properties at the given stack depth and in the given
    # context to their respective values.
    # stack_depth:: Call stack depth to retrieve properties from. 0 is the
    #               current level.
    # context_id:: Context to retrieve properties from. See DBGP::CONTEXT_* for
    #              possible values.
    def get_properties(stack_depth, context_id)
      frame = Frame.new(context, stack_depth)
      case context_id
      when DBGP::CONTEXT_LOCALS
        # Local variables.
        $LOG.debug(self.class.name) { "Retrieving local variables." }
        vars = frame.locals
        unless frame._self.to_s == 'main'
          vars[:self] = frame._self
        end
        vars.each.inject([]) do |props, pair|
          props << DBGP::Property.new(pair[0], value: pair[1])
        end
      when DBGP::CONTEXT_SELF
        # Instance and class variables.
        $LOG.debug(self.class.name) { "Retrieving instance and class variables." }
        binding = frame._self.instance_eval { binding }
        (frame._self.instance_variables +
         frame._self.class.class_variables).inject([]) do |props, v|
          props << DBGP::Property.new(v, binding: binding)
        end
      else
        # Global variables.
        $LOG.debug(self.class.name) { "Retrieving global variables." }
        patt = case context_id
               when DBGP::CONTEXT_GLOBALS then /^\$[a-z_]/ # user-space
               when DBGP::CONTEXT_BUILTINS then /^\$[A-Z]/ # built-in
               when DBGP::CONTEXT_SPECIAL then /^\$[^a-zA-Z_]/ # punctuation
               end
        global_variables.reject do |v|
          [:$IGNORECASE, :$=, :$KCODE, :$-K, :$binding, :$LOG].include?(v)
        end.select { |v| v.to_s =~ patt }.inject([]) do |props, v|
          props << DBGP::Property.new(v, binding: frame._binding)
        end
      end
    end

    # Responds to the IDE 'context_get' command.
    # Returns an array of properties in a given context at a given stack depth.
    # The default context is +DBGP::CONTEXT_LOCALS+ and the default stack depth
    # is the current one. (Thus current local variables are fetched by default.)
    # argv:: The argument string for 'context_get', according to the DBGP
    #        protocol.
    def on_context_get(argv, *)
      response = REXML::Element.new('response')
      response.add_attribute('command', 'context_get')
      
      args = {d: 0, c: 0}
      OptionParser.new do |parser|
        parser.on('-i transaction_id', Integer) { |i| args[:i] = i }
        parser.on('-d depth', (0...context.stack_size).map(&:to_s),
                  Integer) { |d| args[:d] = d }
        parser.on('-c context_id', (0...DBGP::CONTEXT_NAMES.size).map(&:to_s),
                  Integer) { |c| args[:c] = c }
      end.parse(*argv)
      raise OptionParser::MissingArgument unless [:i].all? { |o| args[o] }
      
      response.add_attribute('transaction_id', args[:i])
      get_properties(args[:d], args[:c]).map(&:to_xml).each do |property|
        $LOG.debug(self.class.name) { "Found property: '#{property}'" }
        response.add_element(property)
      end
      
      puts response
    end

    # Responds to the IDE 'typemap_get' command.
    # Returns all supported data types. This allows the IDE to get information
    # on how to map language-specific type names (as received in the property
    # element returned by the 'context_get' and 'property_*' commands).
    # argv:: The argument string for 'typemap_get', according to the DBGP
    #        protocol.
    def on_typemap_get(argv, *)
      response = REXML::Element.new('response')
      response.add_attribute('command', 'typemap_get')
      response.add_namespace('xsi', 'http://www.w3.org/2001/XMLSchema-instance')
      response.add_namespace('xsd', 'http://www.w3.org/2001/XMLSchema')
      
      args = {}
      OptionParser.new do |parser|
        parser.on('-i transaction_id', Integer) { |i| args[:i] = i }
      end.parse(*argv)
      raise OptionParser::MissingArgument unless [:i].all? { |o| args[o] }
      
      response.add_attribute('transaction_id', args[:i])
      DBGP::TYPEMAP.each do |name, type|
        map = REXML::Element.new('map')
        map.add_attribute('type', type)
        map.add_attribute('name', name)
        response.add_element(map)
      end
      
      puts response
    end

    def get_class_prop(klassname, propname)
      klass = context.frame._binding.eval(klassname)
      value = klass.class_variable_get(propname)
      DBGP::Property.new(propname, value: value)
    end
    
    def get_object_prop(objname, propname)
      obj = context.frame._binding.eval(objname)
      value = obj.instance_eval { binding }.eval(propname)
      DBGP::Property.new(propname, value: value)
    end

    # Fetches and returns a particular named Ruby variable given either a stack
    # depth and context or a Ruby object ID.
    # name:: The name of the Ruby variable to fetch.
    # stack_depth:: Optional stack depth the variable exists at. If specified,
    #               'context_id' must also be specified.
    # context_id:: Optional context of the variable. See +DBGP::CONTEXT_*+ for
    #              valid values. If specified, 'stack_depth' must also be
    #              specified.
    # key:: Optional parent key to use for child properties. If specified,
    #       'stack_depth' and 'context_id' are ignored.
    def get_property(name, stack_depth = nil, context_id = nil, key = nil)
      isClassProp = name.include? "@@"
      isObjProp = !isClassProp && (name.include? "@")
      
      # If it's a instance variable or class variable we have to do some digging
      #  to get to the value
      if isClassProp || isObjProp
        # matches foo.@bar object
        # matches foo.@@bar class
        match = /([\w_]+?)\.+(@{1,2}[\w_]+)/.match(name)
        if match
          name = match[1]
          childname = match[2]
        end
      end
      if key.nil?
        property = get_properties(stack_depth, context_id).find do |property|
          property.name == name
        end
        if isClassProp && childname
          property = get_class_prop(name, childname)
        end
        if isObjProp && childname
          property = get_object_prop(name, childname)
        end
      else
        DBGP::Property.new(name, value: ObjectSpace._id2ref(key.to_i))
      end
      
      $LOG.debug(self.class.name) do
            !property.nil? ? "Found requested property '#{name}'"
                           : nil
      end
      property
    end

    # Responds to the IDE 'property_get' command.
    # Gets a property value.
    # The maximum data returned is defined by +@options['max_data']+, which can
    # be configured via 'feature_set'. If the size of the property's data is
    # larger than that, the IDE should send 'property_value' to get the entire
    # data. The IDE can determine if there is more data by inspecting the
    # property's 'size' attribute.
    # The depth of nested elements is defined by +@options['max_children']+,
    # which can also be configured via 'feature_set'.
    # argv:: The argument string for 'property_get', according to the DBGP
    #        protocol.
    def on_property_get(argv, *)
      response = REXML::Element.new('response')
      response.add_attribute('command', 'property_get')
      
      args = {d: 0, c: 0, m: @options['max_data'].to_i, p: 0}
      OptionParser.new do |parser|
        parser.on('-i transaction_id', Integer) { |i| args[:i] = i }
        parser.on('-d depth', (0...context.stack_size).map(&:to_s),
                  Integer) { |d| args[:d] = d }
        parser.on('-c context_id', (0...DBGP::CONTEXT_NAMES.size).map(&:to_s),
                  Integer) { |c| args[:c] = c }
        parser.on('-n name') { |n| args[:n] = n }
        parser.on('-m max_data', Integer) { |m| args[:m] = m }
        parser.on('-p page', Integer) { |p| args[:p] = p }
        parser.on('-k key') { |k| args[:k] = k }
      end.parse(*argv)
      raise OptionParser::MissingArgument unless [:i, :n].all? { |o| args[o] }
      
      response.add_attribute('transaction_id', args[:i])
      property = get_property(args[:n], args[:d], args[:c], args[:k])
      if property.nil?
        raise DBGP::CommandError.new('property_get', args[:i],
                                     DBGP::CommandError::PROPERTY_DOES_NOT_EXIST,
                                     "Unknown property '#{args[:n]}'")
      end
      response.add_element(property.to_xml(page: args[:p]))
      
      puts response
    end

    # Responds to the IDE 'property_set' command.
    # Sets a property value.
    # argv:: The argument string for 'property_set', according to the DBGP
    #        protocol.
    # data:: The variable value to set (encoded in Base64).
    def on_property_set(argv, data)
      response = REXML::Element.new('response')
      response.add_attribute('command', 'property_set')
      
      args = {d: 0, c: 0}
      OptionParser.new do |parser|
        parser.on('-i transaction_id', Integer) { |i| args[:i] = i }
        parser.on('-d depth', (0...context.stack_size).map(&:to_s),
                  Integer) { |d| args[:d] = d }
        parser.on('-c context_id', (0...DBGP::CONTEXT_NAMES.size).map(&:to_s),
                  Integer) { |c| args[:c] = c }
        parser.on('-n name') { |n| args[:n] = n }
        parser.on('-t type') { |t| args[:t] = t }
        parser.on('-k key') { |k| args[:k] = k }
        parser.on('-a address') { |a| args[:a] = a }
      end.parse(*argv)
      raise OptionParser::MissingArgument unless [:i, :n].all? { |o| args[o] }
      
      if args[:t] && args[:t].downcase == "string"
        data = "\""+Base64.decode64(data)+"\""
      else
        data = Base64.decode64(data)
      end

      response.add_attribute('transaction_id', args[:i])
      begin
        case args[:n]
        when /^(.*)\.(@@\w+)$/
          klass = context.frame._binding.eval($1)
          value = klass.module_eval("binding").eval(data)
          klass.class_variable_set($2, value)
        when /^(.*)\.(@\w+)$/
          object = context.frame._binding.eval($1)
          value = object.instance_eval { binding }.eval(data)
          object.instance_variable_set($2, value)
        else
          cmd = "#{args[:n]}=#{data}"
          context.frame._binding.eval(cmd)
        end
        response.add_attribute('success', '1')
      rescue StandardError, ScriptError => e
        $LOG.debug(self.class.name) do
          "Error setting property '#{args[:n]}': #{e}"
        end
        response.add_attribute('success', '0')
      end
      
      puts response
    end

    # Responds to the IDE 'property_value' command.
    # Gets a property's full data value. This is called when the size of the
    # property's data is larger than the maximum data returned (defined by
    # +@options['max_data']+).
    # argv:: The argument string for 'property_value', acoording to the DBGP
    #        protocol.
    def on_property_value(argv, *)
      response = REXML::Element.new('response')
      response.add_attribute('command', 'property_value')
      
      args = {d: 0, c: 0, m: @options['max_data'].to_i, p: 0}
      OptionParser.new do |parser|
        parser.on('-i transaction_id', Integer) { |i| args[:i] = i }
        parser.on('-d depth', (0...context.stack_size).map(&:to_s),
                  Integer) { |d| args[:d] = d }
        parser.on('-c context_id', (0...DBGP::CONTEXT_NAMES.size).map(&:to_s),
                  Integer) { |c| args[:c] = c }
        parser.on('-n name') { |n| args[:n] = n }
        parser.on('-m max_data', Integer) { |m| args[:m] = m }
        parser.on('-p page', Integer) { |p| args[:p] = p }
        parser.on('-k key') { |k| args[:k] = k }
        parser.on('-a address') { |a| args[:a] = a }
      end.parse(*argv)
      raise OptionParser::MissingArgument unless [:i].all? { |o| args[o] }
      
      response.add_attribute('transaction_id', args[:i])
      property = get_property(args[:n], args[:d], args[:c], args[:k])
      if property.nil?
        raise DBGP::CommandError.new('property_value', args[:i],
                                     DBGP::CommandError::PROPERTY_DOES_NOT_EXIST,
                                     "Unknown property '#{args[:n]}'")
      end
      value = !property.value.nil? ? property.value.to_s : 'nil'
      response.text = Base64.encode64(value)
      response.add_attribute('size', value.length)
      response.add_attribute('encoding', 'base64')
      
      puts response
    end

    # Responds to the IDE 'source' command.
    # Returns the data contents of the given URI or file for the current
    # context.
    # argv:: The argument string for 'source', according to the DBGP protocol.
    def on_source(argv, *)
      response = REXML::Element.new('response')
      response.add_attribute('command', 'source')
      
      args = {}
      OptionParser.new do |parser|
        parser.on('-i transaction_id', Integer) { |i| args[:i] = i }
        parser.on('-b line', Integer) { |i| args[:b] = b }
        parser.on('-e line', Integer) { |i| args[:e] = e }
        parser.on('-f uri') { |f| args[:f] = f }
      end.parse(*argv)
      raise OptionParser::MissingArgument unless [:i].all? { |o| args[o] }
      
      response.add_attribute('transaction_id', args[:i])
      filename = args[:f] ? DBGP.uri_to_filename(args[:f]) : context.file
      if !File.exist?(filename)
        raise DBGP::CommandError.new('source', args[:i],
                                     DBGP::CommandError::FILE_ACCESS,
                                     "File '#{args[:f]}' not found.")
      end
      lines = []
      File.foreach(filename).each_with_index do |line, lineno|
        break if args[:e] && lineno + 1 > args[:e]
        next if args[:b] && lineno + 1 < args[:b]
        lines << line
      end
      response.add_attribute('success', '1')
      response.text = Base64.encode64(lines.join)
      
      puts response
    end

    # Responds to the IDE 'stdout' command.
    # Enables or disables the sending of stdout output to the IDE.
    # argv:: The argument string for 'stdout', according to the DBGP protocol.
    def on_stdout(argv, *)
      response = REXML::Element.new('response')
      response.add_attribute('command', 'stdout')
      
      args = {}
      OptionParser.new do |parser|
        parser.on('-i transaction_id', Integer) { |i| args[:i] = i }
        parser.on('-c request', %w(0 1 2), Integer) { |c| args[:c] = c }
      end.parse(*argv)
      raise OptionParser::MissingArgument unless [:i, :c].all? { |o| args[o] }
      
      response.add_attribute('transaction_id', args[:i])
      $stdout.state = args[:c]
      response.add_attribute('success', 1)
      
      puts response
    end

    # Responds to the IDE 'stderr' command.
    # Enables or disables the sending of stderr output to the IDE.
    # argv:: The argument string for 'stderr', according to the DBGP protocol.
    def on_stderr(argv, *)
      response = REXML::Element.new('response')
      response.add_attribute('command', 'stderr')
      
      args = {}
      OptionParser.new do |parser|
        parser.on('-i transaction_id', Integer) { |i| args[:i] = i }
        parser.on('-c request', %w(0 1 2), Integer) { |c| args[:c] = c }
      end.parse(*argv)
      raise OptionParser::MissingArgument unless [:i, :c].all? { |o| args[o] }
      
      response.add_attribute('transaction_id', args[:i])
      $stderr.state = args[:c]
      response.add_attribute('success', 1)
      
      puts response
    end
    
    # Responds to the IDE 'break' command.
    # Interrupts execution of the debugger while it is in the 'run' state.
    # argv:: The argument string for 'break', according to the DBGP protocol.
    def on_break(argv, *)
      args = {}
      OptionParser.new do |parser|
        parser.on('-i transaction_id', Integer) { |i| args[:i] = i }
      end.parse(*argv)
      raise OptionParser::MissingArgument unless [:i].all? { |o| args[o] }
      
      @last_continuation_command = {name: 'break', transaction_id: args[:i]}
      if @status == DBGP::STATUS_RUNNING
        $LOG.debug(self.class.name) { "Debugger pausing." }
        Byebug.thread_context(Thread.main).interrupt
        #proceed!
      else
        $LOG.warn(self.class.name) do
          "Cannot break from state: '#{DBGP::STATUS_NAMES[@status]}'"
        end
        raise DBGP::CommandError.new('break', args[:i],
                                     DBGP::CommandError::COMMAND_NOT_AVAILABLE,
                                     "Cannot break from state '#{DBGP::STATUS_NAMES[@status]}'")
      end
    end
    
    # Responds to the IDE 'interact' command.
    # Compiles and execute chunks of code sent from the IDE. Code sent is
    # buffered until it successfully compiles, reflecting a user typing code
    # into a console. Each line is joined with a newline character. As soon as a
    # successful compile happens, the code is run and any output returned is
    # sent to the IDE (via stdout).
    # argv:: The argument string for 'interact', according to the DBGP protocol.
    # data:: The expression to evaluate (encoded in base64).
    def on_interact(argv, data)
      response = REXML::Element.new('response')
      response.add_attribute('command', 'interact')
      
      args = {}
      OptionParser.new do |parser|
        parser.on('-i transaction_id', Integer) { |i| args[:i] = i }
        parser.on('-m mode', Integer) { |m| args[:m] = m }
      end.parse(*argv)
      raise OptionParser::MissingArgument unless [:i].all? { |o| args[o] }
      
      if @status != DBGP::STATUS_BREAK && @status != DBGP::STATUS_INTERACT
        raise DBGP::CommandError.new('interact', args[:i],
                                     DBGP::CommandError::COMMAND_NOT_AVAILABLE,
                                     "Cannot interact with state '#{DBGP::STATUS_NAMES[@status]}'")
      end
      
      response.add_attribute('transaction_id', args[:i])
      if args[:m] == 0
        $LOG.debug(self.class.name) { "Stopping interactive session." }
        if Byebug.mode != :dbgp_interactive
          @status = DBGP::STATUS_BREAK
        else
          @status = DBGP::STATUS_STOPPING
          proceed!
        end
        @interact_buffer.clear
        response.add_attributes({
          'status' => DBGP::STATUS_NAMES[@status],
          'reason' => DBGP::REASON_NAMES[DBGP::REASON_OK],
          'more' => 0,
          'prompt' => ''
        })
        puts response
        return
      else
        $LOG.debug(self.class.name) do
          (@status == DBGP::STATUS_BREAK ? "Starting" : "Continuing") +
          " interactive session"
        end
        @status = DBGP::STATUS_INTERACT
        response.add_attributes({
          'status' => DBGP::STATUS_NAMES[@status],
          'reason' => DBGP::REASON_NAMES[DBGP::REASON_OK],
        })
      end
      
      @interact_buffer += "\n" unless @interact_buffer.empty?
      @interact_buffer += Base64.decode64(data)
      @interact_buffer.rstrip!
      if @interact_buffer =~ /([^\\](\\\\)*)$/
        # Attempt to evaluate the current buffer.
        # If an error occurs, but that error is due to an incomplete expression,
        # wait for more input and try again later.
        begin
          result = context.frame._binding.eval(@interact_buffer)
          $LOG.debug(self.class.name) do
            "Complete expression evaluated; result: '#{result}'"
          end
          response.add_attributes({'more' => 0, 'prompt' => '>'})
          unless result.nil?
            $stdout.puts(result.inspect) rescue $stdout.puts(result.to_s)
          end
        rescue SyntaxError => e
          $LOG.debug(self.class.name) { "Syntax error: #{e}" }
          response.add_attributes({'more' => 0, 'prompt' => '>'})
          # Depending on the kind of syntax error, it may be resolved after more
          # user input is obtained. Determine this.
          # Note: these checks come from Komodo's Ruby pre-2.0 debug code.
          if e.message =~ /(.*)\n(\s*)\^\s*$/ && $2.length < $1.length
            # Cannot recover from a syntax error before the end of a line.
            $stderr.puts(e.message)
          elsif e.message.scan(/:\d+:\s*syntax error/).count > 1
            # Cannot recover from more than one syntax error.
            $stderr.puts(e.message)
          elsif e.message =~ /:(\d+):\s*syntax error/ &&
                $1.to_i < @interact_buffer.split(/\n/).size
            # Cannot recover from a syntax error on a line before the most
            # recently entered one.
            $stderr.puts(e.message)
          elsif Base64.decode64(data).strip.gsub('\\', '').empty?
            # Allow user to "cancel" an incomplete expression by submitting an
            # empty line or a line that contains only a line continuation char.
          elsif e.message =~ /:\d+:\s*syntax error.+?unexpected.+?expecting end-of-input/
            # Cannot recover from an unexpected token being found when EOF is
            # expected.
            $stderr.puts(e.message)
          else
            # Treat the syntax error as being caused by an incomplete expression
            # and wait for more input.
            $LOG.debug(self.class.name) do
              "Assuming incomplete expression: '#{@interact_buffer}'; waiting for more..."
            end
            response.attributes['more'], response.attributes['prompt'] = 1, '*'
          end
        rescue Exception => e
          $LOG.debug(self.class.name) { "Exception: #{e}" }
          $stderr.puts(e.message)
          response.add_attributes({'more' => 0, 'prompt' => '>'})
        end
      else
        unless @interact_buffer.empty?
          $LOG.debug(self.class.name) do
            "Incomplete expression: '#{@interact_buffer}'; waiting for more..."
          end
        end
        response.add_attributes({
          'more' => @interact_buffer.empty? ? 0 : 1,
          'prompt' => @interact_buffer.empty? ? '>' : '*'
        })
      end
      @interact_buffer.clear unless response.attributes['more'] == '1'
      
      puts response
    end
    
    def on_eval(argv, data)
      current_status = @status
      on_interact(argv, data)
      @status = current_status
    end
  end
end

if $PROGRAM_NAME == __FILE__
  # Default options.
  opts = {filename: (File.realpath(ARGV.shift) rescue nil)}

  # Parse options from the environment variable specified by the IDE.
  ENV['RUBYDB_OPTS'].split.each do |opt|
    key, value = opt.split('=')
    opts[key.downcase.to_sym] = value
  end
  if opts.key?(:remoteport)
    opts[:host], opts[:port] = opts[:remoteport].match(/^(.*):(\d+)$/)[1..2]
  end
  opts[:interactive] = opts[:interactive] != '0' if opts[:interactive]
  opts[:timeout] = opts[:timeout].to_i if opts[:timeout] # used by test suite

  # Configure stdout and stderr to flush as output is written so the IDE can
  # monitor them properly.
  STDOUT.sync = true
  STDERR.sync = true

  # Start debugging.
  Byebug::DBGP.start(opts)
end
