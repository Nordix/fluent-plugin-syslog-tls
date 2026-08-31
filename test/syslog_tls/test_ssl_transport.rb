# Copyright 2016 Acquia, Inc.
# Copyright 2016-2026 t.e.morgan.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require 'test_helper'

class SSLTransportTest < Test::Unit::TestCase
  include SSLTestHelper

  # srvr-min  srvr-max clnt-min should-raise?
  [ [:TLS1_2, :TLS1_2, :TLS1_2],
    [:TLS1_2, :TLS1_3, :TLS1_2],
    [:TLS1_3, :TLS1_3, :TLS1_2],
    [:TLS1_2, :TLS1_2, :TLS1_3, true],
    [:TLS1_2, :TLS1_3, :TLS1_3],
    [:TLS1_3, :TLS1_3, :TLS1_3],
  ].each do |(server_min, server_max, client_min, should_raise)|
    define_method "test_#{server_min}-#{server_max}_server_#{client_min}_client" do
      blk = lambda do
        server = ssl_server(min_version: server_min, max_version: server_max)
        st = Thread.new {
          client = server.accept
          assert_equal "TESTTEST2\n", client.gets
          client.close
        }
        t = SyslogTls::SSLTransport.new("localhost", server.addr[1], ca_cert: false, ssl_version: client_min)
        t.write(+"TEST")
        t.write(+"TEST2\n")
        st.join
      end
      if should_raise
        assert_raises OpenSSL::SSL::SSLError do
          Thread.report_on_exception = false
          blk.call
        ensure
          Thread.report_on_exception = true
        end
      else
        blk.call
      end
    end
  end

  def test_mtls_client
    root_ca = generate_key_pair(name: 'CA 1')
    client  = generate_key_pair(name: 'Client 1', signing_pair: root_ca)
    server = ssl_server(client_ca_cert: root_ca[:cert])
    st = Thread.new do
      client = server.accept
      assert_equal "TEST\n", client.gets
      client.close
    end
    write_key_pair(client) do |client_cert, client_key|
      t = SyslogTls::SSLTransport.new("localhost", server.addr[1], ca_cert: false, client_cert:, client_key:)
      t.write(+"TEST\n")
    end
    st.join
  end

  def test_mtls_client_with_intermediate
    root_ca = generate_key_pair(name: 'CA 1')
    int_ca  = generate_key_pair(name: 'CA 2', signing_pair: root_ca, ca: true)
    client  = generate_key_pair(name: 'Client 1', signing_pair: int_ca)
    server = ssl_server(client_ca_cert: root_ca[:cert])
    st = Thread.new do
      client = server.accept
      assert_equal "TEST\n", client.gets
      client.close
    end
    write_key_pair(client, chain: [int_ca]) do |client_cert, client_key|
      t = SyslogTls::SSLTransport.new("localhost", server.addr[1], ca_cert: false, client_cert:, client_key:)
      t.write(+"TEST\n")
    end
    st.join
  end

  def test_retry
    client = Object.new
    def client.connect_nonblock
      true
    end
    def client.write_nonblock(s)
      raise "Test"
    end

    SyslogTls::SSLTransport.stub_any_instance(:get_ssl_connection, client) do
      assert_raises RuntimeError do
        t = SyslogTls::SSLTransport.new("localhost", 33000, max_retries: 3)
        t.write(+"TEST\n")
      end
    end
  end

  def test_tcp_user_timeout_sockopt
    omit 'Socket::TCP_USER_TIMEOUT is not defined' unless defined?(Socket::TCP_USER_TIMEOUT)

    server = ssl_server
    st = Thread.new {
      client = server.accept
      client.gets
      client.close
    }
    t = SyslogTls::SSLTransport.new("localhost", server.addr[1], ca_cert: false, tcp_user_timeout: 15000)
    tcp = t.socket.to_io
    val = tcp.getsockopt(Socket::IPPROTO_TCP, Socket::TCP_USER_TIMEOUT)
    assert_equal 15000, val.int
    t.write(+"ok\n")
    st.join
  end

  def test_tcp_user_timeout_disabled
    omit 'Socket::TCP_USER_TIMEOUT is not defined' unless defined?(Socket::TCP_USER_TIMEOUT)

    server = ssl_server
    st = Thread.new {
      client = server.accept
      client.gets
      client.close
    }
    t = SyslogTls::SSLTransport.new("localhost", server.addr[1], ca_cert: false, tcp_user_timeout: 0)
    tcp = t.socket.to_io
    val = tcp.getsockopt(Socket::IPPROTO_TCP, Socket::TCP_USER_TIMEOUT)
    refute_equal 15000, val.int
    t.write(+"ok\n")
    st.join
  end
end
