# Copyright 2016 (see commit history)
# Copyright 2023-2026 t.e.morgan.
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

module SSLTestHelper

  def ssl_server(min_version: nil, max_version: nil, client_ca_cert: nil)
    @ssl_server ||= begin
      @root_ca ||= generate_key_pair(name: 'CA A')
      server     = generate_key_pair(name: 'Server A', signing_pair: @root_ca)
      tcp_server = TCPServer.new("localhost", 33000 + Random.rand(1000))
      ctx = OpenSSL::SSL::SSLContext.new.tap do |ctx|
        ctx.cert = server[:cert]
        ctx.key = server[:key]
        ctx.min_version = min_version if min_version
        ctx.max_version = max_version if max_version
        ctx.verify_mode = OpenSSL::SSL::VERIFY_PEER
        if client_ca_cert
          ctx.cert_store = OpenSSL::X509::Store.new.tap do |store|
            store.add_cert client_ca_cert
          end
        end
      end
      OpenSSL::SSL::SSLServer.new(tcp_server, ctx)
    end
  end

  def ssl_client
    tcp = TCPSocket.new("localhost", ssl_server.addr[1])
    ctx = OpenSSL::SSL::SSLContext.new.tap do |ctx|
      ctx.verify_hostname = false
      ctx.verify_mode = OpenSSL::SSL::VERIFY_PEER
      ctx.cert_store = OpenSSL::X509::Store.new.tap do |store|
        store.add_cert @root_ca[:cert]
      end
    end
    OpenSSL::SSL::SSLSocket.new(tcp, ctx)
  end


  def generate_key_pair(name: 'Test', signing_pair: nil, ca: signing_pair.nil?)
    key = OpenSSL::PKey::EC.generate 'prime256v1'
    cert = OpenSSL::X509::Certificate.new.tap do |c|
      signing_key  = signing_pair ? signing_pair[:key]  : key
      signing_cert = signing_pair ? signing_pair[:cert] : c

      c.serial     = rand(2**32)
      c.subject    = OpenSSL::X509::Name.parse("/C=US/O=Test/CN=#{name}")
      c.issuer     = signing_cert.subject
      c.not_before = Time.now - 1
      c.not_after  = Time.now + 86400
      c.public_key = key
      c.version    = 2

      ef = OpenSSL::X509::ExtensionFactory.new
      ef.subject_certificate = c
      ef.issuer_certificate  = signing_cert
      c.add_extension ef.create_extension('basicConstraints', "CA:#{ca.to_s.upcase}", true)
      c.add_extension ef.create_extension('subjectKeyIdentifier', 'hash')
      c.add_extension ef.create_extension('authorityKeyIdentifier', 'keyid:always')

      c.sign(signing_key, OpenSSL::Digest::SHA256.new)
    end
    {cert:, key:}
  end

  def write_key_pair(key_pair, chain: [], &block)
    Tempfile.create do |cert_file|
      cert_file.write key_pair[:cert].to_pem
      chain.each do |ch_pair|
        cert_file.write ch_pair[:cert].to_pem
      end
      cert_file.close
      Tempfile.create do |key_file|
        key_file.write key_pair[:key].to_pem
        key_file.close
        yield cert_file.path, key_file.path
      end
    end
  end

end
