require 'net/http'
require 'digest'
require 'cgi'

##
# An implementation of RFC 2617 Digest Access Authentication.
#
# http://www.rfc-editor.org/rfc/rfc2617.txt

class Net::HTTP::DigestAuth

  ##
  # Version of Net::HTTP::DigestAuth you are using

  VERSION = '1.0'

  ##
  # Creates a new DigestAuth header creator.
  #
  # +cnonce+ is the client nonce value.  This should be an MD5 hexdigest of a
  # secret value.

  def initialize cnonce = make_cnonce
    @nonce_count = -1
    @cnonce = cnonce
  end

  ##
  # Creates a digest auth header for +uri+ from the +www_authenticate+ header
  # for HTTP method +method+.
  #
  # The result of this method should be sent along with the HTTP request as
  # the "Authorization" header.  In Net::HTTP this will look like:
  #
  #   request.add_field 'Authorization', digest_auth.auth_header # ...
  #
  # See Net::HTTP::DigestAuth for a complete example.
  #
  # IIS servers handle the "qop" parameter of digest authentication
  # differently so you may need to set +iis+ to true for such servers.

  def auth_header uri, www_authenticate, method, iis = false
    @nonce_count += 1

    user = CGI.unescape uri.user
    password = CGI.unescape uri.password

    www_authenticate =~ /^(\w+) (.*)/

    params = {}
    $2.gsub(/(\w+)="(.*?)"/) { params[$1] = $2 }

    a_1 = "#{user}:#{params['realm']}:#{password}"
    a_2 = "#{method}:#{uri.path}"

    request_digest = []
    request_digest << Digest::MD5.hexdigest(a_1)
    request_digest << params['nonce']
    request_digest << ('%08x' % @nonce_count)
    request_digest << @cnonce
    request_digest << params['qop']
    request_digest << Digest::MD5.hexdigest(a_2)
    request_digest = request_digest.join ':'

    header = []
    header << "Digest username=\"#{user}\""
    header << "realm=\"#{params['realm']}\""
    if iis then
      header << "qop=\"#{params['qop']}\""
    else
      header << "qop=#{params['qop']}"
    end
    header << "uri=\"#{uri.path}\""
    header << "nonce=\"#{params['nonce']}\""
    header << "nc=#{'%08x' % @nonce_count}"
    header << "cnonce=\"#{@cnonce}\""
    header << "response=\"#{Digest::MD5.hexdigest request_digest}\""

    header.join ', '
  end

  ##
  # Creates a client nonce value that is used across all requests based on the
  # current time.

  def make_cnonce
    Digest::MD5.hexdigest "%x" % (Time.now.to_i + rand(65535))
  end

end

