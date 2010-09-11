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

    user     = CGI.unescape uri.user
    password = CGI.unescape uri.password

    www_authenticate =~ /^(\w+) (.*)/

    params = {}
    $2.gsub(/(\w+)="(.*?)"/) { params[$1] = $2 }

    a_1 = Digest::MD5.hexdigest "#{user}:#{params['realm']}:#{password}"
    a_2 = Digest::MD5.hexdigest "#{method}:#{uri.request_uri}"

    request_digest = [
      a_1,
      params['nonce'],
      ('%08x' % @nonce_count),
      @cnonce,
      params['qop'],
      a_2
    ].join ':'

    header = [
      "Digest username=\"#{user}\"",
      "realm=\"#{params['realm']}\"",
      if iis then
        "qop=\"#{params['qop']}\""
      else
        "qop=#{params['qop']}"
      end,
      "uri=\"#{uri.request_uri}\"",
      "nonce=\"#{params['nonce']}\"",
      "nc=#{'%08x' % @nonce_count}",
      "cnonce=\"#{@cnonce}\"",
      "response=\"#{Digest::MD5.hexdigest request_digest}\""
    ]

    header.join ', '
  end

  ##
  # Creates a client nonce value that is used across all requests based on the
  # current time.

  def make_cnonce
    Digest::MD5.hexdigest "%x" % (Time.now.to_i + rand(65535))
  end

end

