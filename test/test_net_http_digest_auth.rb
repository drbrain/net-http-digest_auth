require 'minitest/autorun'
require 'net/http/digest_auth'

class TestNetHttpDigestAuth < MiniTest::Unit::TestCase

  def setup
    @uri = URI.parse "http://www.example.com/"
    @uri.user = 'user'
    @uri.password = 'password'

    @cnonce = '9ea5ff3bd34554a4165bbdc1df91dcff'

    @header = [
      'Digest qop="auth"',
      'realm="www.example.com"',
      'nonce="4107baa081a592a6021660200000cd6c5686ff5f579324402b374d83e2c9"'
    ].join ', '

    @expected = [
      'Digest username="user"',
      'realm="www.example.com"',
      'qop=auth',
      'uri="/"',
      'nonce="4107baa081a592a6021660200000cd6c5686ff5f579324402b374d83e2c9"',
      'nc=00000000',
      'cnonce="9ea5ff3bd34554a4165bbdc1df91dcff"',
      'response="67be92a5e7b38d08679957db04f5da04"'
    ]

    @da = Net::HTTP::DigestAuth.new @cnonce
  end

  def expected
    @expected.join ', '
  end

  def test_auth_header
    assert_equal expected, @da.auth_header(@uri, @header, 'GET')

    @expected[5] = 'nc=00000001'
    @expected[7] = 'response="1f5f0cd1588690c1303737f081c0b9bb"'

    assert_equal expected, @da.auth_header(@uri, @header, 'GET')
  end

  def test_auth_header_iis
    @expected[2] = 'qop="auth"'

    assert_equal expected, @da.auth_header(@uri, @header, 'GET', true)
  end

  def test_auth_header_no_qop
    @header.sub! ' qop="auth",', ''

    @expected[7] = 'response="32f6ca1631ccf7c42a8075deff44e470"'
    @expected.slice! 2

    assert_equal expected, @da.auth_header(@uri, @header, 'GET')
  end

  def test_auth_header_opaque
    @expected << 'opaque="5ccc069c403ebaf9f0171e9517f40e41"'
    @header   << 'opaque="5ccc069c403ebaf9f0171e9517f40e41"'

    assert_equal expected, @da.auth_header(@uri, @header, 'GET')
  end

  def test_auth_header_post
    @expected[7] = 'response="d82219e1e5430b136bbae1670fa51d48"'

    assert_equal expected, @da.auth_header(@uri, @header, 'POST')
  end

  def test_auth_header_sess
    @header << 'algorithm="MD5-sess"'

    @expected[7] = 'response="76d3ff10007496cee26c61f9d04c72a8"'

    assert_equal expected, @da.auth_header(@uri, @header, 'GET')
  end

  def test_auth_header_sha1
    @expected[7] = 'response="2cb62fc18f7b0ebdc34543f896bb7768"'

    @header << 'algorithm="SHA1"'

    assert_equal expected, @da.auth_header(@uri, @header, 'GET')
  end

  def test_auth_header_unknown_algorithm
    @header << 'algorithm="bogus"'

    e = assert_raises Net::HTTP::DigestAuth::Error do
      @da.auth_header @uri, @header, 'GET'
    end
    
    assert_equal 'unknown algorithm "bogus"', e.message
  end

  def test_make_cnonce
    assert_match %r%\A[a-f\d]{32}\z%, @da.make_cnonce
  end

end

