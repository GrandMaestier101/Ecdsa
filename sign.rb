require 'digest/sha2'
require 'sinatra/base'
require 'ecdsa'
require 'securerandom'
require 'sinatra/contrib/all'
require 'base64'
require 'json'

$group = ECDSA::Group::Secp256k1

def sign(str)
  digest = Digest::SHA256.digest(str)
  hex_string = digest.unpack("H*").first
end
def strict_decode64(str)
  str.unpack1("m0")
end
l1 = sign("ramu")
l2 = sign("ravi")
signature_der_string1 = "MEUCIQDkk9vxwQ2A81geSQSTCxQEzGwTkA7gdYR0+pSr6MTNEwIgYYlY8KvUWFv3M1S2gg1xbKAKUUYYTGhuE2hIHub6q/o="#ravi
signature_der_string2 = "MEUCIQDkk9vxwQ2A81geSQSTCxQEzGwTkA7gdYR0+pSr6MTNEwIgGheiDMU4TXVOM420FmrRGHBgNkn+7dEZSwqaNZZT8WM="#ramu
signature1 = ECDSA::Format::SignatureDerString.decode(strict_decode64(signature_der_string1))
signature2 = ECDSA::Format::SignatureDerString.decode(strict_decode64(signature_der_string2))

File.write('./data.json', JSON.dump(
'sig_1.r': signature1.r,
'sig_1.s': signature1.s.to_s(16),
'sig_2.r': signature2.r,
'sig_2.s': signature2.s.to_s(16),
'hash1': l1,
'hash2': l2,
'order': $group.order))
