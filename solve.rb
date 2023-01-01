require 'digest/sha2'
require 'sinatra/base'
require 'ecdsa'
require 'securerandom'
require 'sinatra/contrib/all'
require 'base64'
$group = ECDSA::Group::Secp256k1
file = File.read('./output.json')
data_hash = JSON.parse(file)
$private_key =  data_hash['privateKey'] #92228332279050618974477679618746543127903843373270329631069559941710066834491
puts "p #{$private_key}"
def sign(str)
    digest = Digest::SHA256.digest(str) 
    temp_key = str.size 
    signature = ECDSA.sign($group, $private_key, digest, temp_key)
end

def verify?(str,signature)
    digest = Digest::SHA256.digest(str)
    ECDSA.valid_signature?($public_key, digest, signature)
end

user = "admin"
sig = sign(user)
cookies= Base64.strict_encode64(user+"--"+ECDSA::Format::SignatureDerString.encode(sig)) 
f = File.open('output.txt', 'w')
f.puts "sig #{sig}"
f.puts "cookie #{cookies}"

