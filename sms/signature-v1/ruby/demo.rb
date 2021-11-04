# -*- coding: UTF-8 -*-
# require ruby>=2.3.0
require 'time'
require 'openssl'
require 'base64'
# 密钥参数，云API密匙查询: https://console.cloud.tencent.com/cam/capi
secret_id = "AKIDz8krbsJ5yKBZQpn74WFkmLPx3*******"
secret_key = "Gu5t9xGARNpq86cd98joQYCN3*******"

method = 'GET'
endpoint = 'sms.tencentcloudapi.com'
# 实际调用需要更新参数，这里仅作为演示签名验证通过的例子
data = {
  'Timestamp' => Time.now.to_i,
  'Region' => 'ap-guangzhou',
  'SecretId' => secret_id,
  'Version' => '2021-01-11',
  'Action' => 'SendSms',
  'Nonce' => 11886,
  'SmsSdkAppId' => '1400006666',
  'SignName' => '腾讯云',
  'TemplateId' => '1234',
  'TemplateParamSet.0' => '12345',
  'PhoneNumberSet.0' =>  '+8618511122266',
  'SessionContext' => 'test',
}
sign = method + endpoint + '/?'
params = []
data.sort.each do |item|
  params << "#{item[0]}=#{item[1]}"
end
sign += params.join('&')
digest = OpenSSL::Digest.new('sha1')
data['Signature'] = Base64.encode64(OpenSSL::HMAC.digest(digest, secret_key, sign))
puts data['Signature']

require 'net/http'
uri = URI('https://' + endpoint)
uri.query = URI.encode_www_form(data)
p uri
res = Net::HTTP.get_response(uri)
puts res.body
curl = 'curl "' + uri.to_s + '"'
puts curl
