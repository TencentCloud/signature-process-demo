# -*- coding: utf8 -*-
import base64
import hashlib
import hmac
import time

import requests

import sys
reload(sys)
sys.setdefaultencoding("utf-8")
# 密钥参数，云API密匙查询: https://console.cloud.tencent.com/cam/capi
secret_id = "AKIDz8krbsJ5yKBZQpn74WFkmLPx3*******"
secret_key = "Gu5t9xGARNpq86cd98joQYCN3*******"

def get_string_to_sign(method, endpoint, params):
    s = method + endpoint + "/?"
    query_str = "&".join("%s=%s" % (k, params[k]) for k in sorted(params))
    return s + query_str

def sign_str(key, s, method):
    hmac_str = hmac.new(key.encode("utf8"), s.encode("utf8"), method).digest()
    return base64.b64encode(hmac_str)

if __name__ == '__main__':
    endpoint = "sms.tencentcloudapi.com"
    # 实际调用需要更新参数，这里仅作为演示签名验证通过的例子
    data = {
        "Nonce":              "11886",
		"Timestamp":          int(time.time()),
		"Region":             "ap-guangzhou",
		"SecretId":           secret_id,
		"Version":            "2021-01-11",
		"Action":             "SendSms",
		"SmsSdkAppId":        "1400006666",
		"SignName":           "腾讯云",
		"TemplateId":         "1234",
		"TemplateParamSet.0": "12345",
		"PhoneNumberSet.0":   "+8618511122266",
		"SessionContext":     "test",
    }
    s = get_string_to_sign("GET", endpoint, data)
    data["Signature"] = sign_str(secret_key, s, hashlib.sha1)
    print(data["Signature"])

    # 此处会实际调用，成功后可能产生计费
    resp = requests.get("https://" + endpoint, params=data)
    print(resp.text)
    print('curl ' + '"' + resp.url + '"')
