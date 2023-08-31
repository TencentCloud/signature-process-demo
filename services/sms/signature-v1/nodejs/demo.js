const crypto = require('crypto');

function get_req_url(params, endpoint){
    for (let k in params) {
        params[k] = encodeURIComponent(params[k]);
    }
    const url_strParam = sort_params(params)
    return "https://" + endpoint + "/?" + url_strParam.slice(1);
}

function formatSignString(reqMethod, endpoint, path, strParam){
    let strSign = reqMethod + endpoint + path + "?" + strParam.slice(1);
    return strSign;
}
function sha1(secretKey, strsign){
    let signMethodMap = {'HmacSHA1': "sha1"};
    let hmac = crypto.createHmac(signMethodMap['HmacSHA1'], secretKey || "");
    return hmac.update(Buffer.from(strsign, 'utf8')).digest('base64')
}

function sort_params(params){
    let strParam = "";
    let keys = Object.keys(params);
    keys.sort();
    for (let k in keys) {
        //k = k.replace(/_/g, '.');
        strParam += ("&" + keys[k] + "=" + params[keys[k]]);
    }
    return strParam
}

function main(){
    // 密钥参数，云API密匙查询: https://console.cloud.tencent.com/cam/capi
    const SECRET_ID = "AKIDz8krbsJ5yKBZQpn74WFkmLPx3*******"
    const SECRET_KEY = "Gu5t9xGARNpq86cd98joQYCN3*******"

    const endpoint = "sms.tencentcloudapi.com"
    const Region = "ap-guangzhou"
    const Version = "2021-01-11"
    const Action = "SendSms"
    const Timestamp = Math.round(new Date().getTime()/1000)
    const Nonce = 11886  // 随机正整数
    //const nonce = Math.round(Math.random() * 65535)
    // 实际调用需要更新参数，这里仅作为演示签名验证通过的例子
    let params = {
        "Nonce":              Nonce,
		"Timestamp":          Timestamp,
		"Region":             Region,
		"SecretId":           SECRET_ID,
		"Version":            Version,
		"Action":             Action,
		"SmsSdkAppId":        "1400006666",
		"SignName":           "腾讯云",
		"TemplateId":         "1234",
		"TemplateParamSet.0": "12345",
		"PhoneNumberSet.0":   "+8618511122266",
		"SessionContext":     "test",
    };

    // 1. 对参数排序,并拼接请求字符串
    strParam = sort_params(params)

    // 2. 拼接签名原文字符串
    const reqMethod = "GET";
    const path = "/";
    strSign = formatSignString(reqMethod, endpoint, path, strParam)
    // console.log(strSign)

    // 3. 生成签名串
    params['Signature'] = sha1(SECRET_KEY, strSign)
    console.log(params['Signature'])

    // 4. 进行url编码并拼接请求url
    const req_url = get_req_url(params, endpoint)
    console.log(params['Signature'])
    console.log('curl ' + '"' + req_url + '"')
}
main()
