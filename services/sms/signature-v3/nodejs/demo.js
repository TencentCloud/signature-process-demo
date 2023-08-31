const crypto = require('crypto');

function sha256(message, secret = '', encoding) {
    const hmac = crypto.createHmac('sha256', secret)
    return hmac.update(message).digest(encoding)
}

function getHash(message, encoding = 'hex') {
    const hash = crypto.createHash('sha256')
    return hash.update(message).digest(encoding)
}

function getDate(timestamp) {
    const date = new Date(timestamp * 1000)
    const year = date.getUTCFullYear()
    const month = ('0' + (date.getUTCMonth() + 1)).slice(-2)
    const day = ('0' + date.getUTCDate()).slice(-2)
    return `${year}-${month}-${day}`
}

function main(){
    // 密钥参数，云API密匙查询: https://console.cloud.tencent.com/cam/capi
    const SECRET_ID = "AKIDz8krbsJ5yKBZQpn74WFkmLPx3*******"
    const SECRET_KEY = "Gu5t9xGARNpq86cd98joQYCN3*******"

    const endpoint = "sms.tencentcloudapi.com"
    const service = "sms"
    const region = "ap-guangzhou"
    const action = "SendSms"
    const version = "2021-01-11"
    const timestamp = Math.round(new Date().getTime()/1000)
    //时间处理, 获取世界时间日期
    const date = getDate(timestamp)

    // ************* 步骤 1：拼接规范请求串 *************
    const signedHeaders = "content-type;host"
    // 实际调用需要更新参数，这里仅作为演示签名验证通过的例子
    let payloadObj = {
        "SmsSdkAppId": "1400006666",
        "SignName": "腾讯云",
        "TemplateId": "1234",
        "TemplateParamSet": ["12345"],
        "PhoneNumberSet": ["+8618511122266"],
        "SessionContext": "test",
    }
    const payload = JSON.stringify(payloadObj)

    const hashedRequestPayload = getHash(payload);
    const httpRequestMethod = "POST"
    const canonicalUri = "/"
    const canonicalQueryString = ""
    const canonicalHeaders = "content-type:application/json; charset=utf-8\n" + "host:" + endpoint + "\n"

    const canonicalRequest = httpRequestMethod + "\n"
                         + canonicalUri + "\n"
                         + canonicalQueryString + "\n"
                         + canonicalHeaders + "\n"
                         + signedHeaders + "\n"
                         + hashedRequestPayload
    console.log(canonicalRequest)

    // ************* 步骤 2：拼接待签名字符串 *************
    const algorithm = "TC3-HMAC-SHA256"
    const hashedCanonicalRequest = getHash(canonicalRequest);
    const credentialScope = date + "/" + service + "/" + "tc3_request"
    const stringToSign = algorithm + "\n" +
                    timestamp + "\n" +
                    credentialScope + "\n" +
                    hashedCanonicalRequest
    console.log(stringToSign)

    // ************* 步骤 3：计算签名 *************
    const kDate = sha256(date, 'TC3' + SECRET_KEY)
    const kService = sha256(service, kDate)
    const kSigning = sha256('tc3_request', kService)
    const signature = sha256(stringToSign, kSigning, 'hex')
    console.log(signature)

    // ************* 步骤 4：拼接 Authorization *************
    const authorization = algorithm + " " +
                    "Credential=" + SECRET_ID + "/" + credentialScope + ", " +
                    "SignedHeaders=" + signedHeaders + ", " +
                    "Signature=" + signature
    console.log(authorization)

    const curlcmd = 'curl -X POST ' + "https://" + endpoint
                           + ' -H "Authorization: ' + authorization + '"'
                           + ' -H "Content-Type: application/json; charset=utf-8"'
                           + ' -H "Host: ' + endpoint + '"'
                           + ' -H "X-TC-Action: ' + action + '"'
                           + ' -H "X-TC-Timestamp: ' + timestamp.toString() + '"'
                           + ' -H "X-TC-Version: ' + version + '"'
                           + ' -H "X-TC-Region: ' + region + '"'
                           + " -d '" + payload + "'"
    console.log(curlcmd)
}
main()
