const crypto = require('crypto');

function get_req_url(params, endpoint){
    params['Signature'] = encodeURIComponent(params['Signature']);
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
    // 密钥参数
    const SECRET_ID = "AKIDz8krbsJ5yKBZQpn74WFkmLPx3*******"
    const SECRET_KEY = "Gu5t9xGARNpq86cd98joQYCN3*******"

    const endpoint = "cvm.tencentcloudapi.com"
    const Region = "ap-guangzhou"
    const Version = "2017-03-12"
    const Action = "DescribeInstances"
    const Timestamp = 1465185768  // 时间戳 2016-06-06 12:02:48, 此参数作为示例，以实际为准
    // const Timestamp = Math.round(Date.now() / 1000)
    const Nonce = 11886  // 随机正整数
    //const nonce = Math.round(Math.random() * 65535)

    let params = {};
    params['Action'] = Action;
    params['InstanceIds.0'] = 'ins-09dx96dg';
    params['Limit'] = 20;
    params['Offset'] = 0;
    params['Nonce'] = Nonce;
    params['Region'] = Region;
    params['SecretId'] = SECRET_ID;
    params['Timestamp'] = Timestamp;
    params['Version'] = Version;

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
    // const req_url = get_req_url(params, endpoint)
    // console.log(params['Signature'])
    // console.log(req_url)
}
main()
