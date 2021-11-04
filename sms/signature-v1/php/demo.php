<?php
// 密钥参数，云API密匙查询: https://console.cloud.tencent.com/cam/capi
$secretId = "AKIDz8krbsJ5yKBZQpn74WFkmLPx3*******";
$secretKey = "Gu5t9xGARNpq86cd98joQYCN3*******";
$host = "sms.tencentcloudapi.com";
// 实际调用需要更新参数，这里仅作为演示签名验证通过的例子
$param = array(
    "Nonce" => 11886, //rand();
    "Timestamp" => time(),
    "Region" => "ap-guangzhou",
    "SecretId" => $secretId,
    "Version" => "2021-01-11",
    "Action" => "SendSms",
    "SmsSdkAppId" => "1400006666",
    "SignName" => "腾讯云",
    "TemplateId" => "1234",
    "TemplateParamSet.0" => "12345",
    "PhoneNumberSet.0" =>  "+8618511122266",
    "SessionContext" => "test",
);

ksort($param);

$signStr = "GET" . $host . "/?";
foreach ( $param as $key => $value ) {
    $signStr = $signStr . $key . "=" . $value . "&";
}
$signStr = substr($signStr, 0, -1);

$signature = base64_encode(hash_hmac("sha1", $signStr, $secretKey, true));
echo $signature.PHP_EOL;

// need to install and enable curl extension in php.ini
$param["Signature"] = $signature;
$paramStr = "";
foreach ( $param as $key => $value ) {
    $paramStr = $paramStr . $key . "=" . urlencode($value) . "&";
}
$paramStr = substr($paramStr, 0, -1);

$curl = "curl 'https://" . $host . "/?". $paramStr . "'";
echo $curl.PHP_EOL;
// $ch = curl_init();
// curl_setopt($ch, CURLOPT_URL, $url);
// $output = curl_exec($ch);
// curl_close($ch);
// echo json_decode($output);