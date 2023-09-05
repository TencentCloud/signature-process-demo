import 'dart:convert';
import 'dart:io';
import 'package:crypto/crypto.dart';
import 'package:intl/intl.dart';

void main() {
  // 密钥参数
  // 需要设置环境变量 TENCENTCLOUD_SECRET_ID，值为示例的 AKIDz8krbsJ5yKBZQpn74WFkmLPx3*******
  final secretId = Platform.environment['TENCENTCLOUD_SECRET_ID'];
  // final secretId = 'AKIDz8krbsJ5yKBZQpn74WFkmLPx3*******';
  // 需要设置环境变量 TENCENTCLOUD_SECRET_KEY，值为示例的 Gu5t9xGARNpq86cd98joQYCN3*******
  final secretKey = Platform.environment['TENCENTCLOUD_SECRET_KEY'];
  // final secretKey = 'Gu5t9xGARNpq86cd98joQYCN3*******';

  final service = 'cvm';
  final host = 'cvm.tencentcloudapi.com';
  final endpoint = 'https://$host';
  final region = 'ap-guangzhou';
  final action = 'DescribeInstances';
  final version = '2017-03-12';
  final algorithm = 'TC3-HMAC-SHA256';
  // final timestamp = 1551113065;
  // 获取当前时间戳
  final timestamp = (DateTime.now().millisecondsSinceEpoch / 1000).toInt();
  final date = DateFormat('yyyy-MM-dd').format(DateTime.fromMillisecondsSinceEpoch(timestamp * 1000, isUtc: true));

  // ************* 步骤 1：拼接规范请求串 *************
  final httpRequestMethod = 'POST';
  final canonicalUri = '/';
  final canonicalQuerystring = '';
  final ct = 'application/json; charset=utf-8';
  final payload = '{"Limit": 1, "Filters": [{"Values": ["未命名"], "Name": "instance-name"}]}';
  final canonicalHeaders = 'content-type:$ct\nhost:$host\nx-tc-action:${action.toLowerCase()}\n';
  final signedHeaders = 'content-type;host;x-tc-action';
  final hashedRequestPayload = sha256.convert(utf8.encode(payload));
  final canonicalRequest = '''
$httpRequestMethod
$canonicalUri
$canonicalQuerystring
$canonicalHeaders
$signedHeaders
$hashedRequestPayload''';
  print(canonicalRequest);

  // ************* 步骤 2：拼接待签名字符串 *************
  final credentialScope = '$date/$service/tc3_request';
  final hashedCanonicalRequest = sha256.convert(utf8.encode(canonicalRequest));
  final stringToSign = '''
$algorithm
$timestamp
$credentialScope
$hashedCanonicalRequest''';
  print(stringToSign);

  // ************* 步骤 3：计算签名 *************
  List<int> sign(List<int> key, String msg) {
    final hmacSha256 = Hmac(sha256, key);
    return hmacSha256.convert(utf8.encode(msg)).bytes;
  }

  final secretDate = sign(utf8.encode('TC3$secretKey'), date);
  final secretService = sign(secretDate, service);
  final secretSigning = sign(secretService, 'tc3_request');
  final signature = Hmac(sha256, secretSigning).convert(utf8.encode(stringToSign)).toString();
  print(signature);

  // ************* 步骤 4：拼接 Authorization *************
  final authorization = '$algorithm Credential=$secretId/$credentialScope, SignedHeaders=$signedHeaders, Signature=$signature';
  print(authorization);

  print('curl -X POST $endpoint'
      ' -H "Authorization: $authorization"'
      ' -H "Content-Type: application/json; charset=utf-8"'
      ' -H "Host: $host"'
      ' -H "X-TC-Action: $action"'
      ' -H "X-TC-Timestamp: $timestamp"'
      ' -H "X-TC-Version: $version"'
      ' -H "X-TC-Region: $region"'
      ' -d \'$payload\'');
}
