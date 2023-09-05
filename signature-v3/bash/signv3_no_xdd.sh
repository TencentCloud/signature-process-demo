#!/bin/bash

# 密钥参数
# 需要设置环境变量 TENCENTCLOUD_SECRET_ID，值为示例的 AKIDz8krbsJ5yKBZQpn74WFkmLPx3*******
#secret_id=AKIDz8krbsJ5yKBZQpn74WFkmLPx3*******
secret_id=$TENCENTCLOUD_SECRET_ID
# 需要设置环境变量 TENCENTCLOUD_SECRET_KEY，值为示例的 Gu5t9xGARNpq86cd98joQYCN3*******
#secret_key=Gu5t9xGARNpq86cd98joQYCN3*******
secret_key=$TENCENTCLOUD_SECRET_KEY

service="cvm"
host="cvm.tencentcloudapi.com"
region="ap-guangzhou"
action="DescribeInstances"
version="2017-03-12"
algorithm="TC3-HMAC-SHA256"
timestamp=1551113065
# 获取真实当前时间戳
timestamp=$(date +%s)
date=$(date -u -d @$timestamp +"%Y-%m-%d")
#payload='{"Limit": 1, "Filters": [{"Values": ["\u672a\u547d\u540d"], "Name": "instance-name"}]}'
payload=$(echo '{"Limit": 1, "Filters": [{"Values": ["未命名"], "Name": "instance-name"}]}' | iconv -t utf-8)


# ************* 步骤 1：拼接规范请求串 *************
http_request_method="POST"
canonical_uri="/"
canonical_querystring=""
canonical_headers="content-type:application/json; charset=utf-8\nhost:$host\nx-tc-action:$(echo $action | awk '{print tolower($0)}')\n"
signed_headers="content-type;host;x-tc-action"
hashed_request_payload=$(echo -n "$payload" | openssl sha256 -hex | awk '{print $2}')
canonical_request="$http_request_method\n$canonical_uri\n$canonical_querystring\n$canonical_headers\n$signed_headers\n$hashed_request_payload"
echo "$canonical_request"

# ************* 步骤 2：拼接待签名字符串 *************
credential_scope="$date/$service/tc3_request"
hashed_canonical_request=$(printf "$canonical_request" | openssl sha256 -hex | awk '{print $2}')
string_to_sign="$algorithm\n$timestamp\n$credential_scope\n$hashed_canonical_request"
echo "$string_to_sign"

# ************* 步骤 3：计算签名 *************
secret_date=$(printf "$date" | openssl sha256 -hmac "TC3$secret_key" | awk '{print $2}')
echo $secret_date
# 转二进制
secret_service=$(printf $service | openssl dgst -sha256 -mac hmac -macopt hexkey:"$secret_date" | awk '{print $2}')
echo $secret_service
secret_signing=$(printf "tc3_request" | openssl dgst -sha256 -mac hmac -macopt hexkey:"$secret_service" | awk '{print $2}')
echo $secret_signing
signature=$(printf "$string_to_sign" | openssl dgst -sha256 -mac hmac -macopt hexkey:"$secret_signing" | awk '{print $2}')
echo "$signature"

# ************* 步骤 4：拼接 Authorization *************
authorization="$algorithm Credential=$secret_id/$credential_scope, SignedHeaders=$signed_headers, Signature=$signature"
echo $authorization

# 使用文档中的例子则必定会失败，因为时间戳离当前时间太大
# 根据注释将密钥和时间戳timestamp调整为当前的实际值则可以调用成功
curl -XPOST "https://$host" -d "$payload" -H "Authorization: $authorization" -H "Content-Type: application/json; charset=utf-8" -H "Host: $host" -H "X-TC-Action: $action" -H "X-TC-Timestamp: $timestamp" -H "X-TC-Version: $version" -H "X-TC-Region: $region"
