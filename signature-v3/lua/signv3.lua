local crypto = require("crypto")

local function toHexBinary(hex)
    local binary = ""
    for i = 1, #hex, 2 do
        local byte = tonumber(hex:sub(i, i + 1), 16)
        binary = binary .. string.char(byte)
    end
    return binary
end

local function sha256hex(s)
    local sha256 = crypto.digest.new("sha256")
    sha256:update(s)
    return sha256:final()
end

local function hmacSha256(s, key)
    local hmac = crypto.hmac.new("sha256", key)
    hmac:update(s)
    return hmac:final()
end

-- 密钥参数
-- 需要设置环境变量 TENCENTCLOUD_SECRET_ID，值为示例的 AKIDz8krbsJ5yKBZQpn74WFkmLPx3*******
local secretId = os.getenv("TENCENTCLOUD_SECRET_ID")
-- 需要设置环境变量 TENCENTCLOUD_SECRET_KEY，值为示例的 Gu5t9xGARNpq86cd98joQYCN3*******
local secretKey = os.getenv("TENCENTCLOUD_SECRET_KEY")

local host = "cvm.tencentcloudapi.com"
local algorithm = "TC3-HMAC-SHA256"
local service = "cvm"
local version = "2017-03-12"
local action = "DescribeInstances"
local region = "ap-guangzhou"
local timestamp = os.time()

-- ************* 步骤 1：拼接规范请求串 *************
local httpRequestMethod = "POST"
local canonicalURI = "/"
local canonicalQueryString = ""
local canonicalHeaders = string.format("content-type:%s\nhost:%s\nx-tc-action:%s\n",
        "application/json; charset=utf-8", host, string.lower(action))
local signedHeaders = "content-type;host;x-tc-action"
local payload = '{"Limit": 1, "Filters": [{"Values": ["\\u672a\\u547d\\u540d"], "Name": "instance-name"}]}'
local hashedRequestPayload = sha256hex(payload)
local canonicalRequest = string.format("%s\n%s\n%s\n%s\n%s\n%s",
        httpRequestMethod,
        canonicalURI,
        canonicalQueryString,
        canonicalHeaders,
        signedHeaders,
        hashedRequestPayload)

-- ************* 步骤 2：拼接待签名字符串 *************
local date = os.date("!%Y-%m-%d", timestamp)
local credentialScope = string.format("%s/%s/tc3_request", date, service)
local hashedCanonicalRequest = sha256hex(canonicalRequest)
local string2sign = string.format("%s\n%d\n%s\n%s",
        algorithm,
        timestamp,
        credentialScope,
        hashedCanonicalRequest)

-- ************* 步骤 3：计算签名 *************
-- 计算签名摘要函数
local secretDate = hmacSha256(date, "TC3" .. secretKey)
local secretService = hmacSha256(service, toHexBinary(secretDate))
local secretSigning = hmacSha256("tc3_request", toHexBinary(secretService))
local signature = hmacSha256(string2sign, toHexBinary(secretSigning))

-- # ************* 步骤 4：拼接 Authorization *************
local authorization = string.format("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
        algorithm,
        secretId,
        credentialScope,
        signedHeaders,
        signature)
local curl = string.format([[curl -X POST https://%s \
-H "Authorization: %s" \
-H "Content-Type: application/json; charset=utf-8" \
-H "Host: %s" -H "X-TC-Action: %s" \
-H "X-TC-Timestamp: %d" \
-H "X-TC-Version: %s" \
-H "X-TC-Region: %s" \
-d '%s']], host, authorization, host, action, timestamp, version, region, payload)

print(curl)

