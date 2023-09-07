import Foundation
import CryptoKit

func sha256(msg: String) -> String {
    let data = msg.data(using: .utf8)!
    let digest = SHA256.hash(data: data)
    return digest.compactMap{String(format: "%02x", $0)}.joined()
}

func main() {
    // 密钥参数
    // 需要设置环境变量 TENCENTCLOUD_SECRET_ID，值为示例的 AKIDz8krbsJ5yKBZQpn74WFkmLPx3*******
    //let secretId = ProcessInfo.processInfo.environment["TENCENTCLOUD_SECRET_ID"]
    let secretId = "AKIDz8krbsJ5yKBZQpn74WFkmLPx3*******"
    // 需要设置环境变量 TENCENTCLOUD_SECRET_KEY，值为示例的 Gu5t9xGARNpq86cd98joQYCN3*******
    //let secretKey = ProcessInfo.processInfo.environment["TENCENTCLOUD_SECRET_KEY"]
    let secretKey = "Gu5t9xGARNpq86cd98joQYCN3*******"

    let service = "cvm"
    let host = "cvm.tencentcloudapi.com"
    let endpoint = "https://\(host)"
    let region = "ap-guangzhou"
    let action = "DescribeInstances"
    let version = "2017-03-12"
    let algorithm = "TC3-HMAC-SHA256"
    let timestamp = 1551113065
    let dateFormatter = DateFormatter()
    dateFormatter.dateFormat = "yyyy-MM-dd"
    dateFormatter.timeZone = TimeZone(identifier: "UTC")
    let date = dateFormatter.string(from: Date(timeIntervalSince1970: TimeInterval(timestamp)))

    // ************* 步骤 1：拼接规范请求串 *************
    let httpRequestMethod = "POST"
    let canonicalUri = "/"
    let canonicalQuerystring = ""
    let ct = "application/json; charset=utf-8"
    //let payload = try! JSONSerialization.data(withJSONObject: params)
    //let payloadString = String(data: payload, encoding: .utf8)!
    let payload = "{\"Limit\": 1, \"Filters\": [{\"Values\": [\"\\u672a\\u547d\\u540d\"], \"Name\": \"instance-name\"}]}"
    let canonicalHeaders = "content-type:\(ct)\nhost:\(host)\nx-tc-action:\(action.lowercased())\n"
    let signedHeaders = "content-type;host;x-tc-action"
    let hashedRequestPayload = sha256(msg: payload)
    let canonicalRequest = """
    \(httpRequestMethod)
    \(canonicalUri)
    \(canonicalQuerystring)
    \(canonicalHeaders)
    \(signedHeaders)
    \(hashedRequestPayload)
    """
    print(canonicalRequest)

    // ************* 步骤 2：拼接待签名字符串 *************
    let credentialScope = "\(date)/\(service)/tc3_request"
    let hashedCanonicalRequest = sha256(msg: canonicalRequest)
    let stringToSign = """
    \(algorithm)
    \(timestamp)
    \(credentialScope)
    \(hashedCanonicalRequest)
    """
    print(stringToSign)

    // ************* 步骤 3：计算签名 *************
    let keyData = Data("TC3\(secretKey)".utf8)
    let dateData = Data(date.utf8)
    var symmetricKey = SymmetricKey(data: keyData)
    let secretDate = HMAC<SHA256>.authenticationCode(for: dateData, using: symmetricKey)
    let secretDateString = Data(secretDate).map{String(format: "%02hhx", $0)}.joined()
    print("\(secretDateString)")

    let serviceData = Data(service.utf8)
    symmetricKey = SymmetricKey(data: Data(secretDate))
    let secretService = HMAC<SHA256>.authenticationCode(for: serviceData, using: symmetricKey)
    let secretServiceString = Data(secretService).map{String(format: "%02hhx", $0)}.joined()
    print("\(secretServiceString)")

    let signingData = Data("tc3_request".utf8)
    symmetricKey = SymmetricKey(data: secretService)
    let secretSigning = HMAC<SHA256>.authenticationCode(for: signingData, using: symmetricKey)
    let secretSigningString = Data(secretSigning).map{String(format: "%02hhx", $0)}.joined()
    print("\(secretSigningString)")

    let stringToSignData = Data(stringToSign.utf8)
    symmetricKey = SymmetricKey(data: secretSigning)
    let signature = HMAC<SHA256>.authenticationCode(for: stringToSignData, using: symmetricKey).map{String(format: "%02hhx", $0)}.joined()
    print(signature)

    // ************* 步骤 4：拼接 Authorization *************
    let authorization = """
    \(algorithm) Credential=\(secretId)/\(credentialScope), SignedHeaders=\(signedHeaders), Signature=\(signature)
    """
    print(authorization)

    print("curl -X POST \(endpoint)"
        + " -H \"Authorization: \(authorization)\""
        + " -H \"Content-Type: \(ct)\""
        + " -H \"Host: \(host)\""
        + " -H \"X-TC-Action: \(action)\""
        + " -H \"X-TC-Timestamp: \(timestamp)\""
        + " -H \"X-TC-Version: \(version)\""
        + " -H \"X-TC-Region: \(region)\""
        + " -d '\(payload)'")
}

main()
