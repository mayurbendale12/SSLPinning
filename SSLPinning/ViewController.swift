//
//  ViewController.swift
//  SSLPinning
//
//  Created by Mayur Bendale on 06/12/23.
//

import CommonCrypto
import UIKit

enum PinningType {
    case certificate
    case publicKey
}

class ViewController: UIViewController {
    private var session: URLSession!
    private var pinningType = PinningType.publicKey
    private let publicKeyHash = "WgoPGXU0SpJ4q65+D5dMK3VNJY9N3ZE9Hi5nVtcGh6I="

    let rsa2048Asn1Header:[UInt8] = [
        0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
        0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00
    ]

    private func sha256(data : Data) -> String {
        var keyWithHeader = Data(rsa2048Asn1Header)
        keyWithHeader.append(data)
        var hash = [UInt8](repeating: 0,  count: Int(CC_SHA256_DIGEST_LENGTH))

        keyWithHeader.withUnsafeBytes {
            _ = CC_SHA256($0, CC_LONG(keyWithHeader.count), &hash)
        }

        return Data(hash).base64EncodedString()
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        session = URLSession(configuration: .default, delegate: self, delegateQueue: nil)
        fetchPersons()
    }

    private func fetchPersons() {
        let url = URL(string: "https://run.mocky.io/v3/60e75769-6f92-4188-a7fb-7164c32c4f65")!
        session.dataTask(with: URLRequest(url: url)) { [weak self] data, response, error in
            guard let self, error == nil else {
                print(error?.localizedDescription ?? "")
                return
            }
            DispatchQueue.main.async {
                self.showAlert(title: "Success", message: "API operation completed successfully")
            }
        }.resume()
    }

    private func showAlert(title: String, message: String) {
        let alertController = UIAlertController(title: title, message: message, preferredStyle: .alert)
        alertController.addAction(UIAlertAction(title: "OK", style: .default))
        self.present(alertController, animated: true)
    }
}

extension ViewController: URLSessionDelegate {
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil);
            return
        }

        if pinningType == .certificate {
            let certificate = SecTrustGetCertificateAtIndex(serverTrust, 0)

            // SSL Policies for domain name check
            let policy = NSMutableArray()
            policy.add(SecPolicyCreateSSL(true, challenge.protectionSpace.host as CFString))

            //evaluate server certifiacte
            let isServerTrusted = SecTrustEvaluateWithError(serverTrust, nil)

            //Local and Remote certificate Data
            let remoteCertificateData:NSData = SecCertificateCopyData(certificate!)

            let pathToCertificate = Bundle.main.path(forResource: "mocky", ofType: "cer")
            let localCertificateData:NSData = NSData(contentsOfFile: pathToCertificate!)!
            //Compare certificates
            if(isServerTrusted && remoteCertificateData.isEqual(to: localCertificateData as Data)){
                let credential = URLCredential(trust:serverTrust)
                print("Certificate pinning is successfully completed")
                completionHandler(.useCredential,nil)
            }
            else {
                DispatchQueue.main.async {
                    self.showAlert(title: "SSL Pinning", message: "Certificate Pinning failed")
                }
                completionHandler(.cancelAuthenticationChallenge,nil)
            }
        } else {
            if let serverCertificate = SecTrustGetCertificateAtIndex(serverTrust, 0) {
                // Server public key
                let serverPublicKey = SecCertificateCopyKey(serverCertificate)
                let serverPublicKeyData = SecKeyCopyExternalRepresentation(serverPublicKey!, nil )!
                let data:Data = serverPublicKeyData as Data
                // Server Hash key
                let serverHashKey = sha256(data: data)
                // Local Hash Key
                let publickKeyLocal = publicKeyHash
                if (serverHashKey == publickKeyLocal) {
                    print("Public key pinning is successfully completed")
                    completionHandler(.useCredential, URLCredential(trust:serverTrust))
                    return
                } else {
                    DispatchQueue.main.async {
                        self.showAlert(title: "SSL Pinning", message: "Public key Pinning failed")
                    }
                    completionHandler(.cancelAuthenticationChallenge,nil)
                }
            }
        }
    }
}
