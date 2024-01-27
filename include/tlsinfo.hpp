//
// MIT License
//
// Copyright (c) 2024 Antoni Tretiakov
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//

#ifndef QTTLSINFO_HPP
#define QTTLSINFO_HPP

#include "QtTlsInfo_global.hpp"

/// Default cipher-suits for TlsInfo::generateSecureConfiguration static method.
/// The cipher suits are arranged with descending priority (the first has the highest priority).
#define CRQTL_DEFAULT_ALLOWED_CIPHERSUIT_LIST "\
TLS_AES_256_GCM_SHA384:\
TLS_CHACHA20_POLY1305_SHA256:\
TLS_AES_128_GCM_SHA256:\
ECDHE-ECDSA-AES256-GCM-SHA384:\
ECDHE-RSA-AES256-GCM-SHA384:\
ECDHE-ECDSA-CHACHA20-POLY1305:\
ECDHE-RSA-CHACHA20-POLY1305:\
ECDHE-ECDSA-AES128-GCM-SHA256:\
ECDHE-RSA-AES128-GCM-SHA256:\
DHE-RSA-AES256-GCM-SHA384:\
DHE-RSA-CHACHA20-POLY1305:\
DHE-RSA-AES128-GCM-SHA256"

#include <QException>
#include <QSslCertificate>
#include <QSslCipher>
#include <QSslConfiguration>
#include <QSslSocket>
#include <QString>

/// library namespace
namespace cr
{
    /// This exception is thrown by TlsInfo class when it fails to load additional certificates
    /// in the TlsInfo::generateSecureConfiguration static method.
    class QTTLSINFO_EXPORT TlsInfoCertificateException : public QException
    {
    public:
        void raise() const override;
        TlsInfoCertificateException *clone() const override;
    private:

    };

    /// This exception is thrown when the m_config attribute has not been initialized
    /// but a method tries to access its data.
    /// Note that if the configuration passed by the user was deleted,
    /// the program may result with undefined behavior.
    class QTTLSINFO_EXPORT TlsInfoNullConfigException : public QException
    {
    public:
        void raise() const override;
        TlsInfoNullConfigException *clone() const override;
    private:

    };

    /// Extracts information about the SSL/TLS configuration.
    /// Provides a simple high level interface to briefly check if the encrypted connection exists.
    /// (Warning: this class does not guarantee that the provided SSL/TLS configuration settings are secure!)
    class QTTLSINFO_EXPORT TlsInfo
    {
    public:

        /// Default constructor
        TlsInfo() = default;

        /// Pass info about the configuration.
        /// TLsInfo class cannot modify the configuration.
        /// (Note that the configuration must exist)
        explicit TlsInfo(const QSslConfiguration& config);

        /// Pass info about the configuration.
        /// TLsInfo class cannot modify the configuration.
        void setConfiguration(const QSslConfiguration& config);

        /// If configuration for TLS exists and was modified
        /// then TLS is considered as supported.
        /// Returns: true if TLS is supported, false otherwise.
        bool isTlsSupported() const;

        /// If the configured protocol is secure and the session protocol is secure,
        /// then the protocol is considered secure.
        /// Returns: true if protocol is supported, false otherwise.
        bool isProtocolSecure() const;

        /// If the retrieved certificate chain is trusted,
        /// then the server is considered trusted.
        /// Returns: true if server is trusted, false otherwise.
        bool isServerValid() const;

        /// If the session protocol is secure and any session ciphers exist,
        /// then the session is considered secure.
        /// Returns: true if session is secure, false otherwise.
        bool isSessionSecure() const;

        /// If configuration exists and was updated
        /// and the protocol is secure
        /// and the server is verified
        /// and the handshake is established
        /// then the connection is considered secure.
        /// Returns: true if connection is secure, false otherwise.
        bool isSecure() const;

        /// Creates and returns TLS configuration with settings that are considered as secure.
        /// Optional, but (recommended) parameters:
        /// 'allowedCipherSuits' - A list of separate cipher suits, first has the highest priority.
        /// (if empty, only 'CRQTL_DEFAULT_ALLOWED_CIPHERSUIT_LIST' ciphers are used.)
        /// 'certPathList' - Paths to additional trusted pem certificates
        /// (Note: one file may contain many certificates).
        static QSslConfiguration generateSecureConfiguration(
                const QList<QString> &allowedCipherSuits = QList<QString>(),
                const QList<QString> &certPathList = QList<QString>());

        /// Prints basic information about the given 'cert' certificate, begining with the 'label'.
        static void debugShowCertificateInfo(const QSslCertificate& cert, QString label="Certificate:");

    private:

        QString errorString(const QString& msg) const;
        bool checkProtocolSecure(const QSsl::SslProtocol& protocol) const;
        bool checkCertChainSecure(const QList<QSslCertificate>& certChain) const;
        bool checkCipher(const QSslCipher& cipher) const;
        // Note that QSslSocket::AutoVerifyPeer setting is considered secure.
        bool checkPeerModeSecure(QSslSocket::PeerVerifyMode mode) const;

        const QSslConfiguration* m_config = nullptr;
    };

}

#endif // QTTLSINFO_HPP
