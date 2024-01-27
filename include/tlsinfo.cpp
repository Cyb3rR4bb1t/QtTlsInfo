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

#include "tlsinfo.hpp"

//
// TlsInfoException
//

void cr::TlsInfoCertificateException::raise() const
{
    throw *this;
}

cr::TlsInfoCertificateException *cr::TlsInfoCertificateException::clone() const
{
    return new TlsInfoCertificateException(*this);
}

void cr::TlsInfoNullConfigException::raise() const
{
    throw *this;
}

cr::TlsInfoNullConfigException *cr::TlsInfoNullConfigException::clone() const
{
    return new TlsInfoNullConfigException(*this);
}

//
// TlsInfo
//

cr::TlsInfo::TlsInfo(const QSslConfiguration& config)
{
    this->setConfiguration(config);
}

void cr::TlsInfo::setConfiguration(const QSslConfiguration& config)
{
    m_config = &config;
}

bool cr::TlsInfo::isTlsSupported() const
{
    if(m_config == nullptr || m_config->isNull())
        return false;

    return true;
}

bool cr::TlsInfo::isProtocolSecure() const
{
    if( !isTlsSupported() )
        return false;

    if( !checkProtocolSecure( m_config->protocol() ) )
        return false;

    if( !checkProtocolSecure( m_config->sessionProtocol() ) && !m_config->sessionCipher().isNull())
        return false;

    return true;
}

bool cr::TlsInfo::isServerValid() const
{
    if( !isTlsSupported() )
        return false;

    if( m_config->peerVerifyDepth() > 0)
        return false;

    if( !checkPeerModeSecure(m_config->peerVerifyMode()) )
        return false;

    if( !checkCertChainSecure( m_config->peerCertificateChain() ))
        return false;

    return true;
}

bool cr::TlsInfo::isSessionSecure() const
{
    if( !checkProtocolSecure(m_config->sessionProtocol()) )
        return false;

    if( !checkCipher( m_config->sessionCipher() ) )
        return false;

    return true;
}

bool cr::TlsInfo::isSecure() const
{
    if( !isServerValid() )
        return false;

    if( !isSessionSecure() )
        return false;

    for(const auto& cipher : m_config->ciphers() )
        if( !checkCipher( cipher ) )
            return false;

    return true;
}

QSslConfiguration cr::TlsInfo::generateSecureConfiguration(
        const QList<QString> &allowedCipherSuits,
        const QList<QString> &certPathList)
{
    QSslConfiguration newConfig;
    newConfig.setPeerVerifyDepth(0);
    newConfig.setPeerVerifyMode(QSslSocket::AutoVerifyPeer);
    newConfig.setProtocol(QSsl::SecureProtocols);

    QString cipherStr;
    if(allowedCipherSuits.isEmpty())
        cipherStr += QStringLiteral(CRQTL_DEFAULT_ALLOWED_CIPHERSUIT_LIST);
    else
    {
        // merge cipher suits into one string separated by ':'
        for(qsizetype i=0, limit = allowedCipherSuits.size(); i < limit; i++)
            cipherStr += allowedCipherSuits.at(i) + (i < limit-1 ? ":" : "");
    }

    newConfig.setCiphers(cipherStr);

    for(const QString& certPath : certPathList)
    {
        if( !newConfig.addCaCertificates(certPath, QSsl::Pem, QSslCertificate::PatternSyntax::FixedString) )
            throw TlsInfoCertificateException();
    }

    return newConfig;
}

void cr::TlsInfo::debugShowCertificateInfo(const QSslCertificate &cert, QString label)
{
    qDebug() << label.toStdString().c_str();
    qDebug() << "  version:       " << cert.version();
    qDebug() << "  issuer:        " << cert.issuerDisplayName();
    qDebug() << "  subject:       " << cert.subjectDisplayName();
    qDebug() << "  isNull:        " << cert.isNull();
    qDebug() << "  isBlacklisted: " << cert.isBlacklisted();
    qDebug() << "  isSelfSigned:  " << cert.isSelfSigned();
    qDebug() << "  effective:     " << cert.effectiveDate();
    qDebug() << "  expires:       " << cert.expiryDate();
}

QString cr::TlsInfo::errorString(const QString& msg) const
{
    return "Error: class cr::TlsInfo; Message: " + msg;
}

bool cr::TlsInfo::checkProtocolSecure(const QSsl::SslProtocol& protocol) const
{
    switch ( protocol )
    {
    case QSsl::TlsV1_2:
    case QSsl::TlsV1_2OrLater:
    case QSsl::DtlsV1_2:
    case QSsl::DtlsV1_2OrLater:
    case QSsl::TlsV1_3:
    case QSsl::TlsV1_3OrLater:
    case QSsl::SecureProtocols:
        return true;

    default:
        return false;
    }
}

bool cr::TlsInfo::checkCertChainSecure(const QList<QSslCertificate>& certChain) const
{
    QList<QSslError> errors = QSslCertificate::verify(certChain);

    if( !errors.isEmpty() )
        return false;

    return true;
}

bool cr::TlsInfo::checkCipher(const QSslCipher& cipher) const
{
    if(cipher.isNull())
        return false;

    if( !checkProtocolSecure(cipher.protocol()) )
        return false;

    return true;
}

bool cr::TlsInfo::checkPeerModeSecure(QSslSocket::PeerVerifyMode mode) const
{
    switch (mode)
    {
    case QSslSocket::VerifyNone: return false;
    case QSslSocket::QueryPeer:  return false;
    case QSslSocket::VerifyPeer: return true;
    case QSslSocket::AutoVerifyPeer: return true;
    default: return false;
    }
}
