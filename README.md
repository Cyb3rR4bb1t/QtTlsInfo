# QtTlsInfo
A small C++ library for Qt, created to simplify configuration of TLS connections.

## Overview

namespace: cr

### TLSInfo
   - Extracts details of the SSL/TLS configuration from QSslConfiguration.
   - Provides a simple interface to check if the loaded SSL/TLS configuration is considered secure.
   ```aa```
   - Can be used to generate a more secure configuration than the default QSslConfiguration.
   - **Use at your own risk**

**Documentation is in the source code only.**

## Requirements
- Qt framework modules: `QCore` `QNetwork`
- A cryptographic toolkit, eg. `OpenSSL`

## Building

- Build the library, add the include directory and link the dependencies.
- Use this library by including `QtTlsInfo`

## Example

``` C++
QNetworkAccessManager client;
QSslConfiguration sslConfig;
cr::TlsInfo tlsinfo;

// Add an additional file with allowed certificate chain for the TLS configuration.
sslConfig = cr::TlsInfo::generateSecureConfiguration( QList<QString>(":/config/isrgrootchain.pem") );
tlsinfo.setConfiguration(sslConfig);

/// Handle replies
connect(&client, &QNetworkAccessManager::finished, this, [&](QNetworkReply *reply)
{
   sslConfig = reply->sslConfiguration();
   const auto& cipher = reply->sslConfiguration().sessionCipher();

   qDebug() << "is secure? url: " << reply->url();
   qDebug() << "tls>=1.2:  " << info.isTlsSupported();
   qDebug() << "protocol:  " << info.isProtocolSecure();
   qDebug() << "server:    " << info.isServerValid();
   qDebug() << "session:   " << info.isSessionSecure();
   qDebug() << "generally: " << info.isSecure();

   qDebug() << "(other)";
   qDebug() << "received " << QString::fromUtf8( reply->readAll() ).size() << " UTF-8 characters";
   qDebug() << "cipher data:";
   qDebug() << "  cipher name:           "<< cipher.name();
   qDebug() << "  authentication method: "<< cipher.authenticationMethod();
   qDebug() << "  encryption method:     "<< cipher.encryptionMethod();
   qDebug() << "  key exchange method:   "<< cipher.keyExchangeMethod();
   qDebug() << "  protocol method:       "<< cipher.protocolString();
});

/// Make a request
QNetworkRequest request;
request.setUrl( "https://badssl.com/" );
request.setSslConfiguration(sslConfig);
client.get(request);
```

## License
This software is licensed under MIT. See the "LICENSE" file.
Note that this library is dependent on Qt modules licensed under LGPL version 3.