QT -= gui
QT += network

TEMPLATE = lib
DEFINES += QTTLSINFO_LIBRARY

CONFIG += c++17

SOURCES += \
    include/tlsinfo.cpp

HEADERS += \
    include/QtTlsInfo_global.hpp \
    include/tlsinfo.hpp \
    include/QtTlsInfo

!isEmpty(target.path): INSTALLS += target
