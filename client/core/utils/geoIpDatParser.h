#ifndef GEOIPDATPARSER_H
#define GEOIPDATPARSER_H

#include <QByteArray>
#include <QMap>
#include <QString>
#include <QStringList>

namespace amnezia::geoip
{

struct ParseResult
{
    QMap<QString, QStringList> cidrsByCode;
    int skippedIpv6 = 0;
};

bool parseGeoIpDat(const QByteArray &data, const QStringList &codes, ParseResult &result, QString &errorMessage);

}

#endif // GEOIPDATPARSER_H
