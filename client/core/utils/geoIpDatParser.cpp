#include "geoIpDatParser.h"

#include "common.pb.h"

#include <QCoreApplication>
#include <QSet>

namespace
{

QString cidrToString(const v2ray::core::app::router::routercommon::CIDR &record)
{
    const std::string &ip = record.ip();
    if (ip.size() != 4 || record.prefix() > 32) {
        return {};
    }

    const auto *bytes = reinterpret_cast<const uchar *>(ip.data());
    return QStringLiteral("%1.%2.%3.%4/%5")
            .arg(bytes[0])
            .arg(bytes[1])
            .arg(bytes[2])
            .arg(bytes[3])
            .arg(record.prefix());
}

}

namespace amnezia::geoip
{

bool parseGeoIpDat(const QByteArray &data, const QStringList &codes, ParseResult &result, QString &errorMessage)
{
    result = {};
    errorMessage.clear();

    QSet<QString> requestedCodes;
    for (const QString &code : codes) {
        const QString normalizedCode = code.trimmed().toUpper();
        if (!normalizedCode.isEmpty()) {
            requestedCodes.insert(normalizedCode);
        }
    }

    if (requestedCodes.isEmpty()) {
        errorMessage = QCoreApplication::translate("GeoIpDatParser", "GeoIP code list is empty");
        return false;
    }

    v2ray::core::app::router::routercommon::GeoIPList geoIpList;
    if (!geoIpList.ParseFromArray(data.constData(), data.size())) {
        errorMessage = QCoreApplication::translate("GeoIpDatParser", "Invalid GeoIP data");
        return false;
    }

    for (const auto &entry : geoIpList.entry()) {
        const QString countryCode = QString::fromStdString(entry.country_code()).trimmed().toUpper();
        if (!requestedCodes.contains(countryCode)) {
            continue;
        }

        QSet<QString> cidrs;
        const QStringList existingCidrs = result.cidrsByCode.value(countryCode);
        for (const QString &cidr : existingCidrs) {
            cidrs.insert(cidr);
        }

        for (const auto &cidrRecord : entry.cidr()) {
            const QString cidr = cidrToString(cidrRecord);
            if (!cidr.isEmpty()) {
                cidrs.insert(cidr);
            } else if (cidrRecord.ip().size() == 16) {
                result.skippedIpv6++;
            }
        }

        QStringList sortedCidrs = cidrs.values();
        sortedCidrs.sort();
        result.cidrsByCode.insert(countryCode, sortedCidrs);
    }

    QSet<QString> matchedCodes;
    for (auto it = result.cidrsByCode.constBegin(); it != result.cidrsByCode.constEnd(); ++it) {
        matchedCodes.insert(it.key());
    }

    const QStringList missingCodes = (requestedCodes - matchedCodes).values();
    if (!missingCodes.isEmpty()) {
        QStringList sortedMissingCodes = missingCodes;
        sortedMissingCodes.sort();
        errorMessage = QCoreApplication::translate("GeoIpDatParser", "GeoIP code not found: %1").arg(sortedMissingCodes.join(QStringLiteral(", ")));
        return false;
    }

    int cidrCount = 0;
    for (const QStringList &cidrs : result.cidrsByCode) {
        cidrCount += cidrs.size();
    }

    if (cidrCount == 0) {
        errorMessage = QCoreApplication::translate("GeoIpDatParser", "GeoIP import contains no IPv4 CIDR ranges");
        return false;
    }

    return true;
}

}
