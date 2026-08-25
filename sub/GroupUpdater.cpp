#include "db/ProfileFilter.hpp"
#include "fmt/includes.h"
#include "fmt/Preset.hpp"
#include "main/HTTPRequestHelper.hpp"

#include "GroupUpdater.hpp"

#include <QInputDialog>
#include <QUrlQuery>
#include <QJsonObject>
#include <QJsonArray>
#include <QJsonDocument>
#include <QRegularExpression>

#ifndef NKR_NO_YAML

#include <yaml-cpp/yaml.h>

#endif

namespace NekoGui_sub {

    GroupUpdater *groupUpdater = new GroupUpdater;

    void RawUpdater_FixEnt(const std::shared_ptr<NekoGui::ProxyEntity> &ent) {
        if (ent == nullptr) return;
        auto stream = NekoGui_fmt::GetStreamSettings(ent->bean.get());
        if (stream == nullptr) return;
        // 1. "security"
        if (stream->security == "none" || stream->security == "0" || stream->security == "false") {
            stream->security = "";
        } else if (stream->security == "1" || stream->security == "true") {
            stream->security = "tls";
        }
        // 2. TLS SNI: v2rayN config builder generate sni like this, so set sni here for their format.
        if (stream->security == "tls" && IsIpAddress(ent->bean->serverAddress) && (!stream->host.isEmpty()) && stream->sni.isEmpty()) {
            stream->sni = stream->host;
        }
    }

    bool ParseAmneziaWGConf(const QString &confText, QJsonObject &outbound, QString &name) {
        if (!confText.contains("[Interface]", Qt::CaseInsensitive)) {
            return false;
        }
        
        QJsonObject peerObj;
        QJsonArray peersArray;
        QJsonArray localAddressArray;
        
        QString privateKey;
        int mtu = 1408;
        int jc = 0, jmin = 0, jmax = 0, s1 = 0, s2 = 0, s3 = 0, s4 = 0;
        QString h1, h2, h3, h4;
        QString i1, i2, i3, i4, i5;
        
        QString server;
        int server_port = 51820;
        QString publicKey;
        QString presharedKey;
        QJsonArray allowedIPsArray;
        int keepalive = 0;

        auto lines = confText.split('\n');
        QString currentSection;
        
        for (auto line : lines) {
            line = line.trimmed();
            if (line.isEmpty() || line.startsWith('#') || line.startsWith(';')) {
                continue;
            }
            if (line.startsWith('[') && line.endsWith(']')) {
                currentSection = line.mid(1, line.length() - 2).trimmed().toLower();
                continue;
            }
            
            auto parts = line.split('=');
            if (parts.length() < 2) continue;
            auto key = parts[0].trimmed().toLower();
            auto val = line.mid(parts[0].length() + 1).trimmed();
            
            if (currentSection == "interface") {
                if (key == "privatekey") privateKey = val;
                else if (key == "address") {
                    for (const auto &addr : val.split(',')) {
                        localAddressArray.append(addr.trimmed());
                    }
                }
                else if (key == "mtu") mtu = val.toInt();
                else if (key == "jc") jc = val.toInt();
                else if (key == "jmin") jmin = val.toInt();
                else if (key == "jmax") jmax = val.toInt();
                else if (key == "s1") s1 = val.toInt();
                else if (key == "s2") s2 = val.toInt();
                else if (key == "s3") s3 = val.toInt();
                else if (key == "s4") s4 = val.toInt();
                else if (key == "h1") h1 = val;
                else if (key == "h2") h2 = val;
                else if (key == "h3") h3 = val;
                else if (key == "h4") h4 = val;
                else if (key == "i1") i1 = val;
                else if (key == "i2") i2 = val;
                else if (key == "i3") i3 = val;
                else if (key == "i4") i4 = val;
                else if (key == "i5") i5 = val;
            } else if (currentSection == "peer") {
                if (key == "publickey") publicKey = val;
                else if (key == "presharedkey") presharedKey = val;
                else if (key == "allowedips") {
                    for (const auto &ip : val.split(',')) {
                        allowedIPsArray.append(ip.trimmed());
                    }
                }
                else if (key == "endpoint") {
                    auto endpointParts = val.split(':');
                    if (endpointParts.length() >= 2) {
                        server_port = endpointParts.last().toInt();
                        endpointParts.removeLast();
                        server = endpointParts.join(':').replace("[", "").replace("]", "");
                    }
                }
                else if (key == "persistentkeepalive") {
                    keepalive = val.toInt();
                }
            }
        }
        
        if (privateKey.isEmpty() || publicKey.isEmpty() || server.isEmpty()) {
            return false;
        }
        
        outbound["type"] = "awg";
        outbound["server"] = server;
        outbound["server_port"] = server_port;
        outbound["private_key"] = privateKey;
        outbound["local_address"] = localAddressArray;
        if (mtu != 1408) outbound["mtu"] = mtu;
        if (jc != 0) outbound["jc"] = jc;
        if (jmin != 0) outbound["jmin"] = jmin;
        if (jmax != 0) outbound["jmax"] = jmax;
        if (s1 != 0) outbound["s1"] = s1;
        if (s2 != 0) outbound["s2"] = s2;
        if (s3 != 0) outbound["s3"] = s3;
        if (s4 != 0) outbound["s4"] = s4;
        if (!h1.isEmpty()) outbound["h1"] = h1;
        if (!h2.isEmpty()) outbound["h2"] = h2;
        if (!h3.isEmpty()) outbound["h3"] = h3;
        if (!h4.isEmpty()) outbound["h4"] = h4;
        if (!i1.isEmpty()) outbound["i1"] = i1;
        if (!i2.isEmpty()) outbound["i2"] = i2;
        if (!i3.isEmpty()) outbound["i3"] = i3;
        if (!i4.isEmpty()) outbound["i4"] = i4;
        if (!i5.isEmpty()) outbound["i5"] = i5;
        
        QJsonObject peer;
        peer["public_key"] = publicKey;
        if (!presharedKey.isEmpty()) peer["pre_shared_key"] = presharedKey;
        peer["allowed_ips"] = allowedIPsArray;
        if (keepalive != 0) peer["persistent_keepalive_interval"] = keepalive;
        peersArray.append(peer);
        
        outbound["peers"] = peersArray;
        
        name = "AmneziaWG_" + server;
        return true;
    }

    bool ParseAmneziaWGLink(const QString &link, QJsonObject &outbound, QString &name) {
        auto url = QUrl(link);
        if (!url.isValid()) return false;
        if (url.scheme() != "awg" && url.scheme() != "wireguard" && url.scheme() != "wg") return false;
        
        auto query = QUrlQuery(url.query());
        
        QString publicKey = url.userName();
        QString server = url.host();
        int server_port = url.port();
        if (server_port == -1) server_port = 51820;
        
        if (publicKey.isEmpty()) {
            publicKey = query.queryItemValue("publickey");
        }
        
        QString privateKey = query.queryItemValue("privatekey");
        if (privateKey.isEmpty()) {
            privateKey = query.queryItemValue("private_key");
        }
        
        QJsonArray localAddressArray;
        auto addressVal = query.queryItemValue("address");
        if (!addressVal.isEmpty()) {
            for (const auto &addr : addressVal.split(',')) {
                localAddressArray.append(addr.trimmed());
            }
        }
        
        QJsonArray allowedIPsArray;
        auto allowedVal = query.queryItemValue("allowedips");
        if (allowedVal.isEmpty()) allowedVal = query.queryItemValue("allowed_ips");
        if (!allowedVal.isEmpty()) {
            for (const auto &ip : allowedVal.split(',')) {
                allowedIPsArray.append(ip.trimmed());
            }
        } else {
            allowedIPsArray.append("0.0.0.0/0");
        }
        
        int mtu = query.queryItemValue("mtu").toInt();
        if (mtu == 0) mtu = 1408;
        
        int jc = query.queryItemValue("jc").toInt();
        int jmin = query.queryItemValue("jmin").toInt();
        int jmax = query.queryItemValue("jmax").toInt();
        int s1 = query.queryItemValue("s1").toInt();
        int s2 = query.queryItemValue("s2").toInt();
        int s3 = query.queryItemValue("s3").toInt();
        int s4 = query.queryItemValue("s4").toInt();
        
        QString h1 = query.queryItemValue("h1");
        QString h2 = query.queryItemValue("h2");
        QString h3 = query.queryItemValue("h3");
        QString h4 = query.queryItemValue("h4");
        QString i1 = query.queryItemValue("i1");
        QString i2 = query.queryItemValue("i2");
        QString i3 = query.queryItemValue("i3");
        QString i4 = query.queryItemValue("i4");
        QString i5 = query.queryItemValue("i5");
        
        QString presharedKey = query.queryItemValue("presharedkey");
        if (presharedKey.isEmpty()) presharedKey = query.queryItemValue("pre_shared_key");
        
        int keepalive = query.queryItemValue("persistentkeepalive").toInt();
        if (keepalive == 0) keepalive = query.queryItemValue("persistent_keepalive_interval").toInt();
        
        if (privateKey.isEmpty() || publicKey.isEmpty() || server.isEmpty()) {
            return false;
        }
        
        outbound["type"] = "awg";
        outbound["server"] = server;
        outbound["server_port"] = server_port;
        outbound["private_key"] = privateKey;
        outbound["local_address"] = localAddressArray;
        if (mtu != 1408) outbound["mtu"] = mtu;
        if (jc != 0) outbound["jc"] = jc;
        if (jmin != 0) outbound["jmin"] = jmin;
        if (jmax != 0) outbound["jmax"] = jmax;
        if (s1 != 0) outbound["s1"] = s1;
        if (s2 != 0) outbound["s2"] = s2;
        if (s3 != 0) outbound["s3"] = s3;
        if (s4 != 0) outbound["s4"] = s4;
        if (!h1.isEmpty()) outbound["h1"] = h1;
        if (!h2.isEmpty()) outbound["h2"] = h2;
        if (!h3.isEmpty()) outbound["h3"] = h3;
        if (!h4.isEmpty()) outbound["h4"] = h4;
        if (!i1.isEmpty()) outbound["i1"] = i1;
        if (!i2.isEmpty()) outbound["i2"] = i2;
        if (!i3.isEmpty()) outbound["i3"] = i3;
        if (!i4.isEmpty()) outbound["i4"] = i4;
        if (!i5.isEmpty()) outbound["i5"] = i5;
        
        QJsonObject peer;
        peer["public_key"] = publicKey;
        if (!presharedKey.isEmpty()) peer["pre_shared_key"] = presharedKey;
        peer["allowed_ips"] = allowedIPsArray;
        if (keepalive != 0) peer["persistent_keepalive_interval"] = keepalive;
        
        QJsonArray peersArray;
        peersArray.append(peer);
        outbound["peers"] = peersArray;
        
        name = url.fragment(QUrl::FullyDecoded);
        if (name.isEmpty()) {
            name = "AmneziaWG_" + server;
        }
        
        return true;
    }

    std::shared_ptr<NekoGui::ProxyEntity> ParseXrayOutbound(const QJsonObject &outbound, const QString &remarks) {
        auto protocol = outbound["protocol"].toString().toLower();
        auto tag = outbound["tag"].toString();

        if (protocol == "freedom" || protocol == "blackhole" || protocol == "dns" || protocol == "loopback") {
            return nullptr;
        }

        std::shared_ptr<NekoGui::ProxyEntity> ent = nullptr;

        if (protocol == "vless" || protocol == "trojan") {
            ent = NekoGui::ProfileManager::NewProxyEntity(protocol == "vless" ? "vless" : "trojan");
            auto bean = ent->TrojanVLESSBean();
            auto settings = outbound["settings"].toObject();
            auto vnext = settings["vnext"].toArray();
            if (!vnext.isEmpty()) {
                auto serverObj = vnext[0].toObject();
                ent->bean->serverAddress = serverObj["address"].toString();
                ent->bean->serverPort = serverObj["port"].toInt(443);
                auto users = serverObj["users"].toArray();
                if (!users.isEmpty()) {
                    auto userObj = users[0].toObject();
                    bean->password = userObj["id"].toString();
                    if (bean->password.isEmpty()) bean->password = userObj["password"].toString();
                    bean->flow = userObj["flow"].toString();
                }
            } else {
                auto servers = settings["servers"].toArray();
                if (!servers.isEmpty()) {
                    auto serverObj = servers[0].toObject();
                    ent->bean->serverAddress = serverObj["address"].toString();
                    ent->bean->serverPort = serverObj["port"].toInt(443);
                    bean->password = serverObj["password"].toString();
                }
            }

            auto streamSettings = outbound["streamSettings"].toObject();
            auto net = streamSettings["network"].toString().toLower();
            if (net == "raw" || net.isEmpty()) net = "tcp";
            bean->stream->network = net;

            auto sec = streamSettings["security"].toString().toLower();
            if (sec == "reality" || sec == "tls") {
                bean->stream->security = "tls";
                if (sec == "reality") {
                    auto realitySettings = streamSettings["realitySettings"].toObject();
                    bean->stream->reality_pbk = realitySettings["password"].toString();
                    if (bean->stream->reality_pbk.isEmpty()) bean->stream->reality_pbk = realitySettings["publicKey"].toString();
                    if (bean->stream->reality_pbk.isEmpty()) bean->stream->reality_pbk = realitySettings["public_key"].toString();

                    auto shortIdVal = realitySettings["shortId"];
                    if (shortIdVal.isString()) bean->stream->reality_sid = shortIdVal.toString();
                    else if (shortIdVal.isArray() && !shortIdVal.toArray().isEmpty()) bean->stream->reality_sid = shortIdVal.toArray()[0].toString();
                    if (bean->stream->reality_sid.isEmpty()) bean->stream->reality_sid = realitySettings["short_id"].toString();

                    bean->stream->reality_spx = realitySettings["spiderX"].toString("/");
                    bean->stream->sni = realitySettings["serverName"].toString();
                    bean->stream->utlsFingerprint = realitySettings["fingerprint"].toString();
                }

                auto tlsSettings = streamSettings["tlsSettings"].toObject();
                if (!tlsSettings.isEmpty()) {
                    if (bean->stream->sni.isEmpty()) bean->stream->sni = tlsSettings["serverName"].toString();
                    if (bean->stream->utlsFingerprint.isEmpty()) bean->stream->utlsFingerprint = tlsSettings["fingerprint"].toString();
                    bean->stream->allow_insecure = tlsSettings["allowInsecure"].toBool();
                    auto alpnArr = tlsSettings["alpn"].toArray();
                    QStringList alpnList;
                    for (const auto &a : alpnArr) alpnList << a.toString();
                    if (!alpnList.isEmpty()) bean->stream->alpn = alpnList.join(",");
                }
            } else {
                bean->stream->security = "";
            }

            if (bean->stream->utlsFingerprint.isEmpty()) {
                bean->stream->utlsFingerprint = NekoGui::dataStore->utlsFingerprint;
            }

            if (net == "xhttp") {
                auto xhttpSettings = streamSettings["xhttpSettings"].toObject();
                bean->stream->path = xhttpSettings["path"].toString();
                bean->stream->host = xhttpSettings["host"].toString();
            } else if (net == "ws") {
                auto wsSettings = streamSettings["wsSettings"].toObject();
                bean->stream->path = wsSettings["path"].toString();
                auto headers = wsSettings["headers"].toObject();
                bean->stream->host = headers["Host"].toString();
            } else if (net == "grpc") {
                auto grpcSettings = streamSettings["grpcSettings"].toObject();
                bean->stream->path = grpcSettings["serviceName"].toString();
            } else if (net == "http" || net == "h2") {
                auto httpSettings = streamSettings["httpSettings"].toObject();
                bean->stream->path = httpSettings["path"].toString();
                auto hostArr = httpSettings["host"].toArray();
                if (!hostArr.isEmpty()) bean->stream->host = hostArr[0].toString();
            } else if (net == "tcp") {
                auto tcpSettings = streamSettings["tcpSettings"].toObject();
                auto header = tcpSettings["header"].toObject();
                if (header["type"].toString().toLower() == "http") {
                    bean->stream->header_type = "http";
                    auto request = header["request"].toObject();
                    auto pathArr = request["path"].toArray();
                    if (!pathArr.isEmpty()) bean->stream->path = pathArr[0].toString();
                    auto headers = request["headers"].toObject();
                    auto hostArr = headers["Host"].toArray();
                    if (!hostArr.isEmpty()) bean->stream->host = hostArr[0].toString();
                }
            }

            if (!remarks.isEmpty()) {
                ent->bean->name = remarks;
            } else if (!tag.isEmpty() && tag != "proxy") {
                ent->bean->name = tag;
            } else {
                ent->bean->name = (protocol == "vless" ? "VLESS_" : "Trojan_") + ent->bean->serverAddress;
            }
        } else if (protocol == "hysteria" || protocol == "hysteria2") {
            ent = NekoGui::ProfileManager::NewProxyEntity("hysteria2");
            auto bean = ent->QUICBean();
            auto settings = outbound["settings"].toObject();
            ent->bean->serverAddress = settings["address"].toString();
            ent->bean->serverPort = settings["port"].toInt(443);

            auto streamSettings = outbound["streamSettings"].toObject();
            auto hysteriaSettings = streamSettings["hysteriaSettings"].toObject();
            bean->password = hysteriaSettings["auth"].toString();
            if (bean->password.isEmpty()) bean->password = settings["auth"].toString();
            if (bean->password.isEmpty()) bean->password = settings["password"].toString();

            auto tlsSettings = streamSettings["tlsSettings"].toObject();
            bean->sni = tlsSettings["serverName"].toString();
            bean->allowInsecure = tlsSettings["allowInsecure"].toBool();
            bean->alpn = "h3";

            if (!remarks.isEmpty()) {
                ent->bean->name = remarks;
            } else if (!tag.isEmpty() && tag != "proxy") {
                ent->bean->name = tag;
            } else {
                ent->bean->name = "HYSTERIA2_" + ent->bean->serverAddress;
            }
        } else if (protocol == "vmess") {
            ent = NekoGui::ProfileManager::NewProxyEntity("vmess");
            auto bean = ent->VMessBean();
            auto settings = outbound["settings"].toObject();
            auto vnext = settings["vnext"].toArray();
            if (!vnext.isEmpty()) {
                auto serverObj = vnext[0].toObject();
                ent->bean->serverAddress = serverObj["address"].toString();
                ent->bean->serverPort = serverObj["port"].toInt(443);
                auto users = serverObj["users"].toArray();
                if (!users.isEmpty()) {
                    auto userObj = users[0].toObject();
                    bean->uuid = userObj["id"].toString();
                    bean->aid = userObj["alterId"].toInt(0);
                    bean->security = userObj["security"].toString("auto");
                }
            }
            auto streamSettings = outbound["streamSettings"].toObject();
            auto net = streamSettings["network"].toString().toLower();
            if (net == "raw" || net.isEmpty()) net = "tcp";
            bean->stream->network = net;
            auto sec = streamSettings["security"].toString().toLower();
            if (sec == "tls") {
                bean->stream->security = "tls";
                auto tlsSettings = streamSettings["tlsSettings"].toObject();
                bean->stream->sni = tlsSettings["serverName"].toString();
                bean->stream->allow_insecure = tlsSettings["allowInsecure"].toBool();
            }
            if (!remarks.isEmpty()) {
                ent->bean->name = remarks;
            } else if (!tag.isEmpty() && tag != "proxy") {
                ent->bean->name = tag;
            } else {
                ent->bean->name = "VMess_" + ent->bean->serverAddress;
            }
        } else if (protocol == "shadowsocks") {
            ent = NekoGui::ProfileManager::NewProxyEntity("shadowsocks");
            auto bean = ent->ShadowSocksBean();
            auto settings = outbound["settings"].toObject();
            auto servers = settings["servers"].toArray();
            if (!servers.isEmpty()) {
                auto serverObj = servers[0].toObject();
                ent->bean->serverAddress = serverObj["address"].toString();
                ent->bean->serverPort = serverObj["port"].toInt(8388);
                bean->method = serverObj["method"].toString();
                bean->password = serverObj["password"].toString();
            }
            if (!remarks.isEmpty()) {
                ent->bean->name = remarks;
            } else if (!tag.isEmpty() && tag != "proxy") {
                ent->bean->name = tag;
            } else {
                ent->bean->name = "Shadowsocks_" + ent->bean->serverAddress;
            }
        } else if (protocol == "socks" || protocol == "http") {
            ent = NekoGui::ProfileManager::NewProxyEntity(protocol == "http" ? "http" : "socks");
            auto bean = ent->SocksHTTPBean();
            auto settings = outbound["settings"].toObject();
            auto servers = settings["servers"].toArray();
            if (!servers.isEmpty()) {
                auto serverObj = servers[0].toObject();
                ent->bean->serverAddress = serverObj["address"].toString();
                ent->bean->serverPort = serverObj["port"].toInt(protocol == "http" ? 80 : 1080);
                auto users = serverObj["users"].toArray();
                if (!users.isEmpty()) {
                    auto userObj = users[0].toObject();
                    bean->username = userObj["user"].toString();
                    bean->password = userObj["pass"].toString();
                }
            }
            if (!remarks.isEmpty()) {
                ent->bean->name = remarks;
            } else if (!tag.isEmpty() && tag != "proxy") {
                ent->bean->name = tag;
            } else {
                ent->bean->name = (protocol == "http" ? "HTTP_" : "SOCKS_") + ent->bean->serverAddress;
            }
        }

        if (ent != nullptr && (ent->bean->serverAddress.isEmpty() || ent->bean->serverPort <= 0)) {
            return nullptr;
        }

        return ent;
    }

    std::shared_ptr<NekoGui::ProxyEntity> ParseSingBoxOutbound(const QJsonObject &outbound, const QString &remarks) {
        auto type = outbound["type"].toString().toLower();
        auto tag = outbound["tag"].toString();

        if (type == "direct" || type == "block" || type == "dns" || type == "urltest" || type == "selector") {
            return nullptr;
        }

        std::shared_ptr<NekoGui::ProxyEntity> ent = nullptr;

        if (type == "vless" || type == "trojan") {
            ent = NekoGui::ProfileManager::NewProxyEntity(type == "vless" ? "vless" : "trojan");
            auto bean = ent->TrojanVLESSBean();
            ent->bean->serverAddress = outbound["server"].toString();
            ent->bean->serverPort = outbound["server_port"].toInt(443);
            if (type == "vless") {
                bean->password = outbound["uuid"].toString();
                bean->flow = outbound["flow"].toString();
            } else {
                bean->password = outbound["password"].toString();
            }

            auto tls = outbound["tls"].toObject();
            if (tls["enabled"].toBool()) {
                bean->stream->security = "tls";
                bean->stream->sni = tls["server_name"].toString();
                bean->stream->allow_insecure = tls["insecure"].toBool();
                auto reality = tls["reality"].toObject();
                if (reality["enabled"].toBool()) {
                    bean->stream->reality_pbk = reality["public_key"].toString();
                    bean->stream->reality_sid = reality["short_id"].toString();
                }
                auto utls = tls["utls"].toObject();
                if (utls["enabled"].toBool()) {
                    bean->stream->utlsFingerprint = utls["fingerprint"].toString();
                }
                auto alpnArr = tls["alpn"].toArray();
                QStringList alpnList;
                for (const auto &a : alpnArr) alpnList << a.toString();
                if (!alpnList.isEmpty()) bean->stream->alpn = alpnList.join(",");
            }

            auto transport = outbound["transport"].toObject();
            auto tType = transport["type"].toString().toLower();
            if (!tType.isEmpty()) {
                bean->stream->network = tType;
                bean->stream->path = transport["path"].toString();
                if (tType == "grpc") {
                    bean->stream->path = transport["service_name"].toString();
                }
                auto hostArr = transport["host"].toArray();
                if (!hostArr.isEmpty()) bean->stream->host = hostArr[0].toString();
                else if (transport["headers"].isObject()) {
                    bean->stream->host = transport["headers"].toObject()["Host"].toString();
                }
            }

            if (!remarks.isEmpty()) {
                ent->bean->name = remarks;
            } else if (!tag.isEmpty()) {
                ent->bean->name = tag;
            } else {
                ent->bean->name = (type == "vless" ? "VLESS_" : "Trojan_") + ent->bean->serverAddress;
            }
        } else if (type == "hysteria2") {
            ent = NekoGui::ProfileManager::NewProxyEntity("hysteria2");
            auto bean = ent->QUICBean();
            ent->bean->serverAddress = outbound["server"].toString();
            ent->bean->serverPort = outbound["server_port"].toInt(443);
            bean->password = outbound["password"].toString();
            auto tls = outbound["tls"].toObject();
            bean->sni = tls["server_name"].toString();
            bean->allowInsecure = tls["insecure"].toBool();
            bean->alpn = "h3";
            if (!remarks.isEmpty()) {
                ent->bean->name = remarks;
            } else if (!tag.isEmpty()) {
                ent->bean->name = tag;
            } else {
                ent->bean->name = "HYSTERIA2_" + ent->bean->serverAddress;
            }
        } else if (type == "shadowsocks") {
            ent = NekoGui::ProfileManager::NewProxyEntity("shadowsocks");
            auto bean = ent->ShadowSocksBean();
            ent->bean->serverAddress = outbound["server"].toString();
            ent->bean->serverPort = outbound["server_port"].toInt(8388);
            bean->method = outbound["method"].toString();
            bean->password = outbound["password"].toString();
            if (!remarks.isEmpty()) {
                ent->bean->name = remarks;
            } else if (!tag.isEmpty()) {
                ent->bean->name = tag;
            } else {
                ent->bean->name = "Shadowsocks_" + ent->bean->serverAddress;
            }
        } else if (type == "vmess") {
            ent = NekoGui::ProfileManager::NewProxyEntity("vmess");
            auto bean = ent->VMessBean();
            ent->bean->serverAddress = outbound["server"].toString();
            ent->bean->serverPort = outbound["server_port"].toInt(443);
            bean->uuid = outbound["uuid"].toString();
            bean->security = outbound["security"].toString("auto");
            bean->aid = outbound["alter_id"].toInt(0);
            if (!remarks.isEmpty()) {
                ent->bean->name = remarks;
            } else if (!tag.isEmpty()) {
                ent->bean->name = tag;
            } else {
                ent->bean->name = "VMess_" + ent->bean->serverAddress;
            }
        } else if (type == "tuic") {
            ent = NekoGui::ProfileManager::NewProxyEntity("tuic");
            auto bean = ent->QUICBean();
            ent->bean->serverAddress = outbound["server"].toString();
            ent->bean->serverPort = outbound["server_port"].toInt(443);
            bean->uuid = outbound["uuid"].toString();
            bean->password = outbound["password"].toString();
            bean->congestionControl = outbound["congestion_control"].toString();
            bean->udpRelayMode = outbound["udp_relay_mode"].toString();
            bean->zeroRttHandshake = outbound["zero_rtt_handshake"].toBool();
            auto tls = outbound["tls"].toObject();
            bean->sni = tls["server_name"].toString();
            bean->allowInsecure = tls["insecure"].toBool();
            if (!remarks.isEmpty()) {
                ent->bean->name = remarks;
            } else if (!tag.isEmpty()) {
                ent->bean->name = tag;
            } else {
                ent->bean->name = "TUIC_" + ent->bean->serverAddress;
            }
        } else if (type == "awg" || type == "wireguard") {
            ent = NekoGui::ProfileManager::NewProxyEntity("custom");
            auto bean = ent->CustomBean();
            ent->bean->name = !remarks.isEmpty() ? remarks : (!tag.isEmpty() ? tag : "AWG_" + outbound["server"].toString());
            bean->core = "internal";
            bean->config_simple = QJsonObject2QString(outbound, false);
            ent->bean->serverAddress = outbound["server"].toString();
            ent->bean->serverPort = outbound["server_port"].toInt(51820);
        }

        if (ent != nullptr && (ent->bean->serverAddress.isEmpty() || ent->bean->serverPort <= 0)) {
            return nullptr;
        }

        return ent;
    }

    void RawUpdater::update(const QString &str) {
        auto trimmed = str.trimmed();
        if (trimmed.isEmpty()) return;

        // HAPP link support: happ://add/<url>
        if (trimmed.startsWith("happ://add/", Qt::CaseInsensitive)) {
            auto subUrl = trimmed.mid(QStringLiteral("happ://add/").length()).trimmed();
            if (subUrl.startsWith("http://", Qt::CaseInsensitive) || subUrl.startsWith("https://", Qt::CaseInsensitive)) {
                auto resp = NekoGui_network::NetworkRequestHelper::HttpGet(QUrl(subUrl));
                if (resp.error.isEmpty() && !resp.data.isEmpty()) {
                    update(QString::fromUtf8(resp.data));
                    return;
                }
            }
        }

        // Base64 encoded subscription
        if (auto str2 = DecodeB64IfValid(trimmed); !str2.isEmpty() && str2 != trimmed) {
            update(str2);
            return;
        }

        // JSON format (e.g. autoXRAY subscription JSON or Xray / sing-box client config)
        if ((trimmed.startsWith("{") && trimmed.endsWith("}")) || (trimmed.startsWith("[") && trimmed.endsWith("]"))) {
            QJsonParseError err;
            auto doc = QJsonDocument::fromJson(trimmed.toUtf8(), &err);
            if (!doc.isNull() && err.error == QJsonParseError::NoError) {
                if (doc.isArray()) {
                    auto arr = doc.array();
                    for (const auto &val : arr) {
                        if (val.isObject()) {
                            auto obj = val.toObject();
                            QString remarks = obj["remarks"].toString();
                            if (remarks.isEmpty()) remarks = obj["remark"].toString();
                            if (remarks.isEmpty()) remarks = obj["tag"].toString();

                            if (obj.contains("outbounds")) {
                                auto outbounds = obj["outbounds"].toArray();
                                for (const auto &outVal : outbounds) {
                                    if (outVal.isObject()) {
                                        auto outObj = outVal.toObject();
                                        auto ent = ParseXrayOutbound(outObj, remarks);
                                        if (ent == nullptr) {
                                            ent = ParseSingBoxOutbound(outObj, remarks);
                                        }
                                        if (ent != nullptr) {
                                            RawUpdater_FixEnt(ent);
                                            NekoGui::profileManager->AddProfile(ent, gid_add_to);
                                            updated_order += ent;
                                        }
                                    }
                                }
                            } else {
                                auto ent = ParseXrayOutbound(obj, remarks);
                                if (ent == nullptr) {
                                    ent = ParseSingBoxOutbound(obj, remarks);
                                }
                                if (ent != nullptr) {
                                    RawUpdater_FixEnt(ent);
                                    NekoGui::profileManager->AddProfile(ent, gid_add_to);
                                    updated_order += ent;
                                }
                            }
                        }
                    }
                    return;
                } else if (doc.isObject()) {
                    auto obj = doc.object();
                    QString remarks = obj["remarks"].toString();
                    if (remarks.isEmpty()) remarks = obj["remark"].toString();
                    if (remarks.isEmpty()) remarks = obj["tag"].toString();

                    if (obj.contains("outbounds")) {
                        auto outbounds = obj["outbounds"].toArray();
                        for (const auto &outVal : outbounds) {
                            if (outVal.isObject()) {
                                auto outObj = outVal.toObject();
                                auto ent = ParseXrayOutbound(outObj, remarks);
                                if (ent == nullptr) {
                                    ent = ParseSingBoxOutbound(outObj, remarks);
                                }
                                if (ent != nullptr) {
                                    RawUpdater_FixEnt(ent);
                                    NekoGui::profileManager->AddProfile(ent, gid_add_to);
                                    updated_order += ent;
                                }
                            }
                        }
                        return;
                    } else {
                        auto ent = ParseXrayOutbound(obj, remarks);
                        if (ent == nullptr) {
                            ent = ParseSingBoxOutbound(obj, remarks);
                        }
                        if (ent != nullptr) {
                            RawUpdater_FixEnt(ent);
                            NekoGui::profileManager->AddProfile(ent, gid_add_to);
                            updated_order += ent;
                            return;
                        }
                    }
                }
            }
        }

        // HTML content or multi-link text extraction
        if (trimmed.contains("<html", Qt::CaseInsensitive) || trimmed.contains("<!DOCTYPE", Qt::CaseInsensitive) ||
            trimmed.contains("config-code", Qt::CaseInsensitive) || trimmed.contains("<br", Qt::CaseInsensitive)) {
            static const QRegularExpression linkRe(QStringLiteral("(?:vless|vmess|ss|trojan|hysteria2|hy2|tuic|awg|wireguard|wg|socks5|socks|naive\\+https|naive\\+quic|nekoslop)://[^\\s\"'<>]+"));
            auto matches = linkRe.globalMatch(trimmed);
            bool foundAny = false;
            while (matches.hasNext()) {
                auto match = matches.next();
                auto linkStr = match.captured(0).trimmed();
                if (!linkStr.isEmpty()) {
                    foundAny = true;
                    update(linkStr);
                }
            }
            if (foundAny) return;
        }

        // Clash
        if (trimmed.contains("proxies:")) {
            updateClash(trimmed);
            return;
        }

        // Multi line
        if (trimmed.count("\n") > 0) {
            auto list = trimmed.split("\n");
            for (const auto &str2: list) {
                update(str2.trimmed());
            }
            return;
        }

        std::shared_ptr<NekoGui::ProxyEntity> ent;
        bool needFix = true;

        // AmneziaWG conf file or wireguard / awg link
        QJsonObject awgOutbound;
        QString awgName;
        bool isAwg = false;
        
        if (str.startsWith("awg://") || str.startsWith("wireguard://") || str.startsWith("wg://")) {
            isAwg = ParseAmneziaWGLink(str, awgOutbound, awgName);
        } else if (str.contains("[Interface]", Qt::CaseInsensitive)) {
            isAwg = ParseAmneziaWGConf(str, awgOutbound, awgName);
        }
        
        if (isAwg) {
            needFix = false;
            ent = NekoGui::ProfileManager::NewProxyEntity("custom");
            auto bean = ent->CustomBean();
            ent->bean->name = awgName;
            bean->core = "internal";
            bean->config_simple = QJsonObject2QString(awgOutbound, false);
            ent->bean->serverAddress = awgOutbound["server"].toString();
            ent->bean->serverPort = awgOutbound["server_port"].toInt();
        }

        // Nekoray format
        if (str.startsWith("nekoslop://")) {
            needFix = false;
            auto link = QUrl(str);
            if (!link.isValid()) return;
            ent = NekoGui::ProfileManager::NewProxyEntity(link.host());
            if (ent->bean->version == -114514) return;
            auto j = DecodeB64IfValid(link.fragment().toUtf8(), QByteArray::Base64UrlEncoding);
            if (j.isEmpty()) return;
            ent->bean->FromJsonBytes(j);
        }

        // SOCKS
        if (str.startsWith("socks5://") || str.startsWith("socks4://") ||
            str.startsWith("socks4a://") || str.startsWith("socks://")) {
            ent = NekoGui::ProfileManager::NewProxyEntity("socks");
            auto ok = ent->SocksHTTPBean()->TryParseLink(str);
            if (!ok) return;
        }

        // HTTP
        if (str.startsWith("http://") || str.startsWith("https://")) {
            ent = NekoGui::ProfileManager::NewProxyEntity("http");
            auto ok = ent->SocksHTTPBean()->TryParseLink(str);
            if (!ok) return;
        }

        // ShadowSocks
        if (str.startsWith("ss://")) {
            ent = NekoGui::ProfileManager::NewProxyEntity("shadowsocks");
            auto ok = ent->ShadowSocksBean()->TryParseLink(str);
            if (!ok) return;
        }

        // VMess
        if (str.startsWith("vmess://")) {
            ent = NekoGui::ProfileManager::NewProxyEntity("vmess");
            auto ok = ent->VMessBean()->TryParseLink(str);
            if (!ok) return;
        }

        // VLESS
        if (str.startsWith("vless://")) {
            ent = NekoGui::ProfileManager::NewProxyEntity("vless");
            auto ok = ent->TrojanVLESSBean()->TryParseLink(str);
            if (!ok) return;
        }

        // Trojan
        if (str.startsWith("trojan://")) {
            ent = NekoGui::ProfileManager::NewProxyEntity("trojan");
            auto ok = ent->TrojanVLESSBean()->TryParseLink(str);
            if (!ok) return;
        }

        // Naive
        if (str.startsWith("naive+")) {
            needFix = false;
            ent = NekoGui::ProfileManager::NewProxyEntity("naive");
            auto ok = ent->NaiveBean()->TryParseLink(str);
            if (!ok) return;
        }

        // Hysteria2
        if (str.startsWith("hysteria2://") || str.startsWith("hy2://")) {
            needFix = false;
            ent = NekoGui::ProfileManager::NewProxyEntity("hysteria2");
            auto ok = ent->QUICBean()->TryParseLink(str);
            if (!ok) return;
        }

        // TUIC
        if (str.startsWith("tuic://")) {
            needFix = false;
            ent = NekoGui::ProfileManager::NewProxyEntity("tuic");
            auto ok = ent->QUICBean()->TryParseLink(str);
            if (!ok) return;
        }

        if (ent == nullptr) return;

        // Fix
        if (needFix) RawUpdater_FixEnt(ent);

        // End
        NekoGui::profileManager->AddProfile(ent, gid_add_to);
        updated_order += ent;
    }

#ifndef NKR_NO_YAML

    QString Node2QString(const YAML::Node &n, const QString &def = "") {
        try {
            return n.as<std::string>().c_str();
        } catch (const YAML::Exception &ex) {
            qDebug() << ex.what();
            return def;
        }
    }

    QStringList Node2QStringList(const YAML::Node &n) {
        try {
            if (n.IsSequence()) {
                QStringList list;
                for (auto item: n) {
                    list << item.as<std::string>().c_str();
                }
                return list;
            } else {
                return {};
            }
        } catch (const YAML::Exception &ex) {
            qDebug() << ex.what();
            return {};
        }
    }

    int Node2Int(const YAML::Node &n, const int &def = 0) {
        try {
            return n.as<int>();
        } catch (const YAML::Exception &ex) {
            qDebug() << ex.what();
            return def;
        }
    }

    bool Node2Bool(const YAML::Node &n, const bool &def = false) {
        try {
            return n.as<bool>();
        } catch (const YAML::Exception &ex) {
            try {
                return n.as<int>();
            } catch (const YAML::Exception &ex2) {
                qDebug() << ex2.what();
            }
            qDebug() << ex.what();
            return def;
        }
    }

    // NodeChild returns the first defined children or Null Node
    YAML::Node NodeChild(const YAML::Node &n, const std::list<std::string> &keys) {
        for (const auto &key: keys) {
            auto child = n[key];
            if (child.IsDefined()) return child;
        }
        return {};
    }

#endif

    // https://github.com/Dreamacro/clash/wiki/configuration
    void RawUpdater::updateClash(const QString &str) {
#ifndef NKR_NO_YAML
        try {
            auto proxies = YAML::Load(str.toStdString())["proxies"];
            for (auto proxy: proxies) {
                auto type = Node2QString(proxy["type"]).toLower();
                auto type_clash = type;

                if (type == "ss" || type == "ssr") type = "shadowsocks";
                if (type == "socks5") type = "socks";

                auto ent = NekoGui::ProfileManager::NewProxyEntity(type);
                if (ent->bean->version == -114514) continue;
                bool needFix = false;

                // common
                ent->bean->name = Node2QString(proxy["name"]);
                ent->bean->serverAddress = Node2QString(proxy["server"]);
                ent->bean->serverPort = Node2Int(proxy["port"]);

                if (type_clash == "ss") {
                    auto bean = ent->ShadowSocksBean();
                    bean->method = Node2QString(proxy["cipher"]).replace("dummy", "none");
                    bean->password = Node2QString(proxy["password"]);
                    auto plugin_n = proxy["plugin"];
                    auto pluginOpts_n = proxy["plugin-opts"];

                    // UDP over TCP
                    if (Node2Bool(proxy["udp-over-tcp"])) {
                        bean->uot = Node2Int(proxy["udp-over-tcp-version"]);
                        if (bean->uot == 0) bean->uot = 2;
                    }

                    if (plugin_n.IsDefined() && pluginOpts_n.IsDefined()) {
                        QStringList ssPlugin;
                        auto plugin = Node2QString(plugin_n);
                        if (plugin == "obfs") {
                            ssPlugin << "obfs-local";
                            ssPlugin << "obfs=" + Node2QString(pluginOpts_n["mode"]);
                            ssPlugin << "obfs-host=" + Node2QString(pluginOpts_n["host"]);
                        } else if (plugin == "v2ray-plugin") {
                            auto mode = Node2QString(pluginOpts_n["mode"]);
                            auto host = Node2QString(pluginOpts_n["host"]);
                            auto path = Node2QString(pluginOpts_n["path"]);
                            ssPlugin << "v2ray-plugin";
                            if (!mode.isEmpty() && mode != "websocket") ssPlugin << "mode=" + mode;
                            if (Node2Bool(pluginOpts_n["tls"])) ssPlugin << "tls";
                            if (!host.isEmpty()) ssPlugin << "host=" + host;
                            if (!path.isEmpty()) ssPlugin << "path=" + path;
                            // clash only: skip-cert-verify
                            // clash only: headers
                            // clash: mux=?
                        }
                        bean->plugin = ssPlugin.join(";");
                    }

                    // sing-mux
                    auto smux = NodeChild(proxy, {"smux"});
                    if (Node2Bool(smux["enabled"])) bean->stream->multiplex_status = 1;
                } else if (type == "socks" || type == "http") {
                    auto bean = ent->SocksHTTPBean();
                    bean->username = Node2QString(proxy["username"]);
                    bean->password = Node2QString(proxy["password"]);
                    if (Node2Bool(proxy["tls"])) bean->stream->security = "tls";
                    if (Node2Bool(proxy["skip-cert-verify"])) bean->stream->allow_insecure = true;
                } else if (type == "trojan" || type == "vless") {
                    needFix = true;
                    auto bean = ent->TrojanVLESSBean();
                    if (type == "vless") {
                        bean->flow = Node2QString(proxy["flow"]);
                        bean->password = Node2QString(proxy["uuid"]);
                        // meta packet encoding
                        if (Node2Bool(proxy["packet-addr"])) {
                            bean->stream->packet_encoding = "packetaddr";
                        } else {
                            // For VLESS, default to use xudp
                            bean->stream->packet_encoding = "xudp";
                        }
                    } else {
                        bean->password = Node2QString(proxy["password"]);
                    }
                    bean->stream->security = "tls";
                    bean->stream->network = Node2QString(proxy["network"], "tcp");
                    bean->stream->sni = FIRST_OR_SECOND(Node2QString(proxy["sni"]), Node2QString(proxy["servername"]));
                    bean->stream->alpn = Node2QStringList(proxy["alpn"]).join(",");
                    bean->stream->allow_insecure = Node2Bool(proxy["skip-cert-verify"]);
                    bean->stream->utlsFingerprint = Node2QString(proxy["client-fingerprint"]);
                    if (bean->stream->utlsFingerprint.isEmpty()) {
                        bean->stream->utlsFingerprint = NekoGui::dataStore->utlsFingerprint;
                    }

                    // sing-mux
                    auto smux = NodeChild(proxy, {"smux"});
                    if (Node2Bool(smux["enabled"])) bean->stream->multiplex_status = 1;

                    // opts
                    auto ws = NodeChild(proxy, {"ws-opts", "ws-opt"});
                    if (ws.IsMap()) {
                        auto headers = ws["headers"];
                        for (auto header: headers) {
                            if (Node2QString(header.first).toLower() == "host") {
                                bean->stream->host = Node2QString(header.second);
                            }
                        }
                        bean->stream->path = Node2QString(ws["path"]);
                        bean->stream->ws_early_data_length = Node2Int(ws["max-early-data"]);
                        bean->stream->ws_early_data_name = Node2QString(ws["early-data-header-name"]);
                    }

                    auto grpc = NodeChild(proxy, {"grpc-opts", "grpc-opt"});
                    if (grpc.IsMap()) {
                        bean->stream->path = Node2QString(grpc["grpc-service-name"]);
                    }

                    auto reality = NodeChild(proxy, {"reality-opts"});
                    if (reality.IsMap()) {
                        bean->stream->reality_pbk = Node2QString(reality["public-key"]);
                        bean->stream->reality_sid = Node2QString(reality["short-id"]);
                    }
                } else if (type == "vmess") {
                    needFix = true;
                    auto bean = ent->VMessBean();
                    bean->uuid = Node2QString(proxy["uuid"]);
                    bean->aid = Node2Int(proxy["alterId"]);
                    bean->security = Node2QString(proxy["cipher"], bean->security);
                    bean->stream->network = Node2QString(proxy["network"], "tcp").replace("h2", "http");
                    bean->stream->sni = FIRST_OR_SECOND(Node2QString(proxy["sni"]), Node2QString(proxy["servername"]));
                    bean->stream->alpn = Node2QStringList(proxy["alpn"]).join(",");
                    if (Node2Bool(proxy["tls"])) bean->stream->security = "tls";
                    if (Node2Bool(proxy["skip-cert-verify"])) bean->stream->allow_insecure = true;
                    bean->stream->utlsFingerprint = Node2QString(proxy["client-fingerprint"]);
                    bean->stream->utlsFingerprint = Node2QString(proxy["client-fingerprint"]);
                    if (bean->stream->utlsFingerprint.isEmpty()) {
                        bean->stream->utlsFingerprint = NekoGui::dataStore->utlsFingerprint;
                    }

                    // sing-mux
                    auto smux = NodeChild(proxy, {"smux"});
                    if (Node2Bool(smux["enabled"])) bean->stream->multiplex_status = 1;

                    // meta packet encoding
                    if (Node2Bool(proxy["xudp"])) bean->stream->packet_encoding = "xudp";
                    if (Node2Bool(proxy["packet-addr"])) bean->stream->packet_encoding = "packetaddr";

                    // opts
                    auto ws = NodeChild(proxy, {"ws-opts", "ws-opt"});
                    if (ws.IsMap()) {
                        auto headers = ws["headers"];
                        for (auto header: headers) {
                            if (Node2QString(header.first).toLower() == "host") {
                                bean->stream->host = Node2QString(header.second);
                            }
                        }
                        bean->stream->path = Node2QString(ws["path"]);
                        bean->stream->ws_early_data_length = Node2Int(ws["max-early-data"]);
                        bean->stream->ws_early_data_name = Node2QString(ws["early-data-header-name"]);
                        // for Xray
                        if (Node2QString(ws["early-data-header-name"]) == "Sec-WebSocket-Protocol") {
                            bean->stream->path += "?ed=" + Node2QString(ws["max-early-data"]);
                        }
                    }

                    auto grpc = NodeChild(proxy, {"grpc-opts", "grpc-opt"});
                    if (grpc.IsMap()) {
                        bean->stream->path = Node2QString(grpc["grpc-service-name"]);
                    }

                    auto h2 = NodeChild(proxy, {"h2-opts", "h2-opt"});
                    if (h2.IsMap()) {
                        auto hosts = h2["host"];
                        for (auto host: hosts) {
                            bean->stream->host = Node2QString(host);
                            break;
                        }
                        bean->stream->path = Node2QString(h2["path"]);
                    }

                    auto tcp_http = NodeChild(proxy, {"http-opts", "http-opt"});
                    if (tcp_http.IsMap()) {
                        bean->stream->network = "tcp";
                        bean->stream->header_type = "http";
                        auto headers = tcp_http["headers"];
                        for (auto header: headers) {
                            if (Node2QString(header.first).toLower() == "host") {
                                bean->stream->host = Node2QString(header.second[0]);
                            }
                            break;
                        }
                        auto paths = tcp_http["path"];
                        for (auto path: paths) {
                            bean->stream->path = Node2QString(path);
                            break;
                        }
                    }
                } else if (type == "hysteria2") {
                    auto bean = ent->QUICBean();

                    bean->hopPort = Node2QString(proxy["ports"]);

                    bean->allowInsecure = Node2Bool(proxy["skip-cert-verify"]);
                    bean->caText = Node2QString(proxy["ca-str"]);
                    bean->sni = Node2QString(proxy["sni"]);

                    bean->obfsPassword = Node2QString(proxy["obfs-password"]);
                    bean->password = Node2QString(proxy["password"]);

                    bean->uploadMbps = Node2QString(proxy["up"]).split(" ")[0].toInt();
                    bean->downloadMbps = Node2QString(proxy["down"]).split(" ")[0].toInt();
                } else if (type == "tuic") {
                    auto bean = ent->QUICBean();

                    bean->uuid = Node2QString(proxy["uuid"]);
                    bean->password = Node2QString(proxy["password"]);

                    if (Node2Int(proxy["heartbeat-interval"]) != 0) {
                        bean->heartbeat = Int2String(Node2Int(proxy["heartbeat-interval"])) + "ms";
                    }

                    bean->udpRelayMode = Node2QString(proxy["udp-relay-mode"], bean->udpRelayMode);
                    bean->congestionControl = Node2QString(proxy["congestion-controller"], bean->congestionControl);

                    bean->disableSni = Node2Bool(proxy["disable-sni"]);
                    bean->zeroRttHandshake = Node2Bool(proxy["reduce-rtt"]);
                    bean->allowInsecure = Node2Bool(proxy["skip-cert-verify"]);
                    bean->alpn = Node2QStringList(proxy["alpn"]).join(",");
                    bean->caText = Node2QString(proxy["ca-str"]);
                    bean->sni = Node2QString(proxy["sni"]);

                    if (Node2Bool(proxy["udp-over-stream"])) bean->uos = true;

                    if (!Node2QString(proxy["ip"]).isEmpty()) {
                        if (bean->sni.isEmpty()) bean->sni = bean->serverAddress;
                        bean->serverAddress = Node2QString(proxy["ip"]);
                    }
                } else {
                    continue;
                }

                if (needFix) RawUpdater_FixEnt(ent);
                NekoGui::profileManager->AddProfile(ent, gid_add_to);
                updated_order += ent;
            }
        } catch (const YAML::Exception &ex) {
            runOnUiThread([=] {
                MessageBoxWarning("YAML Exception", ex.what());
            });
        }
#endif
    }

    // 在新的 thread 运行
    void GroupUpdater::AsyncUpdate(const QString &str, int _sub_gid, const std::function<void()> &finish) {
        auto content = str.trimmed();
        bool asURL = false;
        bool createNewGroup = false;

        if (_sub_gid < 0 && (content.startsWith("http://", Qt::CaseInsensitive) || content.startsWith("https://", Qt::CaseInsensitive) || content.startsWith("happ://add/", Qt::CaseInsensitive))) {
            if (content.startsWith("happ://add/", Qt::CaseInsensitive)) {
                content = content.mid(QString("happ://add/").length()).trimmed();
                asURL = true;
                createNewGroup = true;
            } else if (content.contains("/sub/") || content.contains("sub?") || content.endsWith(".json", Qt::CaseInsensitive) || content.endsWith(".html", Qt::CaseInsensitive) || content.endsWith(".txt", Qt::CaseInsensitive)) {
                asURL = true;
                createNewGroup = true;
            } else {
                auto items = QStringList{
                    QObject::tr("As Subscription (add to this group)"),
                    QObject::tr("As Subscription (create new group)"),
                    QObject::tr("As link"),
                };
                bool ok;
                auto a = QInputDialog::getItem(nullptr,
                                               QObject::tr("url detected"),
                                               QObject::tr("%1\nHow to update?").arg(content),
                                               items, 0, false, &ok);
                if (!ok) return;
                if (items.indexOf(a) <= 1) asURL = true;
                if (items.indexOf(a) == 1) createNewGroup = true;
            }
        }

        runOnNewThread([=] {
            auto gid = _sub_gid;
            if (createNewGroup) {
                auto group = NekoGui::ProfileManager::NewGroup();
                group->name = QUrl(str).host();
                group->url = str;
                NekoGui::profileManager->AddGroup(group);
                gid = group->id;
                MW_dialog_message("SubUpdater", "NewGroup");
            }
            Update(str, gid, asURL);
            emit asyncUpdateCallback(gid);
            if (finish != nullptr) finish();
        });
    }

    void GroupUpdater::Update(const QString &_str, int _sub_gid, bool _not_sub_as_url) {
        // 创建 rawUpdater
        NekoGui::dataStore->imported_count = 0;
        auto rawUpdater = std::make_unique<RawUpdater>();
        rawUpdater->gid_add_to = _sub_gid;

        // 准备
        QString sub_user_info;
        bool asURL = _sub_gid >= 0 || _not_sub_as_url; // 把 _str 当作 url 处理（下载内容）
        auto content = _str.trimmed();
        auto group = NekoGui::profileManager->GetGroup(_sub_gid);
        if (group != nullptr && group->archive) return;

        // 网络请求
        if (asURL) {
            auto groupName = group == nullptr ? content : group->name;
            MW_show_log(">>>>>>>> " + QObject::tr("Requesting subscription: %1").arg(groupName));

            auto resp = NetworkRequestHelper::HttpGet(content);
            if (!resp.error.isEmpty()) {
                MW_show_log("<<<<<<<< " + QObject::tr("Requesting subscription %1 error: %2").arg(groupName, resp.error + "\n" + resp.data));
                return;
            }

            content = resp.data;
            sub_user_info = NetworkRequestHelper::GetHeader(resp.header, "Subscription-UserInfo");

            MW_show_log("<<<<<<<< " + QObject::tr("Subscription request fininshed: %1").arg(groupName));
        }

        QList<std::shared_ptr<NekoGui::ProxyEntity>> in;          // 更新前
        QList<std::shared_ptr<NekoGui::ProxyEntity>> out_all;     // 更新前 + 更新后
        QList<std::shared_ptr<NekoGui::ProxyEntity>> out;         // 更新后
        QList<std::shared_ptr<NekoGui::ProxyEntity>> only_in;     // 只在更新前有的
        QList<std::shared_ptr<NekoGui::ProxyEntity>> only_out;    // 只在更新后有的
        QList<std::shared_ptr<NekoGui::ProxyEntity>> update_del;  // 更新前后都有的，需要删除的新配置
        QList<std::shared_ptr<NekoGui::ProxyEntity>> update_keep; // 更新前后都有的，被保留的旧配置

        // 订阅解析前
        if (group != nullptr) {
            in = group->Profiles();
            group->sub_last_update = QDateTime::currentMSecsSinceEpoch() / 1000;
            group->info = sub_user_info;
            group->order.clear();
            group->Save();
            //
            if (NekoGui::dataStore->sub_clear) {
                MW_show_log(QObject::tr("Clearing servers..."));
                for (const auto &profile: in) {
                    NekoGui::profileManager->DeleteProfile(profile->id);
                }
            }
        }

        // 解析并添加 profile
        rawUpdater->update(content);

        if (group != nullptr) {
            out_all = group->Profiles();

            QString change_text;

            if (NekoGui::dataStore->sub_clear) {
                // all is new profile
                for (const auto &ent: out_all) {
                    change_text += "[+] " + ent->bean->DisplayTypeAndName() + "\n";
                }
            } else {
                // find and delete not updated profile by ProfileFilter
                NekoGui::ProfileFilter::OnlyInSrc_ByPointer(out_all, in, out);
                NekoGui::ProfileFilter::OnlyInSrc(in, out, only_in);
                NekoGui::ProfileFilter::OnlyInSrc(out, in, only_out);
                NekoGui::ProfileFilter::Common(in, out, update_keep, update_del, false);

                QString notice_added;
                QString notice_deleted;
                for (const auto &ent: only_out) {
                    notice_added += "[+] " + ent->bean->DisplayTypeAndName() + "\n";
                }
                for (const auto &ent: only_in) {
                    notice_deleted += "[-] " + ent->bean->DisplayTypeAndName() + "\n";
                }

                // sort according to order in remote
                group->order = {};
                for (const auto &ent: rawUpdater->updated_order) {
                    auto deleted_index = update_del.indexOf(ent);
                    if (deleted_index > 0) {
                        if (deleted_index >= update_keep.count()) continue; // should not happen
                        auto ent2 = update_keep[deleted_index];
                        group->order.append(ent2->id);
                    } else {
                        group->order.append(ent->id);
                    }
                }
                group->Save();

                // cleanup
                for (const auto &ent: out_all) {
                    if (!group->order.contains(ent->id)) {
                        NekoGui::profileManager->DeleteProfile(ent->id);
                    }
                }

                change_text = "\n" + QObject::tr("Added %1 profiles:\n%2\nDeleted %3 Profiles:\n%4")
                                         .arg(only_out.length())
                                         .arg(notice_added)
                                         .arg(only_in.length())
                                         .arg(notice_deleted);
                if (only_out.length() + only_in.length() == 0) change_text = QObject::tr("Nothing");
            }

            MW_show_log("<<<<<<<< " + QObject::tr("Change of %1:").arg(group->name) + "\n" + change_text);
            MW_dialog_message("SubUpdater", "finish-dingyue");
        } else {
            NekoGui::dataStore->imported_count = rawUpdater->updated_order.count();
            MW_dialog_message("SubUpdater", "finish");
        }
    }
} // namespace NekoGui_sub

bool UI_update_all_groups_Updating = false;

#define should_skip_group(g) (g == nullptr || g->url.isEmpty() || g->archive || (onlyAllowed && g->skip_auto_update))

void serialUpdateSubscription(const QList<int> &groupsTabOrder, int _order, bool onlyAllowed) {
    if (_order >= groupsTabOrder.size()) {
        UI_update_all_groups_Updating = false;
        return;
    }

    // calculate this group
    auto group = NekoGui::profileManager->GetGroup(groupsTabOrder[_order]);
    if (group == nullptr || should_skip_group(group)) {
        serialUpdateSubscription(groupsTabOrder, _order + 1, onlyAllowed);
        return;
    }

    int nextOrder = _order + 1;
    while (nextOrder < groupsTabOrder.size()) {
        auto nextGid = groupsTabOrder[nextOrder];
        auto nextGroup = NekoGui::profileManager->GetGroup(nextGid);
        if (!should_skip_group(nextGroup)) {
            break;
        }
        nextOrder += 1;
    }

    // Async update current group
    UI_update_all_groups_Updating = true;
    NekoGui_sub::groupUpdater->AsyncUpdate(group->url, group->id, [=] {
        serialUpdateSubscription(groupsTabOrder, nextOrder, onlyAllowed);
    });
}

void UI_update_all_groups(bool onlyAllowed) {
    if (UI_update_all_groups_Updating) {
        MW_show_log("The last subscription update has not exited.");
        return;
    }

    auto groupsTabOrder = NekoGui::profileManager->groupsTabOrder;
    serialUpdateSubscription(groupsTabOrder, 0, onlyAllowed);
}
