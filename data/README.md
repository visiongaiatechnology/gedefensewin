# Optionale GeoIP/ASN-Daten

Die große GeoIP-/ASN-CSV wird nicht in Git versioniert. Für eigene Builds hier `geoip.csv`
und den passenden SHA-256-Sidecar `geoip.csv.sha256` ablegen. Der Payload-Builder übernimmt
sie neben die Service-EXE.

## Attribution (erforderlich bei Weitergabe)

- **Geolocation:** DB-IP Lite, [DB-IP](https://db-ip.com), [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
- **ASN:** [iplocate/ip-address-databases](https://github.com/iplocate/ip-address-databases), [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/); © iplocate/ip-address-databases contributors. Konkretes Prüfbeispiel: `1.0.4.0/22` → ASN `38803`, Organisation `Gtelecom Pty Ltd`.
- **Kartengeometrie:** jsVectorMap `world-merc.js` 1.7.0 (MIT, © 2020 Mustafa Omar), vollständiger Text in [LICENSES/jsVectorMap-LICENSE](../LICENSES/jsVectorMap-LICENSE).
- Weitere Hinweise: [THIRD-PARTY-NOTICES.md](../THIRD-PARTY-NOTICES.md), [LICENSES/iplocate-ip-address-databases-CC-BY-SA-4.0.md](../LICENSES/iplocate-ip-address-databases-CC-BY-SA-4.0.md), [README.md — Lizenzen](../README.md#lizenzen-und-attribution).

Format, Lizenzattribution und der Datenstand: [GEOIP_LICENSE_AND_DEPLOYMENT.md](../GEOIP_LICENSE_AND_DEPLOYMENT.md).

Ohne Daten bleibt die Karte explizit nicht geladen; andere Schutzbereiche werden dadurch
nicht als ausgefallen ausgegeben.
