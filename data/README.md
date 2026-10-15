# Optionale GeoIP/ASN-Daten

Die große GeoIP-CSV wird nicht in Git versioniert. Für eigene Builds hier `geoip.csv` und den passenden SHA-256-Sidecar `geoip.csv.sha256` ablegen. Der Payload-Builder übernimmt sie neben die Service-EXE.

Format, Lizenzattribution und der im 4.1.3-Installer enthaltene Datenstand: [GEOIP_LICENSE_AND_DEPLOYMENT.md](../GEOIP_LICENSE_AND_DEPLOYMENT.md).

Ohne Daten bleibt die Karte explizit nicht geladen; andere Schutzbereiche werden dadurch nicht als ausgefallen ausgegeben.
