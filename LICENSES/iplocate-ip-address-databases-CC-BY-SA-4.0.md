# iplocate / ip-address-databases — data attribution (CC BY-SA 4.0)

The optional GeoIP/ASN CSV delivered with the GeDefense installer contains IP-to-ASN
data derived from the public **iplocate/ip-address-databases** project.

- Source: https://github.com/iplocate/ip-address-databases
- License: Creative Commons Attribution-ShareAlike 4.0 International (CC BY-SA 4.0)
  https://creativecommons.org/licenses/by-sa/4.0/
- Attribution: © iplocate/ip-address-databases contributors, CC BY-SA 4.0.
- Concrete verification sample: the network `1.0.4.0/22` is listed as ASN `38803`,
  organisation `Gtelecom Pty Ltd`, matching the delivered CSV.
- Redistribution of the derived `data/geoip.csv` must keep this attribution and the
  CC BY-SA 4.0 share-alike terms. The file is delivered as a local data resource,
  not embedded in the service binary.

Geolocation country/coordinate data in the combined CSV additionally credits
**DB-IP Lite** (https://db-ip.com, CC BY 4.0,
https://creativecommons.org/licenses/by/4.0/).

The data is descriptive only and grants no enforcement authority. Country/ASN indicate
an approximate network registration origin, not a person's physical location. See also
`GEOIP_LICENSE_AND_DEPLOYMENT.md` and `THIRD-PARTY-NOTICES.md`.
