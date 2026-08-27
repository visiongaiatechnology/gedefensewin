# GitHub-Veröffentlichung

Der Ordner ist als quelloffenes Repository vorbereitet. Er enthält weder Windows-
Installationsmedien noch erzeugte Binärdateien, private Schlüssel, Laufzeittokens oder
lokale Evidenzdaten.

## Erstveröffentlichung

```powershell
git add .
git commit -S -m 'Initial open-source release of GeDefense Windows 2.3.2'
git remote add origin https://github.com/VisionGaiaTechnology/GeDefense-Windows.git
git push -u origin main
```

Vor dem Push muss auf GitHub ein leeres Repository mit dem Namen
`GeDefense-Windows` unter der Organisation `VisionGaiaTechnology` existieren. GitHub
soll dabei keine eigene README, Lizenz oder `.gitignore` erzeugen, weil diese Dateien
bereits Bestandteil dieses Repositorys sind.

## Empfohlene Repository-Einstellungen

- Branch Protection für `main`
- mindestens ein Review für Pull Requests
- erfolgreiche `security-ci`-Prüfung als Merge-Voraussetzung
- signierte Commits und lineare Historie
- private Schwachstellenmeldungen aktivieren
- Dependabot Security Updates aktivieren
- Secret Scanning und Push Protection aktivieren
- Releases ausschließlich aus signierten Tags erzeugen

## Release-Grenze

Ein GitHub-Release darf Community-Builds enthalten, muss sie aber eindeutig als solche
kennzeichnen. Der Name, die Logos und die Bezeichnung „offizielles VGT-Release“ dürfen
nur gemäß `TRADEMARKS.md` und der Branding-Lizenz verwendet werden. Microsoft-
Komponenten oder Windows-Abbilder werden nicht in diesem Repository verteilt.
