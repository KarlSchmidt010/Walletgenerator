# Walletgenerator

Windows-Programm zum Erzeugen verschlüsselter Electrum-Wallet-Dateien mit regulären Bitcoin-`bc1`-Adressen.

## Windows-Download

[Walletgenerator.exe über Google Drive herunterladen](https://drive.google.com/file/d/12JmmMNM_ns4LL2FxQ26PwXgKrMPIDJXo/view?usp=drivesdk)

SHA-256: `05a78f8bf4ee4ae5b67bea829e53dde193832bcd0849001d05a0abdad13a737c`

## Verwendung

1. `Walletgenerator.exe` über den obigen Download-Link herunterladen.
2. Einen neuen, leeren Zielordner auswählen.
3. CPU-Zielauslastung und maximale Prozesszahl passend zum Rechner einstellen.
4. Die gewünschte Anzahl Wallets festlegen und die Erzeugung starten.

Alle Wallets werden mit der festen PIN `120577` verschlüsselt. Ein abgebrochener Lauf kann im gleichen Zielordner fortgesetzt werden.

## Wichtige Eigenschaften

- Electrum-Walletformat auf Basis von Electrum 4.6.2
- reguläre Bitcoin-SegWit-Adressen mit `bc1`
- bis zu 1.000.000 Wallet-Dateien
- feste PIN `120577` für alle Wallets
- automatische Erkennung der verfügbaren logischen Prozessoren
- einstellbare CPU-Zielauslastung von 1 bis 100 Prozent
- frei begrenzbare Prozesszahl innerhalb der erkannten Rechnerkapazität
- Live-Anzeige der tatsächlich verwendeten Prozesszahl
- reduzierter anfänglicher Adressvorrat, den Electrum beim Öffnen automatisch erweitert
- Pause und Fortsetzen innerhalb eines laufenden Generierungsvorgangs
- Wiederaufnahme vorhandener Datensätze nach einem Abbruch oder Neustart

Die CPU-Zielauslastung wird näherungsweise über die Zahl der Worker-Prozesse begrenzt; sie ist kein exaktes Betriebssystem-Limit. Sechsstellige PINs können durch vollständiges Ausprobieren ermittelt werden. Das Programm eignet sich daher für Testdatensätze. Es sollte kein echtes Bitcoin-Guthaben mit diesen Wallets verwaltet werden.

## Quellcode und Abhängigkeiten

`walletgenerator.py` enthält die Programmoberfläche und Erzeugungslogik. Die veröffentlichte Windows-Datei bündelt Electrum 4.6.2, Python und PyQt6. Hinweise zu eingebundenen Komponenten stehen in `THIRD_PARTY_NOTICES.md`.

