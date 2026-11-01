---
id: doc-3
title: 'RFC: TSL-Prüfung über die Detached-Signatur für Internet-Konsumenten'
type: other
created_date: '2026-11-01T16:11:00Z'
---

# RFC: TSL-Prüfung über die Detached-Signatur für Internet-Konsumenten

**Summary (English).** gemSpec_TSL already requires the TSL service to publish, next to
each TSL, a detached signature of the whole file by the TSL signer (`.sig`) and an OCSP
response for that signer (`.ocsp`), but only as a fallback for Konnektors
(A_21175 to A_21182). gemSpec_PKI 8.2.6 (A_30044) requires internet consumers to verify
the TSL's enveloped XML signature (TUC_PKI_012). This request asks gematik to let internet
consumers verify the TSL through `.sig` and `.ocsp` instead, and to publish both files on
the HTTPS download points as well. The check is cryptographically the same (same signer,
same anchor, same OCSP, the exact bytes that are hashed and compared), and it removes XML
canonicalization and XML signature processing from the trust path of every TI 2.0 client,
including browsers and mobile apps, which is the reason gematik gives for the file in its
own design note, agreed with the BSI. zero-lab has already removed XMLDSig and verifies
this way (TASK-166), as a recorded deviation. Written by zero-lab (TASK-167) on 2026-11-01;
the analysis behind it is doc-2, section 6.

## 1. Ausgangslage

Anwendungen der TI 2.0 prüfen nonQES-Zertifikate der TI aus dem Internet. Dafür gilt
gemSpec_PKI V2.28.0, Kapitel 8.2.6 „Besonderheiten bei der TSL-Prüfung im Internet“:

- A_30044 verlangt die Umsetzung von TUC_PKI_001 „Periodische Aktualisierung
  TI-Vertrauensraum“ mit den dort genannten Abweichungen (konfigurierte
  Internet-Downloadadressen, Hashvergleich vor dem Download, OCSP-Adresse des
  TSL-Signer-Zertifikats aus der AIA-Erweiterung).
- Schritt 4 von TUC_PKI_001 ist TUC_PKI_012 „XML-Signatur-Prüfung“: die in die TSL
  eingebettete XMLDSig/XAdES-Signatur wird mit Kanonisierung (Exclusive C14N) geprüft.
- Die Internet-Downloadpunkte in 8.2.6 (`download.tsl.ti-dienste.de`,
  `download-ref.tsl.ti-dienste.de`, `download-test.tsl.ti-dienste.de`) liefern die TSL
  (`.xml`) und ihren Hashwert (`.sha2`).

Parallel dazu verlangt gemSpec_TSL V1.25.0, Kapitel 6.3.1.3 „Automatisierbarer
TSL-Download aus dem Internet“, vom TSL-Dienst je Umgebung drei Dateien auf dem Host der
CRL (A_21176), nur per HTTP (A_21175):

| Datei | Inhalt | Anforderung |
|---|---|---|
| `.xml` | die TSL, identisch mit der in der TI bereitgestellten | A_21177, A_21178 |
| `.sig` | Detached-Signatur der gesamten TSL-Datei durch den TSL-Signer, der auch die XML-Signatur erzeugt hat; ASN.1 `SEQUENCE { AlgorithmIdentifier, BIT STRING Signatur, Certificate TSL-Signer }`, ECDSA nach BSI TR-03111 5.2.2 bzw. RSASSA-PSS | A_21179 |
| `.ocsp` | OCSP-Antwort für den aktuellen TSL-Signer, stündlich erneuert | A_21181 |

`.xml` und `.sig` werden konsistent zueinander und gleichzeitig bereitgestellt
(A_21177). Die URIs sind in A_21182 für PU, RU und TU festgelegt. Der Zweck ist dort
ausschließlich ein Fallback für Konnektoren bei Nichterreichbarkeit der TI (A_21175).

Die Begründung steht in gematiks Designnotiz
([examples-TelematikInterfaces, tslService/detachedSignature](https://github.com/gematik/examples-TelematikInterfaces/tree/master/tslService/detachedSignature)):
Die Detached-Signatur wurde nach Gesprächen mit dem BSI eingeführt, weil sie „einfacher
prüfbar“ ist, „i. S. v. sicherer prüfbar“: Die TSL muss nicht als XML dekodiert und die
relativ komplexe XMLDSig-Signatur, die potentiell von einem Angreifer modifiziert ist,
nicht ausgewertet werden. Das Format ist bewusst das von X.509-Zertifikaten und
OCSP-Antworten, ohne optionale Felder. Diese Begründung gilt für jeden Internet-Konsumenten,
nicht nur für den Konnektor.

Stand 2026-11-01 sind alle neun Dateien erreichbar (HTTP 200); die `.sig` der PU ist
712 Byte groß, Signaturverfahren ecdsa-with-SHA256, Signaturwert im X9.62-Format nach
TR-03111 5.2.2, Signer-Zertifikat brainpoolP256r1, ausgestellt von GEM.TSL-CA3.

## 2. Problem

Für einen Internet-Konsumenten ist TUC_PKI_012 der aufwendigste und angreifbarste Teil der
TSL-Prüfung:

- XMLDSig mit Exclusive C14N, Transforms und XAdES-Eigenschaften braucht einen
  vollständigen XML-Parser, einen Kanonisierer und eine Signaturbibliothek auf dem
  Vertrauenspfad. Diese Verarbeitung ist historisch die Quelle von Signature-Wrapping-
  und Kanonisierungsfehlern.
- In TI-2.0-Clients (Browser über WebAssembly, iOS, Android, .NET, eingebettete
  Bibliotheken) ist diese Codemenge ein erheblicher Teil der vertrauenswürdigen Basis,
  und sie existiert in den Plattformen nicht als geprüfte Standardbibliothek.
- Die kryptographisch gleichwertige Prüfung liegt bereits vor: der TSL-Dienst signiert mit
  demselben Schlüssel dieselben Bytes noch einmal, detached, in einer ASN.1-Struktur aus
  drei Feldern, und liefert den Sperrstatus des Signers gleich mit. Nur die Zweckbindung
  („Fallback für Konnektoren“) und die Downloadpunkte (HTTP auf dem CRL-Host) verhindern,
  dass ein Internet-Konsument sie normkonform nutzt.

## 3. Vorschlag

**gemSpec_PKI, Kapitel 8.2.6 / A_30044 (Ergänzung).** Produkttypen und Komponenten, die
nonQES-Zertifikate der TI über das Internet prüfen, DÜRFEN abweichend von TUC_PKI_012
die Signatur der TSL über die Detached-Signatur-Datei gemäß gemSpec_TSL A_21179 prüfen.
Dabei MUSS das System

1. die TSL-Datei und die zugehörige Detached-Signatur-Datei vom selben Downloadpunkt
   beziehen und bei fehlgeschlagener Prüfung beide einmal erneut ohne Validatoren laden
   (Konsistenz nach A_21177). Ist der Downloadpunkt nicht per HTTPS erreichbar, darf die
   TSL-Datei von dort nur übernommen werden, wenn sie zum per HTTPS bezogenen Hashwert
   passt; ein unauthentisches „not modified“ dieses Downloadpunkts darf das Alter des
   Vertrauensraums nicht erneuern;
2. das in der Signatur-Datei enthaltene TSL-Signer-Zertifikat gemäß TUC_PKI_011 gegen die
   TSL-Signer-CA des TI-Vertrauensankers prüfen;
3. die Signatur über die vollständigen Bytes der TSL-Datei mit dem öffentlichen
   Schlüssel dieses Zertifikats prüfen; das Signaturverfahren MUSS dem in der
   Signatur-Datei genannten und dem Schlüsseltyp des Signers entsprechen;
4. den Sperrstatus des TSL-Signer-Zertifikats über die OCSP-Antwort-Datei gemäß
   A_21181 oder über eine OCSP-Abfrage an die AIA-Adresse (wie in A_30044) prüfen; die
   OCSP-Antwort MUSS nach TUC_PKI_006 geprüft werden. Weil A_21181 sie nur stündlich
   erneuert, gilt für die Datei eine eigene Höchstfrist; zero-lab verwendet 2 Stunden. Eine
   ältere Antwort DARF NICHT als `good` gewertet werden, eine signierte Antwort `revoked`
   MUSS die TSL in jedem Alter sperren. Bei einer Prüfung zu einem anderen als dem
   aktuellen Zeitpunkt DARF die Datei nicht verwendet werden;
5. alle übrigen Schritte von TUC_PKI_001 unverändert umsetzen (ID und
   TSLSequenceNumber, NextUpdate und Zeitparameter nach Kapitel 8.2.4, Übernahme des
   Vertrauensraums), wobei die TSL-Datei dafür nur gelesen, nicht kanonisiert wird.

Die Schemavalidierung nach TUC_PKI_020 bleibt unberührt.

**gemSpec_TSL, Kapitel 6.3.1 (Ergänzung).** Der TSL-Dienst MUSS die Detached-Signatur-
Datei und die OCSP-Antwort-Datei auch an den Internet-Downloadpunkten nach A_17680-02
(HTTPS, `download*.tsl.ti-dienste.de`) bereitstellen, mit denselben Namensregeln wie für
den Hashwert (A_17682: Endung `.sig` bzw. `.ocsp` statt `.xml`). Die Zweckbindung in
A_21175 („Fallback-Verfahren für Konnektoren“) wird um die Prüfung der TSL durch
Internet-Konsumenten erweitert.

**Hashwert.** Der Vergleich des Hashwerts vor dem Download (A_30044) bleibt bestehen; die
Signatur über dieselben Bytes macht den Hashwert nicht überflüssig, sondern spart nur den
Download.

## 4. Prüfablauf eines Internet-Konsumenten

```text
.sha2 per HTTPS vergleichen ─► unverändert: nichts tun
        │ neu (oder nicht lesbar: .xml nur per HTTPS)
        ▼
.xml + .sig (+ .ocsp) laden; .xml muss zum Hashwert passen, sonst .xml per HTTPS
        ▼
.sig parsen: AlgorithmIdentifier, Signatur, Signer-Zertifikat  (A_21179; Längen begrenzt)
        ▼
TUC_PKI_011: Signer-Zertifikat gegen die TSL-Signer-CA des Ankers
        ▼
Signatur über die vollständigen .xml-Bytes prüfen
        ▼
TUC_PKI_006 für den Signer: .ocsp, höchstens 2 h alt (A_21181), oder OCSP an die AIA-Adresse
        ▼
TUC_PKI_001 Schritte 5 ff.: ID, TSLSequenceNumber, NextUpdate, Zeitparameter
        ▼
TSL lesen (XML, ohne Kanonisierung): CAs und Dienste übernehmen
```

Ersetzt wird genau Schritt 4 von TUC_PKI_001 (TUC_PKI_012). Alle Schritte, die den
Vertrauensanker, den Signer, die Sequenz und die Zeit betreffen, bleiben.

## 5. Sicherheitsbetrachtung

- **Gleicher Schlüssel, gleicher Anker, gleiche Sperrprüfung.** Die Detached-Signatur
  wird vom selben TSL-Signer erzeugt wie die XML-Signatur (A_21179); das Signer-Zertifikat
  wird nach TUC_PKI_011 gegen dieselbe TSL-Signer-CA geprüft; der Sperrstatus kommt vom
  selben OCSP-Responder. Es kommt kein neuer Vertrauensanker und kein neuer Schlüssel ins
  Spiel.
- **Signatur über die exakten Bytes.** Signiert sind die Bytes der Datei, die auch gehasht
  und verglichen werden. Es gibt keine Transformation zwischen Prüfung und Verwendung;
  die Angriffsklasse der XML-Signature-Wrapping- und Kanonisierungsfehler entfällt.
- **Transport unerheblich.** Die Dateien kommen heute per HTTP (A_21175). Für die
  Sicherheit ist das unerheblich, weil Integrität und Herkunft allein aus der Signatur
  folgen; HTTPS an den Downloadpunkten nach 8.2.6 ist dennoch vorzuziehen (Vorschlag in
  Abschnitt 3), weil es Metadaten schützt und Fehlerbilder vereinfacht.
- **Konsistenz.** Ein Angreifer oder ein Zwischenspeicher, der `.xml` und `.sig`
  verschiedener Stände liefert, erzeugt einen Prüffehler, keinen falschen Vertrauensraum;
  der Konsument lädt beide erneut (Abschnitt 3, Punkt 1).
- **Replay und Rückfall.** Unverändert durch ID, TSLSequenceNumber und NextUpdate
  (TUC_PKI_001, Kapitel 8.2.4); eine alte, korrekt signierte TSL wird wie heute
  abgewiesen.
- **Signer-Sperrung.** Die `.ocsp`-Datei wird stündlich erneuert (A_21181); ein
  Konsument, der eine engere Aktualität braucht, fragt die AIA-Adresse direkt ab, wie es
  A_30044 bereits vorsieht. Eine veraltete Antwort `good` ist kein Beleg, eine signierte
  Antwort `revoked` bleibt in jedem Alter gültig.
- **Parser-Angriffsfläche.** Die `.sig` ist eine ASN.1-Struktur aus drei Feldern mit
  einem X.509-Zertifikat; ihr Parser ist klein, längenbegrenzt und fuzzbar. Der
  XML-Parser liest die TSL danach nur noch als Datenquelle und steht nicht mehr auf dem
  Vertrauenspfad.
- **Was nicht geschützt wird.** Verfügbarkeit: ein Angreifer kann wie bisher den
  Download verhindern; das fängt die Aktualitätsregel (NextUpdate, Kapitel 8.2.4) auf.
  Heute kommt hinzu, dass `.sig` nur per HTTP auf dem CRL-Host liegt: Ein Netz, das diesen
  Host sperrt, kann keine neue TSL übernehmen, obwohl sie per HTTPS erreichbar ist. Darum
  ist die Bereitstellung an den HTTPS-Downloadpunkten (Abschnitt 3) mehr als eine
  Bequemlichkeit.

## 6. Übergang

Ein Konsument, der die Detached-Signatur prüft, ist mit heutigen TSL-Dateien sofort
lauffähig, da die Dateien in allen drei Umgebungen bereitstehen. zero-lab prüft bereits so
und hat die XMLDSig-Prüfung entfernt (TASK-166); die Abweichung von TUC_PKI_012 ist in
`spec/tsl-detached` dokumentiert. Testvektoren aus PU, RU und TU mit Aufnahmezeitpunkt und
abgeleitete Negativfälle stehen dem PKI-Team zur Verfügung.

## 7. Fragen an das PKI-Team

1. Ist die Detached-Signatur über den Konnektor-Fallback hinaus als Prüfverfahren
   vorgesehen, oder spricht etwas gegen ihre Nutzung durch Internet-Konsumenten?
2. Können `.sig` und `.ocsp` an den HTTPS-Downloadpunkten nach 8.2.6 bereitgestellt
   werden, damit Konsumenten nicht den CRL-Host nach A_21182 ansprechen müssen?
3. Darf ein Produkt, das die Detached-Signatur prüft, Konformität zu TUC_PKI_001
   beanspruchen, oder braucht es eine eigene Anforderung (etwa A_30044-xx)?
4. Ist die ASN.1-Struktur nach A_21179 stabil, oder sind Änderungen (weitere Felder,
   andere Verfahren) geplant?
5. Welche Aktualität der `.ocsp`-Datei kann ein Konsument zusichern lassen, und soll die
   AIA-Abfrage nach A_30044 die Datei ergänzen oder ersetzen?
6. Enthalten die in Vorbereitung befindlichen Anforderungen für Internet- und
   TI-2.0-Konsumenten eine Aussage zur Detached-Signatur, und falls nicht, kann dieser
   Vorschlag dort aufgenommen werden?

## 8. Referenzen

- gemSpec_PKI V2.28.0: Kapitel 8.2.6 (A_30044), TUC_PKI_001 (GS-A_4642), TUC_PKI_006,
  TUC_PKI_011, TUC_PKI_012, TUC_PKI_020, Kapitel 8.2.4.
- gemSpec_TSL V1.25.0: Kapitel 6.3.1 (A_17680-02, A_17681, A_17682), Kapitel 6.3.1.3
  (A_21175 bis A_21182).
- BSI TR-03111 V2.10, Kapitel 5.2.2 (X9.62-Format, `ECDSA-Sig-Value`).
- gematik, examples-TelematikInterfaces, `tslService/detachedSignature` (Designnotiz).
- zero-lab: doc-2 Abschnitt 6, TASK-166, TASK-167, `spec/tsl-detached`.
