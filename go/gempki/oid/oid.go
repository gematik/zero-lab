// Package oid holds the object identifiers gemSpec_OID defines for the TI,
// as Go values, plus the spec's own names for them.
//
// Values come from https://gemspec.gematik.de/docs/gemSpec/gemSpec_OID/latest/
// (v3.24.0 at the time of writing). The spec table is recorded in each
// group's comment; the arc base is 1.2.276.0.76.4, and any spec-listed OID
// not here simply has not been needed yet. The spec's snake_case
// (`oid_arzt`) is rendered CamelCase under a family prefix:
//
//   - Prof*      — Tab_PKI_402 professions (HBA persons)
//   - Inst*      — Tab_PKI_403 institutions (SMC-B)
//   - Policy*    — Tab_PKI_404 certificate policies
//   - CertType*  — Tab_PKI_405 certificate types
//   - TechRole*  — Tab_PKI_406 technical roles (Fachdienste)
//   - Instance*  — Tab_PKI_401 organisational instances
//
// [Lookup] and [Format] give the spec's reference name and description back.
package oid

import "encoding/asn1"

// --- Structural ------------------------------------------------------------

// AdmissionExtension is the ISIS-MTT Admission extension carrying gematik
// profession info on SMC-B and HBA cards.
var AdmissionExtension = asn1.ObjectIdentifier{1, 3, 36, 8, 3, 3}

// --- Tab_PKI_401 — Instance OIDs ------------------------------------------
//
// Identify the organization that runs an actor in the TI.

var (
	InstanceKBV     = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 3, 1, 1}  // Kassenärztliche Bundesvereinigung
	InstanceBAEK    = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 3, 1, 95} // Bundesärztekammer
	InstanceKZBV    = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 3, 1, 99} // Kassenzahnärztliche Bundesvereinigung
	InstanceBZAEK   = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 3, 1, 96} // Bundeszahnärztekammer
	InstanceDKG     = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 3, 1, 49} // Deutsche Krankenhausgesellschaft
	InstanceBPtK    = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 3, 1, 90} // Bundespsychotherapeutenkammer
	InstanceGematik = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 3, 1, 91} // gematik GmbH
)

// --- Tab_PKI_402 — Profession OIDs (HBA persons) ---------------------------
//
// Appear in the Admission extension of HBA / health-professional cards.

var (
	ProfArzt                      = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 30}  // Ärztin/Arzt
	ProfZahnarzt                  = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 31}  // Zahnärztin/Zahnarzt
	ProfApotheker                 = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 32}  // Apotheker/-in
	ProfApothekerassistent        = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 33}  // Apothekerassistent/-in
	ProfPharmazieingenieur        = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 34}  // Pharmazieingenieur/-in
	ProfPharmTechnAssistent       = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 35}  // pharmazeutisch-technische/-r Assistent/-in
	ProfPharmKaufmAngestellter    = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 36}  // pharmazeutisch-kaufmännische/-r Angestellte
	ProfApothekenhelfer           = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 37}  // Apothekenhelfer/-in
	ProfApothekenassistent        = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 38}  // Apothekenassistent/-in
	ProfPharmAssistent            = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 39}  // Pharmazeutische/-r Assistent/-in
	ProfApothekenfacharbeiter     = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 40}  // Apothekenfacharbeiter/-in
	ProfPharmaziepraktikant       = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 41}  // Pharmaziepraktikant/-in
	ProfFamulant                  = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 42}  // Stud.pharm. / Famulant/-in
	ProfPTAPraktikant             = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 43}  // PTA-Praktikant/-in
	ProfPKAAuszubildender         = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 44}  // PKA Auszubildende/-r
	ProfPsychotherapeut           = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 45}  // Psychotherapeut/-in
	ProfPsPsychotherapeut         = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 46}  // Psychologische/-r Psychotherapeut/-in
	ProfKuJPsychotherapeut        = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 47}  // Kinder- und Jugendlichenpsychotherapeut/-in
	ProfRettungsassistent         = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 48}  // Rettungsassistent/-in
	ProfVersicherter              = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 49}  // Versicherte/-r
	ProfNotfallsanitaeter         = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 178} // Notfallsanitäter/-in
	ProfPflegerHPC                = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 232} // Gesundheits- und Krankenpfleger/-in
	ProfAltenpflegerHPC           = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 233} // Altenpfleger/-in
	ProfPflegefachkraftHPC        = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 234} // Pflegefachfrauen und Pflegefachmänner
	ProfHebammeHPC                = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 235} // Hebamme
	ProfPhysiotherapeutHPC        = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 236} // Physiotherapeut/-in
	ProfAugenoptikerHPC           = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 237} // Augenoptiker/-in
	ProfHoerakustikerHPC          = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 238} // Hörakustiker/-in
	ProfOrthopaedieschuhmacherHPC = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 239} // Orthopädieschuhmacher/-in
	ProfOrthopaedietechnikerHPC   = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 240} // Orthopädietechniker/-in
	ProfZahntechnikerHPC          = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 241} // Zahntechniker/-in
	ProfErgotherapeutHPC          = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 274} // Ergotherapeut/-in
	ProfLogopaedeHPC              = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 275} // Logopäde/Logopädin
	ProfPodologeHPC               = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 276} // Podologe/Podologin
	ProfErnaehrungstherapeutHPC   = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 277} // Leistungserbringer/-in Ernährungstherapie
	ProfOrthopaedHPC              = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 305} // Orthopädieschuhmacher/-in + Orthopädietechniker/-in
	ProfOptoAudioHPC              = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 308} // Augenoptiker/-in + Hörakustiker/-in
	ProfHimiHPC                   = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 312} // Hilfsmittelerbringer/-in
	ProfFriseurHPC                = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 313} // Frisör/-in
	ProfMasseurMBMHPC             = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 315} // Masseur/-in + medizinische/-r Bademeister/-in
	ProfSoziotherapeut            = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 316} // Leistungserbringer/-in Soziotherapie
	ProfSSSSTherapeut             = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 318} // Stimm-, Sprech-, Sprach- und Schluck-Therapie
	ProfDiaetassistent            = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 319} // Diätassistent/-in
)

// --- Tab_PKI_403 — Institution OIDs (SMC-B) -------------------------------
//
// Appear in the Admission extension of institutional (SMC-B) cards.

var (
	InstArztpraxis                 = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 50}  // Betriebsstätte Arzt
	InstZahnarztpraxis             = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 51}  // Zahnarztpraxis
	InstPraxisPsychotherapeut      = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 52}  // Betriebsstätte Psychotherapeut
	InstKrankenhaus                = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 53}  // Krankenhaus
	InstOeffentlicheApo            = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 54}  // Öffentliche Apotheke
	InstKrankenhausapotheke        = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 55}  // Krankenhausapotheke
	InstBundeswehrapotheke         = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 56}  // Bundeswehrapotheke
	InstMobileEinrichtungRettung   = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 57}  // Mobile Einrichtung Rettungsdienst
	InstGematik                    = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 58}  // Betriebsstätte gematik
	InstKostentraeger              = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 59}  // Betriebsstätte Kostenträger
	InstLeoZahnaerzte              = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 187} // LEO Vertragszahnärzte
	InstAdvKtr                     = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 190} // AdV-Umgebung Kostenträger
	InstLeoKassenaerztlicheVerein  = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 210} // LEO Kassenärztliche Vereinigung
	InstGKVSpitzenverband          = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 223} // GKV-Spitzenverband
	InstLeoApothekerverband        = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 224} // Apothekerverband
	InstLeoDAV                     = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 225} // Deutscher Apothekerverband
	InstLeoKrankenhausverband      = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 226} // Mitgliedsverband der Krankenhäuser
	InstLeoDKTIG                   = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 227} // DKTIG
	InstLeoDKG                     = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 228} // Deutsche Krankenhausgesellschaft
	InstLeoBAEK                    = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 229} // Bundesärztekammer
	InstLeoAerztekammer            = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 230} // Ärztekammer
	InstLeoZahnaerztekammer        = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 231} // Zahnärztekammer
	InstLeoKBV                     = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 242} // Kassenärztliche Bundesvereinigung
	InstLeoBZAEK                   = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 243} // Bundeszahnärztekammer
	InstLeoKZBV                    = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 244} // Kassenzahnärztliche Bundesvereinigung
	InstPflege                     = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 245} // Gesundheits-, Kranken- und Altenpflege
	InstGeburtshilfe               = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 246} // Geburtshilfe
	InstPraxisPhysiotherapeut      = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 247} // Physiotherapie
	InstAugenoptiker               = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 248} // Augenoptiker
	InstHoerakustiker              = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 249} // Hörakustiker
	InstOrthopaedieschuhmacher     = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 250} // Orthopädieschuhmacher
	InstOrthopaedietechniker       = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 251} // Orthopädietechniker
	InstZahntechniker              = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 252} // Zahntechniker
	InstRettungsleitstelle         = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 253} // Rettungsleitstelle
	InstSanitaetsdienstBW          = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 254} // Sanitätsdienst Bundeswehr
	InstOEGD                       = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 255} // Öffentlicher Gesundheitsdienst
	InstArbeitsmedizin             = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 256} // Arbeitsmedizin
	InstVorsorgeReha               = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 257} // Vorsorge- und Rehabilitation
	InstPflegeberatung             = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 262} // Pflegeberatung § 7a SGB XI
	InstLeoPsychotherapeuten       = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 263} // Psychotherapeutenkammer
	InstLeoBPtK                    = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 264} // Bundespsychotherapeutenkammer
	InstLeoLAK                     = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 265} // Landesapothekerkammer
	InstLeoBAK                     = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 266} // Bundesapothekerkammer
	InstLeoEGBR                    = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 267} // elektronisches Gesundheitsberuferegister
	InstLeoHandwerkskammer         = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 268} // Handwerkskammer
	InstGesundheitsdatenregister   = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 269} // Register für Gesundheitsdaten
	InstAbrechnungsdienstleister   = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 270} // Abrechnungsdienstleister
	InstPKVVerband                 = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 271} // PKV-Verband
	InstPraxisErgotherapeut        = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 278} // Ergotherapiepraxis
	InstPraxisLogopaede            = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 279} // Logopädische Praxis
	InstPraxisPodologe             = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 280} // Podologiepraxis
	InstPraxisErnaehrungstherapeut = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 281} // Ernährungstherapeutische Praxis
	InstWeitereKostentraeger       = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 284} // Weitere Kostenträger
	InstOrgGesundheitsversorgung   = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 285} // Weitere Organisationen
	InstKIMAnbieter                = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 286} // KIM-Hersteller / -Anbieter
	InstDiGA                       = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 282} // DiGA-Hersteller / -Anbieter
	InstTIMAnbieter                = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 295} // TIM-Hersteller / -Anbieter
	InstNCPeH                      = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 292} // NCPeH Fachdienst
	InstOmbudsstelle               = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 303} // Ombudsstelle eines Kostenträgers
	InstOptoAudio                  = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 304} // Augenoptiker und Hörakustiker
	InstOrthopaedHW                = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 306} // Orthopädieschuhmacher und Orthopädietechniker
	InstHimi                       = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 311} // Hilfsmittelerbringer
	InstFriseur                    = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 314} // Frisör
	InstSoziother                  = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 317} // Soziotherapie
)

// --- Tab_PKI_404 — Certificate Policy OIDs --------------------------------

var (
	// PolicyHbaCP — CP-HPC: QES/SIG/AUT/ENC policy for HBA cards.
	PolicyHbaCP = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 145}

	// PolicyGemOrCP — policy asserted by every cert issued after the
	// online rollout (eGK, SMC, components).
	PolicyGemOrCP = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 163}

	// PolicyGemTSLSigner — TSL signer-certificate policy.
	PolicyGemTSLSigner = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 176}
)

// --- Tab_PKI_405 — Certificate Type OIDs ----------------------------------
//
// Encoded in the Admission extension (or in CertificatePolicies for some
// older profiles) to declare which TI cert profile a certificate is.

var (
	// eGK (Versichertenkarte) certificate types.
	CertTypeEgkQES  = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 66} // C.CH.QES
	CertTypeEgkSIG  = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 67} // C.CH.SIG
	CertTypeEgkENC  = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 68} // C.CH.ENC
	CertTypeEgkENCV = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 69} // C.CH.ENCV
	CertTypeEgkAUT  = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 70} // C.CH.AUT
	CertTypeEgkAUTN = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 71} // C.CH.AUTN

	// HBA (Heilberufsausweis) certificate types.
	CertTypeHbaQES = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 72} // C.HP.QES
	CertTypeHbaENC = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 74} // C.HP.ENC
	CertTypeHbaAUT = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 75} // C.HP.AUT

	// SMC-B (institution) certificate types.
	CertTypeSmcBENC  = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 76} // C.HCI.ENC
	CertTypeSmcBAUT  = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 77} // C.HCI.AUT
	CertTypeSmcBOSIG = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 78} // C.HCI.OSIG

	// Fachdienst (service-provider) certificate types.
	CertTypeFdTLSS = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 169} // C.FD.TLS-S
	CertTypeFdTLSC = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 168} // C.FD.TLS-C
	CertTypeFdSIG  = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 203} // C.FD.SIG
	CertTypeFdENC  = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 202} // C.FD.ENC
	CertTypeFdAUT  = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 155} // C.FD.AUT
	CertTypeFdOSIG = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 283} // C.FD.OSIG

	// Zentraler Dienst (central service) certificate types.
	CertTypeZdTLSS = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 157} // C.ZD.TLS-S
	CertTypeZdSIG  = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 287} // C.ZD.SIG

	// High-speed Konnektor + gematik VER.
	CertTypeHskSIG = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 300} // C.HSK.SIG
	CertTypeHskENC = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 301} // C.HSK.ENC
	CertTypeGemVER = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 321} // C.GEM.VER
)

// --- Tab_PKI_406 — Technical Role OIDs (Fachdienste) ---------------------
//
// Identify the role a Fachdienst certificate is asserting.

var (
	TechRoleVSDD          = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 97}  // Versichertenstammdatendienst
	TechRoleCMS           = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 100} // Card Management System
	TechRoleUFS           = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 101} // Update Flag Service
	TechRoleAK            = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 103} // Anwendungskonnektor
	TechRoleNK            = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 104} // Netzkonnektor
	TechRoleKT            = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 105} // Kartenterminal
	TechRoleSAK           = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 119} // Signaturanwendungskomponente
	TechRoleIntVSDM       = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 159} // Intermediär VSDM
	TechRoleKonfigdienst  = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 160} // Konfigurationsdienst
	TechRoleVPNZTI        = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 161} // VPN-Zugangsdienst-TI
	TechRoleCMFD          = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 174} // Clientmodul
	TechRoleVZDTI         = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 171} // Verzeichnisdienst-TI
	TechRoleKOMLE         = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 172} // KOM-LE Fachdienst
	TechRoleStamp         = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 184} // Betriebsdatenerfassung
	TechRoleTSLTI         = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 189} // TSL-Dienst-TI
	TechRoleWADG          = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 198} // weitere elektronische Anwendungen
	TechRoleEpaAuthn      = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 204} // ePA Authentisierung
	TechRoleEpaAuthz      = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 205} // ePA Autorisierung
	TechRoleEpaDvw        = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 206} // ePA Dokumentenverwaltung
	TechRoleEpaMgmt       = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 207} // ePA Management
	TechRoleEpaRecovery   = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 208} // ePA Berechtigungserhalt
	TechRoleEpaVAU        = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 209} // ePA Vertrauenswürdige Ausführungsumgebung
	TechRoleVzTSP         = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 215} // Zertifikatsverzeichnis TSP X.509
	TechRoleWHK1HSM       = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 216} // HSM Wiederherstellungskomponente 1
	TechRoleWHK2HSM       = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 217} // HSM Wiederherstellungskomponente 2
	TechRoleWHK           = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 218} // Wiederherstellungskomponente
	TechRoleSGD           = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 221} // Schlüsselgenerierungsdienst
	TechRoleERPVAU        = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 258} // E-Rezept VAU
	TechRoleERezept       = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 259} // E-Rezept-Fachdienst
	TechRoleIDPD          = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 260} // IDP-Dienst
	TechRoleEpaLogging    = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 261} // ePA-Aktensystem-Logging
	TechRoleBestandsnetze = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 288} // Bestandsnetze.xml Signatur
	TechRoleEpaVST        = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 289} // ePA Vertrauensstelle
	TechRoleEpaFDZ        = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 290} // ePA Forschungsdatenzentrum
	TechRoleTIM           = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 294} // TI-Messenger
	TechRoleHSK           = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 302} // Highspeed-Konnektor
	TechRoleIDPDSek       = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 307} // sektoraler IDP
	TechRoleTIGWZugm      = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 309} // TI-Gateway Zugangsmodul
	TechRoleZertSMB       = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 310} // Technische Zertifikatsausgabestelle SMC-B
	TechRolePoPP          = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 293} // Proof of Patient Presence
	TechRolePoPPToken     = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 320} // Token-Signatur PoPP
	TechRolePKIVer        = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 322} // PKI Change Verifikation
	TechRoleDipagVAU      = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 323} // Digitale Patientenrechnung VAU
	TechRoleZETAGuard     = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 328} // ZETA Guard
	TechRoleZETAPolicies  = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 324} // ZETA PIP/PAP Policies
	TechRoleZETAOCI       = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 326} // OCI container image für ZETA
	TechRoleZETAPolAuthor = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 329} // ZETA Policy Autor
	TechRoleZETAPolApprov = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 330} // ZETA Policy Freigeber
	TechRoleZETAPolOper   = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 331} // ZETA Policy Leitstand
	TechRoleZETAPrvApprov = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 332} // ZETA Provisioning Container Image Freigeber
	TechRoleTSPEgk        = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 325} // Technische Zertifikatsausgabestelle eGK
	TechRoleCDCP15G       = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 327} // CDC Pseudonymisierung
)

// Professions is the whole of Tab_PKI_402: every profession OID an HBA
// admission extension may carry. Membership here is what makes a
// certificate "an HBA" to the type detector.
var Professions = []asn1.ObjectIdentifier{
	ProfArzt, ProfZahnarzt, ProfApotheker, ProfApothekerassistent,
	ProfPharmazieingenieur, ProfPharmTechnAssistent, ProfPharmKaufmAngestellter, ProfApothekenhelfer,
	ProfApothekenassistent, ProfPharmAssistent, ProfApothekenfacharbeiter, ProfPharmaziepraktikant,
	ProfFamulant, ProfPTAPraktikant, ProfPKAAuszubildender, ProfPsychotherapeut,
	ProfPsPsychotherapeut, ProfKuJPsychotherapeut, ProfRettungsassistent,
	ProfNotfallsanitaeter, ProfPflegerHPC, ProfAltenpflegerHPC, ProfPflegefachkraftHPC,
	ProfHebammeHPC, ProfPhysiotherapeutHPC, ProfAugenoptikerHPC, ProfHoerakustikerHPC,
	ProfOrthopaedieschuhmacherHPC, ProfOrthopaedietechnikerHPC, ProfZahntechnikerHPC, ProfErgotherapeutHPC,
	ProfLogopaedeHPC, ProfPodologeHPC, ProfErnaehrungstherapeutHPC, ProfOrthopaedHPC,
	ProfOptoAudioHPC, ProfHimiHPC, ProfFriseurHPC, ProfMasseurMBMHPC,
	ProfSoziotherapeut, ProfSSSSTherapeut, ProfDiaetassistent,
}

// Institutions is the whole of Tab_PKI_403: every institution OID an SMC-B
// admission extension may carry.
var Institutions = []asn1.ObjectIdentifier{
	InstArztpraxis, InstZahnarztpraxis, InstPraxisPsychotherapeut, InstKrankenhaus,
	InstOeffentlicheApo, InstKrankenhausapotheke, InstBundeswehrapotheke, InstMobileEinrichtungRettung,
	InstGematik, InstKostentraeger, InstLeoZahnaerzte, InstAdvKtr,
	InstLeoKassenaerztlicheVerein, InstGKVSpitzenverband, InstLeoApothekerverband, InstLeoDAV,
	InstLeoKrankenhausverband, InstLeoDKTIG, InstLeoDKG, InstLeoBAEK,
	InstLeoAerztekammer, InstLeoZahnaerztekammer, InstLeoKBV, InstLeoBZAEK,
	InstLeoKZBV, InstPflege, InstGeburtshilfe, InstPraxisPhysiotherapeut,
	InstAugenoptiker, InstHoerakustiker, InstOrthopaedieschuhmacher, InstOrthopaedietechniker,
	InstZahntechniker, InstRettungsleitstelle, InstSanitaetsdienstBW, InstOEGD,
	InstArbeitsmedizin, InstVorsorgeReha, InstPflegeberatung, InstLeoPsychotherapeuten,
	InstLeoBPtK, InstLeoLAK, InstLeoBAK, InstLeoEGBR,
	InstLeoHandwerkskammer, InstGesundheitsdatenregister, InstAbrechnungsdienstleister, InstPKVVerband,
	InstPraxisErgotherapeut, InstPraxisLogopaede, InstPraxisPodologe, InstPraxisErnaehrungstherapeut,
	InstWeitereKostentraeger, InstOrgGesundheitsversorgung, InstKIMAnbieter, InstDiGA,
	InstTIMAnbieter, InstNCPeH, InstOmbudsstelle, InstOptoAudio,
	InstOrthopaedHW, InstHimi, InstFriseur, InstSoziother,
}
