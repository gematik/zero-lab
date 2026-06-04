// Package gempki — OID constants from gemSpec_OID.
//
// All identifier values here are sourced from
// https://gemspec.gematik.de/docs/gemSpec/gemSpec_OID/latest/ (currently
// v3.24.0). The spec table number is recorded in the surrounding group
// comment; if a constant is missing it just hasn't been needed yet — the
// arc base is 1.2.276.0.76.4 and every spec-listed OID is safe to add as a
// constant alongside its siblings.
//
// Naming: the spec uses snake_case (`oid_arzt`); we render that as
// CamelCase under a prefix that flags the OID family:
//
//   - OIDProf*      — Tab_PKI_402 professions (HBA persons)
//   - OIDInst*      — Tab_PKI_403 institutions (SMC-B)
//   - OIDPolicy*    — Tab_PKI_404 certificate policies
//   - OIDCertType*  — Tab_PKI_405 certificate types
//   - OIDTechRole*  — Tab_PKI_406 technical roles (Fachdienste)
//   - OIDInstance*  — Tab_PKI_401 organizational instances
//
// Two OIDs (OIDInstArztpraxis, OIDInstOeffentlicheApo) keep the names they
// had before this expansion so the existing admission_statement tests stay
// stable; the rest are new.
package gempki

import "encoding/asn1"

// --- Structural ------------------------------------------------------------

// OIDAdmissionExtension is the ISIS-MTT Admission extension carrying gematik
// profession info on SMC-B and HBA cards.
var OIDAdmissionExtension = asn1.ObjectIdentifier{1, 3, 36, 8, 3, 3}

// ECDSA signature-algorithm OIDs (RFC 5758 §3.2). RSA-with-SHA-* OIDs are
// intentionally absent — the TI-PKI is ECC-only per gemSpec_Krypt.
var (
	OIDECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	OIDECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
)

// --- Tab_PKI_401 — Instance OIDs ------------------------------------------
//
// Identify the organization that runs an actor in the TI.

var (
	OIDInstanceKBV     = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 3, 1, 1}  // Kassenärztliche Bundesvereinigung
	OIDInstanceBAEK    = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 3, 1, 95} // Bundesärztekammer
	OIDInstanceKZBV    = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 3, 1, 99} // Kassenzahnärztliche Bundesvereinigung
	OIDInstanceBZAEK   = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 3, 1, 96} // Bundeszahnärztekammer
	OIDInstanceDKG     = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 3, 1, 49} // Deutsche Krankenhausgesellschaft
	OIDInstanceBPtK    = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 3, 1, 90} // Bundespsychotherapeutenkammer
	OIDInstanceGematik = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 3, 1, 91} // gematik GmbH
)

// --- Tab_PKI_402 — Profession OIDs (HBA persons) ---------------------------
//
// Appear in the Admission extension of HBA / health-professional cards.

var (
	OIDProfArzt                      = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 30}  // Ärztin/Arzt
	OIDProfZahnarzt                  = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 31}  // Zahnärztin/Zahnarzt
	OIDProfApotheker                 = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 32}  // Apotheker/-in
	OIDProfApothekerassistent        = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 33}  // Apothekerassistent/-in
	OIDProfPharmazieingenieur        = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 34}  // Pharmazieingenieur/-in
	OIDProfPharmTechnAssistent       = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 35}  // pharmazeutisch-technische/-r Assistent/-in
	OIDProfPharmKaufmAngestellter    = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 36}  // pharmazeutisch-kaufmännische/-r Angestellte
	OIDProfApothekenhelfer           = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 37}  // Apothekenhelfer/-in
	OIDProfApothekenassistent        = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 38}  // Apothekenassistent/-in
	OIDProfPharmAssistent            = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 39}  // Pharmazeutische/-r Assistent/-in
	OIDProfApothekenfacharbeiter     = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 40}  // Apothekenfacharbeiter/-in
	OIDProfPharmaziepraktikant       = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 41}  // Pharmaziepraktikant/-in
	OIDProfFamulant                  = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 42}  // Stud.pharm. / Famulant/-in
	OIDProfPTAPraktikant             = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 43}  // PTA-Praktikant/-in
	OIDProfPKAAuszubildender         = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 44}  // PKA Auszubildende/-r
	OIDProfPsychotherapeut           = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 45}  // Psychotherapeut/-in
	OIDProfPsPsychotherapeut         = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 46}  // Psychologische/-r Psychotherapeut/-in
	OIDProfKuJPsychotherapeut        = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 47}  // Kinder- und Jugendlichenpsychotherapeut/-in
	OIDProfRettungsassistent         = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 48}  // Rettungsassistent/-in
	OIDProfVersicherter              = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 49}  // Versicherte/-r
	OIDProfNotfallsanitaeter         = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 178} // Notfallsanitäter/-in
	OIDProfPflegerHPC                = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 232} // Gesundheits- und Krankenpfleger/-in
	OIDProfAltenpflegerHPC           = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 233} // Altenpfleger/-in
	OIDProfPflegefachkraftHPC        = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 234} // Pflegefachfrauen und Pflegefachmänner
	OIDProfHebammeHPC                = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 235} // Hebamme
	OIDProfPhysiotherapeutHPC        = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 236} // Physiotherapeut/-in
	OIDProfAugenoptikerHPC           = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 237} // Augenoptiker/-in
	OIDProfHoerakustikerHPC          = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 238} // Hörakustiker/-in
	OIDProfOrthopaedieschuhmacherHPC = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 239} // Orthopädieschuhmacher/-in
	OIDProfOrthopaedietechnikerHPC   = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 240} // Orthopädietechniker/-in
	OIDProfZahntechnikerHPC          = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 241} // Zahntechniker/-in
	OIDProfErgotherapeutHPC          = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 274} // Ergotherapeut/-in
	OIDProfLogopaedeHPC              = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 275} // Logopäde/Logopädin
	OIDProfPodologeHPC               = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 276} // Podologe/Podologin
	OIDProfErnaehrungstherapeutHPC   = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 277} // Leistungserbringer/-in Ernährungstherapie
	OIDProfOrthopaedHPC              = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 305} // Orthopädieschuhmacher/-in + Orthopädietechniker/-in
	OIDProfOptoAudioHPC              = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 308} // Augenoptiker/-in + Hörakustiker/-in
	OIDProfHimiHPC                   = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 312} // Hilfsmittelerbringer/-in
	OIDProfFriseurHPC                = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 313} // Frisör/-in
	OIDProfMasseurMBMHPC             = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 315} // Masseur/-in + medizinische/-r Bademeister/-in
	OIDProfSoziotherapeut            = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 316} // Leistungserbringer/-in Soziotherapie
	OIDProfSSSSTherapeut             = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 318} // Stimm-, Sprech-, Sprach- und Schluck-Therapie
	OIDProfDiaetassistent            = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 319} // Diätassistent/-in
)

// --- Tab_PKI_403 — Institution OIDs (SMC-B) -------------------------------
//
// Appear in the Admission extension of institutional (SMC-B) cards.

var (
	OIDInstArztpraxis                 = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 50}  // Betriebsstätte Arzt
	OIDInstZahnarztpraxis             = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 51}  // Zahnarztpraxis
	OIDInstPraxisPsychotherapeut      = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 52}  // Betriebsstätte Psychotherapeut
	OIDInstKrankenhaus                = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 53}  // Krankenhaus
	OIDInstOeffentlicheApo            = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 54}  // Öffentliche Apotheke
	OIDInstKrankenhausapotheke        = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 55}  // Krankenhausapotheke
	OIDInstBundeswehrapotheke         = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 56}  // Bundeswehrapotheke
	OIDInstMobileEinrichtungRettung   = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 57}  // Mobile Einrichtung Rettungsdienst
	OIDInstGematik                    = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 58}  // Betriebsstätte gematik
	OIDInstKostentraeger              = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 59}  // Betriebsstätte Kostenträger
	OIDInstLeoZahnaerzte              = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 187} // LEO Vertragszahnärzte
	OIDInstAdvKtr                     = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 190} // AdV-Umgebung Kostenträger
	OIDInstLeoKassenaerztlicheVerein  = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 210} // LEO Kassenärztliche Vereinigung
	OIDInstGKVSpitzenverband          = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 223} // GKV-Spitzenverband
	OIDInstLeoApothekerverband        = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 224} // Apothekerverband
	OIDInstLeoDAV                     = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 225} // Deutscher Apothekerverband
	OIDInstLeoKrankenhausverband      = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 226} // Mitgliedsverband der Krankenhäuser
	OIDInstLeoDKTIG                   = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 227} // DKTIG
	OIDInstLeoDKG                     = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 228} // Deutsche Krankenhausgesellschaft
	OIDInstLeoBAEK                    = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 229} // Bundesärztekammer
	OIDInstLeoAerztekammer            = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 230} // Ärztekammer
	OIDInstLeoZahnaerztekammer        = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 231} // Zahnärztekammer
	OIDInstLeoKBV                     = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 242} // Kassenärztliche Bundesvereinigung
	OIDInstLeoBZAEK                   = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 243} // Bundeszahnärztekammer
	OIDInstLeoKZBV                    = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 244} // Kassenzahnärztliche Bundesvereinigung
	OIDInstPflege                     = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 245} // Gesundheits-, Kranken- und Altenpflege
	OIDInstGeburtshilfe               = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 246} // Geburtshilfe
	OIDInstPraxisPhysiotherapeut      = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 247} // Physiotherapie
	OIDInstAugenoptiker               = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 248} // Augenoptiker
	OIDInstHoerakustiker              = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 249} // Hörakustiker
	OIDInstOrthopaedieschuhmacher     = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 250} // Orthopädieschuhmacher
	OIDInstOrthopaedietechniker       = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 251} // Orthopädietechniker
	OIDInstZahntechniker              = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 252} // Zahntechniker
	OIDInstRettungsleitstelle         = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 253} // Rettungsleitstelle
	OIDInstSanitaetsdienstBW          = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 254} // Sanitätsdienst Bundeswehr
	OIDInstOEGD                       = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 255} // Öffentlicher Gesundheitsdienst
	OIDInstArbeitsmedizin             = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 256} // Arbeitsmedizin
	OIDInstVorsorgeReha               = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 257} // Vorsorge- und Rehabilitation
	OIDInstPflegeberatung             = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 262} // Pflegeberatung § 7a SGB XI
	OIDInstLeoPsychotherapeuten       = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 263} // Psychotherapeutenkammer
	OIDInstLeoBPtK                    = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 264} // Bundespsychotherapeutenkammer
	OIDInstLeoLAK                     = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 265} // Landesapothekerkammer
	OIDInstLeoBAK                     = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 266} // Bundesapothekerkammer
	OIDInstLeoEGBR                    = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 267} // elektronisches Gesundheitsberuferegister
	OIDInstLeoHandwerkskammer         = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 268} // Handwerkskammer
	OIDInstGesundheitsdatenregister   = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 269} // Register für Gesundheitsdaten
	OIDInstAbrechnungsdienstleister   = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 270} // Abrechnungsdienstleister
	OIDInstPKVVerband                 = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 271} // PKV-Verband
	OIDInstPraxisErgotherapeut        = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 278} // Ergotherapiepraxis
	OIDInstPraxisLogopaede            = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 279} // Logopädische Praxis
	OIDInstPraxisPodologe             = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 280} // Podologiepraxis
	OIDInstPraxisErnaehrungstherapeut = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 281} // Ernährungstherapeutische Praxis
	OIDInstWeitereKostentraeger       = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 284} // Weitere Kostenträger
	OIDInstOrgGesundheitsversorgung   = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 285} // Weitere Organisationen
	OIDInstKIMAnbieter                = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 286} // KIM-Hersteller / -Anbieter
	OIDInstDiGA                       = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 282} // DiGA-Hersteller / -Anbieter
	OIDInstTIMAnbieter                = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 295} // TIM-Hersteller / -Anbieter
	OIDInstNCPeH                      = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 292} // NCPeH Fachdienst
	OIDInstOmbudsstelle               = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 303} // Ombudsstelle eines Kostenträgers
	OIDInstOptoAudio                  = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 304} // Augenoptiker und Hörakustiker
	OIDInstOrthopaedHW                = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 306} // Orthopädieschuhmacher und Orthopädietechniker
	OIDInstHimi                       = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 311} // Hilfsmittelerbringer
	OIDInstFriseur                    = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 314} // Frisör
	OIDInstSoziother                  = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 317} // Soziotherapie
)

// --- Tab_PKI_404 — Certificate Policy OIDs --------------------------------

var (
	// OIDPolicyHbaCP — CP-HPC: QES/SIG/AUT/ENC policy for HBA cards.
	OIDPolicyHbaCP = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 145}

	// OIDPolicyGemOrCP — policy asserted by every cert issued after the
	// online rollout (eGK, SMC, components).
	OIDPolicyGemOrCP = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 163}

	// OIDPolicyGemTSLSigner — TSL signer-certificate policy.
	OIDPolicyGemTSLSigner = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 176}
)

// --- Tab_PKI_405 — Certificate Type OIDs ----------------------------------
//
// Encoded in the Admission extension (or in CertificatePolicies for some
// older profiles) to declare which TI cert profile a certificate is.

var (
	// eGK (Versichertenkarte) certificate types.
	OIDCertTypeEgkQES  = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 66} // C.CH.QES
	OIDCertTypeEgkSIG  = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 67} // C.CH.SIG
	OIDCertTypeEgkENC  = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 68} // C.CH.ENC
	OIDCertTypeEgkENCV = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 69} // C.CH.ENCV
	OIDCertTypeEgkAUT  = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 70} // C.CH.AUT
	OIDCertTypeEgkAUTN = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 71} // C.CH.AUTN

	// HBA (Heilberufsausweis) certificate types.
	OIDCertTypeHbaQES = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 72} // C.HP.QES
	OIDCertTypeHbaENC = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 74} // C.HP.ENC
	OIDCertTypeHbaAUT = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 75} // C.HP.AUT

	// SMC-B (institution) certificate types.
	OIDCertTypeSmcBENC  = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 76} // C.HCI.ENC
	OIDCertTypeSmcBAUT  = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 77} // C.HCI.AUT
	OIDCertTypeSmcBOSIG = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 78} // C.HCI.OSIG

	// Fachdienst (service-provider) certificate types.
	OIDCertTypeFdTLSS = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 169} // C.FD.TLS-S
	OIDCertTypeFdTLSC = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 168} // C.FD.TLS-C
	OIDCertTypeFdSIG  = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 203} // C.FD.SIG
	OIDCertTypeFdENC  = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 202} // C.FD.ENC
	OIDCertTypeFdAUT  = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 155} // C.FD.AUT
	OIDCertTypeFdOSIG = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 283} // C.FD.OSIG

	// Zentraler Dienst (central service) certificate types.
	OIDCertTypeZdTLSS = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 157} // C.ZD.TLS-S
	OIDCertTypeZdSIG  = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 287} // C.ZD.SIG

	// High-speed Konnektor + gematik VER.
	OIDCertTypeHskSIG = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 300} // C.HSK.SIG
	OIDCertTypeHskENC = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 301} // C.HSK.ENC
	OIDCertTypeGemVER = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 321} // C.GEM.VER
)

// --- Tab_PKI_406 — Technical Role OIDs (Fachdienste) ---------------------
//
// Identify the role a Fachdienst certificate is asserting.

var (
	OIDTechRoleVSDD          = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 97}  // Versichertenstammdatendienst
	OIDTechRoleCMS           = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 100} // Card Management System
	OIDTechRoleUFS           = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 101} // Update Flag Service
	OIDTechRoleAK            = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 103} // Anwendungskonnektor
	OIDTechRoleNK            = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 104} // Netzkonnektor
	OIDTechRoleKT            = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 105} // Kartenterminal
	OIDTechRoleSAK           = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 119} // Signaturanwendungskomponente
	OIDTechRoleIntVSDM       = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 159} // Intermediär VSDM
	OIDTechRoleKonfigdienst  = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 160} // Konfigurationsdienst
	OIDTechRoleVPNZTI        = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 161} // VPN-Zugangsdienst-TI
	OIDTechRoleCMFD          = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 174} // Clientmodul
	OIDTechRoleVZDTI         = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 171} // Verzeichnisdienst-TI
	OIDTechRoleKOMLE         = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 172} // KOM-LE Fachdienst
	OIDTechRoleStamp         = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 184} // Betriebsdatenerfassung
	OIDTechRoleTSLTI         = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 189} // TSL-Dienst-TI
	OIDTechRoleWADG          = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 198} // weitere elektronische Anwendungen
	OIDTechRoleEpaAuthn      = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 204} // ePA Authentisierung
	OIDTechRoleEpaAuthz      = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 205} // ePA Autorisierung
	OIDTechRoleEpaDvw        = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 206} // ePA Dokumentenverwaltung
	OIDTechRoleEpaMgmt       = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 207} // ePA Management
	OIDTechRoleEpaRecovery   = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 208} // ePA Berechtigungserhalt
	OIDTechRoleEpaVAU        = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 209} // ePA Vertrauenswürdige Ausführungsumgebung
	OIDTechRoleVzTSP         = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 215} // Zertifikatsverzeichnis TSP X.509
	OIDTechRoleWHK1HSM       = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 216} // HSM Wiederherstellungskomponente 1
	OIDTechRoleWHK2HSM       = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 217} // HSM Wiederherstellungskomponente 2
	OIDTechRoleWHK           = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 218} // Wiederherstellungskomponente
	OIDTechRoleSGD           = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 221} // Schlüsselgenerierungsdienst
	OIDTechRoleERPVAU        = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 258} // E-Rezept VAU
	OIDTechRoleERezept       = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 259} // E-Rezept-Fachdienst
	OIDTechRoleIDPD          = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 260} // IDP-Dienst
	OIDTechRoleEpaLogging    = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 261} // ePA-Aktensystem-Logging
	OIDTechRoleBestandsnetze = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 288} // Bestandsnetze.xml Signatur
	OIDTechRoleEpaVST        = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 289} // ePA Vertrauensstelle
	OIDTechRoleEpaFDZ        = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 290} // ePA Forschungsdatenzentrum
	OIDTechRoleTIM           = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 294} // TI-Messenger
	OIDTechRoleHSK           = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 302} // Highspeed-Konnektor
	OIDTechRoleIDPDSek       = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 307} // sektoraler IDP
	OIDTechRoleTIGWZugm      = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 309} // TI-Gateway Zugangsmodul
	OIDTechRoleZertSMB       = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 310} // Technische Zertifikatsausgabestelle SMC-B
	OIDTechRolePoPP          = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 293} // Proof of Patient Presence
	OIDTechRolePoPPToken     = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 320} // Token-Signatur PoPP
	OIDTechRolePKIVer        = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 322} // PKI Change Verifikation
	OIDTechRoleDipagVAU      = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 323} // Digitale Patientenrechnung VAU
	OIDTechRoleZETAGuard     = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 328} // ZETA Guard
	OIDTechRoleZETAPolicies  = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 324} // ZETA PIP/PAP Policies
	OIDTechRoleZETAOCI       = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 326} // OCI container image für ZETA
	OIDTechRoleZETAPolAuthor = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 329} // ZETA Policy Autor
	OIDTechRoleZETAPolApprov = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 330} // ZETA Policy Freigeber
	OIDTechRoleZETAPolOper   = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 331} // ZETA Policy Leitstand
	OIDTechRoleZETAPrvApprov = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 332} // ZETA Provisioning Container Image Freigeber
	OIDTechRoleTSPEgk        = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 325} // Technische Zertifikatsausgabestelle eGK
	OIDTechRoleCDCP15G       = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 327} // CDC Pseudonymisierung
)
