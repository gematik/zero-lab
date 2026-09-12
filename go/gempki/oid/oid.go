// Package oid holds the object identifiers gemSpec_OID defines for the TI,
// as Go values, each defined together with the spec's reference name and
// description so the two can never drift; [Lookup] and [Format] give them
// back. The tables are complete as of gemSpec_OID V3.25.0
// (https://gemspec.gematik.de/docs/gemSpec/gemSpec_OID/latest/); the spec's
// snake_case (`oid_arzt`) is rendered CamelCase under a family prefix:
//
//   - Instance*  — Tab_PKI_401 organisational instances
//   - Prof*      — Tab_PKI_402 professions (HBA persons)
//   - Inst*      — Tab_PKI_403 institutions (SMC-B)
//   - Policy*    — Tab_PKI_404 certificate policies
//   - CertType*  — Tab_PKI_405 certificate types
//   - TechRole*  — Tab_PKI_406 technical roles (Fachdienste)
//
// The arc base is 1.2.276.0.76.4 unless an entry spells its OID out.
package oid

import "encoding/asn1"

// --- Structural ------------------------------------------------------------

// AdmissionExtension is the ISIS-MTT Admission extension carrying gematik
// profession info on SMC-B and HBA cards.
var AdmissionExtension = asn1.ObjectIdentifier{1, 3, 36, 8, 3, 3}

// --- Tab_PKI_401 — Instance OIDs -----------------------------------------------
//
// Identify the organization that runs an actor in the TI.

var (
	InstanceKBV     = defAt(asn1.ObjectIdentifier{1, 2, 276, 0, 76, 3, 1, 1}, "oid_kbv", "KBV Kassenärztliche Bundesvereinigung")
	InstanceBAEK    = defAt(asn1.ObjectIdentifier{1, 2, 276, 0, 76, 3, 1, 95}, "oid_baek", "Bundesärztekammer")
	InstanceKZBV    = defAt(asn1.ObjectIdentifier{1, 2, 276, 0, 76, 3, 1, 99}, "oid_kzbv", "Kassenzahnärztliche Bundesvereinigung KZBV")
	InstanceBZAEK   = defAt(asn1.ObjectIdentifier{1, 2, 276, 0, 76, 3, 1, 96}, "oid_bzaek", "Bundeszahnärztekammer")
	InstanceDKG     = defAt(asn1.ObjectIdentifier{1, 2, 276, 0, 76, 3, 1, 49}, "oid_dkg", "Deutsche Krankenhausgesellschaft DKG")
	InstanceBPtK    = defAt(asn1.ObjectIdentifier{1, 2, 276, 0, 76, 3, 1, 90}, "oid_bptk", "Bundespsychotherapeutenkammer BPTK")
	InstanceGematik = defAt(asn1.ObjectIdentifier{1, 2, 276, 0, 76, 3, 1, 91}, "oid_gematik", "gematik Gesellschaft für Telematikanwendungen der Gesundheitskarte mbH")
)

// --- Tab_PKI_402 — Profession OIDs (HBA persons) -------------------------------
//
// Appear in the Admission extension of HBA / health-professional cards.

var (
	ProfArzt                      = def(30, "oid_arzt", "Ärztin/Arzt")
	ProfZahnarzt                  = def(31, "oid_zahnarzt", "Zahnärztin/Zahnarzt")
	ProfApotheker                 = def(32, "oid_apotheker", "Apotheker/-in")
	ProfApothekerassistent        = def(33, "oid_apothekerassistent", "Apothekerassistent/-in")
	ProfPharmazieingenieur        = def(34, "oid_pharmazieingenieur", "Pharmazieingenieur/-in")
	ProfPharmTechnAssistent       = def(35, "oid_pharm_techn_assistent", "pharmazeutisch-technische/-r Assistent/-in")
	ProfPharmKaufmAngestellter    = def(36, "oid_pharm_kaufm_angestellter", "pharmazeutisch-kaufmännische/-r Angestellte")
	ProfApothekenhelfer           = def(37, "oid_apothekenhelfer", "Apothekenhelfer/-in")
	ProfApothekenassistent        = def(38, "oid_apothekenassistent", "Apothekenassistent/-in")
	ProfPharmAssistent            = def(39, "oid_pharm_assistent", "Pharmazeutische/-r Assistent/-in")
	ProfApothekenfacharbeiter     = def(40, "oid_apothekenfacharbeiter", "Apothekenfacharbeiter/-in")
	ProfPharmaziepraktikant       = def(41, "oid_pharmaziepraktikant", "Pharmaziepraktikant/-in")
	ProfFamulant                  = def(42, "oid_famulant", "Stud.pharm. oder Famulant/-in")
	ProfPTAPraktikant             = def(43, "oid_pta_praktikant", "PTA-Praktikant/-in")
	ProfPKAAuszubildender         = def(44, "oid_pka_auszubildender", "PKA Auszubildende/-r")
	ProfPsychotherapeut           = def(45, "oid_psychotherapeut", "Psychotherapeut/-in")
	ProfPsPsychotherapeut         = def(46, "oid_ps_psychotherapeut", "Psychologische/-r Psychotherapeut/-in")
	ProfKuJPsychotherapeut        = def(47, "oid_kuj_psychotherapeut", "Kinder- und Jugendlichenpsychotherapeut/-in")
	ProfRettungsassistent         = def(48, "oid_rettungsassistent", "Rettungsassistent/-in")
	ProfVersicherter              = def(49, "oid_versicherter", "Versicherte/-r")
	ProfNotfallsanitaeter         = def(178, "oid_notfallsanitaeter", "Notfallsanitäter/-in")
	ProfPflegerHPC                = def(232, "oid_pfleger-hpc", "Gesundheits- und Krankenpfleger/-in, Gesundheits- und Kinderkrankenpfleger/-in")
	ProfAltenpflegerHPC           = def(233, "oid_altenpfleger-hpc", "Altenpfleger/-in")
	ProfPflegefachkraftHPC        = def(234, "oid_pflegefachkraft-hpc", "Pflegefachfrauen und Pflegefachmänner")
	ProfHebammeHPC                = def(235, "oid_hebamme-hpc", "Hebamme")
	ProfPhysiotherapeutHPC        = def(236, "oid_physiotherapeut-hpc", "Physiotherapeut/-in")
	ProfAugenoptikerHPC           = def(237, "oid_augenoptiker-hpc", "Augenoptiker/-in")
	ProfHoerakustikerHPC          = def(238, "oid_hoerakustiker-hpc", "Hörakustiker/-in")
	ProfOrthopaedieschuhmacherHPC = def(239, "oid_orthopaedieschuhmacher-hpc", "Orthopädieschuhmacher/-in")
	ProfOrthopaedietechnikerHPC   = def(240, "oid_orthopaedietechniker-hpc", "Orthopädietechniker/-in")
	ProfZahntechnikerHPC          = def(241, "oid_zahntechniker-hpc", "Zahntechniker/-in")
	ProfErgotherapeutHPC          = def(274, "oid_ergotherapeut-hpc", "Ergotherapeut/-in")
	ProfLogopaedeHPC              = def(275, "oid_logopaede-hpc", "Logopäde/Logopädin")
	ProfPodologeHPC               = def(276, "oid_podologe-hpc", "Podologe/Podologin")
	ProfErnaehrungstherapeutHPC   = def(277, "oid_ernaehrungstherapeut-hpc", "Leistungserbringer/-in Ernährungstherapie")
	ProfOptoAudioHPC              = def(308, "oid_opto-audio-hpc", "Augenoptiker/-in und Hörakustiker/-in")
	ProfOrthopaedHPC              = def(305, "oid_orthopaed-hpc", "Orthopädieschuhmacher/-in und Orthopädietechniker/-in")
	ProfHimiHPC                   = def(312, "oid_himi-hpc", "Hilfsmittelerbringer/-in")
	ProfFriseurHPC                = def(313, "oid_friseur-hpc", "Frisör/-in")
	ProfSoziotherapeut            = def(316, "oid_soziotherapeut", "Leistungserbringer/-in Soziotherapie")
	ProfSSSSTherapeut             = def(318, "oid_ssss-therapeut", "Leistungserbringer/in Stimm-, Sprech-, Sprach- und Schluck-Therapie")
	ProfMasseurMBMHPC             = def(315, "oid_masseur-mbm-hpc", "Masseur/-in und medizinische/-r Bademeister/-in")
	ProfDiaetassistent            = def(319, "oid_diaetassistent", "Diätassistent/-in")
)

// --- Tab_PKI_403 — Institution OIDs (SMC-B) ------------------------------------
//
// Appear in the Admission extension of institutional (SMC-B) cards.

var (
	InstArztpraxis                 = def(50, "oid_praxis_arzt", "Betriebsstätte Arzt")
	InstZahnarztpraxis             = def(51, "oid_zahnarztpraxis", "Zahnarztpraxis")
	InstPraxisPsychotherapeut      = def(52, "oid_praxis_psychotherapeut", "Betriebsstätte Psychotherapeut")
	InstKrankenhaus                = def(53, "oid_krankenhaus", "Krankenhaus")
	InstOeffentlicheApo            = def(54, "oid_oeffentliche_apotheke", "Öffentliche Apotheke")
	InstKrankenhausapotheke        = def(55, "oid_krankenhausapotheke", "Krankenhausapotheke")
	InstBundeswehrapotheke         = def(56, "oid_bundeswehrapotheke", "Bundeswehrapotheke")
	InstMobileEinrichtungRettung   = def(57, "oid_mobile_einrichtung_rettungsdienst", "Betriebsstätte Mobile Einrichtung Rettungsdienst")
	InstGematik                    = def(58, "oid_bs_gematik", "Betriebsstätte gematik")
	InstKostentraeger              = def(59, "oid_kostentraeger", "Betriebsstätte Kostenträger")
	InstLeoZahnaerzte              = def(187, "oid_leo_zahnaerzte", "Betriebsstätte Leistungserbringerorganisation Vertragszahnärzte")
	InstAdvKtr                     = def(190, "oid_adv_ktr", "AdV-Umgebung bei Kostenträger")
	InstLeoKassenaerztlicheVerein  = def(210, "oid_leo_kassenaerztliche_vereinigung", "Betriebsstätte Leistungserbringerorganisation Kassenärztliche Vereinigung")
	InstGKVSpitzenverband          = def(223, "oid_bs_gkv_spitzenverband", "Betriebsstätte GKV-Spitzenverband")
	InstLeoKrankenhausverband      = def(226, "oid_leo_krankenhausverband", "Betriebsstätte Mitgliedsverband der Krankenhäuser")
	InstLeoDKTIG                   = def(227, "oid_leo_dktig", "Betriebsstätte der Deutsche Krankenhaus TrustCenter und Informationsverarbeitung GmbH")
	InstLeoDKG                     = def(228, "oid_leo_dkg", "Betriebsstätte der Deutschen Krankenhausgesellschaft")
	InstLeoApothekerverband        = def(224, "oid_leo_apothekerverband", "Betriebsstätte Apothekerverband")
	InstLeoDAV                     = def(225, "oid_leo_dav", "Betriebsstätte Deutscher Apothekerverband")
	InstLeoBAEK                    = def(229, "oid_leo_baek", "Betriebsstätte der Bundesärztekammer")
	InstLeoAerztekammer            = def(230, "oid_leo_aerztekammer", "Betriebsstätte einer Ärztekammer")
	InstLeoZahnaerztekammer        = def(231, "oid_leo_zahnaerztekammer", "Betriebsstätte einer Zahnärztekammer")
	InstLeoKBV                     = def(242, "oid_leo-kbv", "Betriebsstätte der Kassenärztlichen Bundesvereinigung")
	InstLeoBZAEK                   = def(243, "oid_leo-bzaek", "Betriebsstätte der Bundeszahnärztekammer")
	InstLeoKZBV                    = def(244, "oid_leo-kzbv", "Betriebsstätte der Kassenzahnärztlichen Bundesvereinigung")
	InstPflege                     = def(245, "oid_institution-pflege", "Betriebsstätte Gesundheits-, Kranken- und Altenpflege")
	InstGeburtshilfe               = def(246, "oid_institution-geburtshilfe", "Betriebsstätte Geburtshilfe")
	InstPraxisPhysiotherapeut      = def(247, "oid_praxis-physiotherapeut", "Betriebsstätte Physiotherapie")
	InstAugenoptiker               = def(248, "oid_institution-augenoptiker", "Betriebsstätte Augenoptiker")
	InstHoerakustiker              = def(249, "oid_institution-hoerakustiker", "Betriebsstätte Hörakustiker")
	InstOrthopaedieschuhmacher     = def(250, "oid_institution-orthopaedieschuhmacher", "Betriebsstätte Orthopädieschuhmacher")
	InstOrthopaedietechniker       = def(251, "oid_institution-orthopaedietechniker", "Betriebsstätte Orthopädietechniker")
	InstZahntechniker              = def(252, "oid_institution-zahntechniker", "Betriebsstätte Zahntechniker")
	InstRettungsleitstelle         = def(253, "oid_institution-rettungsleitstellen", "Rettungsleitstelle")
	InstSanitaetsdienstBW          = def(254, "oid_sanitaetsdienst-bundeswehr", "Betriebsstätte Sanitätsdienst Bundeswehr")
	InstOEGD                       = def(255, "oid_institution-oegd", "Betriebsstätte Öffentlicher Gesundheitsdienst")
	InstArbeitsmedizin             = def(256, "oid_institution-arbeitsmedizin", "Betriebsstätte Arbeitsmedizin")
	InstVorsorgeReha               = def(257, "oid_institution-vorsorge-reha", "Betriebsstätte Vorsorge- und Rehabilitation")
	InstPflegeberatung             = def(262, "oid_pflegeberatung", "Betriebsstätte Pflegeberatung nach § 7a SGB XI")
	InstLeoPsychotherapeuten       = def(263, "oid_leo_psychotherapeuten", "Betriebsstätte Psychotherapeutenkammer")
	InstLeoBPtK                    = def(264, "oid_leo_bptk", "Betriebsstätte Bundespsychotherapeutenkammer")
	InstLeoLAK                     = def(265, "oid_leo_lak", "Betriebsstätte Landesapothekerkammer")
	InstLeoBAK                     = def(266, "oid_leo_bak", "Betriebsstätte Bundesapothekerkammer")
	InstLeoEGBR                    = def(267, "oid_leo_egbr", "Betriebsstätte elektronisches Gesundheitsberuferegister")
	InstLeoHandwerkskammer         = def(268, "oid_leo_handwerkskammer", "Betriebsstätte Handwerkskammer")
	InstGesundheitsdatenregister   = def(269, "oid_gesundheitsdatenregister", "Betriebsstätte Register für Gesundheitsdaten")
	InstAbrechnungsdienstleister   = def(270, "oid_abrechnungsdienstleister", "Betriebsstätte Abrechnungsdienstleister")
	InstPKVVerband                 = def(271, "oid_pkv_verband", "Betriebsstätte PKV-Verband")
	InstPraxisErgotherapeut        = def(278, "oid_praxis-ergotherapeut", "Ergotherapiepraxis")
	InstPraxisLogopaede            = def(279, "oid_praxis-logopaede", "Logopaedische Praxis")
	InstPraxisPodologe             = def(280, "oid_praxis-podologe", "Podologiepraxis")
	InstPraxisErnaehrungstherapeut = def(281, "oid_praxis-ernaehrungstherapeut", "Ernährungstherapeutische Praxis")
	InstWeitereKostentraeger       = def(284, "oid_bs-weitere-kostentraeger", "Betriebsstätte Weitere Kostenträger im Gesundheitswesen")
	InstOrgGesundheitsversorgung   = def(285, "oid_org-gesundheitsversorgung", "Weitere Organisationen der Gesundheitsversorgung")
	InstKIMAnbieter                = def(286, "oid_kim-anbieter", "KIM-Hersteller und -Anbieter")
	InstDiGA                       = def(282, "oid_diga", "DiGA-Hersteller und -Anbieter")
	InstTIMAnbieter                = def(295, "oid_tim-anbieter", "TIM-Hersteller und -Anbieter")
	InstNCPeH                      = def(292, "oid_ncpeh", "NCPeH Fachdienst")
	InstOmbudsstelle               = def(303, "oid_ombudsstelle", "Ombudsstelle eines Kostenträgers")
	InstOptoAudio                  = def(304, "oid_bs-opto-audio", "Betriebsstätte Augenoptiker und Hörakustiker")
	InstOrthopaedHW                = def(306, "oid_bs-orthopaed-hw", "Betriebsstätte Orthopädieschuhmacher und Orthopädietechniker")
	InstHimi                       = def(311, "oid_bs-himi", "Betriebsstätte Hilfsmittelerbringer")
	InstFriseur                    = def(314, "oid_bs-friseur", "Betriebsstätte Frisör")
	InstSoziother                  = def(317, "oid_bs-soziother", "Betriebsstätte Soziotherapie")
)

// --- Tab_PKI_404 — Certificate Policy OIDs -------------------------------------
//
// Asserted in CertificatePolicies; the defining document rides along.

var (
	PolicyHbaCP        = defIn(145, "oid_policy_hba_cp", "Policy HPC QES, SIG, AUT, ENC", "[CP-HPC]")
	PolicyGemOrCP      = defIn(163, "oid_policy_gem_or_cp", "Policy für alle Zertifikate ab Online-Rollout (eGK, SMC, Komponentenzertifikate) außer für das TSL-Signerzertifikat", "[gemRL_TSL_SP_CP]")
	PolicyGemTSLSigner = defIn(176, "oid_policy_gem_tsl_signer", "Policy für das TSL-Signerzertifikat", "[gemSpec_TSL]")
)

// --- Tab_PKI_405 — Certificate Type OIDs ---------------------------------------
//
// Encoded in the Admission extension (or in CertificatePolicies for some
// older profiles) to declare which TI cert profile a certificate is. The
// description is the type name gemSpec_PKI uses.

var (
	CertTypeEgkQES     = defIn(66, "oid_egk_qes", "C.CH.QES", "[gemSpec_PKI]")
	CertTypeEgkSIG     = defIn(67, "oid_egk_sig", "C.CH.SIG", "[gemSpec_PKI]")
	CertTypeEgkENC     = defIn(68, "oid_egk_enc", "C.CH.ENC", "[gemSpec_PKI]")
	CertTypeEgkENCV    = defIn(69, "oid_egk_encv", "C.CH.ENCV", "[gemSpec_PKI]")
	CertTypeEgkAUT     = defIn(70, "oid_egk_aut", "C.CH.AUT", "[gemSpec_PKI]")
	CertTypeEgkAUTN    = defIn(71, "oid_egk_autn", "C.CH.AUTN", "[gemSpec_PKI]")
	CertTypeEgkENCAlt  = defIn(211, "oid_egk_enc_alt", "C.CH.ENC_ALT", "")
	CertTypeEgkAUTAlt  = defIn(212, "oid_egk_aut_alt", "C.CH.AUT_ALT", "[gemSpec_PKI]")
	CertTypeHbaQES     = defIn(72, "oid_hba_qes", "C.HP.QES", "[CertsBÄK#1]")
	CertTypeHbaSIG     = defIn(73, "oid_hba_sig", "C.HP.SIG", "")
	CertTypeHbaENC     = defIn(74, "oid_hba_enc", "C.HP.ENC", "[CertsBÄK#1]")
	CertTypeHbaAUT     = defIn(75, "oid_hba_aut", "C.HP.AUT", "[CertsBÄK#1]")
	CertTypeSmcBENC    = defIn(76, "oid_smc_b_enc", "C.HCI.ENC", "[gemSpec_PKI]")
	CertTypeSmcBAUT    = defIn(77, "oid_smc_b_aut", "C.HCI.AUT", "[gemSpec_PKI]")
	CertTypeSmcBOSIG   = defIn(78, "oid_smc_b_osig", "C.HCI.OSIG", "[gemSpec_PKI]")
	CertTypeAkAUT      = defIn(79, "oid_ak_aut", "C.AK.AUT", "[gemSpec_PKI]")
	CertTypeNkVPN      = defIn(80, "oid_nk_vpn", "C.NK.VPN", "[gemSpec_PKI]")
	CertTypeVpnkVPN    = defIn(81, "oid_vpnk_vpn", "C.VPNK.VPN", "[gemSpec_PKI]")
	CertTypeSmktAUT    = defIn(82, "oid_smkt_aut", "C.SMKT.AUT", "[gemSpec_PKI]")
	CertTypeSakAUT     = defIn(113, "oid_sak_aut", "C.SAK.AUT", "[gemSpec_PKI]")
	CertTypeCmTLSCS    = defIn(175, "oid_cm_tls_c", "C.CM.TLS-CS", "[gemSpec_PKI]")
	CertTypeFdTLSC     = defIn(168, "oid_fd_tls_c", "C.FD.TLS-C", "[gemSpec_PKI]")
	CertTypeFdTLSS     = defIn(169, "oid_fd_tls_s", "C.FD.TLS-S", "[gemSpec_PKI]")
	CertTypeFdAUT      = defIn(155, "oid_fd_aut", "C.FD.AUT", "[gemSpec_PKI]")
	CertTypeZdTLSC     = defIn(156, "oid_zd_tls_c", "C.ZD.TLS-C", "")
	CertTypeZdTLSS     = defIn(157, "oid_zd_tls_s", "C.ZD.TLS-S", "[gemSpec_PKI]")
	CertTypeZdAUT      = defIn(158, "oid_zd_aut", "C.ZD.AUT", "")
	CertTypeVpnkVPNSIS = defIn(165, "oid_vpnk_vpn_sis", "C.VPNK.VPN-SIS", "[gemSpec_PKI]")
	CertTypeFdSIG      = defIn(203, "oid_fd_sig", "C.FD.SIG", "[gemSpec_PKI]")
	CertTypeFdENC      = defIn(202, "oid_fd_enc", "C.FD.ENC", "[gemSpec_PKI]")
	CertTypeWhkHsmAUT  = defIn(213, "oid_whk_hsm_aut", "C.WHK-HSM.AUT", "")
	CertTypeVkPtENC    = defIn(62, "oid_vk_pt_enc", "C.HP.ENC", "[BÄK_ePA]")
	CertTypeVkEaaENC   = defAtIn(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 24796, 1, 10}, "oid_vk_eaa_enc", "C.HP.ENC", "[BÄK_eAA]")
	CertTypeFdOSIG     = defIn(283, "oid_fd_osig", "C.FD.OSIG", "[gemSpec_PKI]")
	CertTypeZdSIG      = defIn(287, "oid_zd_sig", "C.ZD.SIG", "[gemSpec_PKI]")
	CertTypeHskSIG     = defIn(300, "oid_hsk_sig", "C.HSK.SIG", "[gemSpec_PKI]")
	CertTypeHskENC     = defIn(301, "oid_hsk_enc", "C.HSK.ENC", "[gemSpec_PKI]")
	CertTypeGemVER     = defIn(321, "oid_gem-ver", "C.GEM.VER", "[gemSpec_PKI]")
)

// --- Tab_PKI_406 — Technical Role OIDs (Fachdienste) ---------------------------
//
// Identify the role a Fachdienst certificate is asserting.

var (
	TechRoleVSDD                 = def(97, "oid_vsdd", "Versichertenstammdatendienst")
	TechRoleOCSP                 = def(99, "oid_ocsp", "Online Certificate Status Protocol")
	TechRoleCMS                  = def(100, "oid_cms", "Card Management System")
	TechRoleUFS                  = def(101, "oid_ufs", "Update Flag Service")
	TechRoleAK                   = def(103, "oid_ak", "Anwendungskonnektor")
	TechRoleNK                   = def(104, "oid_nk", "Netzkonnektor")
	TechRoleKT                   = def(105, "oid_kt", "Kartenterminal")
	TechRoleSAK                  = def(119, "oid_sak", "Signaturanwendungskomponente")
	TechRoleIntVSDM              = def(159, "oid_int_vsdm", "Intermediär VSDM")
	TechRoleKonfigdienst         = def(160, "oid_konfigdienst", "Konfigurationsdienst")
	TechRoleVPNZTI               = def(161, "oid_vpnz_ti", "VPN-Zugangsdienst-TI")
	TechRoleVPNZSIS              = def(166, "oid_vpnz_sis", "VPN-Zugangsdienst-SIS")
	TechRoleCMFD                 = def(174, "oid_cmfd", "Clientmodul")
	TechRoleVZDTI                = def(171, "oid_vzd_ti", "Verzeichnisdienst-TI")
	TechRoleKOMLE                = def(172, "oid_komle", "KOM-LE Fachdienst")
	TechRoleKOMLERecipientEmails = def(173, "oid_komle-recipient-emails", "KOM-LE S/MIME Attribut recipient-emails")
	TechRoleStamp                = def(184, "oid_stamp", "Betriebsdatenerfassung")
	TechRoleTSLTI                = def(189, "oid_tsl_ti", "TSL-Dienst-TI")
	TechRoleWADG                 = def(198, "oid_wadg", "Weitere elektronische Anwendungen des Gesundheitswesens sowie für die Gesundheitsforschung n. P. 291a Abs. 7 Satz 3 SGB V")
	TechRoleEpaAuthn             = def(204, "oid_epa_authn", "ePA Authentisierung")
	TechRoleEpaAuthz             = def(205, "oid_epa_authz", "ePA Autorisierung")
	TechRoleEpaDvw               = def(206, "oid_epa_dvw", "ePA Dokumentenverwaltung")
	TechRoleEpaMgmt              = def(207, "oid_epa_mgmt", "ePA Management")
	TechRoleEpaRecovery          = def(208, "oid_epa_recovery", "ePA automatisierter Berechtigungserhalt")
	TechRoleEpaVAU               = def(209, "oid_epa_vau", "ePA vertrauenswürdige Ausführungsumgebung")
	TechRoleVzTSP                = def(215, "oid_vz_tsp", "Zertifikatsverzeichnis TSP X.509")
	TechRoleWHK1HSM              = def(216, "oid_whk1_hsm", "HSM Wiederherstellungskomponente 1")
	TechRoleWHK2HSM              = def(217, "oid_whk2_hsm", "HSM Wiederherstellungskomponente 2")
	TechRoleWHK                  = def(218, "oid_whk", "Wiederherstellungskomponente")
	TechRoleSGD                  = def(221, "oid_sgd", "Schlüsselgenerierungsdienst")
	TechRoleERPVAU               = def(258, "oid_erp-vau", "E-Rezept vertrauenswürdige Ausführungsumgebung")
	TechRoleERezept              = def(259, "oid_erezept", "E-Rezept")
	TechRoleIDPD                 = def(260, "oid_idpd", "IDP-Dienst")
	TechRoleEpaLogging           = def(261, "oid_epa_logging", "ePA-Aktensystem-Logging")
	TechRoleBestandsnetze        = def(288, "oid_bestandsnetze", "Bestandsnetze.xml Signatur")
	TechRoleEpaVST               = def(289, "oid_epa_vst", "ePA Vertrauensstelle")
	TechRoleEpaFDZ               = def(290, "oid_epa_fdz", "ePA Forschungsdatenzentrum")
	TechRoleTIM                  = def(294, "oid_tim", "TI-Messenger")
	TechRoleHSK                  = def(302, "oid_hsk", "Highspeed-Konnektor")
	TechRoleIDPDSek              = def(307, "oid_idpd_sek", "sektoraler IDP")
	TechRoleTIGWZugm             = def(309, "oid_tigw_zugm", "TI-Gateway Zugangsmodul")
	TechRoleZertSMB              = def(310, "oid_zert_smb", "Technische Zertifikatsausgabestelle eines Anbieters SMC-B")
	TechRolePoPP                 = def(293, "oid_popp", "Proof of Patient Presence (PoPP) Dienst")
	TechRolePoPPToken            = def(320, "oid_popp-token", "Token-Signatur-Identität für Proof of Patient Presence")
	TechRolePKIVer               = def(322, "oid_pki-ver", "PKI Change Verifikation")
	TechRoleDipagVAU             = def(323, "oid_dipag-vau", "Digitale Patientenrechnung vertrauenswürdige Ausführungsumgebung")
	TechRoleZETAGuard            = def(328, "oid_zeta-guard", "ZETA Guard")
	TechRoleZETAPolicies         = def(324, "oid_zeta-policies", "ZETA PIP/PAP Policies")
	TechRoleZETAOCI              = def(326, "oid_zeta-oci", "OCI container image für ZETA")
	TechRoleZETAPolAuthor        = def(329, "oid_zeta-pol-author", "ZETA Policy Autor")
	TechRoleZETAPolApprov        = def(330, "oid_zeta-pol-approv", "ZETA Policy Freigeber")
	TechRoleZETAPolOper          = def(331, "oid_zeta-pol-oper", "ZETA Policy Leitstand")
	TechRoleTSPEgk               = def(325, "oid_tsp-egk", "Technische Zertifikatsausgabestelle eines Anbieters EGK")
	TechRoleCDCP15G              = def(327, "oid_cdc-p15g", "Cyber Defense Center Pseudonymisierung")
	TechRoleZETAPrvApprov        = def(332, "oid_zeta-prv-approv", "ZETA Provisioning Container Image Freigeber")
)

// Professions is Tab_PKI_402 minus ProfVersicherter: every profession OID
// an HBA admission extension may carry. Membership here is what makes a
// certificate "an HBA" to the type detector, and the insured person's
// marker sits in eGK certificates, not on an HBA.
var Professions = []asn1.ObjectIdentifier{
	ProfArzt, ProfZahnarzt, ProfApotheker, ProfApothekerassistent,
	ProfPharmazieingenieur, ProfPharmTechnAssistent, ProfPharmKaufmAngestellter, ProfApothekenhelfer,
	ProfApothekenassistent, ProfPharmAssistent, ProfApothekenfacharbeiter, ProfPharmaziepraktikant,
	ProfFamulant, ProfPTAPraktikant, ProfPKAAuszubildender, ProfPsychotherapeut,
	ProfPsPsychotherapeut, ProfKuJPsychotherapeut, ProfRettungsassistent,
	ProfNotfallsanitaeter, ProfPflegerHPC, ProfAltenpflegerHPC, ProfPflegefachkraftHPC,
	ProfHebammeHPC, ProfPhysiotherapeutHPC, ProfAugenoptikerHPC, ProfHoerakustikerHPC,
	ProfOrthopaedieschuhmacherHPC, ProfOrthopaedietechnikerHPC, ProfZahntechnikerHPC, ProfErgotherapeutHPC,
	ProfLogopaedeHPC, ProfPodologeHPC, ProfErnaehrungstherapeutHPC, ProfOptoAudioHPC,
	ProfOrthopaedHPC, ProfHimiHPC, ProfFriseurHPC, ProfSoziotherapeut,
	ProfSSSSTherapeut, ProfMasseurMBMHPC, ProfDiaetassistent,
}

// Institutions is the whole of Tab_PKI_403: every institution OID an SMC-B
// admission extension may carry.
var Institutions = []asn1.ObjectIdentifier{
	InstArztpraxis, InstZahnarztpraxis, InstPraxisPsychotherapeut, InstKrankenhaus,
	InstOeffentlicheApo, InstKrankenhausapotheke, InstBundeswehrapotheke, InstMobileEinrichtungRettung,
	InstGematik, InstKostentraeger, InstLeoZahnaerzte, InstAdvKtr,
	InstLeoKassenaerztlicheVerein, InstGKVSpitzenverband, InstLeoKrankenhausverband, InstLeoDKTIG,
	InstLeoDKG, InstLeoApothekerverband, InstLeoDAV, InstLeoBAEK,
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
