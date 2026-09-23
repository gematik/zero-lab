//! The object identifiers gemSpec_OID defines for the TI, each declared together with
//! the spec's reference name and description so the two can never drift; [`lookup`] and
//! [`format()`] give them back. The tables are complete as of gemSpec_OID V3.25.0
//! (<https://gemspec.gematik.de/docs/gemSpec/gemSpec_OID/latest/>) with the pending change
//! C_12646 to Tab_PKI_406 applied
//! (<https://gemspec.gematik.de/downloads/prereleases/Draft_CI_26_3/C_12646_Anlage_V1.0.0.html>).
//! Constant names follow `go/gempki/oid` under a family prefix:
//!
//! - `INSTANCE_*`  — Tab_PKI_401 organisational instances
//! - `PROF_*`      — Tab_PKI_402 professions (HBA persons)
//! - `INST_*`      — Tab_PKI_403 institutions (SMC-B)
//! - `POLICY_*`    — Tab_PKI_404 certificate policies
//! - `CERT_TYPE_*` — Tab_PKI_405 certificate types
//! - `TECH_ROLE_*` — Tab_PKI_406 technical roles (Fachdienste)
//!
//! The arc base is [`TI_ARC`] (1.2.276.0.76.4) unless an entry spells its OID out.

use const_oid::ObjectIdentifier;

/// The gematik arc every TI OID lives under unless it spells its own out.
pub const TI_ARC: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.276.0.76.4");

/// The ISIS-MTT Admission extension carrying gematik profession information
/// on SMC-B and HBA cards.
pub const ADMISSION_EXTENSION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.36.8.3.3");

/// What gemSpec_OID records about an object identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Info {
    /// The identifier.
    pub oid: ObjectIdentifier,
    /// The gemSpec_OID reference name, e.g. `oid_policy_gem_or_cp`.
    pub reference: &'static str,
    /// The spec's own wording, in German where the table reads so; for certificate
    /// types the type name.
    pub description: &'static str,
    /// The defining document, e.g. `[gemSpec_TSL]`; empty when the table names none.
    pub document: &'static str,
    /// For a technical role (Tab_PKI_406), the certificate types whose admission
    /// extension may carry it, e.g. `C.FD.AUT`; empty otherwise.
    pub certificate_types: &'static [&'static str],
}

/// What gemSpec_OID says about `oid`, if this module declares it.
pub fn lookup(oid: &ObjectIdentifier) -> Option<&'static Info> {
    TABLE.iter().find(|info| info.oid == *oid)
}

/// `oid` for display: `1.2.276.0.76.4.328 (ZETA Guard)` when the name is known, the
/// bare dotted form otherwise.
pub fn format(oid: &ObjectIdentifier) -> String {
    match lookup(oid) {
        Some(info) if !info.description.is_empty() => format!("{oid} ({})", info.description),
        _ => oid.to_string(),
    }
}

/// Declares each OID as a constant and as a [`TABLE`] entry in one place.
macro_rules! oids {
    ($(
        $name:ident = $oid:literal, $reference:literal, $description:literal, $document:literal,
        [$($certificate_type:literal),*];
    )*) => {
        $(
            #[doc = concat!("`", $reference, "`: ", $description)]
            pub const $name: ObjectIdentifier = ObjectIdentifier::new_unwrap($oid);
        )*

        static TABLE: &[Info] = &[$(
            Info {
                oid: $name,
                reference: $reference,
                description: $description,
                document: $document,
                certificate_types: &[$($certificate_type),*],
            },
        )*];
    };
}

oids! {

    // Tab_PKI_401 — instance OIDs: the organisation that runs an actor in the TI.
    INSTANCE_KBV = "1.2.276.0.76.3.1.1", "oid_kbv", "KBV Kassenärztliche Bundesvereinigung", "", [];
    INSTANCE_BAEK = "1.2.276.0.76.3.1.95", "oid_baek", "Bundesärztekammer", "", [];
    INSTANCE_KZBV = "1.2.276.0.76.3.1.99", "oid_kzbv", "Kassenzahnärztliche Bundesvereinigung KZBV", "", [];
    INSTANCE_BZAEK = "1.2.276.0.76.3.1.96", "oid_bzaek", "Bundeszahnärztekammer", "", [];
    INSTANCE_DKG = "1.2.276.0.76.3.1.49", "oid_dkg", "Deutsche Krankenhausgesellschaft DKG", "", [];
    INSTANCE_BPTK = "1.2.276.0.76.3.1.90", "oid_bptk", "Bundespsychotherapeutenkammer BPTK", "", [];
    INSTANCE_GEMATIK = "1.2.276.0.76.3.1.91", "oid_gematik", "gematik Gesellschaft für Telematikanwendungen der Gesundheitskarte mbH", "", [];

    // Tab_PKI_402 — profession OIDs, in the admission extension of HBA / health-
    // professional cards.
    PROF_ARZT = "1.2.276.0.76.4.30", "oid_arzt", "Ärztin/Arzt", "", [];
    PROF_ZAHNARZT = "1.2.276.0.76.4.31", "oid_zahnarzt", "Zahnärztin/Zahnarzt", "", [];
    PROF_APOTHEKER = "1.2.276.0.76.4.32", "oid_apotheker", "Apotheker/-in", "", [];
    PROF_APOTHEKERASSISTENT = "1.2.276.0.76.4.33", "oid_apothekerassistent", "Apothekerassistent/-in", "", [];
    PROF_PHARMAZIEINGENIEUR = "1.2.276.0.76.4.34", "oid_pharmazieingenieur", "Pharmazieingenieur/-in", "", [];
    PROF_PHARM_TECHN_ASSISTENT = "1.2.276.0.76.4.35", "oid_pharm_techn_assistent", "pharmazeutisch-technische/-r Assistent/-in", "", [];
    PROF_PHARM_KAUFM_ANGESTELLTER = "1.2.276.0.76.4.36", "oid_pharm_kaufm_angestellter", "pharmazeutisch-kaufmännische/-r Angestellte", "", [];
    PROF_APOTHEKENHELFER = "1.2.276.0.76.4.37", "oid_apothekenhelfer", "Apothekenhelfer/-in", "", [];
    PROF_APOTHEKENASSISTENT = "1.2.276.0.76.4.38", "oid_apothekenassistent", "Apothekenassistent/-in", "", [];
    PROF_PHARM_ASSISTENT = "1.2.276.0.76.4.39", "oid_pharm_assistent", "Pharmazeutische/-r Assistent/-in", "", [];
    PROF_APOTHEKENFACHARBEITER = "1.2.276.0.76.4.40", "oid_apothekenfacharbeiter", "Apothekenfacharbeiter/-in", "", [];
    PROF_PHARMAZIEPRAKTIKANT = "1.2.276.0.76.4.41", "oid_pharmaziepraktikant", "Pharmaziepraktikant/-in", "", [];
    PROF_FAMULANT = "1.2.276.0.76.4.42", "oid_famulant", "Stud.pharm. oder Famulant/-in", "", [];
    PROF_PTA_PRAKTIKANT = "1.2.276.0.76.4.43", "oid_pta_praktikant", "PTA-Praktikant/-in", "", [];
    PROF_PKA_AUSZUBILDENDER = "1.2.276.0.76.4.44", "oid_pka_auszubildender", "PKA Auszubildende/-r", "", [];
    PROF_PSYCHOTHERAPEUT = "1.2.276.0.76.4.45", "oid_psychotherapeut", "Psychotherapeut/-in", "", [];
    PROF_PS_PSYCHOTHERAPEUT = "1.2.276.0.76.4.46", "oid_ps_psychotherapeut", "Psychologische/-r Psychotherapeut/-in", "", [];
    PROF_KUJ_PSYCHOTHERAPEUT = "1.2.276.0.76.4.47", "oid_kuj_psychotherapeut", "Kinder- und Jugendlichenpsychotherapeut/-in", "", [];
    PROF_RETTUNGSASSISTENT = "1.2.276.0.76.4.48", "oid_rettungsassistent", "Rettungsassistent/-in", "", [];
    PROF_VERSICHERTER = "1.2.276.0.76.4.49", "oid_versicherter", "Versicherte/-r", "", [];
    PROF_NOTFALLSANITAETER = "1.2.276.0.76.4.178", "oid_notfallsanitaeter", "Notfallsanitäter/-in", "", [];
    PROF_PFLEGER_HPC = "1.2.276.0.76.4.232", "oid_pfleger-hpc", "Gesundheits- und Krankenpfleger/-in, Gesundheits- und Kinderkrankenpfleger/-in", "", [];
    PROF_ALTENPFLEGER_HPC = "1.2.276.0.76.4.233", "oid_altenpfleger-hpc", "Altenpfleger/-in", "", [];
    PROF_PFLEGEFACHKRAFT_HPC = "1.2.276.0.76.4.234", "oid_pflegefachkraft-hpc", "Pflegefachfrauen und Pflegefachmänner", "", [];
    PROF_HEBAMME_HPC = "1.2.276.0.76.4.235", "oid_hebamme-hpc", "Hebamme", "", [];
    PROF_PHYSIOTHERAPEUT_HPC = "1.2.276.0.76.4.236", "oid_physiotherapeut-hpc", "Physiotherapeut/-in", "", [];
    PROF_AUGENOPTIKER_HPC = "1.2.276.0.76.4.237", "oid_augenoptiker-hpc", "Augenoptiker/-in", "", [];
    PROF_HOERAKUSTIKER_HPC = "1.2.276.0.76.4.238", "oid_hoerakustiker-hpc", "Hörakustiker/-in", "", [];
    PROF_ORTHOPAEDIESCHUHMACHER_HPC = "1.2.276.0.76.4.239", "oid_orthopaedieschuhmacher-hpc", "Orthopädieschuhmacher/-in", "", [];
    PROF_ORTHOPAEDIETECHNIKER_HPC = "1.2.276.0.76.4.240", "oid_orthopaedietechniker-hpc", "Orthopädietechniker/-in", "", [];
    PROF_ZAHNTECHNIKER_HPC = "1.2.276.0.76.4.241", "oid_zahntechniker-hpc", "Zahntechniker/-in", "", [];
    PROF_ERGOTHERAPEUT_HPC = "1.2.276.0.76.4.274", "oid_ergotherapeut-hpc", "Ergotherapeut/-in", "", [];
    PROF_LOGOPAEDE_HPC = "1.2.276.0.76.4.275", "oid_logopaede-hpc", "Logopäde/Logopädin", "", [];
    PROF_PODOLOGE_HPC = "1.2.276.0.76.4.276", "oid_podologe-hpc", "Podologe/Podologin", "", [];
    PROF_ERNAEHRUNGSTHERAPEUT_HPC = "1.2.276.0.76.4.277", "oid_ernaehrungstherapeut-hpc", "Leistungserbringer/-in Ernährungstherapie", "", [];
    PROF_OPTO_AUDIO_HPC = "1.2.276.0.76.4.308", "oid_opto-audio-hpc", "Augenoptiker/-in und Hörakustiker/-in", "", [];
    PROF_ORTHOPAED_HPC = "1.2.276.0.76.4.305", "oid_orthopaed-hpc", "Orthopädieschuhmacher/-in und Orthopädietechniker/-in", "", [];
    PROF_HIMI_HPC = "1.2.276.0.76.4.312", "oid_himi-hpc", "Hilfsmittelerbringer/-in", "", [];
    PROF_FRISEUR_HPC = "1.2.276.0.76.4.313", "oid_friseur-hpc", "Frisör/-in", "", [];
    PROF_SOZIOTHERAPEUT = "1.2.276.0.76.4.316", "oid_soziotherapeut", "Leistungserbringer/-in Soziotherapie", "", [];
    PROF_SSSS_THERAPEUT = "1.2.276.0.76.4.318", "oid_ssss-therapeut", "Leistungserbringer/in Stimm-, Sprech-, Sprach- und Schluck-Therapie", "", [];
    PROF_MASSEUR_MBM_HPC = "1.2.276.0.76.4.315", "oid_masseur-mbm-hpc", "Masseur/-in und medizinische/-r Bademeister/-in", "", [];
    PROF_DIAETASSISTENT = "1.2.276.0.76.4.319", "oid_diaetassistent", "Diätassistent/-in", "", [];

    // Tab_PKI_403 — institution OIDs, in the admission extension of institutional (SMC-B)
    // cards.
    INST_ARZTPRAXIS = "1.2.276.0.76.4.50", "oid_praxis_arzt", "Betriebsstätte Arzt", "", [];
    INST_ZAHNARZTPRAXIS = "1.2.276.0.76.4.51", "oid_zahnarztpraxis", "Zahnarztpraxis", "", [];
    INST_PRAXIS_PSYCHOTHERAPEUT = "1.2.276.0.76.4.52", "oid_praxis_psychotherapeut", "Betriebsstätte Psychotherapeut", "", [];
    INST_KRANKENHAUS = "1.2.276.0.76.4.53", "oid_krankenhaus", "Krankenhaus", "", [];
    INST_OEFFENTLICHE_APO = "1.2.276.0.76.4.54", "oid_oeffentliche_apotheke", "Öffentliche Apotheke", "", [];
    INST_KRANKENHAUSAPOTHEKE = "1.2.276.0.76.4.55", "oid_krankenhausapotheke", "Krankenhausapotheke", "", [];
    INST_BUNDESWEHRAPOTHEKE = "1.2.276.0.76.4.56", "oid_bundeswehrapotheke", "Bundeswehrapotheke", "", [];
    INST_MOBILE_EINRICHTUNG_RETTUNG = "1.2.276.0.76.4.57", "oid_mobile_einrichtung_rettungsdienst", "Betriebsstätte Mobile Einrichtung Rettungsdienst", "", [];
    INST_GEMATIK = "1.2.276.0.76.4.58", "oid_bs_gematik", "Betriebsstätte gematik", "", [];
    INST_KOSTENTRAEGER = "1.2.276.0.76.4.59", "oid_kostentraeger", "Betriebsstätte Kostenträger", "", [];
    INST_LEO_ZAHNAERZTE = "1.2.276.0.76.4.187", "oid_leo_zahnaerzte", "Betriebsstätte Leistungserbringerorganisation Vertragszahnärzte", "", [];
    INST_ADV_KTR = "1.2.276.0.76.4.190", "oid_adv_ktr", "AdV-Umgebung bei Kostenträger", "", [];
    INST_LEO_KASSENAERZTLICHE_VEREIN = "1.2.276.0.76.4.210", "oid_leo_kassenaerztliche_vereinigung", "Betriebsstätte Leistungserbringerorganisation Kassenärztliche Vereinigung", "", [];
    INST_GKV_SPITZENVERBAND = "1.2.276.0.76.4.223", "oid_bs_gkv_spitzenverband", "Betriebsstätte GKV-Spitzenverband", "", [];
    INST_LEO_KRANKENHAUSVERBAND = "1.2.276.0.76.4.226", "oid_leo_krankenhausverband", "Betriebsstätte Mitgliedsverband der Krankenhäuser", "", [];
    INST_LEO_DKTIG = "1.2.276.0.76.4.227", "oid_leo_dktig", "Betriebsstätte der Deutsche Krankenhaus TrustCenter und Informationsverarbeitung GmbH", "", [];
    INST_LEO_DKG = "1.2.276.0.76.4.228", "oid_leo_dkg", "Betriebsstätte der Deutschen Krankenhausgesellschaft", "", [];
    INST_LEO_APOTHEKERVERBAND = "1.2.276.0.76.4.224", "oid_leo_apothekerverband", "Betriebsstätte Apothekerverband", "", [];
    INST_LEO_DAV = "1.2.276.0.76.4.225", "oid_leo_dav", "Betriebsstätte Deutscher Apothekerverband", "", [];
    INST_LEO_BAEK = "1.2.276.0.76.4.229", "oid_leo_baek", "Betriebsstätte der Bundesärztekammer", "", [];
    INST_LEO_AERZTEKAMMER = "1.2.276.0.76.4.230", "oid_leo_aerztekammer", "Betriebsstätte einer Ärztekammer", "", [];
    INST_LEO_ZAHNAERZTEKAMMER = "1.2.276.0.76.4.231", "oid_leo_zahnaerztekammer", "Betriebsstätte einer Zahnärztekammer", "", [];
    INST_LEO_KBV = "1.2.276.0.76.4.242", "oid_leo-kbv", "Betriebsstätte der Kassenärztlichen Bundesvereinigung", "", [];
    INST_LEO_BZAEK = "1.2.276.0.76.4.243", "oid_leo-bzaek", "Betriebsstätte der Bundeszahnärztekammer", "", [];
    INST_LEO_KZBV = "1.2.276.0.76.4.244", "oid_leo-kzbv", "Betriebsstätte der Kassenzahnärztlichen Bundesvereinigung", "", [];
    INST_PFLEGE = "1.2.276.0.76.4.245", "oid_institution-pflege", "Betriebsstätte Gesundheits-, Kranken- und Altenpflege", "", [];
    INST_GEBURTSHILFE = "1.2.276.0.76.4.246", "oid_institution-geburtshilfe", "Betriebsstätte Geburtshilfe", "", [];
    INST_PRAXIS_PHYSIOTHERAPEUT = "1.2.276.0.76.4.247", "oid_praxis-physiotherapeut", "Betriebsstätte Physiotherapie", "", [];
    INST_AUGENOPTIKER = "1.2.276.0.76.4.248", "oid_institution-augenoptiker", "Betriebsstätte Augenoptiker", "", [];
    INST_HOERAKUSTIKER = "1.2.276.0.76.4.249", "oid_institution-hoerakustiker", "Betriebsstätte Hörakustiker", "", [];
    INST_ORTHOPAEDIESCHUHMACHER = "1.2.276.0.76.4.250", "oid_institution-orthopaedieschuhmacher", "Betriebsstätte Orthopädieschuhmacher", "", [];
    INST_ORTHOPAEDIETECHNIKER = "1.2.276.0.76.4.251", "oid_institution-orthopaedietechniker", "Betriebsstätte Orthopädietechniker", "", [];
    INST_ZAHNTECHNIKER = "1.2.276.0.76.4.252", "oid_institution-zahntechniker", "Betriebsstätte Zahntechniker", "", [];
    INST_RETTUNGSLEITSTELLE = "1.2.276.0.76.4.253", "oid_institution-rettungsleitstellen", "Rettungsleitstelle", "", [];
    INST_SANITAETSDIENST_BW = "1.2.276.0.76.4.254", "oid_sanitaetsdienst-bundeswehr", "Betriebsstätte Sanitätsdienst Bundeswehr", "", [];
    INST_OEGD = "1.2.276.0.76.4.255", "oid_institution-oegd", "Betriebsstätte Öffentlicher Gesundheitsdienst", "", [];
    INST_ARBEITSMEDIZIN = "1.2.276.0.76.4.256", "oid_institution-arbeitsmedizin", "Betriebsstätte Arbeitsmedizin", "", [];
    INST_VORSORGE_REHA = "1.2.276.0.76.4.257", "oid_institution-vorsorge-reha", "Betriebsstätte Vorsorge- und Rehabilitation", "", [];
    INST_PFLEGEBERATUNG = "1.2.276.0.76.4.262", "oid_pflegeberatung", "Betriebsstätte Pflegeberatung nach § 7a SGB XI", "", [];
    INST_LEO_PSYCHOTHERAPEUTEN = "1.2.276.0.76.4.263", "oid_leo_psychotherapeuten", "Betriebsstätte Psychotherapeutenkammer", "", [];
    INST_LEO_BPTK = "1.2.276.0.76.4.264", "oid_leo_bptk", "Betriebsstätte Bundespsychotherapeutenkammer", "", [];
    INST_LEO_LAK = "1.2.276.0.76.4.265", "oid_leo_lak", "Betriebsstätte Landesapothekerkammer", "", [];
    INST_LEO_BAK = "1.2.276.0.76.4.266", "oid_leo_bak", "Betriebsstätte Bundesapothekerkammer", "", [];
    INST_LEO_EGBR = "1.2.276.0.76.4.267", "oid_leo_egbr", "Betriebsstätte elektronisches Gesundheitsberuferegister", "", [];
    INST_LEO_HANDWERKSKAMMER = "1.2.276.0.76.4.268", "oid_leo_handwerkskammer", "Betriebsstätte Handwerkskammer", "", [];
    INST_GESUNDHEITSDATENREGISTER = "1.2.276.0.76.4.269", "oid_gesundheitsdatenregister", "Betriebsstätte Register für Gesundheitsdaten", "", [];
    INST_ABRECHNUNGSDIENSTLEISTER = "1.2.276.0.76.4.270", "oid_abrechnungsdienstleister", "Betriebsstätte Abrechnungsdienstleister", "", [];
    INST_PKV_VERBAND = "1.2.276.0.76.4.271", "oid_pkv_verband", "Betriebsstätte PKV-Verband", "", [];
    INST_PRAXIS_ERGOTHERAPEUT = "1.2.276.0.76.4.278", "oid_praxis-ergotherapeut", "Ergotherapiepraxis", "", [];
    INST_PRAXIS_LOGOPAEDE = "1.2.276.0.76.4.279", "oid_praxis-logopaede", "Logopaedische Praxis", "", [];
    INST_PRAXIS_PODOLOGE = "1.2.276.0.76.4.280", "oid_praxis-podologe", "Podologiepraxis", "", [];
    INST_PRAXIS_ERNAEHRUNGSTHERAPEUT = "1.2.276.0.76.4.281", "oid_praxis-ernaehrungstherapeut", "Ernährungstherapeutische Praxis", "", [];
    INST_WEITERE_KOSTENTRAEGER = "1.2.276.0.76.4.284", "oid_bs-weitere-kostentraeger", "Betriebsstätte Weitere Kostenträger im Gesundheitswesen", "", [];
    INST_ORG_GESUNDHEITSVERSORGUNG = "1.2.276.0.76.4.285", "oid_org-gesundheitsversorgung", "Weitere Organisationen der Gesundheitsversorgung", "", [];
    INST_KIM_ANBIETER = "1.2.276.0.76.4.286", "oid_kim-anbieter", "KIM-Hersteller und -Anbieter", "", [];
    INST_DIGA = "1.2.276.0.76.4.282", "oid_diga", "DiGA-Hersteller und -Anbieter", "", [];
    INST_TIM_ANBIETER = "1.2.276.0.76.4.295", "oid_tim-anbieter", "TIM-Hersteller und -Anbieter", "", [];
    INST_NCPEH = "1.2.276.0.76.4.292", "oid_ncpeh", "NCPeH Fachdienst", "", [];
    INST_OMBUDSSTELLE = "1.2.276.0.76.4.303", "oid_ombudsstelle", "Ombudsstelle eines Kostenträgers", "", [];
    INST_OPTO_AUDIO = "1.2.276.0.76.4.304", "oid_bs-opto-audio", "Betriebsstätte Augenoptiker und Hörakustiker", "", [];
    INST_ORTHOPAED_HW = "1.2.276.0.76.4.306", "oid_bs-orthopaed-hw", "Betriebsstätte Orthopädieschuhmacher und Orthopädietechniker", "", [];
    INST_HIMI = "1.2.276.0.76.4.311", "oid_bs-himi", "Betriebsstätte Hilfsmittelerbringer", "", [];
    INST_FRISEUR = "1.2.276.0.76.4.314", "oid_bs-friseur", "Betriebsstätte Frisör", "", [];
    INST_SOZIOTHER = "1.2.276.0.76.4.317", "oid_bs-soziother", "Betriebsstätte Soziotherapie", "", [];

    // Tab_PKI_404 — certificate policy OIDs, asserted in CertificatePolicies.
    POLICY_HBA_CP = "1.2.276.0.76.4.145", "oid_policy_hba_cp", "Policy HPC QES, SIG, AUT, ENC", "[CP-HPC]", [];
    POLICY_GEM_OR_CP = "1.2.276.0.76.4.163", "oid_policy_gem_or_cp", "Policy für alle Zertifikate ab Online-Rollout (eGK, SMC, Komponentenzertifikate) außer für das TSL-Signerzertifikat", "[gemRL_TSL_SP_CP]", [];
    POLICY_GEM_TSL_SIGNER = "1.2.276.0.76.4.176", "oid_policy_gem_tsl_signer", "Policy für das TSL-Signerzertifikat", "[gemSpec_TSL]", [];

    // Tab_PKI_405 — certificate type OIDs; the description is the type name gemSpec_PKI
    // uses.
    CERT_TYPE_EGK_QES = "1.2.276.0.76.4.66", "oid_egk_qes", "C.CH.QES", "[gemSpec_PKI]", [];
    CERT_TYPE_EGK_SIG = "1.2.276.0.76.4.67", "oid_egk_sig", "C.CH.SIG", "[gemSpec_PKI]", [];
    CERT_TYPE_EGK_ENC = "1.2.276.0.76.4.68", "oid_egk_enc", "C.CH.ENC", "[gemSpec_PKI]", [];
    CERT_TYPE_EGK_ENCV = "1.2.276.0.76.4.69", "oid_egk_encv", "C.CH.ENCV", "[gemSpec_PKI]", [];
    CERT_TYPE_EGK_AUT = "1.2.276.0.76.4.70", "oid_egk_aut", "C.CH.AUT", "[gemSpec_PKI]", [];
    CERT_TYPE_EGK_AUTN = "1.2.276.0.76.4.71", "oid_egk_autn", "C.CH.AUTN", "[gemSpec_PKI]", [];
    CERT_TYPE_EGK_ENC_ALT = "1.2.276.0.76.4.211", "oid_egk_enc_alt", "C.CH.ENC_ALT", "", [];
    CERT_TYPE_EGK_AUT_ALT = "1.2.276.0.76.4.212", "oid_egk_aut_alt", "C.CH.AUT_ALT", "[gemSpec_PKI]", [];
    CERT_TYPE_HBA_QES = "1.2.276.0.76.4.72", "oid_hba_qes", "C.HP.QES", "[CertsBÄK#1]", [];
    CERT_TYPE_HBA_SIG = "1.2.276.0.76.4.73", "oid_hba_sig", "C.HP.SIG", "", [];
    CERT_TYPE_HBA_ENC = "1.2.276.0.76.4.74", "oid_hba_enc", "C.HP.ENC", "[CertsBÄK#1]", [];
    CERT_TYPE_HBA_AUT = "1.2.276.0.76.4.75", "oid_hba_aut", "C.HP.AUT", "[CertsBÄK#1]", [];
    CERT_TYPE_SMC_B_ENC = "1.2.276.0.76.4.76", "oid_smc_b_enc", "C.HCI.ENC", "[gemSpec_PKI]", [];
    CERT_TYPE_SMC_B_AUT = "1.2.276.0.76.4.77", "oid_smc_b_aut", "C.HCI.AUT", "[gemSpec_PKI]", [];
    CERT_TYPE_SMC_B_OSIG = "1.2.276.0.76.4.78", "oid_smc_b_osig", "C.HCI.OSIG", "[gemSpec_PKI]", [];
    CERT_TYPE_AK_AUT = "1.2.276.0.76.4.79", "oid_ak_aut", "C.AK.AUT", "[gemSpec_PKI]", [];
    CERT_TYPE_NK_VPN = "1.2.276.0.76.4.80", "oid_nk_vpn", "C.NK.VPN", "[gemSpec_PKI]", [];
    CERT_TYPE_VPNK_VPN = "1.2.276.0.76.4.81", "oid_vpnk_vpn", "C.VPNK.VPN", "[gemSpec_PKI]", [];
    CERT_TYPE_SMKT_AUT = "1.2.276.0.76.4.82", "oid_smkt_aut", "C.SMKT.AUT", "[gemSpec_PKI]", [];
    CERT_TYPE_SAK_AUT = "1.2.276.0.76.4.113", "oid_sak_aut", "C.SAK.AUT", "[gemSpec_PKI]", [];
    CERT_TYPE_CM_TLSCS = "1.2.276.0.76.4.175", "oid_cm_tls_c", "C.CM.TLS-CS", "[gemSpec_PKI]", [];
    CERT_TYPE_FD_TLS_C = "1.2.276.0.76.4.168", "oid_fd_tls_c", "C.FD.TLS-C", "[gemSpec_PKI]", [];
    CERT_TYPE_FD_TLS_S = "1.2.276.0.76.4.169", "oid_fd_tls_s", "C.FD.TLS-S", "[gemSpec_PKI]", [];
    CERT_TYPE_FD_AUT = "1.2.276.0.76.4.155", "oid_fd_aut", "C.FD.AUT", "[gemSpec_PKI]", [];
    CERT_TYPE_ZD_TLS_C = "1.2.276.0.76.4.156", "oid_zd_tls_c", "C.ZD.TLS-C", "", [];
    CERT_TYPE_ZD_TLS_S = "1.2.276.0.76.4.157", "oid_zd_tls_s", "C.ZD.TLS-S", "[gemSpec_PKI]", [];
    CERT_TYPE_ZD_AUT = "1.2.276.0.76.4.158", "oid_zd_aut", "C.ZD.AUT", "", [];
    CERT_TYPE_VPNK_VPN_SIS = "1.2.276.0.76.4.165", "oid_vpnk_vpn_sis", "C.VPNK.VPN-SIS", "[gemSpec_PKI]", [];
    CERT_TYPE_FD_SIG = "1.2.276.0.76.4.203", "oid_fd_sig", "C.FD.SIG", "[gemSpec_PKI]", [];
    CERT_TYPE_FD_ENC = "1.2.276.0.76.4.202", "oid_fd_enc", "C.FD.ENC", "[gemSpec_PKI]", [];
    CERT_TYPE_WHK_HSM_AUT = "1.2.276.0.76.4.213", "oid_whk_hsm_aut", "C.WHK-HSM.AUT", "", [];
    CERT_TYPE_VK_PT_ENC = "1.2.276.0.76.4.62", "oid_vk_pt_enc", "C.HP.ENC", "[BÄK_ePA]", [];
    CERT_TYPE_VK_EAA_ENC = "1.3.6.1.4.1.24796.1.10", "oid_vk_eaa_enc", "C.HP.ENC", "[BÄK_eAA]", [];
    CERT_TYPE_FD_OSIG = "1.2.276.0.76.4.283", "oid_fd_osig", "C.FD.OSIG", "[gemSpec_PKI]", [];
    CERT_TYPE_ZD_SIG = "1.2.276.0.76.4.287", "oid_zd_sig", "C.ZD.SIG", "[gemSpec_PKI]", [];
    CERT_TYPE_HSK_SIG = "1.2.276.0.76.4.300", "oid_hsk_sig", "C.HSK.SIG", "[gemSpec_PKI]", [];
    CERT_TYPE_HSK_ENC = "1.2.276.0.76.4.301", "oid_hsk_enc", "C.HSK.ENC", "[gemSpec_PKI]", [];
    CERT_TYPE_GEM_VER = "1.2.276.0.76.4.321", "oid_gem-ver", "C.GEM.VER", "[gemSpec_PKI]", [];

    // Tab_PKI_406 — technical role OIDs (Fachdienste), with the certificate types allowed
    // to carry them. Amended by change C_12646 (Draft_CI_26_3): ZETA Guard moves to
    // C.FD.AUT / C.FD.TLS-C, the OCI image role is renamed, the provisioning-approver role
    // is withdrawn.
    TECH_ROLE_VSDD = "1.2.276.0.76.4.97", "oid_vsdd", "Versichertenstammdatendienst", "", ["C.FD.TLS-S"];
    TECH_ROLE_OCSP = "1.2.276.0.76.4.99", "oid_ocsp", "Online Certificate Status Protocol", "", [];
    TECH_ROLE_CMS = "1.2.276.0.76.4.100", "oid_cms", "Card Management System", "", ["C.FD.TLS-S"];
    TECH_ROLE_UFS = "1.2.276.0.76.4.101", "oid_ufs", "Update Flag Service", "", ["C.FD.TLS-S"];
    TECH_ROLE_AK = "1.2.276.0.76.4.103", "oid_ak", "Anwendungskonnektor", "", ["C.AK.AUT"];
    TECH_ROLE_NK = "1.2.276.0.76.4.104", "oid_nk", "Netzkonnektor", "", ["C.NK.VPN"];
    TECH_ROLE_KT = "1.2.276.0.76.4.105", "oid_kt", "Kartenterminal", "", ["C.SMKT.AUT"];
    TECH_ROLE_SAK = "1.2.276.0.76.4.119", "oid_sak", "Signaturanwendungskomponente", "", ["C.SAK.AUT"];
    TECH_ROLE_INT_VSDM = "1.2.276.0.76.4.159", "oid_int_vsdm", "Intermediär VSDM", "", ["C.FD.TLS-S", "C.FD.TLS-C"];
    TECH_ROLE_KONFIGDIENST = "1.2.276.0.76.4.160", "oid_konfigdienst", "Konfigurationsdienst", "", ["C.ZD.TLS-S"];
    TECH_ROLE_VPNZ_TI = "1.2.276.0.76.4.161", "oid_vpnz_ti", "VPN-Zugangsdienst-TI", "", ["C.VPNK.VPN", "C.ZD.TLS-S"];
    TECH_ROLE_VPNZ_SIS = "1.2.276.0.76.4.166", "oid_vpnz_sis", "VPN-Zugangsdienst-SIS", "", ["C.VPNK.VPN-SIS"];
    TECH_ROLE_CMFD = "1.2.276.0.76.4.174", "oid_cmfd", "Clientmodul", "", ["C.CM.TLS-CS"];
    TECH_ROLE_VZD_TI = "1.2.276.0.76.4.171", "oid_vzd_ti", "Verzeichnisdienst-TI", "", ["C.ZD.TLS-S", "C.FD.SIG"];
    TECH_ROLE_KOMLE = "1.2.276.0.76.4.172", "oid_komle", "KOM-LE Fachdienst", "", ["C.FD.TLS-S", "C.FD.TLS-C"];
    TECH_ROLE_KOMLE_RECIPIENT_EMAILS = "1.2.276.0.76.4.173", "oid_komle-recipient-emails", "KOM-LE S/MIME Attribut recipient-emails", "", [];
    TECH_ROLE_STAMP = "1.2.276.0.76.4.184", "oid_stamp", "Betriebsdatenerfassung", "", ["C.ZD.TLS-S"];
    TECH_ROLE_TSL_TI = "1.2.276.0.76.4.189", "oid_tsl_ti", "TSL-Dienst-TI", "", ["C.ZD.TLS-S"];
    TECH_ROLE_WADG = "1.2.276.0.76.4.198", "oid_wadg", "Weitere elektronische Anwendungen des Gesundheitswesens sowie für die Gesundheitsforschung n. P. 291a Abs. 7 Satz 3 SGB V", "", ["C.FD.TLS-S", "C.FD.SIG", "C.FD.AUT", "C.FD.ENC"];
    TECH_ROLE_EPA_AUTHN = "1.2.276.0.76.4.204", "oid_epa_authn", "ePA Authentisierung", "", ["C.FD.TLS-S", "C.FD.SIG"];
    TECH_ROLE_EPA_AUTHZ = "1.2.276.0.76.4.205", "oid_epa_authz", "ePA Autorisierung", "", ["C.FD.TLS-S", "C.FD.SIG"];
    TECH_ROLE_EPA_DVW = "1.2.276.0.76.4.206", "oid_epa_dvw", "ePA Dokumentenverwaltung", "", ["C.FD.TLS-S"];
    TECH_ROLE_EPA_MGMT = "1.2.276.0.76.4.207", "oid_epa_mgmt", "ePA Management", "", ["C.FD.TLS-S", "C.FD.TLS-C"];
    TECH_ROLE_EPA_RECOVERY = "1.2.276.0.76.4.208", "oid_epa_recovery", "ePA automatisierter Berechtigungserhalt", "", ["C.FD.ENC"];
    TECH_ROLE_EPA_VAU = "1.2.276.0.76.4.209", "oid_epa_vau", "ePA vertrauenswürdige Ausführungsumgebung", "", ["C.FD.AUT", "C.FD.ENC", "C.FD.SIG"];
    TECH_ROLE_VZ_TSP = "1.2.276.0.76.4.215", "oid_vz_tsp", "Zertifikatsverzeichnis TSP X.509", "", [];
    TECH_ROLE_WHK1_HSM = "1.2.276.0.76.4.216", "oid_whk1_hsm", "HSM Wiederherstellungskomponente 1", "", [];
    TECH_ROLE_WHK2_HSM = "1.2.276.0.76.4.217", "oid_whk2_hsm", "HSM Wiederherstellungskomponente 2", "", [];
    TECH_ROLE_WHK = "1.2.276.0.76.4.218", "oid_whk", "Wiederherstellungskomponente", "", [];
    TECH_ROLE_SGD = "1.2.276.0.76.4.221", "oid_sgd", "Schlüsselgenerierungsdienst", "", ["C.FD.TLS-S"];
    TECH_ROLE_ERP_VAU = "1.2.276.0.76.4.258", "oid_erp-vau", "E-Rezept vertrauenswürdige Ausführungsumgebung", "", ["C.FD.ENC", "C.FD.AUT"];
    TECH_ROLE_EREZEPT = "1.2.276.0.76.4.259", "oid_erezept", "E-Rezept", "", ["C.FD.TLS-S", "C.FD.SIG", "C.FD.OSIG", "C.FD.TLS-C"];
    TECH_ROLE_IDPD = "1.2.276.0.76.4.260", "oid_idpd", "IDP-Dienst", "", ["C.FD.TLS-S", "C.FD.SIG"];
    TECH_ROLE_EPA_LOGGING = "1.2.276.0.76.4.261", "oid_epa_logging", "ePA-Aktensystem-Logging", "", ["C.FD.SIG"];
    TECH_ROLE_BESTANDSNETZE = "1.2.276.0.76.4.288", "oid_bestandsnetze", "Bestandsnetze.xml Signatur", "", ["C.ZD.SIG"];
    TECH_ROLE_EPA_VST = "1.2.276.0.76.4.289", "oid_epa_vst", "ePA Vertrauensstelle", "", ["C.FD.TLS-S", "C.FD.ENC", "C.FD.AUT"];
    TECH_ROLE_EPA_FDZ = "1.2.276.0.76.4.290", "oid_epa_fdz", "ePA Forschungsdatenzentrum", "", ["C.FD.TLS-S", "C.FD.ENC", "C.FD.AUT"];
    TECH_ROLE_TIM = "1.2.276.0.76.4.294", "oid_tim", "TI-Messenger", "", ["C.FD.SIG"];
    TECH_ROLE_HSK = "1.2.276.0.76.4.302", "oid_hsk", "Highspeed-Konnektor", "", ["C.HSK.SIG", "C.HSK.ENC"];
    TECH_ROLE_IDPD_SEK = "1.2.276.0.76.4.307", "oid_idpd_sek", "sektoraler IDP", "", ["C.FD.SIG"];
    TECH_ROLE_TIGW_ZUGM = "1.2.276.0.76.4.309", "oid_tigw_zugm", "TI-Gateway Zugangsmodul", "", ["C.FD.OSIG", "C.FD.TLS-S"];
    TECH_ROLE_ZERT_SMB = "1.2.276.0.76.4.310", "oid_zert_smb", "Technische Zertifikatsausgabestelle eines Anbieters SMC-B", "", ["C.FD.TLS-C"];
    TECH_ROLE_POPP = "1.2.276.0.76.4.293", "oid_popp", "Proof of Patient Presence (PoPP) Dienst", "", ["C.ZD.SIG"];
    TECH_ROLE_POPP_TOKEN = "1.2.276.0.76.4.320", "oid_popp-token", "Token-Signatur-Identität für Proof of Patient Presence", "", ["C.ZD.SIG"];
    TECH_ROLE_PKI_VER = "1.2.276.0.76.4.322", "oid_pki-ver", "PKI Change Verifikation", "", ["C.GEM.VER"];
    TECH_ROLE_DIPAG_VAU = "1.2.276.0.76.4.323", "oid_dipag-vau", "Digitale Patientenrechnung vertrauenswürdige Ausführungsumgebung", "", ["C.FD.AUT"];
    TECH_ROLE_ZETA_GUARD = "1.2.276.0.76.4.328", "oid_zeta-guard", "ZETA Guard", "", ["C.FD.AUT", "C.FD.TLS-C"];
    TECH_ROLE_ZETA_POLICIES = "1.2.276.0.76.4.324", "oid_zeta-policies", "ZETA PIP/PAP Policies", "", ["C.FD.SIG"];
    TECH_ROLE_ZETA_OCI = "1.2.276.0.76.4.326", "oid_zeta-oci", "OCI container image für ZETA", "", ["C.FD.SIG"];
    TECH_ROLE_ZETA_POL_AUTHOR = "1.2.276.0.76.4.329", "oid_zeta-pol-author", "ZETA Policy Autor", "", ["C.FD.SIG"];
    TECH_ROLE_ZETA_POL_APPROV = "1.2.276.0.76.4.330", "oid_zeta-pol-approv", "ZETA Policy Freigeber", "", ["C.FD.SIG"];
    TECH_ROLE_ZETA_POL_OPER = "1.2.276.0.76.4.331", "oid_zeta-pol-oper", "ZETA Policy Leitstand", "", ["C.FD.SIG"];
    TECH_ROLE_TSP_EGK = "1.2.276.0.76.4.325", "oid_tsp-egk", "Technische Zertifikatsausgabestelle eines Anbieters EGK", "", ["C.FD.OSIG", "C.FD.TLS-C"];
    TECH_ROLE_CDC_P15G = "1.2.276.0.76.4.327", "oid_cdc-p15g", "Cyber Defense Center Pseudonymisierung", "", ["C.FD.ENC"];
}

/// Tab_PKI_402 minus [`PROF_VERSICHERTER`]: every profession OID an HBA admission
/// extension may carry. Membership here is what makes a certificate "an HBA" to the type
/// detector; the insured person's marker sits in eGK certificates, not on an HBA.
pub const PROFESSIONS: &[ObjectIdentifier] = &[
    PROF_ARZT,
    PROF_ZAHNARZT,
    PROF_APOTHEKER,
    PROF_APOTHEKERASSISTENT,
    PROF_PHARMAZIEINGENIEUR,
    PROF_PHARM_TECHN_ASSISTENT,
    PROF_PHARM_KAUFM_ANGESTELLTER,
    PROF_APOTHEKENHELFER,
    PROF_APOTHEKENASSISTENT,
    PROF_PHARM_ASSISTENT,
    PROF_APOTHEKENFACHARBEITER,
    PROF_PHARMAZIEPRAKTIKANT,
    PROF_FAMULANT,
    PROF_PTA_PRAKTIKANT,
    PROF_PKA_AUSZUBILDENDER,
    PROF_PSYCHOTHERAPEUT,
    PROF_PS_PSYCHOTHERAPEUT,
    PROF_KUJ_PSYCHOTHERAPEUT,
    PROF_RETTUNGSASSISTENT,
    PROF_NOTFALLSANITAETER,
    PROF_PFLEGER_HPC,
    PROF_ALTENPFLEGER_HPC,
    PROF_PFLEGEFACHKRAFT_HPC,
    PROF_HEBAMME_HPC,
    PROF_PHYSIOTHERAPEUT_HPC,
    PROF_AUGENOPTIKER_HPC,
    PROF_HOERAKUSTIKER_HPC,
    PROF_ORTHOPAEDIESCHUHMACHER_HPC,
    PROF_ORTHOPAEDIETECHNIKER_HPC,
    PROF_ZAHNTECHNIKER_HPC,
    PROF_ERGOTHERAPEUT_HPC,
    PROF_LOGOPAEDE_HPC,
    PROF_PODOLOGE_HPC,
    PROF_ERNAEHRUNGSTHERAPEUT_HPC,
    PROF_OPTO_AUDIO_HPC,
    PROF_ORTHOPAED_HPC,
    PROF_HIMI_HPC,
    PROF_FRISEUR_HPC,
    PROF_SOZIOTHERAPEUT,
    PROF_SSSS_THERAPEUT,
    PROF_MASSEUR_MBM_HPC,
    PROF_DIAETASSISTENT,
];

/// The whole of Tab_PKI_403: every institution OID an SMC-B admission extension may
/// carry.
pub const INSTITUTIONS: &[ObjectIdentifier] = &[
    INST_ARZTPRAXIS,
    INST_ZAHNARZTPRAXIS,
    INST_PRAXIS_PSYCHOTHERAPEUT,
    INST_KRANKENHAUS,
    INST_OEFFENTLICHE_APO,
    INST_KRANKENHAUSAPOTHEKE,
    INST_BUNDESWEHRAPOTHEKE,
    INST_MOBILE_EINRICHTUNG_RETTUNG,
    INST_GEMATIK,
    INST_KOSTENTRAEGER,
    INST_LEO_ZAHNAERZTE,
    INST_ADV_KTR,
    INST_LEO_KASSENAERZTLICHE_VEREIN,
    INST_GKV_SPITZENVERBAND,
    INST_LEO_KRANKENHAUSVERBAND,
    INST_LEO_DKTIG,
    INST_LEO_DKG,
    INST_LEO_APOTHEKERVERBAND,
    INST_LEO_DAV,
    INST_LEO_BAEK,
    INST_LEO_AERZTEKAMMER,
    INST_LEO_ZAHNAERZTEKAMMER,
    INST_LEO_KBV,
    INST_LEO_BZAEK,
    INST_LEO_KZBV,
    INST_PFLEGE,
    INST_GEBURTSHILFE,
    INST_PRAXIS_PHYSIOTHERAPEUT,
    INST_AUGENOPTIKER,
    INST_HOERAKUSTIKER,
    INST_ORTHOPAEDIESCHUHMACHER,
    INST_ORTHOPAEDIETECHNIKER,
    INST_ZAHNTECHNIKER,
    INST_RETTUNGSLEITSTELLE,
    INST_SANITAETSDIENST_BW,
    INST_OEGD,
    INST_ARBEITSMEDIZIN,
    INST_VORSORGE_REHA,
    INST_PFLEGEBERATUNG,
    INST_LEO_PSYCHOTHERAPEUTEN,
    INST_LEO_BPTK,
    INST_LEO_LAK,
    INST_LEO_BAK,
    INST_LEO_EGBR,
    INST_LEO_HANDWERKSKAMMER,
    INST_GESUNDHEITSDATENREGISTER,
    INST_ABRECHNUNGSDIENSTLEISTER,
    INST_PKV_VERBAND,
    INST_PRAXIS_ERGOTHERAPEUT,
    INST_PRAXIS_LOGOPAEDE,
    INST_PRAXIS_PODOLOGE,
    INST_PRAXIS_ERNAEHRUNGSTHERAPEUT,
    INST_WEITERE_KOSTENTRAEGER,
    INST_ORG_GESUNDHEITSVERSORGUNG,
    INST_KIM_ANBIETER,
    INST_DIGA,
    INST_TIM_ANBIETER,
    INST_NCPEH,
    INST_OMBUDSSTELLE,
    INST_OPTO_AUDIO,
    INST_ORTHOPAED_HW,
    INST_HIMI,
    INST_FRISEUR,
    INST_SOZIOTHER,
];

#[cfg(test)]
mod tests {
    use super::*;

    // Spot checks against gemSpec_OID, one or more per table, against typos in the data
    // port; re-validating every constant would only shuffle data between two places.
    #[test]
    fn constants_match_the_spec() {
        for (got, want) in [
            (INSTANCE_GEMATIK, "1.2.276.0.76.3.1.91"),
            (PROF_ARZT, "1.2.276.0.76.4.30"),
            (PROF_APOTHEKER, "1.2.276.0.76.4.32"),
            (PROF_PSYCHOTHERAPEUT, "1.2.276.0.76.4.45"),
            (PROF_NOTFALLSANITAETER, "1.2.276.0.76.4.178"),
            (PROF_PFLEGER_HPC, "1.2.276.0.76.4.232"),
            (INST_ARZTPRAXIS, "1.2.276.0.76.4.50"),
            (INST_KRANKENHAUS, "1.2.276.0.76.4.53"),
            (INST_OEFFENTLICHE_APO, "1.2.276.0.76.4.54"),
            (INST_GEMATIK, "1.2.276.0.76.4.58"),
            (POLICY_HBA_CP, "1.2.276.0.76.4.145"),
            (POLICY_GEM_OR_CP, "1.2.276.0.76.4.163"),
            (CERT_TYPE_HBA_QES, "1.2.276.0.76.4.72"),
            (CERT_TYPE_SMC_B_AUT, "1.2.276.0.76.4.77"),
            (CERT_TYPE_FD_TLS_S, "1.2.276.0.76.4.169"),
            (TECH_ROLE_IDPD, "1.2.276.0.76.4.260"),
            (TECH_ROLE_EPA_VAU, "1.2.276.0.76.4.209"),
            (TECH_ROLE_EREZEPT, "1.2.276.0.76.4.259"),
            (TECH_ROLE_ZETA_GUARD, "1.2.276.0.76.4.328"),
        ] {
            assert_eq!(got.to_string(), want);
        }
    }

    #[test]
    fn tables_cover_their_constants() {
        for (name, table) in [("PROFESSIONS", PROFESSIONS), ("INSTITUTIONS", INSTITUTIONS)] {
            for (i, oid) in table.iter().enumerate() {
                assert!(!table[..i].contains(oid), "{name} lists {oid} twice");
            }
            assert!(table.len() > 40, "{name} looks truncated");
        }
        assert!(INSTITUTIONS.contains(&INST_ARZTPRAXIS));
        assert!(PROFESSIONS.contains(&PROF_ARZT));
        assert!(
            !PROFESSIONS.contains(&PROF_VERSICHERTER),
            "the eGK marker is not a profession"
        );
    }

    #[test]
    fn every_constant_has_one_entry() {
        for (i, info) in TABLE.iter().enumerate() {
            assert!(
                !TABLE[..i].iter().any(|other| other.oid == info.oid),
                "{} declared twice",
                info.oid
            );
        }
    }

    #[test]
    fn format_and_lookup() {
        assert_eq!(
            format(&TECH_ROLE_ZETA_GUARD),
            "1.2.276.0.76.4.328 (ZETA Guard)"
        );
        assert_eq!(format(&CERT_TYPE_FD_AUT), "1.2.276.0.76.4.155 (C.FD.AUT)");
        assert_eq!(format(&ObjectIdentifier::new_unwrap("1.2.3.4")), "1.2.3.4");

        let info = lookup(&POLICY_GEM_TSL_SIGNER).unwrap();
        assert_eq!(info.reference, "oid_policy_gem_tsl_signer");
        assert_eq!(info.document, "[gemSpec_TSL]");
        assert_eq!(
            lookup(&TECH_ROLE_ZETA_GUARD).unwrap().certificate_types,
            ["C.FD.AUT", "C.FD.TLS-C"]
        );
    }
}
