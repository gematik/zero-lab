// Copyright (Change Date see Readme), gematik GmbH
//
// Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the
// European Commission – subsequent versions of the EUPL (the "Licence").
// You may not use this work except in compliance with the Licence.
//
// You find a copy of the Licence in the "Licence" file or at
// https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the Licence is distributed on an "AS IS" basis,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied.
// In case of changes by gematik find details in the "Readme" file.
//
// See the Licence for the specific language governing permissions and limitations under the Licence.
//
// *******
//
// For additional notes and disclaimer from gematik and in case of changes by gematik,
// find details in the "Readme" file.

// Package oid holds the object identifiers gemSpec_OID defines for the TI, each with the
// specification's reference name and description. The tables are those of Rust's ti-pki, as of
// gemSpec_OID V3.26.0, and spec/pki-profiles holds the two to the same values. Identifiers are
// binary, as crypto/x509 reads them from a certificate; the dotted form is for reading.
package oid

import (
	"crypto/x509"
	"fmt"
)

// AdmissionExtension is the ISIS-MTT admission extension, carrying the profession information of
// SMC-B and HBA cards.
var AdmissionExtension = MustParse("1.3.36.8.3.3")

// The identifiers, by the name of the Go gempki, under Tab_PKI_401 to 406.
var (
	InstanceKBV                    = MustParse("1.2.276.0.76.3.1.1")     // oid_kbv
	InstanceBAEK                   = MustParse("1.2.276.0.76.3.1.95")    // oid_baek
	InstanceKZBV                   = MustParse("1.2.276.0.76.3.1.99")    // oid_kzbv
	InstanceBZAEK                  = MustParse("1.2.276.0.76.3.1.96")    // oid_bzaek
	InstanceDKG                    = MustParse("1.2.276.0.76.3.1.49")    // oid_dkg
	InstanceBPtK                   = MustParse("1.2.276.0.76.3.1.90")    // oid_bptk
	InstanceGematik                = MustParse("1.2.276.0.76.3.1.91")    // oid_gematik
	ProfArzt                       = MustParse("1.2.276.0.76.4.30")      // oid_arzt
	ProfZahnarzt                   = MustParse("1.2.276.0.76.4.31")      // oid_zahnarzt
	ProfApotheker                  = MustParse("1.2.276.0.76.4.32")      // oid_apotheker
	ProfApothekerassistent         = MustParse("1.2.276.0.76.4.33")      // oid_apothekerassistent
	ProfPharmazieingenieur         = MustParse("1.2.276.0.76.4.34")      // oid_pharmazieingenieur
	ProfPharmTechnAssistent        = MustParse("1.2.276.0.76.4.35")      // oid_pharm_techn_assistent
	ProfPharmKaufmAngestellter     = MustParse("1.2.276.0.76.4.36")      // oid_pharm_kaufm_angestellter
	ProfApothekenhelfer            = MustParse("1.2.276.0.76.4.37")      // oid_apothekenhelfer
	ProfApothekenassistent         = MustParse("1.2.276.0.76.4.38")      // oid_apothekenassistent
	ProfPharmAssistent             = MustParse("1.2.276.0.76.4.39")      // oid_pharm_assistent
	ProfApothekenfacharbeiter      = MustParse("1.2.276.0.76.4.40")      // oid_apothekenfacharbeiter
	ProfPharmaziepraktikant        = MustParse("1.2.276.0.76.4.41")      // oid_pharmaziepraktikant
	ProfFamulant                   = MustParse("1.2.276.0.76.4.42")      // oid_famulant
	ProfPTAPraktikant              = MustParse("1.2.276.0.76.4.43")      // oid_pta_praktikant
	ProfPKAAuszubildender          = MustParse("1.2.276.0.76.4.44")      // oid_pka_auszubildender
	ProfPsychotherapeut            = MustParse("1.2.276.0.76.4.45")      // oid_psychotherapeut
	ProfPsPsychotherapeut          = MustParse("1.2.276.0.76.4.46")      // oid_ps_psychotherapeut
	ProfKuJPsychotherapeut         = MustParse("1.2.276.0.76.4.47")      // oid_kuj_psychotherapeut
	ProfRettungsassistent          = MustParse("1.2.276.0.76.4.48")      // oid_rettungsassistent
	ProfVersicherter               = MustParse("1.2.276.0.76.4.49")      // oid_versicherter
	ProfNotfallsanitaeter          = MustParse("1.2.276.0.76.4.178")     // oid_notfallsanitaeter
	ProfPflegerHPC                 = MustParse("1.2.276.0.76.4.232")     // oid_pfleger-hpc
	ProfAltenpflegerHPC            = MustParse("1.2.276.0.76.4.233")     // oid_altenpfleger-hpc
	ProfPflegefachkraftHPC         = MustParse("1.2.276.0.76.4.234")     // oid_pflegefachkraft-hpc
	ProfHebammeHPC                 = MustParse("1.2.276.0.76.4.235")     // oid_hebamme-hpc
	ProfPhysiotherapeutHPC         = MustParse("1.2.276.0.76.4.236")     // oid_physiotherapeut-hpc
	ProfAugenoptikerHPC            = MustParse("1.2.276.0.76.4.237")     // oid_augenoptiker-hpc
	ProfHoerakustikerHPC           = MustParse("1.2.276.0.76.4.238")     // oid_hoerakustiker-hpc
	ProfOrthopaedieschuhmacherHPC  = MustParse("1.2.276.0.76.4.239")     // oid_orthopaedieschuhmacher-hpc
	ProfOrthopaedietechnikerHPC    = MustParse("1.2.276.0.76.4.240")     // oid_orthopaedietechniker-hpc
	ProfZahntechnikerHPC           = MustParse("1.2.276.0.76.4.241")     // oid_zahntechniker-hpc
	ProfErgotherapeutHPC           = MustParse("1.2.276.0.76.4.274")     // oid_ergotherapeut-hpc
	ProfLogopaedeHPC               = MustParse("1.2.276.0.76.4.275")     // oid_logopaede-hpc
	ProfPodologeHPC                = MustParse("1.2.276.0.76.4.276")     // oid_podologe-hpc
	ProfErnaehrungstherapeutHPC    = MustParse("1.2.276.0.76.4.277")     // oid_ernaehrungstherapeut-hpc
	ProfOptoAudioHPC               = MustParse("1.2.276.0.76.4.308")     // oid_opto-audio-hpc
	ProfOrthopaedHPC               = MustParse("1.2.276.0.76.4.305")     // oid_orthopaed-hpc
	ProfHimiHPC                    = MustParse("1.2.276.0.76.4.312")     // oid_himi-hpc
	ProfFriseurHPC                 = MustParse("1.2.276.0.76.4.313")     // oid_friseur-hpc
	ProfSoziotherapeut             = MustParse("1.2.276.0.76.4.316")     // oid_soziotherapeut
	ProfSSSSTherapeut              = MustParse("1.2.276.0.76.4.318")     // oid_ssss-therapeut
	ProfMasseurMBMHPC              = MustParse("1.2.276.0.76.4.315")     // oid_masseur-mbm-hpc
	ProfDiaetassistent             = MustParse("1.2.276.0.76.4.319")     // oid_diaetassistent
	InstArztpraxis                 = MustParse("1.2.276.0.76.4.50")      // oid_praxis_arzt
	InstZahnarztpraxis             = MustParse("1.2.276.0.76.4.51")      // oid_zahnarztpraxis
	InstPraxisPsychotherapeut      = MustParse("1.2.276.0.76.4.52")      // oid_praxis_psychotherapeut
	InstKrankenhaus                = MustParse("1.2.276.0.76.4.53")      // oid_krankenhaus
	InstOeffentlicheApo            = MustParse("1.2.276.0.76.4.54")      // oid_oeffentliche_apotheke
	InstKrankenhausapotheke        = MustParse("1.2.276.0.76.4.55")      // oid_krankenhausapotheke
	InstBundeswehrapotheke         = MustParse("1.2.276.0.76.4.56")      // oid_bundeswehrapotheke
	InstMobileEinrichtungRettung   = MustParse("1.2.276.0.76.4.57")      // oid_mobile_einrichtung_rettungsdienst
	InstGematik                    = MustParse("1.2.276.0.76.4.58")      // oid_bs_gematik
	InstKostentraeger              = MustParse("1.2.276.0.76.4.59")      // oid_kostentraeger
	InstLeoZahnaerzte              = MustParse("1.2.276.0.76.4.187")     // oid_leo_zahnaerzte
	InstAdvKtr                     = MustParse("1.2.276.0.76.4.190")     // oid_adv_ktr
	InstLeoKassenaerztlicheVerein  = MustParse("1.2.276.0.76.4.210")     // oid_leo_kassenaerztliche_vereinigung
	InstGKVSpitzenverband          = MustParse("1.2.276.0.76.4.223")     // oid_bs_gkv_spitzenverband
	InstLeoKrankenhausverband      = MustParse("1.2.276.0.76.4.226")     // oid_leo_krankenhausverband
	InstLeoDKTIG                   = MustParse("1.2.276.0.76.4.227")     // oid_leo_dktig
	InstLeoDKG                     = MustParse("1.2.276.0.76.4.228")     // oid_leo_dkg
	InstLeoApothekerverband        = MustParse("1.2.276.0.76.4.224")     // oid_leo_apothekerverband
	InstLeoDAV                     = MustParse("1.2.276.0.76.4.225")     // oid_leo_dav
	InstLeoBAEK                    = MustParse("1.2.276.0.76.4.229")     // oid_leo_baek
	InstLeoAerztekammer            = MustParse("1.2.276.0.76.4.230")     // oid_leo_aerztekammer
	InstLeoZahnaerztekammer        = MustParse("1.2.276.0.76.4.231")     // oid_leo_zahnaerztekammer
	InstLeoKBV                     = MustParse("1.2.276.0.76.4.242")     // oid_leo-kbv
	InstLeoBZAEK                   = MustParse("1.2.276.0.76.4.243")     // oid_leo-bzaek
	InstLeoKZBV                    = MustParse("1.2.276.0.76.4.244")     // oid_leo-kzbv
	InstPflege                     = MustParse("1.2.276.0.76.4.245")     // oid_institution-pflege
	InstGeburtshilfe               = MustParse("1.2.276.0.76.4.246")     // oid_institution-geburtshilfe
	InstPraxisPhysiotherapeut      = MustParse("1.2.276.0.76.4.247")     // oid_praxis-physiotherapeut
	InstAugenoptiker               = MustParse("1.2.276.0.76.4.248")     // oid_institution-augenoptiker
	InstHoerakustiker              = MustParse("1.2.276.0.76.4.249")     // oid_institution-hoerakustiker
	InstOrthopaedieschuhmacher     = MustParse("1.2.276.0.76.4.250")     // oid_institution-orthopaedieschuhmacher
	InstOrthopaedietechniker       = MustParse("1.2.276.0.76.4.251")     // oid_institution-orthopaedietechniker
	InstZahntechniker              = MustParse("1.2.276.0.76.4.252")     // oid_institution-zahntechniker
	InstRettungsleitstelle         = MustParse("1.2.276.0.76.4.253")     // oid_institution-rettungsleitstellen
	InstSanitaetsdienstBW          = MustParse("1.2.276.0.76.4.254")     // oid_sanitaetsdienst-bundeswehr
	InstOEGD                       = MustParse("1.2.276.0.76.4.255")     // oid_institution-oegd
	InstArbeitsmedizin             = MustParse("1.2.276.0.76.4.256")     // oid_institution-arbeitsmedizin
	InstVorsorgeReha               = MustParse("1.2.276.0.76.4.257")     // oid_institution-vorsorge-reha
	InstPflegeberatung             = MustParse("1.2.276.0.76.4.262")     // oid_pflegeberatung
	InstLeoPsychotherapeuten       = MustParse("1.2.276.0.76.4.263")     // oid_leo_psychotherapeuten
	InstLeoBPtK                    = MustParse("1.2.276.0.76.4.264")     // oid_leo_bptk
	InstLeoLAK                     = MustParse("1.2.276.0.76.4.265")     // oid_leo_lak
	InstLeoBAK                     = MustParse("1.2.276.0.76.4.266")     // oid_leo_bak
	InstLeoEGBR                    = MustParse("1.2.276.0.76.4.267")     // oid_leo_egbr
	InstLeoHandwerkskammer         = MustParse("1.2.276.0.76.4.268")     // oid_leo_handwerkskammer
	InstGesundheitsdatenregister   = MustParse("1.2.276.0.76.4.269")     // oid_gesundheitsdatenregister
	InstAbrechnungsdienstleister   = MustParse("1.2.276.0.76.4.270")     // oid_abrechnungsdienstleister
	InstPKVVerband                 = MustParse("1.2.276.0.76.4.271")     // oid_pkv_verband
	InstPraxisErgotherapeut        = MustParse("1.2.276.0.76.4.278")     // oid_praxis-ergotherapeut
	InstPraxisLogopaede            = MustParse("1.2.276.0.76.4.279")     // oid_praxis-logopaede
	InstPraxisPodologe             = MustParse("1.2.276.0.76.4.280")     // oid_praxis-podologe
	InstPraxisErnaehrungstherapeut = MustParse("1.2.276.0.76.4.281")     // oid_praxis-ernaehrungstherapeut
	InstWeitereKostentraeger       = MustParse("1.2.276.0.76.4.284")     // oid_bs-weitere-kostentraeger
	InstOrgGesundheitsversorgung   = MustParse("1.2.276.0.76.4.285")     // oid_org-gesundheitsversorgung
	InstKIMAnbieter                = MustParse("1.2.276.0.76.4.286")     // oid_kim-anbieter
	InstDiGA                       = MustParse("1.2.276.0.76.4.282")     // oid_diga
	InstTIMAnbieter                = MustParse("1.2.276.0.76.4.295")     // oid_tim-anbieter
	InstNCPeH                      = MustParse("1.2.276.0.76.4.292")     // oid_ncpeh
	InstOmbudsstelle               = MustParse("1.2.276.0.76.4.303")     // oid_ombudsstelle
	InstOptoAudio                  = MustParse("1.2.276.0.76.4.304")     // oid_bs-opto-audio
	InstOrthopaedHW                = MustParse("1.2.276.0.76.4.306")     // oid_bs-orthopaed-hw
	InstHimi                       = MustParse("1.2.276.0.76.4.311")     // oid_bs-himi
	InstFriseur                    = MustParse("1.2.276.0.76.4.314")     // oid_bs-friseur
	InstSoziother                  = MustParse("1.2.276.0.76.4.317")     // oid_bs-soziother
	PolicyHbaCP                    = MustParse("1.2.276.0.76.4.145")     // oid_policy_hba_cp
	PolicyGemOrCP                  = MustParse("1.2.276.0.76.4.163")     // oid_policy_gem_or_cp
	PolicyGemTSLSigner             = MustParse("1.2.276.0.76.4.176")     // oid_policy_gem_tsl_signer
	CertTypeEgkQES                 = MustParse("1.2.276.0.76.4.66")      // oid_egk_qes
	CertTypeEgkSIG                 = MustParse("1.2.276.0.76.4.67")      // oid_egk_sig
	CertTypeEgkENC                 = MustParse("1.2.276.0.76.4.68")      // oid_egk_enc
	CertTypeEgkENCV                = MustParse("1.2.276.0.76.4.69")      // oid_egk_encv
	CertTypeEgkAUT                 = MustParse("1.2.276.0.76.4.70")      // oid_egk_aut
	CertTypeEgkAUTN                = MustParse("1.2.276.0.76.4.71")      // oid_egk_autn
	CertTypeEgkENCAlt              = MustParse("1.2.276.0.76.4.211")     // oid_egk_enc_alt
	CertTypeEgkAUTAlt              = MustParse("1.2.276.0.76.4.212")     // oid_egk_aut_alt
	CertTypeHbaQES                 = MustParse("1.2.276.0.76.4.72")      // oid_hba_qes
	CertTypeHbaSIG                 = MustParse("1.2.276.0.76.4.73")      // oid_hba_sig
	CertTypeHbaENC                 = MustParse("1.2.276.0.76.4.74")      // oid_hba_enc
	CertTypeHbaAUT                 = MustParse("1.2.276.0.76.4.75")      // oid_hba_aut
	CertTypeSmcBENC                = MustParse("1.2.276.0.76.4.76")      // oid_smc_b_enc
	CertTypeSmcBAUT                = MustParse("1.2.276.0.76.4.77")      // oid_smc_b_aut
	CertTypeSmcBOSIG               = MustParse("1.2.276.0.76.4.78")      // oid_smc_b_osig
	CertTypeAkAUT                  = MustParse("1.2.276.0.76.4.79")      // oid_ak_aut
	CertTypeNkVPN                  = MustParse("1.2.276.0.76.4.80")      // oid_nk_vpn
	CertTypeVpnkVPN                = MustParse("1.2.276.0.76.4.81")      // oid_vpnk_vpn
	CertTypeSmktAUT                = MustParse("1.2.276.0.76.4.82")      // oid_smkt_aut
	CertTypeSakAUT                 = MustParse("1.2.276.0.76.4.113")     // oid_sak_aut
	CertTypeCmTLSCS                = MustParse("1.2.276.0.76.4.175")     // oid_cm_tls_c
	CertTypeFdTLSC                 = MustParse("1.2.276.0.76.4.168")     // oid_fd_tls_c
	CertTypeFdTLSS                 = MustParse("1.2.276.0.76.4.169")     // oid_fd_tls_s
	CertTypeFdAUT                  = MustParse("1.2.276.0.76.4.155")     // oid_fd_aut
	CertTypeZdTLSC                 = MustParse("1.2.276.0.76.4.156")     // oid_zd_tls_c
	CertTypeZdTLSS                 = MustParse("1.2.276.0.76.4.157")     // oid_zd_tls_s
	CertTypeZdAUT                  = MustParse("1.2.276.0.76.4.158")     // oid_zd_aut
	CertTypeVpnkVPNSIS             = MustParse("1.2.276.0.76.4.165")     // oid_vpnk_vpn_sis
	CertTypeFdSIG                  = MustParse("1.2.276.0.76.4.203")     // oid_fd_sig
	CertTypeFdENC                  = MustParse("1.2.276.0.76.4.202")     // oid_fd_enc
	CertTypeWhkHsmAUT              = MustParse("1.2.276.0.76.4.213")     // oid_whk_hsm_aut
	CertTypeVkPtENC                = MustParse("1.2.276.0.76.4.62")      // oid_vk_pt_enc
	CertTypeVkEaaENC               = MustParse("1.3.6.1.4.1.24796.1.10") // oid_vk_eaa_enc
	CertTypeFdOSIG                 = MustParse("1.2.276.0.76.4.283")     // oid_fd_osig
	CertTypeZdSIG                  = MustParse("1.2.276.0.76.4.287")     // oid_zd_sig
	CertTypeHskSIG                 = MustParse("1.2.276.0.76.4.300")     // oid_hsk_sig
	CertTypeHskENC                 = MustParse("1.2.276.0.76.4.301")     // oid_hsk_enc
	CertTypeGemVER                 = MustParse("1.2.276.0.76.4.321")     // oid_gem-ver
	CVRootCert                     = MustParse("1.2.276.0.76.4.185")     // oid_cv_rootcert
	CVCert                         = MustParse("1.2.276.0.76.4.186")     // oid_cv_cert
	TechRoleVSDD                   = MustParse("1.2.276.0.76.4.97")      // oid_vsdd
	TechRoleOCSP                   = MustParse("1.2.276.0.76.4.99")      // oid_ocsp
	TechRoleCMS                    = MustParse("1.2.276.0.76.4.100")     // oid_cms
	TechRoleUFS                    = MustParse("1.2.276.0.76.4.101")     // oid_ufs
	TechRoleAK                     = MustParse("1.2.276.0.76.4.103")     // oid_ak
	TechRoleNK                     = MustParse("1.2.276.0.76.4.104")     // oid_nk
	TechRoleKT                     = MustParse("1.2.276.0.76.4.105")     // oid_kt
	TechRoleSAK                    = MustParse("1.2.276.0.76.4.119")     // oid_sak
	TechRoleIntVSDM                = MustParse("1.2.276.0.76.4.159")     // oid_int_vsdm
	TechRoleKonfigdienst           = MustParse("1.2.276.0.76.4.160")     // oid_konfigdienst
	TechRoleVPNZTI                 = MustParse("1.2.276.0.76.4.161")     // oid_vpnz_ti
	TechRoleVPNZSIS                = MustParse("1.2.276.0.76.4.166")     // oid_vpnz_sis
	TechRoleCMFD                   = MustParse("1.2.276.0.76.4.174")     // oid_cmfd
	TechRoleVZDTI                  = MustParse("1.2.276.0.76.4.171")     // oid_vzd_ti
	TechRoleKOMLE                  = MustParse("1.2.276.0.76.4.172")     // oid_komle
	TechRoleKOMLERecipientEmails   = MustParse("1.2.276.0.76.4.173")     // oid_komle-recipient-emails
	TechRoleStamp                  = MustParse("1.2.276.0.76.4.184")     // oid_stamp
	TechRoleTSLTI                  = MustParse("1.2.276.0.76.4.189")     // oid_tsl_ti
	TechRoleWADG                   = MustParse("1.2.276.0.76.4.198")     // oid_wadg
	TechRoleEpaAuthn               = MustParse("1.2.276.0.76.4.204")     // oid_epa_authn
	TechRoleEpaAuthz               = MustParse("1.2.276.0.76.4.205")     // oid_epa_authz
	TechRoleEpaDvw                 = MustParse("1.2.276.0.76.4.206")     // oid_epa_dvw
	TechRoleEpaMgmt                = MustParse("1.2.276.0.76.4.207")     // oid_epa_mgmt
	TechRoleEpaRecovery            = MustParse("1.2.276.0.76.4.208")     // oid_epa_recovery
	TechRoleEpaVAU                 = MustParse("1.2.276.0.76.4.209")     // oid_epa_vau
	TechRoleVzTSP                  = MustParse("1.2.276.0.76.4.215")     // oid_vz_tsp
	TechRoleWHK1HSM                = MustParse("1.2.276.0.76.4.216")     // oid_whk1_hsm
	TechRoleWHK2HSM                = MustParse("1.2.276.0.76.4.217")     // oid_whk2_hsm
	TechRoleWHK                    = MustParse("1.2.276.0.76.4.218")     // oid_whk
	TechRoleSGD                    = MustParse("1.2.276.0.76.4.221")     // oid_sgd
	TechRoleERPVAU                 = MustParse("1.2.276.0.76.4.258")     // oid_erp-vau
	TechRoleERezept                = MustParse("1.2.276.0.76.4.259")     // oid_erezept
	TechRoleIDPD                   = MustParse("1.2.276.0.76.4.260")     // oid_idpd
	TechRoleEpaLogging             = MustParse("1.2.276.0.76.4.261")     // oid_epa_logging
	TechRoleBestandsnetze          = MustParse("1.2.276.0.76.4.288")     // oid_bestandsnetze
	TechRoleEpaVST                 = MustParse("1.2.276.0.76.4.289")     // oid_epa_vst
	TechRoleEpaFDZ                 = MustParse("1.2.276.0.76.4.290")     // oid_epa_fdz
	TechRoleTIM                    = MustParse("1.2.276.0.76.4.294")     // oid_tim
	TechRoleHSK                    = MustParse("1.2.276.0.76.4.302")     // oid_hsk
	TechRoleIDPDSek                = MustParse("1.2.276.0.76.4.307")     // oid_idpd_sek
	TechRoleTIGWZugm               = MustParse("1.2.276.0.76.4.309")     // oid_tigw_zugm
	TechRoleZertSMB                = MustParse("1.2.276.0.76.4.310")     // oid_zert_smb
	TechRolePoPP                   = MustParse("1.2.276.0.76.4.293")     // oid_popp
	TechRolePoPPToken              = MustParse("1.2.276.0.76.4.320")     // oid_popp-token
	TechRolePKIVer                 = MustParse("1.2.276.0.76.4.322")     // oid_pki-ver
	TechRoleDipagVAU               = MustParse("1.2.276.0.76.4.323")     // oid_dipag-vau
	TechRoleZETAGuard              = MustParse("1.2.276.0.76.4.328")     // oid_zeta-guard
	TechRoleZETAPolicies           = MustParse("1.2.276.0.76.4.324")     // oid_zeta-policies
	TechRoleZETAOCI                = MustParse("1.2.276.0.76.4.326")     // oid_zeta-oci
	TechRoleZETAPolAuthor          = MustParse("1.2.276.0.76.4.329")     // oid_zeta-pol-author
	TechRoleZETAPolApprov          = MustParse("1.2.276.0.76.4.330")     // oid_zeta-pol-approv
	TechRoleZETAPolOper            = MustParse("1.2.276.0.76.4.331")     // oid_zeta-pol-oper
	TechRoleZETAPrvApprov          = MustParse("1.2.276.0.76.4.332")     // oid_zeta-prv-approv
	TechRoleTSPEgk                 = MustParse("1.2.276.0.76.4.325")     // oid_tsp-egk
	TechRoleCDCP15G                = MustParse("1.2.276.0.76.4.327")     // oid_cdc-p15g
)

// Info is what gemSpec_OID records about an identifier.
type Info struct {
	OID x509.OID
	// Reference is the gemSpec_OID reference name, e.g. oid_policy_gem_or_cp.
	Reference string
	// Description is the specification's wording, in German where its table reads so; for a
	// certificate type the type's name.
	Description string
	// Document is the defining document, e.g. [gemSpec_TSL]; empty if the table names none.
	Document string
	// CertificateTypes are, for a technical role, the types whose admission may carry it.
	CertificateTypes []string
}

var table = []Info{
	{OID: InstanceKBV, Reference: "oid_kbv", Description: "KBV Kassenärztliche Bundesvereinigung"},
	{OID: InstanceBAEK, Reference: "oid_baek", Description: "Bundesärztekammer"},
	{OID: InstanceKZBV, Reference: "oid_kzbv", Description: "Kassenzahnärztliche Bundesvereinigung KZBV"},
	{OID: InstanceBZAEK, Reference: "oid_bzaek", Description: "Bundeszahnärztekammer"},
	{OID: InstanceDKG, Reference: "oid_dkg", Description: "Deutsche Krankenhausgesellschaft DKG"},
	{OID: InstanceBPtK, Reference: "oid_bptk", Description: "Bundespsychotherapeutenkammer BPTK"},
	{OID: InstanceGematik, Reference: "oid_gematik", Description: "gematik Gesellschaft für Telematikanwendungen der Gesundheitskarte mbH"},
	{OID: ProfArzt, Reference: "oid_arzt", Description: "Ärztin/Arzt"},
	{OID: ProfZahnarzt, Reference: "oid_zahnarzt", Description: "Zahnärztin/Zahnarzt"},
	{OID: ProfApotheker, Reference: "oid_apotheker", Description: "Apotheker/-in"},
	{OID: ProfApothekerassistent, Reference: "oid_apothekerassistent", Description: "Apothekerassistent/-in"},
	{OID: ProfPharmazieingenieur, Reference: "oid_pharmazieingenieur", Description: "Pharmazieingenieur/-in"},
	{OID: ProfPharmTechnAssistent, Reference: "oid_pharm_techn_assistent", Description: "pharmazeutisch-technische/-r Assistent/-in"},
	{OID: ProfPharmKaufmAngestellter, Reference: "oid_pharm_kaufm_angestellter", Description: "pharmazeutisch-kaufmännische/-r Angestellte"},
	{OID: ProfApothekenhelfer, Reference: "oid_apothekenhelfer", Description: "Apothekenhelfer/-in"},
	{OID: ProfApothekenassistent, Reference: "oid_apothekenassistent", Description: "Apothekenassistent/-in"},
	{OID: ProfPharmAssistent, Reference: "oid_pharm_assistent", Description: "Pharmazeutische/-r Assistent/-in"},
	{OID: ProfApothekenfacharbeiter, Reference: "oid_apothekenfacharbeiter", Description: "Apothekenfacharbeiter/-in"},
	{OID: ProfPharmaziepraktikant, Reference: "oid_pharmaziepraktikant", Description: "Pharmaziepraktikant/-in"},
	{OID: ProfFamulant, Reference: "oid_famulant", Description: "Stud.pharm. oder Famulant/-in"},
	{OID: ProfPTAPraktikant, Reference: "oid_pta_praktikant", Description: "PTA-Praktikant/-in"},
	{OID: ProfPKAAuszubildender, Reference: "oid_pka_auszubildender", Description: "PKA Auszubildende/-r"},
	{OID: ProfPsychotherapeut, Reference: "oid_psychotherapeut", Description: "Psychotherapeut/-in"},
	{OID: ProfPsPsychotherapeut, Reference: "oid_ps_psychotherapeut", Description: "Psychologische/-r Psychotherapeut/-in"},
	{OID: ProfKuJPsychotherapeut, Reference: "oid_kuj_psychotherapeut", Description: "Kinder- und Jugendlichenpsychotherapeut/-in"},
	{OID: ProfRettungsassistent, Reference: "oid_rettungsassistent", Description: "Rettungsassistent/-in"},
	{OID: ProfVersicherter, Reference: "oid_versicherter", Description: "Versicherte/-r"},
	{OID: ProfNotfallsanitaeter, Reference: "oid_notfallsanitaeter", Description: "Notfallsanitäter/-in"},
	{OID: ProfPflegerHPC, Reference: "oid_pfleger-hpc", Description: "Gesundheits- und Krankenpfleger/-in, Gesundheits- und Kinderkrankenpfleger/-in"},
	{OID: ProfAltenpflegerHPC, Reference: "oid_altenpfleger-hpc", Description: "Altenpfleger/-in"},
	{OID: ProfPflegefachkraftHPC, Reference: "oid_pflegefachkraft-hpc", Description: "Pflegefachfrauen und Pflegefachmänner"},
	{OID: ProfHebammeHPC, Reference: "oid_hebamme-hpc", Description: "Hebamme"},
	{OID: ProfPhysiotherapeutHPC, Reference: "oid_physiotherapeut-hpc", Description: "Physiotherapeut/-in"},
	{OID: ProfAugenoptikerHPC, Reference: "oid_augenoptiker-hpc", Description: "Augenoptiker/-in"},
	{OID: ProfHoerakustikerHPC, Reference: "oid_hoerakustiker-hpc", Description: "Hörakustiker/-in"},
	{OID: ProfOrthopaedieschuhmacherHPC, Reference: "oid_orthopaedieschuhmacher-hpc", Description: "Orthopädieschuhmacher/-in"},
	{OID: ProfOrthopaedietechnikerHPC, Reference: "oid_orthopaedietechniker-hpc", Description: "Orthopädietechniker/-in"},
	{OID: ProfZahntechnikerHPC, Reference: "oid_zahntechniker-hpc", Description: "Zahntechniker/-in"},
	{OID: ProfErgotherapeutHPC, Reference: "oid_ergotherapeut-hpc", Description: "Ergotherapeut/-in"},
	{OID: ProfLogopaedeHPC, Reference: "oid_logopaede-hpc", Description: "Logopäde/Logopädin"},
	{OID: ProfPodologeHPC, Reference: "oid_podologe-hpc", Description: "Podologe/Podologin"},
	{OID: ProfErnaehrungstherapeutHPC, Reference: "oid_ernaehrungstherapeut-hpc", Description: "Leistungserbringer/-in Ernährungstherapie"},
	{OID: ProfOptoAudioHPC, Reference: "oid_opto-audio-hpc", Description: "Augenoptiker/-in und Hörakustiker/-in"},
	{OID: ProfOrthopaedHPC, Reference: "oid_orthopaed-hpc", Description: "Orthopädieschuhmacher/-in und Orthopädietechniker/-in"},
	{OID: ProfHimiHPC, Reference: "oid_himi-hpc", Description: "Hilfsmittelerbringer/-in"},
	{OID: ProfFriseurHPC, Reference: "oid_friseur-hpc", Description: "Frisör/-in"},
	{OID: ProfSoziotherapeut, Reference: "oid_soziotherapeut", Description: "Leistungserbringer/-in Soziotherapie"},
	{OID: ProfSSSSTherapeut, Reference: "oid_ssss-therapeut", Description: "Leistungserbringer/in Stimm-, Sprech-, Sprach- und Schluck-Therapie"},
	{OID: ProfMasseurMBMHPC, Reference: "oid_masseur-mbm-hpc", Description: "Masseur/-in und medizinische/-r Bademeister/-in"},
	{OID: ProfDiaetassistent, Reference: "oid_diaetassistent", Description: "Diätassistent/-in"},
	{OID: InstArztpraxis, Reference: "oid_praxis_arzt", Description: "Betriebsstätte Arzt"},
	{OID: InstZahnarztpraxis, Reference: "oid_zahnarztpraxis", Description: "Zahnarztpraxis"},
	{OID: InstPraxisPsychotherapeut, Reference: "oid_praxis_psychotherapeut", Description: "Betriebsstätte Psychotherapeut"},
	{OID: InstKrankenhaus, Reference: "oid_krankenhaus", Description: "Krankenhaus"},
	{OID: InstOeffentlicheApo, Reference: "oid_oeffentliche_apotheke", Description: "Öffentliche Apotheke"},
	{OID: InstKrankenhausapotheke, Reference: "oid_krankenhausapotheke", Description: "Krankenhausapotheke"},
	{OID: InstBundeswehrapotheke, Reference: "oid_bundeswehrapotheke", Description: "Bundeswehrapotheke"},
	{OID: InstMobileEinrichtungRettung, Reference: "oid_mobile_einrichtung_rettungsdienst", Description: "Betriebsstätte Mobile Einrichtung Rettungsdienst"},
	{OID: InstGematik, Reference: "oid_bs_gematik", Description: "Betriebsstätte gematik"},
	{OID: InstKostentraeger, Reference: "oid_kostentraeger", Description: "Betriebsstätte Kostenträger"},
	{OID: InstLeoZahnaerzte, Reference: "oid_leo_zahnaerzte", Description: "Betriebsstätte Leistungserbringerorganisation Vertragszahnärzte"},
	{OID: InstAdvKtr, Reference: "oid_adv_ktr", Description: "AdV-Umgebung bei Kostenträger"},
	{OID: InstLeoKassenaerztlicheVerein, Reference: "oid_leo_kassenaerztliche_vereinigung", Description: "Betriebsstätte Leistungserbringerorganisation Kassenärztliche Vereinigung"},
	{OID: InstGKVSpitzenverband, Reference: "oid_bs_gkv_spitzenverband", Description: "Betriebsstätte GKV-Spitzenverband"},
	{OID: InstLeoKrankenhausverband, Reference: "oid_leo_krankenhausverband", Description: "Betriebsstätte Mitgliedsverband der Krankenhäuser"},
	{OID: InstLeoDKTIG, Reference: "oid_leo_dktig", Description: "Betriebsstätte der Deutsche Krankenhaus TrustCenter und Informationsverarbeitung GmbH"},
	{OID: InstLeoDKG, Reference: "oid_leo_dkg", Description: "Betriebsstätte der Deutschen Krankenhausgesellschaft"},
	{OID: InstLeoApothekerverband, Reference: "oid_leo_apothekerverband", Description: "Betriebsstätte Apothekerverband"},
	{OID: InstLeoDAV, Reference: "oid_leo_dav", Description: "Betriebsstätte Deutscher Apothekerverband"},
	{OID: InstLeoBAEK, Reference: "oid_leo_baek", Description: "Betriebsstätte der Bundesärztekammer"},
	{OID: InstLeoAerztekammer, Reference: "oid_leo_aerztekammer", Description: "Betriebsstätte einer Ärztekammer"},
	{OID: InstLeoZahnaerztekammer, Reference: "oid_leo_zahnaerztekammer", Description: "Betriebsstätte einer Zahnärztekammer"},
	{OID: InstLeoKBV, Reference: "oid_leo-kbv", Description: "Betriebsstätte der Kassenärztlichen Bundesvereinigung"},
	{OID: InstLeoBZAEK, Reference: "oid_leo-bzaek", Description: "Betriebsstätte der Bundeszahnärztekammer"},
	{OID: InstLeoKZBV, Reference: "oid_leo-kzbv", Description: "Betriebsstätte der Kassenzahnärztlichen Bundesvereinigung"},
	{OID: InstPflege, Reference: "oid_institution-pflege", Description: "Betriebsstätte Gesundheits-, Kranken- und Altenpflege"},
	{OID: InstGeburtshilfe, Reference: "oid_institution-geburtshilfe", Description: "Betriebsstätte Geburtshilfe"},
	{OID: InstPraxisPhysiotherapeut, Reference: "oid_praxis-physiotherapeut", Description: "Betriebsstätte Physiotherapie"},
	{OID: InstAugenoptiker, Reference: "oid_institution-augenoptiker", Description: "Betriebsstätte Augenoptiker"},
	{OID: InstHoerakustiker, Reference: "oid_institution-hoerakustiker", Description: "Betriebsstätte Hörakustiker"},
	{OID: InstOrthopaedieschuhmacher, Reference: "oid_institution-orthopaedieschuhmacher", Description: "Betriebsstätte Orthopädieschuhmacher"},
	{OID: InstOrthopaedietechniker, Reference: "oid_institution-orthopaedietechniker", Description: "Betriebsstätte Orthopädietechniker"},
	{OID: InstZahntechniker, Reference: "oid_institution-zahntechniker", Description: "Betriebsstätte Zahntechniker"},
	{OID: InstRettungsleitstelle, Reference: "oid_institution-rettungsleitstellen", Description: "Rettungsleitstelle"},
	{OID: InstSanitaetsdienstBW, Reference: "oid_sanitaetsdienst-bundeswehr", Description: "Betriebsstätte Sanitätsdienst Bundeswehr"},
	{OID: InstOEGD, Reference: "oid_institution-oegd", Description: "Betriebsstätte Öffentlicher Gesundheitsdienst"},
	{OID: InstArbeitsmedizin, Reference: "oid_institution-arbeitsmedizin", Description: "Betriebsstätte Arbeitsmedizin"},
	{OID: InstVorsorgeReha, Reference: "oid_institution-vorsorge-reha", Description: "Betriebsstätte Vorsorge- und Rehabilitation"},
	{OID: InstPflegeberatung, Reference: "oid_pflegeberatung", Description: "Betriebsstätte Pflegeberatung nach § 7a SGB XI"},
	{OID: InstLeoPsychotherapeuten, Reference: "oid_leo_psychotherapeuten", Description: "Betriebsstätte Psychotherapeutenkammer"},
	{OID: InstLeoBPtK, Reference: "oid_leo_bptk", Description: "Betriebsstätte Bundespsychotherapeutenkammer"},
	{OID: InstLeoLAK, Reference: "oid_leo_lak", Description: "Betriebsstätte Landesapothekerkammer"},
	{OID: InstLeoBAK, Reference: "oid_leo_bak", Description: "Betriebsstätte Bundesapothekerkammer"},
	{OID: InstLeoEGBR, Reference: "oid_leo_egbr", Description: "Betriebsstätte elektronisches Gesundheitsberuferegister"},
	{OID: InstLeoHandwerkskammer, Reference: "oid_leo_handwerkskammer", Description: "Betriebsstätte Handwerkskammer"},
	{OID: InstGesundheitsdatenregister, Reference: "oid_gesundheitsdatenregister", Description: "Betriebsstätte Register für Gesundheitsdaten"},
	{OID: InstAbrechnungsdienstleister, Reference: "oid_abrechnungsdienstleister", Description: "Betriebsstätte Abrechnungsdienstleister"},
	{OID: InstPKVVerband, Reference: "oid_pkv_verband", Description: "Betriebsstätte PKV-Verband"},
	{OID: InstPraxisErgotherapeut, Reference: "oid_praxis-ergotherapeut", Description: "Ergotherapiepraxis"},
	{OID: InstPraxisLogopaede, Reference: "oid_praxis-logopaede", Description: "Logopaedische Praxis"},
	{OID: InstPraxisPodologe, Reference: "oid_praxis-podologe", Description: "Podologiepraxis"},
	{OID: InstPraxisErnaehrungstherapeut, Reference: "oid_praxis-ernaehrungstherapeut", Description: "Ernährungstherapeutische Praxis"},
	{OID: InstWeitereKostentraeger, Reference: "oid_bs-weitere-kostentraeger", Description: "Betriebsstätte Weitere Kostenträger im Gesundheitswesen"},
	{OID: InstOrgGesundheitsversorgung, Reference: "oid_org-gesundheitsversorgung", Description: "Weitere Organisationen der Gesundheitsversorgung"},
	{OID: InstKIMAnbieter, Reference: "oid_kim-anbieter", Description: "KIM-Hersteller und -Anbieter"},
	{OID: InstDiGA, Reference: "oid_diga", Description: "DiGA-Hersteller und -Anbieter"},
	{OID: InstTIMAnbieter, Reference: "oid_tim-anbieter", Description: "TIM-Hersteller und -Anbieter"},
	{OID: InstNCPeH, Reference: "oid_ncpeh", Description: "NCPeH Fachdienst"},
	{OID: InstOmbudsstelle, Reference: "oid_ombudsstelle", Description: "Ombudsstelle eines Kostenträgers"},
	{OID: InstOptoAudio, Reference: "oid_bs-opto-audio", Description: "Betriebsstätte Augenoptiker und Hörakustiker"},
	{OID: InstOrthopaedHW, Reference: "oid_bs-orthopaed-hw", Description: "Betriebsstätte Orthopädieschuhmacher und Orthopädietechniker"},
	{OID: InstHimi, Reference: "oid_bs-himi", Description: "Betriebsstätte Hilfsmittelerbringer"},
	{OID: InstFriseur, Reference: "oid_bs-friseur", Description: "Betriebsstätte Frisör"},
	{OID: InstSoziother, Reference: "oid_bs-soziother", Description: "Betriebsstätte Soziotherapie"},
	{OID: PolicyHbaCP, Reference: "oid_policy_hba_cp", Description: "Policy HPC QES, SIG, AUT, ENC", Document: "[CP-HPC]"},
	{OID: PolicyGemOrCP, Reference: "oid_policy_gem_or_cp", Description: "Policy für alle Zertifikate ab Online-Rollout (eGK, SMC, Komponentenzertifikate) außer für das TSL-Signerzertifikat", Document: "[gemRL_TSL_SP_CP]"},
	{OID: PolicyGemTSLSigner, Reference: "oid_policy_gem_tsl_signer", Description: "Policy für das TSL-Signerzertifikat", Document: "[gemSpec_TSL]"},
	{OID: CertTypeEgkQES, Reference: "oid_egk_qes", Description: "C.CH.QES", Document: "[gemSpec_PKI]"},
	{OID: CertTypeEgkSIG, Reference: "oid_egk_sig", Description: "C.CH.SIG", Document: "[gemSpec_PKI]"},
	{OID: CertTypeEgkENC, Reference: "oid_egk_enc", Description: "C.CH.ENC", Document: "[gemSpec_PKI]"},
	{OID: CertTypeEgkENCV, Reference: "oid_egk_encv", Description: "C.CH.ENCV", Document: "[gemSpec_PKI]"},
	{OID: CertTypeEgkAUT, Reference: "oid_egk_aut", Description: "C.CH.AUT", Document: "[gemSpec_PKI]"},
	{OID: CertTypeEgkAUTN, Reference: "oid_egk_autn", Description: "C.CH.AUTN", Document: "[gemSpec_PKI]"},
	{OID: CertTypeEgkENCAlt, Reference: "oid_egk_enc_alt", Description: "C.CH.ENC_ALT"},
	{OID: CertTypeEgkAUTAlt, Reference: "oid_egk_aut_alt", Description: "C.CH.AUT_ALT", Document: "[gemSpec_PKI]"},
	{OID: CertTypeHbaQES, Reference: "oid_hba_qes", Description: "C.HP.QES", Document: "[CertsBÄK#1]"},
	{OID: CertTypeHbaSIG, Reference: "oid_hba_sig", Description: "C.HP.SIG"},
	{OID: CertTypeHbaENC, Reference: "oid_hba_enc", Description: "C.HP.ENC", Document: "[CertsBÄK#1]"},
	{OID: CertTypeHbaAUT, Reference: "oid_hba_aut", Description: "C.HP.AUT", Document: "[CertsBÄK#1]"},
	{OID: CertTypeSmcBENC, Reference: "oid_smc_b_enc", Description: "C.HCI.ENC", Document: "[gemSpec_PKI]"},
	{OID: CertTypeSmcBAUT, Reference: "oid_smc_b_aut", Description: "C.HCI.AUT", Document: "[gemSpec_PKI]"},
	{OID: CertTypeSmcBOSIG, Reference: "oid_smc_b_osig", Description: "C.HCI.OSIG", Document: "[gemSpec_PKI]"},
	{OID: CertTypeAkAUT, Reference: "oid_ak_aut", Description: "C.AK.AUT", Document: "[gemSpec_PKI]"},
	{OID: CertTypeNkVPN, Reference: "oid_nk_vpn", Description: "C.NK.VPN", Document: "[gemSpec_PKI]"},
	{OID: CertTypeVpnkVPN, Reference: "oid_vpnk_vpn", Description: "C.VPNK.VPN", Document: "[gemSpec_PKI]"},
	{OID: CertTypeSmktAUT, Reference: "oid_smkt_aut", Description: "C.SMKT.AUT", Document: "[gemSpec_PKI]"},
	{OID: CertTypeSakAUT, Reference: "oid_sak_aut", Description: "C.SAK.AUT", Document: "[gemSpec_PKI]"},
	{OID: CertTypeCmTLSCS, Reference: "oid_cm_tls_c", Description: "C.CM.TLS-CS", Document: "[gemSpec_PKI]"},
	{OID: CertTypeFdTLSC, Reference: "oid_fd_tls_c", Description: "C.FD.TLS-C", Document: "[gemSpec_PKI]"},
	{OID: CertTypeFdTLSS, Reference: "oid_fd_tls_s", Description: "C.FD.TLS-S", Document: "[gemSpec_PKI]"},
	{OID: CertTypeFdAUT, Reference: "oid_fd_aut", Description: "C.FD.AUT", Document: "[gemSpec_PKI]"},
	{OID: CertTypeZdTLSC, Reference: "oid_zd_tls_c", Description: "C.ZD.TLS-C"},
	{OID: CertTypeZdTLSS, Reference: "oid_zd_tls_s", Description: "C.ZD.TLS-S", Document: "[gemSpec_PKI]"},
	{OID: CertTypeZdAUT, Reference: "oid_zd_aut", Description: "C.ZD.AUT"},
	{OID: CertTypeVpnkVPNSIS, Reference: "oid_vpnk_vpn_sis", Description: "C.VPNK.VPN-SIS", Document: "[gemSpec_PKI]"},
	{OID: CertTypeFdSIG, Reference: "oid_fd_sig", Description: "C.FD.SIG", Document: "[gemSpec_PKI]"},
	{OID: CertTypeFdENC, Reference: "oid_fd_enc", Description: "C.FD.ENC", Document: "[gemSpec_PKI]"},
	{OID: CertTypeWhkHsmAUT, Reference: "oid_whk_hsm_aut", Description: "C.WHK-HSM.AUT"},
	{OID: CertTypeVkPtENC, Reference: "oid_vk_pt_enc", Description: "C.HP.ENC", Document: "[BÄK_ePA]"},
	{OID: CertTypeVkEaaENC, Reference: "oid_vk_eaa_enc", Description: "C.HP.ENC", Document: "[BÄK_eAA]"},
	{OID: CertTypeFdOSIG, Reference: "oid_fd_osig", Description: "C.FD.OSIG", Document: "[gemSpec_PKI]"},
	{OID: CertTypeZdSIG, Reference: "oid_zd_sig", Description: "C.ZD.SIG", Document: "[gemSpec_PKI]"},
	{OID: CertTypeHskSIG, Reference: "oid_hsk_sig", Description: "C.HSK.SIG", Document: "[gemSpec_PKI]"},
	{OID: CertTypeHskENC, Reference: "oid_hsk_enc", Description: "C.HSK.ENC", Document: "[gemSpec_PKI]"},
	{OID: CertTypeGemVER, Reference: "oid_gem-ver", Description: "C.GEM.VER", Document: "[gemSpec_PKI]"},
	{OID: CVRootCert, Reference: "oid_cv_rootcert", Description: "Root-CV-Zertifikat", Document: "[gemSpec_TSL]"},
	{OID: CVCert, Reference: "oid_cv_cert", Description: "Cross-CV-Zertifikat", Document: "[gemSpec_TSL]"},
	{OID: TechRoleVSDD, Reference: "oid_vsdd", Description: "Versichertenstammdatendienst", CertificateTypes: []string{"C.FD.TLS-S"}},
	{OID: TechRoleOCSP, Reference: "oid_ocsp", Description: "Online Certificate Status Protocol"},
	{OID: TechRoleCMS, Reference: "oid_cms", Description: "Card Management System", CertificateTypes: []string{"C.FD.TLS-S"}},
	{OID: TechRoleUFS, Reference: "oid_ufs", Description: "Update Flag Service", CertificateTypes: []string{"C.FD.TLS-S"}},
	{OID: TechRoleAK, Reference: "oid_ak", Description: "Anwendungskonnektor", CertificateTypes: []string{"C.AK.AUT"}},
	{OID: TechRoleNK, Reference: "oid_nk", Description: "Netzkonnektor", CertificateTypes: []string{"C.NK.VPN"}},
	{OID: TechRoleKT, Reference: "oid_kt", Description: "Kartenterminal", CertificateTypes: []string{"C.SMKT.AUT"}},
	{OID: TechRoleSAK, Reference: "oid_sak", Description: "Signaturanwendungskomponente", CertificateTypes: []string{"C.SAK.AUT"}},
	{OID: TechRoleIntVSDM, Reference: "oid_int_vsdm", Description: "Intermediär VSDM", CertificateTypes: []string{"C.FD.TLS-S", "C.FD.TLS-C"}},
	{OID: TechRoleKonfigdienst, Reference: "oid_konfigdienst", Description: "Konfigurationsdienst", CertificateTypes: []string{"C.ZD.TLS-S"}},
	{OID: TechRoleVPNZTI, Reference: "oid_vpnz_ti", Description: "VPN-Zugangsdienst-TI", CertificateTypes: []string{"C.VPNK.VPN", "C.ZD.TLS-S"}},
	{OID: TechRoleVPNZSIS, Reference: "oid_vpnz_sis", Description: "VPN-Zugangsdienst-SIS", CertificateTypes: []string{"C.VPNK.VPN-SIS"}},
	{OID: TechRoleCMFD, Reference: "oid_cmfd", Description: "Clientmodul", CertificateTypes: []string{"C.CM.TLS-CS"}},
	{OID: TechRoleVZDTI, Reference: "oid_vzd_ti", Description: "Verzeichnisdienst-TI", CertificateTypes: []string{"C.ZD.TLS-S", "C.FD.SIG"}},
	{OID: TechRoleKOMLE, Reference: "oid_komle", Description: "KOM-LE Fachdienst", CertificateTypes: []string{"C.FD.TLS-S", "C.FD.TLS-C"}},
	{OID: TechRoleKOMLERecipientEmails, Reference: "oid_komle-recipient-emails", Description: "KOM-LE S/MIME Attribut recipient-emails"},
	{OID: TechRoleStamp, Reference: "oid_stamp", Description: "Betriebsdatenerfassung", CertificateTypes: []string{"C.ZD.TLS-S"}},
	{OID: TechRoleTSLTI, Reference: "oid_tsl_ti", Description: "TSL-Dienst-TI", CertificateTypes: []string{"C.ZD.TLS-S"}},
	{OID: TechRoleWADG, Reference: "oid_wadg", Description: "Weitere elektronische Anwendungen des Gesundheitswesens sowie für die Gesundheitsforschung n. P. 291a Abs. 7 Satz 3 SGB V", CertificateTypes: []string{"C.FD.TLS-S", "C.FD.SIG", "C.FD.AUT", "C.FD.ENC"}},
	{OID: TechRoleEpaAuthn, Reference: "oid_epa_authn", Description: "ePA Authentisierung", CertificateTypes: []string{"C.FD.TLS-S", "C.FD.SIG"}},
	{OID: TechRoleEpaAuthz, Reference: "oid_epa_authz", Description: "ePA Autorisierung", CertificateTypes: []string{"C.FD.TLS-S", "C.FD.SIG"}},
	{OID: TechRoleEpaDvw, Reference: "oid_epa_dvw", Description: "ePA Dokumentenverwaltung", CertificateTypes: []string{"C.FD.TLS-S"}},
	{OID: TechRoleEpaMgmt, Reference: "oid_epa_mgmt", Description: "ePA Management", CertificateTypes: []string{"C.FD.TLS-S", "C.FD.TLS-C"}},
	{OID: TechRoleEpaRecovery, Reference: "oid_epa_recovery", Description: "ePA automatisierter Berechtigungserhalt", CertificateTypes: []string{"C.FD.ENC"}},
	{OID: TechRoleEpaVAU, Reference: "oid_epa_vau", Description: "ePA vertrauenswürdige Ausführungsumgebung", CertificateTypes: []string{"C.FD.AUT", "C.FD.ENC", "C.FD.SIG"}},
	{OID: TechRoleVzTSP, Reference: "oid_vz_tsp", Description: "Zertifikatsverzeichnis TSP X.509"},
	{OID: TechRoleWHK1HSM, Reference: "oid_whk1_hsm", Description: "HSM Wiederherstellungskomponente 1"},
	{OID: TechRoleWHK2HSM, Reference: "oid_whk2_hsm", Description: "HSM Wiederherstellungskomponente 2"},
	{OID: TechRoleWHK, Reference: "oid_whk", Description: "Wiederherstellungskomponente"},
	{OID: TechRoleSGD, Reference: "oid_sgd", Description: "Schlüsselgenerierungsdienst", CertificateTypes: []string{"C.FD.TLS-S"}},
	{OID: TechRoleERPVAU, Reference: "oid_erp-vau", Description: "E-Rezept vertrauenswürdige Ausführungsumgebung", CertificateTypes: []string{"C.FD.ENC", "C.FD.AUT"}},
	{OID: TechRoleERezept, Reference: "oid_erezept", Description: "E-Rezept", CertificateTypes: []string{"C.FD.TLS-S", "C.FD.SIG", "C.FD.OSIG", "C.FD.TLS-C"}},
	{OID: TechRoleIDPD, Reference: "oid_idpd", Description: "IDP-Dienst", CertificateTypes: []string{"C.FD.TLS-S", "C.FD.SIG"}},
	{OID: TechRoleEpaLogging, Reference: "oid_epa_logging", Description: "ePA-Aktensystem-Logging", CertificateTypes: []string{"C.FD.SIG"}},
	{OID: TechRoleBestandsnetze, Reference: "oid_bestandsnetze", Description: "Bestandsnetze.xml Signatur", CertificateTypes: []string{"C.ZD.SIG"}},
	{OID: TechRoleEpaVST, Reference: "oid_epa_vst", Description: "ePA Vertrauensstelle", CertificateTypes: []string{"C.FD.TLS-S", "C.FD.ENC", "C.FD.AUT"}},
	{OID: TechRoleEpaFDZ, Reference: "oid_epa_fdz", Description: "ePA Forschungsdatenzentrum", CertificateTypes: []string{"C.FD.TLS-S", "C.FD.ENC", "C.FD.AUT"}},
	{OID: TechRoleTIM, Reference: "oid_tim", Description: "TI-Messenger", CertificateTypes: []string{"C.FD.SIG"}},
	{OID: TechRoleHSK, Reference: "oid_hsk", Description: "Highspeed-Konnektor", CertificateTypes: []string{"C.HSK.SIG", "C.HSK.ENC"}},
	{OID: TechRoleIDPDSek, Reference: "oid_idpd_sek", Description: "sektoraler IDP", CertificateTypes: []string{"C.FD.SIG"}},
	{OID: TechRoleTIGWZugm, Reference: "oid_tigw_zugm", Description: "TI-Gateway Zugangsmodul", CertificateTypes: []string{"C.FD.OSIG", "C.FD.TLS-S"}},
	{OID: TechRoleZertSMB, Reference: "oid_zert_smb", Description: "Technische Zertifikatsausgabestelle eines Anbieters SMC-B", CertificateTypes: []string{"C.FD.TLS-C"}},
	{OID: TechRolePoPP, Reference: "oid_popp", Description: "Proof of Patient Presence (PoPP) Dienst", CertificateTypes: []string{"C.ZD.SIG"}},
	{OID: TechRolePoPPToken, Reference: "oid_popp-token", Description: "Token-Signatur-Identität für Proof of Patient Presence", CertificateTypes: []string{"C.ZD.SIG"}},
	{OID: TechRolePKIVer, Reference: "oid_pki-ver", Description: "PKI Change Verifikation", CertificateTypes: []string{"C.GEM.VER"}}, //nolint:misspell // German, as gemSpec_OID writes it
	{OID: TechRoleDipagVAU, Reference: "oid_dipag-vau", Description: "Digitale Patientenrechnung vertrauenswürdige Ausführungsumgebung", CertificateTypes: []string{"C.FD.AUT"}},
	{OID: TechRoleZETAGuard, Reference: "oid_zeta-guard", Description: "ZETA Guard", CertificateTypes: []string{"C.FD.AUT"}},
	{OID: TechRoleZETAPolicies, Reference: "oid_zeta-policies", Description: "ZETA PIP/PAP Policies", CertificateTypes: []string{"C.FD.SIG"}},
	{OID: TechRoleZETAOCI, Reference: "oid_zeta-oci", Description: "OCI container image für ZETA", CertificateTypes: []string{"C.FD.SIG"}},
	{OID: TechRoleZETAPolAuthor, Reference: "oid_zeta-pol-author", Description: "ZETA Policy Autor", CertificateTypes: []string{"C.FD.SIG"}}, //nolint:misspell // German, as gemSpec_OID writes it
	{OID: TechRoleZETAPolApprov, Reference: "oid_zeta-pol-approv", Description: "ZETA Policy Freigeber", CertificateTypes: []string{"C.FD.SIG"}},
	{OID: TechRoleZETAPolOper, Reference: "oid_zeta-pol-oper", Description: "ZETA Policy Leitstand", CertificateTypes: []string{"C.FD.SIG"}},
	{OID: TechRoleZETAPrvApprov, Reference: "oid_zeta-prv-approv", Description: "ZETA Provisioning Container Image Freigeber", CertificateTypes: []string{"C.FD.SIG"}},
	{OID: TechRoleTSPEgk, Reference: "oid_tsp-egk", Description: "Technische Zertifikatsausgabestelle eines Anbieters EGK", CertificateTypes: []string{"C.FD.OSIG", "C.FD.TLS-C"}},
	{OID: TechRoleCDCP15G, Reference: "oid_cdc-p15g", Description: "Cyber Defense Center Pseudonymisierung", CertificateTypes: []string{"C.FD.ENC"}},
}

// All returns every identifier the package declares.
func All() []Info { return table }

// Lookup says what gemSpec_OID records about id.
func Lookup(id x509.OID) (Info, bool) {
	for _, info := range table {
		if info.OID.Equal(id) {
			return info, true
		}
	}
	return Info{}, false
}

// Format gives id for display: 1.2.276.0.76.4.328 (ZETA Guard) if its name is known, the dotted
// form otherwise.
func Format(id x509.OID) string {
	if info, ok := Lookup(id); ok && info.Description != "" {
		return id.String() + " (" + info.Description + ")"
	}
	return id.String()
}

// Parse reads an identifier in its canonical dotted form. It is stricter than [x509.ParseOID], which
// reads 1.2.030 as 1.2.30: text that is not what the identifier prints as is refused, so one
// identifier has one spelling.
func Parse(text string) (x509.OID, error) {
	id, err := x509.ParseOID(text)
	if err != nil {
		return x509.OID{}, fmt.Errorf("object identifier %q: %w", text, err)
	}
	if id.String() != text {
		return x509.OID{}, fmt.Errorf("object identifier %q: not in canonical form", text)
	}
	return id, nil
}

// MustParse is [Parse] for the identifiers written in this module's source; it panics on an error.
func MustParse(text string) x509.OID {
	id, err := Parse(text)
	if err != nil {
		panic(err)
	}
	return id
}

// Professions is Tab_PKI_402 without Versicherter: what makes a certificate an HBA.
var Professions = []x509.OID{
	ProfArzt,
	ProfZahnarzt,
	ProfApotheker,
	ProfApothekerassistent,
	ProfPharmazieingenieur,
	ProfPharmTechnAssistent,
	ProfPharmKaufmAngestellter,
	ProfApothekenhelfer,
	ProfApothekenassistent,
	ProfPharmAssistent,
	ProfApothekenfacharbeiter,
	ProfPharmaziepraktikant,
	ProfFamulant,
	ProfPTAPraktikant,
	ProfPKAAuszubildender,
	ProfPsychotherapeut,
	ProfPsPsychotherapeut,
	ProfKuJPsychotherapeut,
	ProfRettungsassistent,
	ProfNotfallsanitaeter,
	ProfPflegerHPC,
	ProfAltenpflegerHPC,
	ProfPflegefachkraftHPC,
	ProfHebammeHPC,
	ProfPhysiotherapeutHPC,
	ProfAugenoptikerHPC,
	ProfHoerakustikerHPC,
	ProfOrthopaedieschuhmacherHPC,
	ProfOrthopaedietechnikerHPC,
	ProfZahntechnikerHPC,
	ProfErgotherapeutHPC,
	ProfLogopaedeHPC,
	ProfPodologeHPC,
	ProfErnaehrungstherapeutHPC,
	ProfOptoAudioHPC,
	ProfOrthopaedHPC,
	ProfHimiHPC,
	ProfFriseurHPC,
	ProfSoziotherapeut,
	ProfSSSSTherapeut,
	ProfMasseurMBMHPC,
	ProfDiaetassistent,
}

// Institutions is Tab_PKI_403: what makes a certificate an SMC-B.
var Institutions = []x509.OID{
	InstArztpraxis,
	InstZahnarztpraxis,
	InstPraxisPsychotherapeut,
	InstKrankenhaus,
	InstOeffentlicheApo,
	InstKrankenhausapotheke,
	InstBundeswehrapotheke,
	InstMobileEinrichtungRettung,
	InstGematik,
	InstKostentraeger,
	InstLeoZahnaerzte,
	InstAdvKtr,
	InstLeoKassenaerztlicheVerein,
	InstGKVSpitzenverband,
	InstLeoKrankenhausverband,
	InstLeoDKTIG,
	InstLeoDKG,
	InstLeoApothekerverband,
	InstLeoDAV,
	InstLeoBAEK,
	InstLeoAerztekammer,
	InstLeoZahnaerztekammer,
	InstLeoKBV,
	InstLeoBZAEK,
	InstLeoKZBV,
	InstPflege,
	InstGeburtshilfe,
	InstPraxisPhysiotherapeut,
	InstAugenoptiker,
	InstHoerakustiker,
	InstOrthopaedieschuhmacher,
	InstOrthopaedietechniker,
	InstZahntechniker,
	InstRettungsleitstelle,
	InstSanitaetsdienstBW,
	InstOEGD,
	InstArbeitsmedizin,
	InstVorsorgeReha,
	InstPflegeberatung,
	InstLeoPsychotherapeuten,
	InstLeoBPtK,
	InstLeoLAK,
	InstLeoBAK,
	InstLeoEGBR,
	InstLeoHandwerkskammer,
	InstGesundheitsdatenregister,
	InstAbrechnungsdienstleister,
	InstPKVVerband,
	InstPraxisErgotherapeut,
	InstPraxisLogopaede,
	InstPraxisPodologe,
	InstPraxisErnaehrungstherapeut,
	InstWeitereKostentraeger,
	InstOrgGesundheitsversorgung,
	InstKIMAnbieter,
	InstDiGA,
	InstTIMAnbieter,
	InstNCPeH,
	InstOmbudsstelle,
	InstOptoAudio,
	InstOrthopaedHW,
	InstHimi,
	InstFriseur,
	InstSoziother,
}
