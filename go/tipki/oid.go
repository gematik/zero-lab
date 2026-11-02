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

package tipki

// The object identifiers this package needs, by their gemSpec_OID reference names, as ti-pki
// declares them. spec/pki-profiles/testdata/corpus.json holds the two to the same values.
const (
	admissionExtension   = "1.3.36.8.3.3"
	extKeyUsageExtension = "2.5.29.37"
	anyExtendedKeyUsage  = "2.5.29.37.0"

	serverAuth            = "1.3.6.1.5.5.7.3.1"
	clientAuth            = "1.3.6.1.5.5.7.3.2"
	emailProtection       = "1.3.6.1.5.5.7.3.4"
	tslSigning            = "0.4.0.2231.3.0"
	oidCertTypeEgkQes     = "1.2.276.0.76.4.66"      // oid_egk_qes
	oidCertTypeEgkSig     = "1.2.276.0.76.4.67"      // oid_egk_sig
	oidCertTypeEgkEnc     = "1.2.276.0.76.4.68"      // oid_egk_enc
	oidCertTypeEgkEncv    = "1.2.276.0.76.4.69"      // oid_egk_encv
	oidCertTypeEgkAut     = "1.2.276.0.76.4.70"      // oid_egk_aut
	oidCertTypeEgkAutn    = "1.2.276.0.76.4.71"      // oid_egk_autn
	oidCertTypeEgkEncAlt  = "1.2.276.0.76.4.211"     // oid_egk_enc_alt
	oidCertTypeEgkAutAlt  = "1.2.276.0.76.4.212"     // oid_egk_aut_alt
	oidCertTypeHbaQes     = "1.2.276.0.76.4.72"      // oid_hba_qes
	oidCertTypeHbaSig     = "1.2.276.0.76.4.73"      // oid_hba_sig
	oidCertTypeHbaEnc     = "1.2.276.0.76.4.74"      // oid_hba_enc
	oidCertTypeHbaAut     = "1.2.276.0.76.4.75"      // oid_hba_aut
	oidCertTypeSmcBEnc    = "1.2.276.0.76.4.76"      // oid_smc_b_enc
	oidCertTypeSmcBAut    = "1.2.276.0.76.4.77"      // oid_smc_b_aut
	oidCertTypeSmcBOsig   = "1.2.276.0.76.4.78"      // oid_smc_b_osig
	oidCertTypeAkAut      = "1.2.276.0.76.4.79"      // oid_ak_aut
	oidCertTypeNkVpn      = "1.2.276.0.76.4.80"      // oid_nk_vpn
	oidCertTypeVpnkVpn    = "1.2.276.0.76.4.81"      // oid_vpnk_vpn
	oidCertTypeSmktAut    = "1.2.276.0.76.4.82"      // oid_smkt_aut
	oidCertTypeSakAut     = "1.2.276.0.76.4.113"     // oid_sak_aut
	oidCertTypeCmTlsC     = "1.2.276.0.76.4.175"     // oid_cm_tls_c
	oidCertTypeFdTlsC     = "1.2.276.0.76.4.168"     // oid_fd_tls_c
	oidCertTypeFdTlsS     = "1.2.276.0.76.4.169"     // oid_fd_tls_s
	oidCertTypeFdAut      = "1.2.276.0.76.4.155"     // oid_fd_aut
	oidCertTypeZdTlsC     = "1.2.276.0.76.4.156"     // oid_zd_tls_c
	oidCertTypeZdTlsS     = "1.2.276.0.76.4.157"     // oid_zd_tls_s
	oidCertTypeZdAut      = "1.2.276.0.76.4.158"     // oid_zd_aut
	oidCertTypeVpnkVpnSis = "1.2.276.0.76.4.165"     // oid_vpnk_vpn_sis
	oidCertTypeFdSig      = "1.2.276.0.76.4.203"     // oid_fd_sig
	oidCertTypeFdEnc      = "1.2.276.0.76.4.202"     // oid_fd_enc
	oidCertTypeWhkHsmAut  = "1.2.276.0.76.4.213"     // oid_whk_hsm_aut
	oidCertTypeVkPtEnc    = "1.2.276.0.76.4.62"      // oid_vk_pt_enc
	oidCertTypeVkEaaEnc   = "1.3.6.1.4.1.24796.1.10" // oid_vk_eaa_enc
	oidCertTypeFdOsig     = "1.2.276.0.76.4.283"     // oid_fd_osig
	oidCertTypeZdSig      = "1.2.276.0.76.4.287"     // oid_zd_sig
	oidCertTypeHskSig     = "1.2.276.0.76.4.300"     // oid_hsk_sig
	oidCertTypeHskEnc     = "1.2.276.0.76.4.301"     // oid_hsk_enc
	oidCertTypeGemVer     = "1.2.276.0.76.4.321"     // oid_gem-ver
	oidPolicyGemOrCp      = "1.2.276.0.76.4.163"     // oid_policy_gem_or_cp
	oidPolicyHbaCp        = "1.2.276.0.76.4.145"     // oid_policy_hba_cp
	oidPolicyGemTslSigner = "1.2.276.0.76.4.176"     // oid_policy_gem_tsl_signer
	oidProfVersicherter   = "1.2.276.0.76.4.49"      // oid_versicherter
	oidTechRoleHsk        = "1.2.276.0.76.4.302"     // oid_hsk
	oidTechRoleEpaVau     = "1.2.276.0.76.4.209"     // oid_epa_vau
	oidTechRoleIdpd       = "1.2.276.0.76.4.260"     // oid_idpd
	oidTechRoleZetaGuard  = "1.2.276.0.76.4.328"     // oid_zeta-guard
)

// Tab_PKI_402 without oid_versicherter: what makes a certificate an HBA.
var professions = []string{
	"1.2.276.0.76.4.30",  // oid_arzt
	"1.2.276.0.76.4.31",  // oid_zahnarzt
	"1.2.276.0.76.4.32",  // oid_apotheker
	"1.2.276.0.76.4.33",  // oid_apothekerassistent
	"1.2.276.0.76.4.34",  // oid_pharmazieingenieur
	"1.2.276.0.76.4.35",  // oid_pharm_techn_assistent
	"1.2.276.0.76.4.36",  // oid_pharm_kaufm_angestellter
	"1.2.276.0.76.4.37",  // oid_apothekenhelfer
	"1.2.276.0.76.4.38",  // oid_apothekenassistent
	"1.2.276.0.76.4.39",  // oid_pharm_assistent
	"1.2.276.0.76.4.40",  // oid_apothekenfacharbeiter
	"1.2.276.0.76.4.41",  // oid_pharmaziepraktikant
	"1.2.276.0.76.4.42",  // oid_famulant
	"1.2.276.0.76.4.43",  // oid_pta_praktikant
	"1.2.276.0.76.4.44",  // oid_pka_auszubildender
	"1.2.276.0.76.4.45",  // oid_psychotherapeut
	"1.2.276.0.76.4.46",  // oid_ps_psychotherapeut
	"1.2.276.0.76.4.47",  // oid_kuj_psychotherapeut
	"1.2.276.0.76.4.48",  // oid_rettungsassistent
	"1.2.276.0.76.4.178", // oid_notfallsanitaeter
	"1.2.276.0.76.4.232", // oid_pfleger-hpc
	"1.2.276.0.76.4.233", // oid_altenpfleger-hpc
	"1.2.276.0.76.4.234", // oid_pflegefachkraft-hpc
	"1.2.276.0.76.4.235", // oid_hebamme-hpc
	"1.2.276.0.76.4.236", // oid_physiotherapeut-hpc
	"1.2.276.0.76.4.237", // oid_augenoptiker-hpc
	"1.2.276.0.76.4.238", // oid_hoerakustiker-hpc
	"1.2.276.0.76.4.239", // oid_orthopaedieschuhmacher-hpc
	"1.2.276.0.76.4.240", // oid_orthopaedietechniker-hpc
	"1.2.276.0.76.4.241", // oid_zahntechniker-hpc
	"1.2.276.0.76.4.274", // oid_ergotherapeut-hpc
	"1.2.276.0.76.4.275", // oid_logopaede-hpc
	"1.2.276.0.76.4.276", // oid_podologe-hpc
	"1.2.276.0.76.4.277", // oid_ernaehrungstherapeut-hpc
	"1.2.276.0.76.4.308", // oid_opto-audio-hpc
	"1.2.276.0.76.4.305", // oid_orthopaed-hpc
	"1.2.276.0.76.4.312", // oid_himi-hpc
	"1.2.276.0.76.4.313", // oid_friseur-hpc
	"1.2.276.0.76.4.316", // oid_soziotherapeut
	"1.2.276.0.76.4.318", // oid_ssss-therapeut
	"1.2.276.0.76.4.315", // oid_masseur-mbm-hpc
	"1.2.276.0.76.4.319", // oid_diaetassistent
}

// Tab_PKI_403: what makes a certificate an SMC-B.
var institutions = []string{
	"1.2.276.0.76.4.50",  // oid_praxis_arzt
	"1.2.276.0.76.4.51",  // oid_zahnarztpraxis
	"1.2.276.0.76.4.52",  // oid_praxis_psychotherapeut
	"1.2.276.0.76.4.53",  // oid_krankenhaus
	"1.2.276.0.76.4.54",  // oid_oeffentliche_apotheke
	"1.2.276.0.76.4.55",  // oid_krankenhausapotheke
	"1.2.276.0.76.4.56",  // oid_bundeswehrapotheke
	"1.2.276.0.76.4.57",  // oid_mobile_einrichtung_rettungsdienst
	"1.2.276.0.76.4.58",  // oid_bs_gematik
	"1.2.276.0.76.4.59",  // oid_kostentraeger
	"1.2.276.0.76.4.187", // oid_leo_zahnaerzte
	"1.2.276.0.76.4.190", // oid_adv_ktr
	"1.2.276.0.76.4.210", // oid_leo_kassenaerztliche_vereinigung
	"1.2.276.0.76.4.223", // oid_bs_gkv_spitzenverband
	"1.2.276.0.76.4.226", // oid_leo_krankenhausverband
	"1.2.276.0.76.4.227", // oid_leo_dktig
	"1.2.276.0.76.4.228", // oid_leo_dkg
	"1.2.276.0.76.4.224", // oid_leo_apothekerverband
	"1.2.276.0.76.4.225", // oid_leo_dav
	"1.2.276.0.76.4.229", // oid_leo_baek
	"1.2.276.0.76.4.230", // oid_leo_aerztekammer
	"1.2.276.0.76.4.231", // oid_leo_zahnaerztekammer
	"1.2.276.0.76.4.242", // oid_leo-kbv
	"1.2.276.0.76.4.243", // oid_leo-bzaek
	"1.2.276.0.76.4.244", // oid_leo-kzbv
	"1.2.276.0.76.4.245", // oid_institution-pflege
	"1.2.276.0.76.4.246", // oid_institution-geburtshilfe
	"1.2.276.0.76.4.247", // oid_praxis-physiotherapeut
	"1.2.276.0.76.4.248", // oid_institution-augenoptiker
	"1.2.276.0.76.4.249", // oid_institution-hoerakustiker
	"1.2.276.0.76.4.250", // oid_institution-orthopaedieschuhmacher
	"1.2.276.0.76.4.251", // oid_institution-orthopaedietechniker
	"1.2.276.0.76.4.252", // oid_institution-zahntechniker
	"1.2.276.0.76.4.253", // oid_institution-rettungsleitstellen
	"1.2.276.0.76.4.254", // oid_sanitaetsdienst-bundeswehr
	"1.2.276.0.76.4.255", // oid_institution-oegd
	"1.2.276.0.76.4.256", // oid_institution-arbeitsmedizin
	"1.2.276.0.76.4.257", // oid_institution-vorsorge-reha
	"1.2.276.0.76.4.262", // oid_pflegeberatung
	"1.2.276.0.76.4.263", // oid_leo_psychotherapeuten
	"1.2.276.0.76.4.264", // oid_leo_bptk
	"1.2.276.0.76.4.265", // oid_leo_lak
	"1.2.276.0.76.4.266", // oid_leo_bak
	"1.2.276.0.76.4.267", // oid_leo_egbr
	"1.2.276.0.76.4.268", // oid_leo_handwerkskammer
	"1.2.276.0.76.4.269", // oid_gesundheitsdatenregister
	"1.2.276.0.76.4.270", // oid_abrechnungsdienstleister
	"1.2.276.0.76.4.271", // oid_pkv_verband
	"1.2.276.0.76.4.278", // oid_praxis-ergotherapeut
	"1.2.276.0.76.4.279", // oid_praxis-logopaede
	"1.2.276.0.76.4.280", // oid_praxis-podologe
	"1.2.276.0.76.4.281", // oid_praxis-ernaehrungstherapeut
	"1.2.276.0.76.4.284", // oid_bs-weitere-kostentraeger
	"1.2.276.0.76.4.285", // oid_org-gesundheitsversorgung
	"1.2.276.0.76.4.286", // oid_kim-anbieter
	"1.2.276.0.76.4.282", // oid_diga
	"1.2.276.0.76.4.295", // oid_tim-anbieter
	"1.2.276.0.76.4.292", // oid_ncpeh
	"1.2.276.0.76.4.303", // oid_ombudsstelle
	"1.2.276.0.76.4.304", // oid_bs-opto-audio
	"1.2.276.0.76.4.306", // oid_bs-orthopaed-hw
	"1.2.276.0.76.4.311", // oid_bs-himi
	"1.2.276.0.76.4.314", // oid_bs-friseur
	"1.2.276.0.76.4.317", // oid_bs-soziother
}
