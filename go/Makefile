
REG_FQDN ?= "zerobin.zt.ccs.gematik.solutions"
REG_SECRETS_DIR ?= "secrets/reg"

info:
	@echo "REG_FQDN: ${REG_FQDN}"
	@echo "REG_SECRETS_DIR: ${REG_SECRETS_DIR}"

testsecrets:
	mkdir -p ${REG_SECRETS_DIR}
	openssl ecparam -name prime256v1 -genkey -noout -out ${REG_SECRETS_DIR}/sig_prk.pem
	openssl ec -pubout -in ${REG_SECRETS_DIR}/sig_prk.pem -out ${REG_SECRETS_DIR}/sig_puk.pem
	
	openssl ecparam -name prime256v1 -genkey -noout -out ${REG_SECRETS_DIR}/enc_prk.pem

	openssl ecparam -name prime256v1 -genkey -noout -out ${REG_SECRETS_DIR}/client_prk.pem
	openssl req -x509 -key ${REG_SECRETS_DIR}/client_prk.pem -subj "/CN=${REG_FQDN}" -addext 'basicConstraints=critical,CA:TRUE' -days 1001 -out ${REG_SECRETS_DIR}/client_cert.pem

