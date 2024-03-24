
.PHONY: info, docker, dockerhub, version

ZERO_VERSION ?= "0.5.0-beta2"
REG_FQDN ?= "dms-01.zt.ccs.gematik.solutions"
REG_SECRETS_DIR ?= "secrets/reg"

info: 
	$(info Usage: make [docker|dockerhub])
	$(info docker: build docker image)
	$(info dockerhub: push docker image to dockerhub)

version:
	$(info Version: ${ZERO_VERSION})
	@echo "package pkg" > pkg/version.go
	@echo "" >> pkg/version.go
	@echo "const Version = \"$(ZERO_VERSION)\"" >> pkg/version.go

docker: version
	docker build --platform linux/amd64 -t "spilikin/zero-zerobin:${ZERO_VERSION}" -f cmd/zero-zerobin/Dockerfile .

dockerhub: docker
	$(info Dockerhub)
	docker push "spilikin/zero-zerobin:${ZERO_VERSION}"

testsecrets:
	mkdir -p ${REG_SECRETS_DIR}
	openssl ecparam -name prime256v1 -genkey -noout -out ${REG_SECRETS_DIR}/sig_prk.pem
	openssl ec -pubout -in ${REG_SECRETS_DIR}/sig_prk.pem -out ${REG_SECRETS_DIR}/sig_puk.pem
	
	openssl ecparam -name prime256v1 -genkey -noout -out ${REG_SECRETS_DIR}/enc_prk.pem

	openssl ecparam -name prime256v1 -genkey -noout -out ${REG_SECRETS_DIR}/client_prk.pem
	openssl req -x509 -key ${REG_SECRETS_DIR}/client_prk.pem -subj "/CN=Client Cert for ${REG_FQDN}" -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=digitalSignature,keyCertSign' -days 1001 -out ${REG_SECRETS_DIR}/client_cert.pem

make testdeploy: dockerhub
	ssh zerobin.spilikin.dev docker-compose pull
	ssh zerobin.spilikin.dev docker-compose down
	ssh zerobin.spilikin.dev docker-compose up -d
