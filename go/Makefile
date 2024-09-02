include .env

.PHONY: info, docker, dockerhub, version

ZERO_VERSION ?= "0.9.5"
REG_FQDN ?= "zerobin.zt.ccs.gematik.solutions"
REG_SECRETS_DIR ?= "secrets/reg"

info: 
	$(info ZERO_VERSION: ${ZERO_VERSION})
	$(info Usage: make target)
	$(info Targets:)
	$(info - version: Generate version.go file)
	$(info - docker-build: Build docker images)
	$(info - docker-push: Push docker images)

version:
	$(info Version: ${ZERO_VERSION})
	@echo "package libzero" > ./libzero/version.go
	@echo "" >> ./libzero/version.go
	@echo "const Version = \"$(ZERO_VERSION)\"" >> ./libzero/version.go

docker-build: docker-build-caddy docker-build-zerobin

docker-push: docker-push-caddy docker-push-zerobin

docker-build-caddy: version
	docker build --platform linux/amd64 -t "${DOCKER_IMAGE_CADDY}:${ZERO_VERSION}" -f ./zaddy/cmd/zero-caddy/Dockerfile .

docker-push-caddy: docker-build-caddy
	docker tag "${DOCKER_IMAGE_CADDY}:${ZERO_VERSION}" "${DOCKER_IMAGE_CADDY}:latest"
	docker push "${DOCKER_IMAGE_CADDY}:${ZERO_VERSION}"
	docker push "${DOCKER_IMAGE_CADDY}:latest"

docker-build-zerobin: version
	docker build --platform linux/amd64 -t "${DOCKER_IMAGE_ZEROBIN}:${ZERO_VERSION}" -f cmd/zero-zerobin/Dockerfile .

docker-push-zerobin: docker-build-zerobin
	docker push "${DOCKER_IMAGE_ZEROBIN}:${ZERO_VERSION}"

testsecrets:
	mkdir -p ${REG_SECRETS_DIR}
	openssl ecparam -name prime256v1 -genkey -noout -out ${REG_SECRETS_DIR}/sig_prk.pem
	openssl ec -pubout -in ${REG_SECRETS_DIR}/sig_prk.pem -out ${REG_SECRETS_DIR}/sig_puk.pem
	
	openssl ecparam -name prime256v1 -genkey -noout -out ${REG_SECRETS_DIR}/enc_prk.pem

	openssl ecparam -name prime256v1 -genkey -noout -out ${REG_SECRETS_DIR}/client_prk.pem
	openssl req -x509 -key ${REG_SECRETS_DIR}/client_prk.pem -subj "/CN=${REG_FQDN}" -addext 'basicConstraints=critical,CA:TRUE' -days 1001 -out ${REG_SECRETS_DIR}/client_cert.pem

