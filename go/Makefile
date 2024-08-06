
.PHONY: info, docker, dockerhub, version

ZERO_VERSION ?= "0.9.0"
REG_FQDN ?= "zerobin.zt.ccs.gematik.solutions"
REG_SECRETS_DIR ?= "secrets/reg"

info: 
	$(info Usage: make [docker|dockerhub])
	$(info docker: build docker image)
	$(info dockerhub: push docker image to dockerhub)

version:
	$(info Version: ${ZERO_VERSION})
	@echo "package libzero" > ./libzero/version.go
	@echo "" >> ./libzero/version.go
	@echo "const Version = \"$(ZERO_VERSION)\"" >> ./libzero/version.go

docker-build-caddy: version
	docker build --platform linux/amd64 -t "spilikin/zero-caddy:${ZERO_VERSION}" -f ./zaddy/cmd/zero-caddy/Dockerfile .

docker-build-zerobin: version
	docker build --platform linux/amd64 -t "spilikin/zero-zerobin:${ZERO_VERSION}" -f cmd/zero-zerobin/Dockerfile .

docker-push-caddy: docker-build-caddy
	docker tag "spilikin/zero-caddy:${ZERO_VERSION}" "spilikin/zero-caddy:latest"
	docker push "spilikin/zero-caddy:${ZERO_VERSION}"
	docker push "spilikin/zero-caddy:latest"

docker-push-zerobin: docker-build-zerobin
	docker push "spilikin/zero-zerobin:${ZERO_VERSION}"

testsecrets:
	mkdir -p ${REG_SECRETS_DIR}
	openssl ecparam -name prime256v1 -genkey -noout -out ${REG_SECRETS_DIR}/sig_prk.pem
	openssl ec -pubout -in ${REG_SECRETS_DIR}/sig_prk.pem -out ${REG_SECRETS_DIR}/sig_puk.pem
	
	openssl ecparam -name prime256v1 -genkey -noout -out ${REG_SECRETS_DIR}/enc_prk.pem

	openssl ecparam -name prime256v1 -genkey -noout -out ${REG_SECRETS_DIR}/client_prk.pem
	openssl req -x509 -key ${REG_SECRETS_DIR}/client_prk.pem -subj "/CN=${REG_FQDN}" -addext 'basicConstraints=critical,CA:TRUE' -days 1001 -out ${REG_SECRETS_DIR}/client_cert.pem

