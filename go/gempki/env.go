package gempki

type Environment string

const (
	EnvDev  Environment = "dev"
	EnvRef  Environment = "ref"
	EnvTest Environment = "test"
	EnvProd Environment = "prod"
)
