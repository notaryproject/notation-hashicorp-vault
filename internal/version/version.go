package version

var (
	Version = "v0.1.0"

	BuildMetadata = "unreleased"
)

func GetVersion() string {
	if BuildMetadata == "" {
		return Version
	}
	return Version + "+" + BuildMetadata
}
