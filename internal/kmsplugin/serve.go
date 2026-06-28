package kmsplugin

import (
	"os"

	kmswrappingplugin "github.com/openbao/go-kms-wrapping/plugin/v2"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

// MagicCookieKey is set by OpenBao when the binary is launched as a KMS plugin.
const MagicCookieKey = "OPENBAO_KMS_PLUGIN"

// ShouldServePlugin returns true when the process should serve the plugin RPC.
func ShouldServePlugin() bool {
	return os.Getenv(MagicCookieKey) != ""
}

// ServePlugin starts the OpenBao KMS plugin server.
func ServePlugin() {
	kmswrappingplugin.Serve(&kmswrappingplugin.ServeOpts{
		WrapperFactoryFunc: func() wrapping.Wrapper {
			return NewWrapper()
		},
	})
}
