package handlers

import (
	_ "embed"
)

//go:embed login-status-iframe.html
var loginStatusIframeHTML string

//go:embed 3p-cookies-iframe.html
var thirdPartyCookiesIframeHTML string
