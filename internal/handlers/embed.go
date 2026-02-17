package handlers

import (
	_ "embed"
)

//go:embed login-status-iframe.html
var loginStatusIframeHTML string

//go:embed 3p-cookies-step1.html
var thirdPartyCookiesStep1HTML string

//go:embed 3p-cookies-step2.html
var thirdPartyCookiesStep2HTML string

//go:embed login.html
var loginHTML string
