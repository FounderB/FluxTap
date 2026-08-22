package web

import _ "embed"

//go:embed static/index.html
var indexHTML string

//go:embed static/favicon.png
var faviconPNG []byte
