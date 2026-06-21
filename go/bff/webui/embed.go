// Package webui holds the static, framework-free single-page app served in front of the BFF API.
// It talks to the BFF only over the /bff/auth/* JSON API, so it can be swapped for a React/Svelte
// build later by replacing these assets — the API stays the same.
package webui

import "embed"

//go:embed index.html app.js style.css
var FS embed.FS
