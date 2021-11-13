package headscale

import (
	"bytes"
	_ "embed"
	"net/http"
	"text/template"

	"github.com/rs/zerolog/log"

	"github.com/gin-gonic/gin"
)

//go:embed gen/openapiv2/headscale/v1/headscale.swagger.json
var apiV1JSON []byte

func SwaggerUI(c *gin.Context) {
	t := template.Must(template.New("swagger").Parse(`
<html>
	<head>
	<link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@3/swagger-ui.css">

	<script src="https://unpkg.com/swagger-ui-dist@3/swagger-ui-standalone-preset.js"></script>
	<script src="https://unpkg.com/swagger-ui-dist@3/swagger-ui-bundle.js" charset="UTF-8"></script>
	</head>
	<body>
	<div id="swagger-ui"></div>
	<script>
		window.addEventListener('load', (event) => {
			const ui = SwaggerUIBundle({
			    url: "/swagger/v1/openapiv2.json",
			    dom_id: '#swagger-ui',
			    presets: [
			      SwaggerUIBundle.presets.apis,
			      SwaggerUIBundle.SwaggerUIStandalonePreset
			    ],
				plugins: [
                	SwaggerUIBundle.plugins.DownloadUrl
            	],
				deepLinking: true,
				// TODO(kradalby): Figure out why this does not work
				// layout: "StandaloneLayout",
			  })
			window.ui = ui
		});
	</script>
	</body>
</html>`))

	var payload bytes.Buffer
	if err := t.Execute(&payload, struct{}{}); err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Could not render Swagger")
		c.Data(
			http.StatusInternalServerError,
			"text/html; charset=utf-8",
			[]byte("Could not render Swagger"),
		)
		return
	}

	c.Data(http.StatusOK, "text/html; charset=utf-8", payload.Bytes())
}

func SwaggerAPIv1(c *gin.Context) {
	c.Data(http.StatusOK, "application/json; charset=utf-8", apiV1JSON)
}
