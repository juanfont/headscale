package headscale

import (
	"bytes"
	_ "embed"
	"html/template"
	"net/http"

	"github.com/rs/zerolog/log"
)

//go:embed gen/openapiv2/headscale/v1/headscale.swagger.json
var apiV1JSON []byte

func SwaggerUI(
	w http.ResponseWriter,
	r *http.Request,
) {
	swaggerTemplate := template.Must(template.New("swagger").Parse(`
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
	if err := swaggerTemplate.Execute(&payload, struct{}{}); err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Could not render Swagger")

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Could not render Swagger"))

		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write(payload.Bytes())
}

func SwaggerAPIv1(
	w http.ResponseWriter,
	r *http.Request,
) {
	w.Header().Set("Content-Type", "application/json; charset=utf-88")
	w.WriteHeader(http.StatusOK)
	w.Write(apiV1JSON)
}
