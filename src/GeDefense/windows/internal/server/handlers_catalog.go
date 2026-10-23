// STATUS: DIAMANT VGT SUPREME
package server

import (
	"net/http"

	"github.com/visiongaiatechnology/gedefense/windows/internal/settings"
)

// settingsCatalogResponse is the tolerant GET /api/v1/settings/catalog payload.
// Controls are published both as "controls" and as a "fields" alias so the
// frontend can migrate without a breaking contract change.
type settingsCatalogResponse struct {
	settings.Catalog
	Fields []settings.Control `json:"fields"`
	Schema settings.Schema    `json:"schema"`
}

// settingsCatalog serves GET /api/v1/settings/catalog. The catalog is static, so
// this endpoint stays available even before the applier is wired.
func (s *Server) settingsCatalog(w http.ResponseWriter, _ *http.Request) {
	catalog := settings.CatalogDefinition()
	s.writeJSON(w, http.StatusOK, settingsCatalogResponse{
		Catalog: catalog,
		Fields:  catalog.Controls,
		Schema: settings.Schema{
			Version:        catalog.SchemaVersion,
			CatalogVersion: catalog.CatalogVersion,
		},
	})
}
