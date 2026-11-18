package api

import (
	"net/http"
	"strings"

	"github.com/maekom-hub/maekom-env/internal/db"
)

func (s *Server) handleListProjects(w http.ResponseWriter, r *http.Request) {
	projects, err := s.db.ListProjects(r.Context())
	if err != nil {
		writeDBError(w, err)
		return
	}
	if projects == nil {
		projects = []db.Project{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"projects": projects})
}

func (s *Server) handleCreateProject(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "project name is required")
		return
	}

	proj, err := s.db.CreateProject(r.Context(), req.Name, strings.TrimSpace(req.Description))
	if err != nil {
		writeDBError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, proj)
}

func (s *Server) handleGetProject(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("projectID")
	proj, err := s.db.GetProject(r.Context(), projectID)
	if err != nil {
		writeDBError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, proj)
}

func (s *Server) handleUpdateProject(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("projectID")
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "project name is required")
		return
	}

	proj, err := s.db.UpdateProject(r.Context(), projectID, req.Name, strings.TrimSpace(req.Description))
	if err != nil {
		writeDBError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, proj)
}

func (s *Server) handleDeleteProject(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("projectID")
	if err := s.db.DeleteProject(r.Context(), projectID); err != nil {
		writeDBError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleListEnvironments(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("projectID")
	principal, ok := PrincipalFromContext(r.Context())
	if !ok || !principal.CanAccessProject(projectID) {
		writeError(w, http.StatusForbidden, "access denied for this project")
		return
	}

	if _, err := s.db.GetProject(r.Context(), projectID); err != nil {
		writeDBError(w, err)
		return
	}

	envs, err := s.db.ListEnvironments(r.Context(), projectID)
	if err != nil {
		writeDBError(w, err)
		return
	}
	if !principal.IsAdmin && principal.ServiceToken != nil && principal.ServiceToken.EnvID != nil {
		filtered := make([]db.Environment, 0, 1)
		for _, env := range envs {
			if env.ID == *principal.ServiceToken.EnvID {
				filtered = append(filtered, env)
			}
		}
		envs = filtered
	}
	if envs == nil {
		envs = []db.Environment{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"environments": envs})
}

func (s *Server) handleCreateEnvironment(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("projectID")
	if _, err := s.db.GetProject(r.Context(), projectID); err != nil {
		writeDBError(w, err)
		return
	}

	var req struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "environment name is required")
		return
	}

	env, err := s.db.CreateEnvironment(r.Context(), projectID, req.Name)
	if err != nil {
		writeDBError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, env)
}

func (s *Server) handleDeleteEnvironment(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("projectID")
	envID := r.PathValue("envID")
	if err := s.db.DeleteEnvironment(r.Context(), projectID, envID); err != nil {
		writeDBError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
