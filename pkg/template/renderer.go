// Package template provides template rendering utilities
package template

import (
	"html/template"
	"log"
	"net/http"
)

// Renderer handles template parsing and rendering
type Renderer struct {
	templateDir  string
	baseTemplate string
}

// NewRenderer creates a new template renderer
func NewRenderer(templateDir, baseTemplate string) *Renderer {
	return &Renderer{
		templateDir:  templateDir,
		baseTemplate: baseTemplate,
	}
}

// RenderWithBase renders a template with the base layout
func (r *Renderer) RenderWithBase(w http.ResponseWriter, name string, data interface{}) error {
	tmpl, err := template.ParseFiles(r.templateDir+"/"+r.baseTemplate, r.templateDir+"/"+name)
	if err != nil {
		log.Printf("Error parsing template '%s': %v", name, err)
		return err
	}

	err = tmpl.ExecuteTemplate(w, r.baseTemplate, data)
	if err != nil {
		log.Printf("Error rendering template '%s': %v", name, err)
		return err
	}
	return nil
}

// RenderStandalone renders a standalone template without base layout
func (r *Renderer) RenderStandalone(w http.ResponseWriter, name string, data interface{}) error {
	tmpl, err := template.ParseFiles(r.templateDir + "/" + name)
	if err != nil {
		log.Printf("Error parsing simple template '%s': %v", name, err)
		return err
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		log.Printf("Error rendering standalone template '%s': %v", name, err)
		return err
	}
	return nil
}

// Global renderer instance
var DefaultRenderer *Renderer

// InitRenderer initializes the default renderer
func InitRenderer(templateDir, baseTemplate string) {
	DefaultRenderer = NewRenderer(templateDir, baseTemplate)
}

// RenderWithBase renders using the default renderer with base layout
func RenderWithBase(w http.ResponseWriter, name string, data interface{}) error {
	if DefaultRenderer == nil {
		log.Fatal("Default renderer not initialized. Call template.InitRenderer() first")
	}
	return DefaultRenderer.RenderWithBase(w, name, data)
}

// RenderStandalone renders using the default renderer without base layout
func RenderStandalone(w http.ResponseWriter, name string, data interface{}) error {
	if DefaultRenderer == nil {
		log.Fatal("Default renderer not initialized. Call template.InitRenderer() first")
	}
	return DefaultRenderer.RenderStandalone(w, name, data)
}
