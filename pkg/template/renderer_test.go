// Package template tests
package template

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewRenderer(t *testing.T) {
	tests := []struct {
		name         string
		templateDir  string
		baseTemplate string
	}{
		{
			name:         "Create renderer with valid paths",
			templateDir:  "templates",
			baseTemplate: "base.html",
		},
		{
			name:         "Create renderer with different paths",
			templateDir:  "views",
			baseTemplate: "layout.html",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			renderer := NewRenderer(tt.templateDir, tt.baseTemplate)

			if renderer.templateDir != tt.templateDir {
				t.Errorf("NewRenderer() templateDir = %v, expected %v", renderer.templateDir, tt.templateDir)
			}
			if renderer.baseTemplate != tt.baseTemplate {
				t.Errorf("NewRenderer() baseTemplate = %v, expected %v", renderer.baseTemplate, tt.baseTemplate)
			}
		})
	}
}

func TestRenderer_RenderWithBase(t *testing.T) {
	// Create temporary directory for test templates
	tmpDir := t.TempDir()

	// Create base template
	baseContent := `<!DOCTYPE html>
<html>
<head><title>{{.Title}}</title></head>
<body>
{{template "content" .}}
</body>
</html>`

	baseFile := filepath.Join(tmpDir, "base.html")
	err := os.WriteFile(baseFile, []byte(baseContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create base template: %v", err)
	}

	// Create content template
	contentTemplate := `{{define "content"}}
<h1>{{.Heading}}</h1>
<p>{{.Message}}</p>
{{end}}`

	contentFile := filepath.Join(tmpDir, "content.html")
	err = os.WriteFile(contentFile, []byte(contentTemplate), 0644)
	if err != nil {
		t.Fatalf("Failed to create content template: %v", err)
	}

	tests := []struct {
		name           string
		templateName   string
		data           interface{}
		expectedStatus int
		shouldContain  []string
		shouldError    bool
	}{
		{
			name:         "Valid template with data",
			templateName: "content.html",
			data: map[string]string{
				"Title":   "Test Page",
				"Heading": "Welcome",
				"Message": "This is a test",
			},
			expectedStatus: 200,
			shouldContain:  []string{"Test Page", "Welcome", "This is a test"},
			shouldError:    false,
		},
		{
			name:         "Template with nil data",
			templateName: "content.html",
			data:         nil,
			shouldError:  false,
		},
		{
			name:         "Non-existent template",
			templateName: "nonexistent.html",
			data:         nil,
			shouldError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			renderer := NewRenderer(tmpDir, "base.html")
			rr := httptest.NewRecorder()

			err := renderer.RenderWithBase(rr, tt.templateName, tt.data)

			if (err != nil) != tt.shouldError {
				t.Errorf("RenderWithBase() error = %v, shouldError %v", err, tt.shouldError)
				return
			}

			if !tt.shouldError {
				if rr.Code != tt.expectedStatus && tt.expectedStatus != 0 {
					t.Errorf("RenderWithBase() status = %v, expected %v", rr.Code, tt.expectedStatus)
				}

				for _, expected := range tt.shouldContain {
					if !strings.Contains(rr.Body.String(), expected) {
						t.Errorf("RenderWithBase() body should contain %q, got %q", expected, rr.Body.String())
					}
				}
			}
		})
	}
}

func TestRenderer_RenderStandalone(t *testing.T) {
	// Create temporary directory for test templates
	tmpDir := t.TempDir()

	// Create standalone template
	standaloneContent := `<!DOCTYPE html>
<html>
<head><title>Standalone</title></head>
<body>
<h1>{{.Title}}</h1>
<p>{{.Content}}</p>
</body>
</html>`

	standaloneFile := filepath.Join(tmpDir, "standalone.html")
	err := os.WriteFile(standaloneFile, []byte(standaloneContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create standalone template: %v", err)
	}

	tests := []struct {
		name          string
		templateName  string
		data          interface{}
		shouldContain []string
		shouldError   bool
	}{
		{
			name:         "Valid standalone template",
			templateName: "standalone.html",
			data: map[string]string{
				"Title":   "Test Title",
				"Content": "Test Content",
			},
			shouldContain: []string{"Test Title", "Test Content"},
			shouldError:   false,
		},
		{
			name:         "Template with nil data",
			templateName: "standalone.html",
			data:         nil,
			shouldError:  false,
		},
		{
			name:         "Non-existent template",
			templateName: "missing.html",
			data:         nil,
			shouldError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			renderer := NewRenderer(tmpDir, "base.html")
			rr := httptest.NewRecorder()

			err := renderer.RenderStandalone(rr, tt.templateName, tt.data)

			if (err != nil) != tt.shouldError {
				t.Errorf("RenderStandalone() error = %v, shouldError %v", err, tt.shouldError)
				return
			}

			if !tt.shouldError {
				for _, expected := range tt.shouldContain {
					if !strings.Contains(rr.Body.String(), expected) {
						t.Errorf("RenderStandalone() body should contain %q, got %q", expected, rr.Body.String())
					}
				}
			}
		})
	}
}

func TestInitRenderer(t *testing.T) {
	// Test initialization
	templateDir := "test_templates"
	baseTemplate := "test_base.html"

	InitRenderer(templateDir, baseTemplate)

	if DefaultRenderer == nil {
		t.Error("InitRenderer() should set DefaultRenderer")
	}

	if DefaultRenderer.templateDir != templateDir {
		t.Errorf("InitRenderer() templateDir = %v, expected %v", DefaultRenderer.templateDir, templateDir)
	}

	if DefaultRenderer.baseTemplate != baseTemplate {
		t.Errorf("InitRenderer() baseTemplate = %v, expected %v", DefaultRenderer.baseTemplate, baseTemplate)
	}
}

func TestDefaultRendererFunctions(t *testing.T) {
	// Create temporary directory for test templates
	tmpDir := t.TempDir()

	// Create base template
	baseContent := `<!DOCTYPE html>
<html>
<head><title>{{.Title}}</title></head>
<body>
{{template "content" .}}
</body>
</html>`

	baseFile := filepath.Join(tmpDir, "base.html")
	err := os.WriteFile(baseFile, []byte(baseContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create base template: %v", err)
	}

	// Create content template
	contentTemplate := `{{define "content"}}
<h1>{{.Heading}}</h1>
{{end}}`

	contentFile := filepath.Join(tmpDir, "content.html")
	err = os.WriteFile(contentFile, []byte(contentTemplate), 0644)
	if err != nil {
		t.Fatalf("Failed to create content template: %v", err)
	}

	// Create standalone template
	standaloneContent := `<h1>{{.Title}}</h1>`
	standaloneFile := filepath.Join(tmpDir, "standalone.html")
	err = os.WriteFile(standaloneFile, []byte(standaloneContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create standalone template: %v", err)
	}

	// Initialize default renderer
	InitRenderer(tmpDir, "base.html")

	t.Run("RenderWithBase", func(t *testing.T) {
		rr := httptest.NewRecorder()
		data := map[string]string{
			"Title":   "Test",
			"Heading": "Hello",
		}

		err := RenderWithBase(rr, "content.html", data)
		if err != nil {
			t.Errorf("RenderWithBase() error = %v", err)
		}

		if !strings.Contains(rr.Body.String(), "Hello") {
			t.Errorf("RenderWithBase() should contain 'Hello', got %q", rr.Body.String())
		}
	})

	t.Run("RenderStandalone", func(t *testing.T) {
		rr := httptest.NewRecorder()
		data := map[string]string{"Title": "Standalone Test"}

		err := RenderStandalone(rr, "standalone.html", data)
		if err != nil {
			t.Errorf("RenderStandalone() error = %v", err)
		}

		if !strings.Contains(rr.Body.String(), "Standalone Test") {
			t.Errorf("RenderStandalone() should contain 'Standalone Test', got %q", rr.Body.String())
		}
	})
}

func TestDefaultRendererNotInitialized(t *testing.T) {
	// Save current DefaultRenderer
	original := DefaultRenderer
	defer func() {
		DefaultRenderer = original
	}()

	// Set DefaultRenderer to nil to test the error case
	DefaultRenderer = nil

	// Test that DefaultRenderer is nil (we can't test log.Fatal without causing test to exit)
	t.Run("RenderWithBase without init", func(t *testing.T) {
		// We can only verify that DefaultRenderer is nil
		// The actual log.Fatal behavior can't be tested in unit tests
		if DefaultRenderer != nil {
			t.Error("DefaultRenderer should be nil for this test")
		}

		// Skip the actual function call that would cause log.Fatal
		t.Skip("Cannot test log.Fatal behavior in unit tests")
	})
}

func TestTemplateErrorHandling(t *testing.T) {
	// Create temporary directory for test templates
	tmpDir := t.TempDir()

	// Create template with syntax error
	invalidContent := `{{define "content"}}
<h1>{{.Title</h1>
{{end}}`

	invalidFile := filepath.Join(tmpDir, "invalid.html")
	err := os.WriteFile(invalidFile, []byte(invalidContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create invalid template: %v", err)
	}

	renderer := NewRenderer(tmpDir, "base.html")
	rr := httptest.NewRecorder()

	err = renderer.RenderStandalone(rr, "invalid.html", nil)
	if err == nil {
		t.Error("RenderStandalone() should return error for invalid template")
	}
}
