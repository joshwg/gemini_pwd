package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetCurrentUser(t *testing.T) {
	tests := []struct {
		name        string
		user        *User
		expectUser  bool
		expectEqual bool
	}{
		{
			name: "user exists in request context",
			user: &User{
				ID:       1,
				Username: "testuser",
				IsAdmin:  false,
			},
			expectUser:  true,
			expectEqual: true,
		},
		{
			name:        "no user in request context",
			user:        nil,
			expectUser:  false,
			expectEqual: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)

			if tt.user != nil {
				req = SetUserContext(req, tt.user)
			}

			user, ok := GetCurrentUser(req)

			if ok != tt.expectUser {
				t.Errorf("Expected ok=%t, got %t", tt.expectUser, ok)
			}

			if tt.expectEqual {
				if user == nil {
					t.Fatal("Expected user, got nil")
				}
				if user.ID != tt.user.ID {
					t.Errorf("Expected user ID %d, got %d", tt.user.ID, user.ID)
				}
				if user.Username != tt.user.Username {
					t.Errorf("Expected username %s, got %s", tt.user.Username, user.Username)
				}
				if user.IsAdmin != tt.user.IsAdmin {
					t.Errorf("Expected IsAdmin %t, got %t", tt.user.IsAdmin, user.IsAdmin)
				}
			} else {
				if user != nil {
					t.Errorf("Expected nil user, got %+v", user)
				}
			}
		})
	}
}

func TestSetUserContext(t *testing.T) {
	user := &User{
		ID:       42,
		Username: "contextuser",
		IsAdmin:  true,
	}

	req := httptest.NewRequest("POST", "/test", nil)
	newReq := SetUserContext(req, user)

	// Verify the request was modified
	if newReq == req {
		t.Error("SetUserContext should return a new request")
	}

	// Verify user can be retrieved from new request
	retrievedUser, ok := GetCurrentUser(newReq)
	if !ok {
		t.Fatal("User not found in context after SetUserContext")
	}

	if retrievedUser.ID != user.ID {
		t.Errorf("Expected user ID %d, got %d", user.ID, retrievedUser.ID)
	}

	if retrievedUser.Username != user.Username {
		t.Errorf("Expected username %s, got %s", user.Username, retrievedUser.Username)
	}

	if retrievedUser.IsAdmin != user.IsAdmin {
		t.Errorf("Expected IsAdmin %t, got %t", user.IsAdmin, retrievedUser.IsAdmin)
	}

	// Verify original request is unchanged
	_, ok = GetCurrentUser(req)
	if ok {
		t.Error("Original request should not have user context")
	}
}

func TestRequireAuth(t *testing.T) {
	called := false
	handler := RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	tests := []struct {
		name           string
		user           *User
		expectedStatus int
		shouldCallNext bool
	}{
		{
			name: "authenticated user",
			user: &User{
				ID:       1,
				Username: "authuser",
				IsAdmin:  false,
			},
			expectedStatus: http.StatusOK,
			shouldCallNext: true,
		},
		{
			name:           "no user in context",
			user:           nil,
			expectedStatus: http.StatusUnauthorized,
			shouldCallNext: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called = false
			req := httptest.NewRequest("GET", "/protected", nil)

			if tt.user != nil {
				req = SetUserContext(req, tt.user)
			}

			w := httptest.NewRecorder()
			handler(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if called != tt.shouldCallNext {
				t.Errorf("Expected called=%t, got %t", tt.shouldCallNext, called)
			}
		})
	}
}

func TestRequireAdmin(t *testing.T) {
	called := false
	handler := RequireAdmin(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	tests := []struct {
		name           string
		user           *User
		expectedStatus int
		shouldCallNext bool
	}{
		{
			name: "admin user",
			user: &User{
				ID:       1,
				Username: "admin",
				IsAdmin:  true,
			},
			expectedStatus: http.StatusOK,
			shouldCallNext: true,
		},
		{
			name: "non-admin user",
			user: &User{
				ID:       2,
				Username: "user",
				IsAdmin:  false,
			},
			expectedStatus: http.StatusForbidden,
			shouldCallNext: false,
		},
		{
			name:           "no user in context",
			user:           nil,
			expectedStatus: http.StatusUnauthorized,
			shouldCallNext: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called = false
			req := httptest.NewRequest("GET", "/admin", nil)

			if tt.user != nil {
				req = SetUserContext(req, tt.user)
			}

			w := httptest.NewRecorder()
			handler(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if called != tt.shouldCallNext {
				t.Errorf("Expected called=%t, got %t", tt.shouldCallNext, called)
			}
		})
	}
}

func TestMustGetCurrentUser(t *testing.T) {
	t.Run("user exists in context", func(t *testing.T) {
		user := &User{
			ID:       99,
			Username: "mustuser",
			IsAdmin:  false,
		}

		req := httptest.NewRequest("GET", "/", nil)
		req = SetUserContext(req, user)

		retrievedUser := MustGetCurrentUser(req)

		if retrievedUser == nil {
			t.Fatal("Expected user, got nil")
		}

		if retrievedUser.ID != user.ID {
			t.Errorf("Expected user ID %d, got %d", user.ID, retrievedUser.ID)
		}

		if retrievedUser.Username != user.Username {
			t.Errorf("Expected username %s, got %s", user.Username, retrievedUser.Username)
		}
	})

	t.Run("no user in context - should panic", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic, but function did not panic")
			}
		}()

		req := httptest.NewRequest("GET", "/", nil)
		MustGetCurrentUser(req)
	})
}
