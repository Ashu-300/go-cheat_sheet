Here is your **complete, clean, production-ready Go Backend Cheatsheet Markdown file** with the `main.go` section correctly placed after routes 👇

You can **copy-paste this entire file directly into `README.md` or `go-backend-cheatsheet.md`**.

---

# 🚀 Go Backend Cheatsheet

A **practical Markdown reference** of the **most-used Go backend packages** and **common production-ready code patterns**.

This file is ideal for:

* Backend interviews
* New Go projects
* Copy-paste starter utilities
* Giving to Copilot / teammates

---

## 📦 Most Used Go Packages (Backend)

### 🔐 Authentication / Security

| Purpose          | Package                        |
| ---------------- | ------------------------------ |
| JWT              | `github.com/golang-jwt/jwt/v5` |
| Password hashing | `golang.org/x/crypto/bcrypt`   |

---

### 🌐 HTTP & Routing

| Purpose     | Package                               |
| ----------- | ------------------------------------- |
| HTTP server | `net/http`                            |
| Router      | `github.com/go-chi/chi/v5`            |
| Middleware  | `github.com/go-chi/chi/v5/middleware` |

---

### 🗄️ Databases

#### MongoDB

| Purpose      | Package                             |
| ------------ | ----------------------------------- |
| Mongo Driver | `go.mongodb.org/mongo-driver/mongo` |

#### PostgreSQL

| Purpose     | Package                          |
| ----------- | -------------------------------- |
| SQL toolkit | `github.com/jmoiron/sqlx`        |
| PG Driver   | `github.com/jackc/pgx/v5/stdlib` |

---

### ⚙️ Config & Utilities

| Purpose       | Package                                  |
| ------------- | ---------------------------------------- |
| Env variables | `github.com/joho/godotenv`               |
| UUID          | `github.com/google/uuid`                 |
| Validation    | `github.com/go-playground/validator/v10` |

---

## 🌍 Environment Variables (.env)

```env
PORT=8080
JWT_SECRET=supersecretkey
DATABASE_URL=postgres://user:pass@localhost:5432/dbname
MONGO_URI=mongodb://localhost:27017
```

Load env:

```go
import "github.com/joho/godotenv"

godotenv.Load()
```

---

## 📥 Get & Set Headers (Chi / net/http)

### Get Header

```go
auth := r.Header.Get("Authorization")
```

### Set Header

```go
w.Header().Set("Content-Type", "application/json")
w.Header().Set("X-App-Version", "1.0")
```

⚠️ Headers must be set **before** `WriteHeader()` or `Write()`.

---

## 🔗 URL Params & Query Params (Chi)

### URL Params

```go
id := chi.URLParam(r, "id")
```

Route:

```go
r.Get("/users/{id}", handler)
```

---

### Query Params

```go
page := r.URL.Query().Get("page")
limit := r.URL.Query().Get("limit")
```

Example:

```
GET /users?page=1&limit=10
```

---

## 🍪 Cookies (Correct Way)

### Get Cookie

```go
cookie, err := r.Cookie("token")
if err != nil {
	// not found
}
```

### Set Cookie

```go
http.SetCookie(w, &http.Cookie{
	Name:     "token",
	Value:    token,
	HttpOnly: true,
	Secure:   true,
	Path:     "/",
	SameSite: http.SameSiteStrictMode,
})
```

---

## 🔐 JWT Utility (Generate & Verify)

### jwt.go

```go
package utils

import (
	"auth/src/dto"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func GenerateToken(userId string , email string , role string ) (string , string , error) {
	accessSecret := os.Getenv("JWT_ACCESS_SECRET")
	accessClaim := dto.AccessClaim{
		ID: userId,
		Email: email,
		Role: role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
    		IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256 , accessClaim)
	signedAccessToken , err := accessToken.SignedString([]byte(accessSecret))
	if err != nil {
		return "", "" , err
	}

	refreshSecret := os.Getenv("JWT_REFRESH_SECRET")
	refreshClaim := dto.RefreshClaim{
		ID: userId,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(7 * 24 * time.Hour)),
    		IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256 , refreshClaim)
	signedRefreshToken , err := refreshToken.SignedString([]byte(refreshSecret))
	if err != nil {
		return "" , "" , err
	}

	return signedAccessToken , signedRefreshToken , nil
}

func ValidateToken(tokenString string) (*dto.AccessClaim, error) {
	secret := os.Getenv("JWT_ACCESS_SECRET")
	if secret == "" {
		return nil, fmt.Errorf("missing JWT_ACCESS_SECRET")
	}

	var claim dto.AccessClaim

	token, err := jwt.ParseWithClaims(
		tokenString,
		&claim,
		func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("invalid signing method")
			}
			return []byte(secret), nil
		},
	)

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return &claim, nil
}
```

---

## 🛡️ Auth Middleware (JWT + Chi)

```go
package middleware

import (
	"context"
	"net/http"
	"strings"

	"auth/src/jwtutil"
)

type contextKey string

const AuthKey contextKey = "auth_context"

type AuthContext struct {
	UserID string
	Email  string
	Role   string
}

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			http.Error(w, "Invalid Authorization header", http.StatusUnauthorized)
			return
		}

		claims, err := jwtutil.ValidateToken(parts[1])
		if err != nil {
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}

		authCtx := AuthContext{
			UserID: claims.ID,
			Email:  claims.Email,
			Role:   claims.Role,
		}

		ctx := context.WithValue(r.Context(), AuthKey, authCtx)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
```

---

## 🧭 Routes Example (Public + Protected)

```go
package routes

import (
	"auth/src/controller"
	"auth/src/middleware"

	"github.com/go-chi/chi/v5"
)

func SetupAuthRoutes() chi.Router {
	r := chi.NewRouter()

	// Public routes
	r.Post("/register", controller.Register)
	r.Post("/login", controller.Login)

	// Protected routes
	r.Group(func(protected chi.Router) {
		protected.Use(middleware.AuthMiddleware)
		protected.Get("/me", controller.Me)
	})

	return r
}
```

---

## 🔓 Access Auth Context in Controller (IMPORTANT)

✅ Extract AuthContext in any controller

```go
package controller

import (
	"fmt"
	"net/http"

	"auth/src/middleware"
)

func Me(w http.ResponseWriter, r *http.Request) {

	// Extract auth context from request
	auth, ok := r.Context().Value(middleware.AuthKey).(middleware.AuthContext)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Access user data
	userID := auth.UserID
	email := auth.Email
	role := auth.Role

	fmt.Fprintf(w, "UserID: %s\nEmail: %s\nRole: %s", userID, email, role)
}

```

---
## 🚀 Application Entry Point (`main.go`)

```go
package main

import (
	"auth/src/db"
	"auth/src/routes"
	"log"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
	"github.com/joho/godotenv"
)

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Println("⚠️ No .env file found, using system env")
	}

	// Initialize database
	db.ConnectDB()

	// Create router
	router := chi.NewRouter()

	// CORS Middleware
	router.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"}, // ⚠️ change in production
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// Routes
	router.Mount("/api/auth", routes.SetupAuthRoutes())

	// Get port
	port := os.Getenv("PORT")
	if port == "" {
		port = "8001"
	}

	log.Printf("🚀 Auth service running on http://localhost:%s\n", port)

	if err := http.ListenAndServe(":"+port, router); err != nil {
		log.Fatal("❌ Server failed:", err)
	}
}
```

---

## 🗄️ PostgreSQL Connection (sqlx)

```go
package db

import (
	"fmt"
	"log"
	"os"

	"github.com/jmoiron/sqlx"
	_ "github.com/jackc/pgx/v5/stdlib"
)

var DB *sqlx.DB

func ConnectDB() {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatal("DATABASE_URL not set")
	}

	var err error
	DB, err = sqlx.Connect("pgx", dbURL)
	if err != nil {
		log.Fatalf("DB connection failed: %v", err)
	}

	fmt.Println("✅ Connected to PostgreSQL")
}
```

---

## 🍃 MongoDB Connection

```go
package db

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var Client *mongo.Client

func MongoInit() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	mongoURI := os.Getenv("MONGO_URI")

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(mongoURI))
	if err != nil {
		log.Fatal("❌ Mongo connection error:", err)
	}

	err = client.Ping(ctx, nil)
	if err != nil {
		log.Fatal("❌ Mongo ping error:", err)
	}

	Client = client
	fmt.Println("✅ Connected to MongoDB")
}
```

---

## 🧠 Best Practices (Important)

* Use **context** everywhere (`context.Context`)
* Never parse cookies manually
* JWT secret must come from env
* Close DB connections on shutdown
* Use middleware for auth

---

## 🚀 Recommended Next Utilities to Add

* Auth middleware (JWT + context)
* Graceful shutdown
* Request validation
* Central error handler
* Logging (zap / slog)

---


