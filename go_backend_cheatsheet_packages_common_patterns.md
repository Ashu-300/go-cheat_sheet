# Go Backend Cheatsheet

A **practical Markdown reference** of the **most-used Go backend packages** and **common production-ready code patterns**.

This file is ideal for:
- Backend interviews
- New Go projects
- Copy‑paste starter utilities
- Giving to Copilot / teammates

---

## 📦 Most Used Go Packages (Backend)

### 🔐 Authentication / Security
| Purpose | Package |
|------|------|
| JWT | `github.com/golang-jwt/jwt/v5` |
| Password hashing | `golang.org/x/crypto/bcrypt` |

---

### 🌐 HTTP & Routing
| Purpose | Package |
|------|------|
| HTTP server | `net/http` |
| Router | `github.com/go-chi/chi/v5` |
| Middleware | `github.com/go-chi/chi/v5/middleware` |

---

### 🗄️ Databases

#### MongoDB
| Purpose | Package |
|------|------|
| Mongo Driver | `go.mongodb.org/mongo-driver/mongo` |

#### PostgreSQL
| Purpose | Package |
|------|------|
| SQL toolkit | `github.com/jmoiron/sqlx` |
| PG Driver | `github.com/jackc/pgx/v5/stdlib` |

---

### ⚙️ Config & Utilities
| Purpose | Package |
|------|------|
| Env variables | `github.com/joho/godotenv` |
| UUID | `github.com/google/uuid` |
| Validation | `github.com/go-playground/validator/v10` |

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
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var jwtSecret = []byte(os.Getenv("JWT_SECRET"))

func GenerateToken(userID string, role string) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"role": role,
		"exp": time.Now().Add(24 * time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func ValidateToken(tokenString string) (*dto.AccessClaim, error) {
	secret := os.Getenv("JWT_ACCESS_SECRET")
	if secret == "" {
		return nil, fmt.Errorf("missing JWT_ACCESS_SECRET")
	}

	var claim dto.AccessClaim

	// Parse the token into our custom claim struct
	token, err := jwt.ParseWithClaims(
		tokenString,
		&claim,
		func(t *jwt.Token) (interface{}, error) {
			// Check if signing method is HS256
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("invalid signing method")
			}
			return []byte(secret), nil
		},
	)

	if err != nil {
		return nil, err // parsing or validation failed
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

- Use **context** everywhere (`context.Context`)
- Never parse cookies manually
- JWT secret must come from env
- Close DB connections on shutdown
- Use middleware for auth

---

## 🚀 Recommended Next Utilities to Add

- Auth middleware (JWT + context)
- Graceful shutdown
- Request validation
- Central error handler
- Logging (zap / slog)

---

### ✅ This file is production‑ready & interview‑ready.
If you want:
- **JWT auth middleware**
- **Role‑based access control**
- **Go project folder structure**
- **Microservices version of this**

Tell me and I’ll extend this doc 👊

