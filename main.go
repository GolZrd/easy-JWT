package main

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

type Todo struct {
	Text     string `json:"text"`
	Priority int    `json:"priority"`
	Done     bool   `json:"done"`
}

var db = map[string]string{
	"senior":   "password",
	"employee": "password",
}

var todos []Todo
var loggedInUser string

var secretKey = []byte("very-secret-key")

func main() {
	router := gin.Default()

	router.LoadHTMLGlob("templates/*")

	router.GET("/", showpage)
	router.POST("/add", authenticateMiddleware, todoAdd)
	router.POST("/toggle", authenticateMiddleware, todoToggle)

	router.POST("/login", loginhandler)
	router.GET("/logout", logouthandler)

	router.Run(":8000")
}

func showpage(c *gin.Context) {
	c.HTML(
		http.StatusOK,
		"index.html",
		gin.H{
			"todos":    todos,
			"LoggedIn": loggedInUser,
			"Username": loggedInUser,
			"Role":     getRole(loggedInUser),
		})
}

func todoAdd(c *gin.Context) {
	text := c.PostForm("Text")
	priority, _ := strconv.Atoi(c.PostForm("Priority"))

	newTodo := Todo{
		Text:     text,
		Priority: priority,
		Done:     false}

	todos = append(todos, newTodo)

	c.Redirect(http.StatusSeeOther, "/")
}

func todoToggle(c *gin.Context) {
	index := c.PostForm("index")
	i, _ := strconv.Atoi(index)

	todos[i].Done = !todos[i].Done

	c.Redirect(http.StatusSeeOther, "/")
}

// Function to create JWT tokens with claims
func createToken(username string) (string, error) {
	// Создаем JWT токен с утверждениями (claims)
	claims := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": username,                         // subject - имя пользователя
		"aud": getRole(username),                // audience - роль пользователя
		"exp": time.Now().Add(time.Hour).Unix(), // время истечения токена
		"iat": time.Now().Unix(),                // время создания токена
	})

	tokenString, err := claims.SignedString(secretKey)
	if err != nil {
		return "", err
	}

	// Выводим информацию о создании токена
	fmt.Printf("Token claims: %v\n", claims)
	return tokenString, nil
}

func getRole(username string) string {
	if username == "senior" {
		return "senior"
	}
	return "employee"
}

func loginhandler(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")

	// Проверяем, что имя пользователя и пароль соответствуют
	if db[username] == password {
		// Генерируем JWT токен
		tokenString, err := createToken(username)
		if err != nil {
			c.String(http.StatusInternalServerError, "Error creating token")
			return
		}
		loggedInUser = username
		fmt.Printf("Token created: %s\n", tokenString)
		// создаем cookie с токеном
		c.SetCookie("token", tokenString, 3600, "/", "localhost", false, true)

		c.Redirect(http.StatusSeeOther, "/")
	} else {
		c.String(http.StatusUnauthorized, "Invalid username or password")
	}
}

func authenticateMiddleware(c *gin.Context) {
	// Извлекаем токен из cookie
	tokenString, err := c.Cookie("token")
	if err != nil {
		fmt.Println("Token not found in cookie")
		c.Redirect(http.StatusSeeOther, "/login")
		c.Abort()
		return
	}

	// Проверяем, что токен валиден
	token, err := verifyToken(tokenString)
	if err != nil {
		fmt.Printf("Token verification failed: %v\n", err)
		c.Redirect(http.StatusSeeOther, "/login")
		c.Abort()
		return
	}

	// Выводим информацию о проверенном токене
	fmt.Printf("Token verified successfully. Claims: %v\n", token.Claims)

	c.Next()
}

// Функция для проверки JWT токенов
func verifyToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return secretKey, nil
	})

	// Проверяем, нет ли ошибок
	if err != nil {
		return nil, err
	}

	// Проверяем, что токен валиден
	if !token.Valid {
		return nil, fmt.Errorf("Invalid token")
	}

	// Возвращаем проверенный токен
	return token, nil

}

func logouthandler(c *gin.Context) {
	loggedInUser = ""
	// Удаляем cookie с токеном
	c.SetCookie("token", "", -1, "/", "localhost", false, true)
	c.Redirect(http.StatusSeeOther, "/")
}
