frontend github repo link-https://github.com/sandeep14k/spo-task3-frontend

## User Signup Backend Server with Go and Gin
This is a backend server written in Go using the Gin framework.
It provides endpoints for user signup, login, and home access, with authentication and token validation middleware.
User credentials are encrypted and stored in a database

## Code Structure
controller/: Contains handler functions for different routes such as signup, login, and home.

database/: Contains functions for database connection.

encryption/: Contains functions for encrypting and decrypting user credentials.

helper/: Contains helper functions for generating and validating JWT tokens.

middleware/: Contains middleware functions for authenticating user requests and checking token validity.

model/: Contains data models for user entities.

routes/: Contains route definitions for different endpoints.

.env: Configuration file for environment variables like port number and database URI.

go.mod, go.sum: Go module files.

main.go: Entry point of the application, where the server is initialized.

## Routes
/signup: Endpoint for user signup.
/login: Endpoint for user login.
/home: Endpoint for accessing home after successful login (requires valid token).

