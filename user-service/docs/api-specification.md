
# FootballSim User Service

## Register

- POST /api/v0/user/register/
- Request Body
  - **email**
  - **password**
- Response Body
  - **status**
  - **refresh**
  - **access**
  - **message**

## Log In

- POST /api/v0/user/login/
- Request Body
  - **email**
  - **password**
- Response Body
  - **status**
  - **refresh**
  - **access**
  - **message**

## Generate Access Token

- POST /api/v0/user/generate/
- Request Body
  - **refresh**
- Response Body
  - **status**
  - **access**
  - **message**

## Update Account

- PUT /api/v0/user/update/
- Request Body
  - **access**
  - **email**
  - **password**
- Response Body
  - **status**
  - **message**

## Logout

- PUT /api/v0/user/logout/
- Request Body
  - **access**
- Response Body
  - **status**
  - **message**

## Deactivate Account

- PUT /api/v0/user/deactivate/
- Request Body
  - **access**
- Response Body
  - **status**
  - **message**