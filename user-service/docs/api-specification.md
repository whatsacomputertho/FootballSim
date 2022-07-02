
# FootballSim User Service

## Log In

- POST /api/v0/user/login/
- Request Body
  - **email**
  - **password**
- Response Body
  - **status**
  - **token**
  - **message**

## Register

- POST /api/v0/user/register/
- Request Body
  - **email**
  - **password**
- Response Body
  - **status**
  - **token**
  - **message**

## Update Account
- PUT /api/v0/user/update/
- Request Body
  - **email**
  - **password**
  - **updated-email**
  - **updated-password**
- Response Body
  - **status**
  - **message**

## Deactivate Account

- PUT /api/v0/user/deactivate/
- Request Body
  - **email**
  - **password**
- Response Body
  - **status**
  - **message**