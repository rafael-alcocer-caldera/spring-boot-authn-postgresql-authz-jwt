# SPRING BOOT AUTHENTICATION POSTGRESQL AUTHORIZATION JWT

## Synopsis

The project is a Spring Boot Application that calls the Authentication PostgresQL Service and creates the JSON Web Token. 

## Motivation

I wanted to extend the Authorization JWT Service [Spring Boot Authorization JWT](https://github.com/rafael-alcocer-caldera/spring-boot-authorization-jwt) that I have.

## Pre Requirements

- You need PostgresQL installed
- You need my [Spring Boot Authentication PostgresQL](https://github.com/rafael-alcocer-caldera/spring-boot-authentication-postgresql) and start it. It creates the database, after this you need to execute the queries that are in the queries.sql within the resource folder


USING POSTMAN:
--------------

ADMIN USER
----------
POST
http://localhost:9090/authorization

Body
----
```json
{
    "username": "admin",
    "password": "admin"
}
```

Response:
---------
```json
{
    "username": "admin",
    "password": null,
    "jwt": "eyJhbGciOiJIUzUxMiJ9.eyJqdGkiOiIxYmQ4MDc3ZmIwMDg0OGE3YmZiYzQ1MTI3MDhiOWFkNSIsImlzcyI6InJhcGlkc2hvcCIsInN1YiI6InRva2VuIiwiZXhwIjoxNjQzODU3NDQ2LCJhdXRob3JpdGllcyI6WyJST0xFX1VTRVIiXX0.P328bf8YI2CoR1bdaivvqFFgJDV5P0ir63Js7ZiaUYxI9PHqGQUQSzTb6tGPXj9eCcyCDFMX9pamb_5xIfWvqw"
}
```

Eclipse Console:
----------------

&#35;&#35;&#35;&#35;&#35; LoginController... username: admin

&#35;&#35;&#35;&#35;&#35; LoginController... password: admin

&#35;&#35;&#35;&#35;&#35; webSecurityConfiguration.getSecretKey(): JvKyO3sH3QHpJTZ5aZikk9QdZY1wL5H0J47B9IRSRsD6nA7F25AzGnVc9P96Zwf0wwtgAvAMz+G24hVLUJ2n1A==

&#35;&#35;&#35;&#35;&#35; responseBody: {"id":1,"username":"admin","email":"admin@admin.com","authorities":[{"authority":"ROLE_ADMIN"}],"enabled":true,"accountNonExpired":true,"accountNonLocked":true,"credentialsNonExpired":true}

&#35;&#35;&#35;&#35;&#35; responseBody.getString("username"): admin

&#35;&#35;&#35;&#35;&#35; responseBody.getString("authorities"): [{"authority":"ROLE_ADMIN"}]

&#35;&#35;&#35;&#35;&#35; responseBody.getJSONArray("authorities"): [{"authority":"ROLE_ADMIN"}]

&#35;&#35;&#35;&#35;&#35; responseBody.getJSONArray("authorities").size(): 1

&#35;&#35;&#35;&#35;&#35; responseBody.getJSONArray("authorities").getJSONObject(0): {"authority":"ROLE_ADMIN"}

&#35;&#35;&#35;&#35;&#35; responseBody.getJSONArray("authorities").getJSONObject(0).getString("authority"): ROLE_ADMIN

&#35;&#35;&#35;&#35;&#35; dateTime (including minutes added: Wed Feb 02 21:04:06 CST 2022

&#35;&#35;&#35;&#35;&#35; JWT: eyJhbGciOiJIUzUxMiJ9.eyJqdGkiOiIxYmQ4MDc3ZmIwMDg0OGE3YmZiYzQ1MTI3MDhiOWFkNSIsImlzcyI6InJhcGlkc2hvcCIsInN1YiI6InRva2VuIiwiZXhwIjoxNjQzODU3NDQ2LCJhdXRob3JpdGllcyI6WyJST0xFX1VTRVIiXX0.P328bf8YI2CoR1bdaivvqFFgJDV5P0ir63Js7ZiaUYxI9PHqGQUQSzTb6tGPXj9eCcyCDFMX9pamb_5xIfWvqw


## License

All work is under Apache 2.0 license