# Arrow Digital test repository.

Based on express and mongoose

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

```
1. Node.js version >= 16
2. npm version >= 8
3. MongoDB cluster (local or on Atlas)
```

### Deploying

1. provision MongoDB cluster
2. _fill in .env file_
3. `npm run populateData` _data generation script, this creates random strings_
4. `npm run dev` _runs nodemon dev server_
5. `node run start` _runs normal node server_
6. `npm run lint` _runs code linting_
7. `npm run test` _runs code testing_

### Objective

The objective of this test is to create an authorization API that allows the user to create, login and logout.
This login should generate a JWT that contains:
* The ID of the Lab **or** the ID of the Clinic that the user is tied to,
* The permissions of the user (admin, user, etc),
* The expiration date of the token.  

This JWT authentication middleware should be used to protect the routes of the API, and to set the user context in the request object, so that the routes can use it to check if the user has the required permissions to access the route, and to get the ID of the Lab or Clinic that the user is tied to, so that the routes can use it to filter the data that is returned to the user to only the data that belongs to the Lab or Clinic that the user is tied to.
This type of authentication is called Role Based Access Control (RBAC), and it is a very common way of handling authentication in APIs.

## Built With

- [Node.js](https://nodejs.org/en/)
- [Express]()
- [MongoDB]()
- [Mongoose]()

## Authors

- **Caio Fleury** - [CaioF](https://github.com/CaioF)

## License

This project is licensed under the AllRights-Attribution-NonCommercial-NoDerivatives 4.1 International License - see the [LICENSE.md](LICENSE.md) file for details
