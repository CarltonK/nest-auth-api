## Requirements

1. Node 22.XX

## Installation

```bash
$ npm install
```

## Running the app

Running the app for the first time requires

```bash
$ docker compose up --build
```

for subsequent runs you can use

```bash
$ docker compose up
```

## Accessing the database

Once confirmed that the app is running locally, access the database via

```bash
$ npx prisma studio
```

## Creating a database migration

1. Define your models in prisma/schema.prisma
2. Enter the following command to create a migration

```bash
$ npx prisma migrate dev --name NAME_HERE
```
3. [IFF(IF AND ONLY IF) SQL NEEDED] Enter the following command to create an empty migration

```bash
$ npx prisma migrate dev --name NAME_HERE --create-only
```

Replace <strong>NAME_HERE</strong> with the migration name.

For easier identification the name should be in small caps and separate by underscore. Please also make sure to start with the action (create/delete/update) followed by the table, column/index in that order. For Example:-

```bash
$ npx prisma migrate dev --name create_user_table
```

## Updating configuration

Configuration is managed via environment variables.

To add or update a configuration value:
1. Add it in docker-compose.yaml
2. Add it in src/utils/config.ts
3. Validate it in validationSchema inside config.ts
4. Restart the app

## API Documentation

Once confirmed that the app is running you can access the documentation on http://localhost:3000/swagger