# Auth Microservice

## Cómo levantar el proyecto en desarrollo

1. Clonar el repositorio
2. Instalar dependencias

```
npm install
```

3. Copiar y renombrar el archivo `.env.template` a `.env`

4. Levantar servidor de nats

```
docker run -d --name nats-server -p 4222:4222 -p 8222:8222 nats
```

5. Ejecutar

```
npm run start:dev
```

## Cómo crear imagen sin aplicar MultiStage Build

1. Crear un archivo llamado `dockerfile.prod` en la raiz del proyecto con la siguiente configuración

```
FROM node:21-alpine3.19

WORKDIR /usr/src/app

COPY package.json ./
COPY package-lock.json ./

RUN npm install

COPY . .

RUN npm run build

EXPOSE 3000
EXPOSE 4200

CMD [ "node", "dist/main.js" ]

```

2. Ejecutar el siguiente comando

```
docker build -f dockerfile.prod -t client-gateway .
```

**-f** Indica el archivo a buscar.  
**-t** Se refiere al tag.  
**.** Busca el archivo en el contexto donde está.

**IMPORTANTE:**  
Al crear la imagen así toma la arquitectura de la computadora donde se crea

## Cómo crear imagen aplicando MultiStage Build

El MultiStage Build es mejor opción que el anterior para producción ya que reduce el tamaño de la imagen y la velocidad con la que se construye.

1. En un archivo `dockerfile.prod` aplicamos la siguiente configuración

```
# Etapa de Dependencias - as deps significa que toda la etapa de conocerá como deps
FROM node:21-alpine3.19 as deps

WORKDIR /usr/src/app

COPY package*.json ./

RUN npm install

# Etapa del Builder - Se construye la aplicación, usualmente para indicar que viene una nueva etapa se hace referencia a una nueva imagen, por eso de nuevo se escribe FROM node:21...
FROM node:21-alpine3.19 as build

WORKDIR /usr/src/app

# Copiar de deps los módulos de node
COPY --from=deps /usr/src/app/node_modules ./node_modules

# Copiar todo el código fuente de la aplicación
COPY . .

RUN npm run build

# Limpiamos todos los módulos de node que no se necesitan, solo se dejan los de producción para reducir el peso
RUN npm ci -f --only=production && npm cache clean --force

# Etapa de creación - Se crea la imagen final de docker
FROM node:21-alpine3.19 as prod

WORKDIR /usr/src/app

COPY --from=build /usr/src/app/node_modules ./node_modules

COPY --from=build /usr/src/app/dist ./dist

# Creamos una variable de entorno para indicar que estamos en producción
ENV NODE_ENV=production

# Creamos un usuario que se llame Node y nos movemos a él, es coveniente porque el usuario original tiene demasiado privilegio, entonces creamos uno que solo tenga permiso de ejecución
USER node

EXPOSE 3000

# Ejecutamos la aplicación con node dist/main.js
CMD ["node", "dist/main.js"]
```

2. Ejecutar el siguiente comando

```
docker build -f dockerfile.prod -t client-gateway .
```

**-f** Indica el archivo a buscar.  
**-t** Se refiere al tag.  
**.** Busca el archivo en el contexto donde está.
