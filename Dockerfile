FROM maven:3.9.16-eclipse-temurin-21 AS build
WORKDIR /workspace
COPY pom.xml ./
COPY security-common ./security-common
COPY security-app ./security-app
COPY secret-providers ./secret-providers
ARG APP_MODULE=security-app
RUN mvn -B -ntp -pl ${APP_MODULE} -am package -DskipTests

FROM eclipse-temurin:21-jre-jammy
WORKDIR /app
ARG APP_MODULE=security-app
COPY --from=build /workspace/${APP_MODULE}/target/${APP_MODULE}-0.1.0-SNAPSHOT.jar application.jar
USER 10001:10001
ENTRYPOINT ["java", "-jar", "/app/application.jar"]
