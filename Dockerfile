FROM maven:3.9.9-eclipse-temurin-21 AS builder
WORKDIR /app

COPY pom.xml .
RUN mvn -q -DskipTests dependency:go-offline

COPY src ./src
RUN mvn -q -DskipTests package

FROM eclipse-temurin:21-jre
WORKDIR /opt/arc-auth
COPY --from=builder /app/target/arc-auth-*.jar app.jar

RUN useradd --system --no-create-home --shell /usr/sbin/nologin arcauth
USER arcauth

EXPOSE 8082
ENV JAVA_OPTS=""
ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar /opt/arc-auth/app.jar"]
