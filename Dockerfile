# Etap 1: Budowanie (używamy Mavena z JDK 23)
FROM maven:3.9.9-eclipse-temurin-23 AS build
WORKDIR /app
# Kopiujemy pom.xml i pobieramy zależności (cache'owanie)
COPY pom.xml .
# Instalujemy ręcznie bibliotekę jFuzzyLogic (musi być w repozytorium Mavena w kontenerze!)
COPY jFuzzyLogic.jar /app/
RUN mvn install:install-file -Dfile=/app/jFuzzyLogic.jar -DgroupId=net.sourceforge.jFuzzyLogic -DartifactId=jFuzzyLogic -Dversion=1.2.1 -Dpackaging=jar
# Kopiujemy resztę kodu i budujemy
COPY src ./src
RUN mvn clean package -DskipTests

# Etap 2: Uruchamianie
FROM eclipse-temurin:23-jre-alpine
WORKDIR /app
COPY --from=build /app/target/*.jar app.jar
# Porty: 8080 dla API/Web, 9000 dla sondy
EXPOSE 8080 9000
ENTRYPOINT ["java", "-jar", "app.jar"]