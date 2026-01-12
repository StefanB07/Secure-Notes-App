# Use an official OpenJDK runtime as a parent image
FROM eclipse-temurin:21-jdk-alpine

# Set the working directory inside the container
WORKDIR /app

# Copy the Maven wrapper and pom.xml file
COPY .mvn/ .mvn
COPY mvnw pom.xml ./

# Ensure the mvnw script is executable (important for Windows users)
RUN chmod +x mvnw

# Copy the project source code
COPY src ./src

# Build the application inside the container
RUN ./mvnw clean package -DskipTests

RUN mv target/secure-notes-0.0.1-SNAPSHOT.jar app.jar

# Expose the port the app runs on
EXPOSE 8080

# Run the jar file
ENTRYPOINT ["java", "-jar", "app.jar"]