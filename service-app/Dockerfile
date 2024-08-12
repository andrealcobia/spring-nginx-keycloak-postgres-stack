# Use an official OpenJDK runtime as a parent image
FROM eclipse-temurin:17-jre-jammy

# Create a non-privileged user that the app will run under.
# See https://docs.docker.com/go/dockerfile-user-best-practices/
ARG UID=10001
RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "/nonexistent" \
    --shell "/sbin/nologin" \
    --no-create-home \
    --uid "${UID}" \
    appuser
USER appuser

# Set the working directory in the container
WORKDIR /app

# Copy the jar file into the container
COPY build/libs/demo-0.0.1-SNAPSHOT.jar app.jar

# Expose port 8080 to the outside world
EXPOSE 9080

# Run the jar file
ENTRYPOINT ["java", "-jar", "app.jar"]
