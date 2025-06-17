# ========================================
# Optimized Multi-stage Dockerfile for ProjectTracker
# ========================================

# Build stage - Maven build
FROM eclipse-temurin:17-jdk-alpine as builder

# Install Maven
RUN apk add --no-cache maven

# Set working directory
WORKDIR /app

# Copy Maven files
COPY pom.xml .
COPY src ./src

# Build the application
RUN mvn clean package -DskipTests

# Extract JAR layers for better caching
RUN java -Djarmode=layertools -jar target/*.jar extract

# Final run stage
FROM eclipse-temurin:17-jre-alpine

# Set working directory
WORKDIR /app

# Copy the extracted JAR layers (optimizes Docker layer caching)
COPY --from=builder /app/dependencies/ ./
COPY --from=builder /app/spring-boot-loader/ ./
COPY --from=builder /app/snapshot-dependencies/ ./
COPY --from=builder /app/application/ ./

# Set timezone to a more standard one (change as needed)
RUN apk --no-cache add tzdata && \
    cp /usr/share/zoneinfo/UTC /etc/localtime && \
    echo "UTC" > /etc/timezone && \
    apk del tzdata

# Add non-root user for security
RUN addgroup -S spring && \
    adduser -S spring -G spring && \
    chown -R spring:spring /app

# Switch to non-root user
USER spring:spring

# Expose port
EXPOSE 8080

# Environment variables
ENV SPRING_PROFILES_ACTIVE=docker
ENV JAVA_OPTS="-Xmx1024m -Xms512m"

# Health check (optional - you can also rely on Docker Compose health checks)
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8080/actuator/health || exit 1

# Run the application using Spring Boot's optimized launcher
ENTRYPOINT ["java", "org.springframework.boot.loader.launch.JarLauncher"]