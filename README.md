# auth-service-multi-provider-poc

**Build**  
* ./auth-service/gradlew --build-file auth-service/build.gradle --settings-file auth-service/settings.gradle bootBuildImage
* ./resource-server/gradlew --build-file resource-server/build.gradle --settings-file resource-server/settings.gradle bootBuildImage
* docker-compose up