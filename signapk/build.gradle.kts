plugins {
    application
    id("com.github.johnrengelman.shadow") version "7.1.2"
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.conscrypt:conscrypt-openjdk-uber:2.5.2")
}

application {
    mainClass.set("com.android.signapk.SignApk")
}

sourceSets {
    getByName("main") {
        java.srcDirs("${rootDir}/../external/apksig/src/main/java")
        // Use AOSP's fork of bouncycastle because signapk depends on some
        // private classes that the fork makes public
        java.srcDirs("${rootDir}/../external/bouncycastle/bcpkix/src/main/java")
        java.srcDirs("${rootDir}/../external/bouncycastle/bcprov/src/main/java")
        java.srcDirs("${rootDir}/../external/build/tools/signapk/src")
    }
}
