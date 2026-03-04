pluginManagement {
    repositories {
        val useMirror = (System.getenv("ZAGORA_ANDROID_USE_MIRROR") ?: "").lowercase() in setOf("1", "true", "yes")
        if (useMirror) {
            maven(url = "https://maven.aliyun.com/repository/google")
            maven(url = "https://maven.aliyun.com/repository/public")
            maven(url = "https://mirrors.cloud.tencent.com/nexus/repository/maven-public/")
            maven(url = "https://mirrors.cloud.tencent.com/gradle/")
        }
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        val useMirror = (System.getenv("ZAGORA_ANDROID_USE_MIRROR") ?: "").lowercase() in setOf("1", "true", "yes")
        if (useMirror) {
            maven(url = "https://maven.aliyun.com/repository/google")
            maven(url = "https://maven.aliyun.com/repository/public")
            maven(url = "https://mirrors.cloud.tencent.com/nexus/repository/maven-public/")
        }
        google()
        mavenCentral()
    }
}

rootProject.name = "zagora-android"
include(":app")
