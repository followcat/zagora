plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.followcat.zagora"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.followcat.zagora"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
        freeCompilerArgs += "-Xskip-metadata-version-check"
    }

    buildFeatures {
        compose = true
    }
    composeOptions {
        kotlinCompilerExtensionVersion = "1.5.14"
    }
}

dependencies {
    val composeBom = enforcedPlatform("androidx.compose:compose-bom:2024.09.00")
    implementation(composeBom)
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.activity:activity-compose:1.9.2")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.6")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.6")
    implementation("androidx.lifecycle:lifecycle-viewmodel-ktx:2.8.6")

    implementation("com.squareup.retrofit2:retrofit:2.11.0")
    implementation("com.squareup.retrofit2:converter-moshi:2.11.0")
    implementation("com.squareup.okhttp3:logging-interceptor:4.12.0")
    implementation("com.squareup.moshi:moshi-kotlin:1.15.1")
    implementation("com.github.mwiede:jsch:0.2.18")
    implementation("org.connectbot:termlib:0.0.2") {
        exclude(group = "androidx.compose")
        exclude(group = "androidx.compose.animation")
        exclude(group = "androidx.compose.foundation")
        exclude(group = "androidx.compose.material3")
        exclude(group = "androidx.compose.runtime")
        exclude(group = "androidx.compose.ui")
        exclude(group = "androidx.core")
        exclude(group = "androidx.lifecycle")
        exclude(group = "androidx.activity")
        exclude(group = "androidx.transition")
    }

    constraints {
        implementation("androidx.lifecycle:lifecycle-runtime-compose") {
            version { strictly("2.8.6") }
            because("keep lifecycle stack aligned with AGP 8.5.x toolchain")
        }
        implementation("androidx.lifecycle:lifecycle-viewmodel-compose") {
            version { strictly("2.8.6") }
            because("keep lifecycle stack aligned with AGP 8.5.x toolchain")
        }
        implementation("androidx.lifecycle:lifecycle-viewmodel-ktx") {
            version { strictly("2.8.6") }
            because("keep lifecycle stack aligned with AGP 8.5.x toolchain")
        }
        implementation("org.jetbrains.kotlin:kotlin-stdlib") {
            version { strictly("1.9.24") }
            because("app compiler is Kotlin 1.9.x; avoid kotlin-stdlib 2.x metadata mismatch")
        }
        implementation("org.jetbrains.kotlin:kotlin-stdlib-jdk8") {
            version { strictly("1.9.24") }
            because("keep stdlib aligned with Kotlin Gradle plugin 1.9.24")
        }
        implementation("org.jetbrains.kotlin:kotlin-stdlib-jdk7") {
            version { strictly("1.9.24") }
            because("keep stdlib aligned with Kotlin Gradle plugin 1.9.24")
        }
    }

    testImplementation("junit:junit:4.13.2")

    debugImplementation("androidx.compose.ui:ui-tooling")
}
