package com.followcat.zagora.net

import com.followcat.zagora.model.Session
import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.Retrofit
import retrofit2.converter.moshi.MoshiConverterFactory
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.Body
import retrofit2.http.Path
import retrofit2.http.POST
import retrofit2.http.Query
import java.util.concurrent.TimeUnit

interface ZagoraApi {
    @GET("sessions")
    suspend fun listSessions(@Query("host") host: String? = null): List<Session>

    @DELETE("sessions/{name}")
    suspend fun deleteSession(
        @Path("name") name: String,
        @Query("host") host: String
    )

    @POST("sessions")
    suspend fun createSession(@Body body: CreateSessionRequest): Session
}

data class CreateSessionRequest(
    val name: String,
    val host: String,
    val status: String = "running"
)

object ZagoraApiFactory {
    fun create(server: String, token: String?): ZagoraApi {
        val baseUrl = ensureBaseUrl(server)
        val authInterceptor = Interceptor { chain ->
            val original = chain.request()
            val req = if (token.isNullOrBlank()) {
                original
            } else {
                original.newBuilder()
                    .addHeader("Authorization", "Bearer $token")
                    .build()
            }
            chain.proceed(req)
        }
        val logger = HttpLoggingInterceptor().apply {
            level = HttpLoggingInterceptor.Level.BASIC
        }
        val client = OkHttpClient.Builder()
            .addInterceptor(authInterceptor)
            .addInterceptor(logger)
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(10, TimeUnit.SECONDS)
            .build()
        val moshi = Moshi.Builder()
            .addLast(KotlinJsonAdapterFactory())
            .build()

        return Retrofit.Builder()
            .baseUrl(baseUrl)
            .addConverterFactory(MoshiConverterFactory.create(moshi))
            .client(client)
            .build()
            .create(ZagoraApi::class.java)
    }

    private fun ensureBaseUrl(server: String): String {
        val withScheme = if (server.startsWith("http://") || server.startsWith("https://")) {
            server
        } else {
            "http://$server"
        }
        return if (withScheme.endsWith("/")) withScheme else "$withScheme/"
    }
}
