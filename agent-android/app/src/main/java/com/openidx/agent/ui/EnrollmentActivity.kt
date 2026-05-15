package com.openidx.agent.ui

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.openidx.agent.BuildConfig
import com.openidx.agent.core.IdentityStore
import com.openidx.agent.enrollment.OAuthEnrollmentFlow
import com.openidx.agent.service.OpenIDXAgentService
import kotlinx.coroutines.launch

/**
 * Single-activity host for the agent's user-facing screens. Three states:
 *
 *   - Not enrolled: shows the OAuth sign-in form (server URL + Sign In).
 *   - Enrollment in progress: launches the AppAuth tab and waits for the
 *     redirect to come back via onNewIntent.
 *   - Enrolled: shows agent status (id, server, last seen) and a button to
 *     unenroll for development/testing.
 *
 * QR / Device-Owner provisioning bypasses this activity entirely — that
 * flow runs in [com.openidx.agent.admin.OpenIDXDeviceAdminReceiver] without
 * any UI.
 */
class EnrollmentActivity : ComponentActivity() {

    private var oauthFlow: OAuthEnrollmentFlow? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { EnrollmentScreen(::startOAuth) }

        intent?.data?.let { handleRedirect() }
    }

    override fun onNewIntent(intent: android.content.Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleRedirect()
    }

    private fun startOAuth(serverUrl: String) {
        oauthFlow = OAuthEnrollmentFlow(this, serverUrl).also { it.launch() }
    }

    private fun handleRedirect() {
        val flow = oauthFlow ?: return
        val intent = intent ?: return
        if (intent.data == null) return
        lifecycleScope().launch {
            flow.handleRedirect(intent)
                .onSuccess { OpenIDXAgentService.start(this@EnrollmentActivity) }
        }
    }

    override fun onDestroy() {
        oauthFlow?.dispose()
        super.onDestroy()
    }
}

// Small helper to keep imports tidy in this file.
private fun ComponentActivity.lifecycleScope() = androidx.lifecycle.lifecycleScope

@Composable
private fun EnrollmentScreen(onSignIn: (String) -> Unit) {
    val ctx = androidx.compose.ui.platform.LocalContext.current
    val identity = remember { IdentityStore(ctx).load() }
    var serverUrl by remember { mutableStateOf(BuildConfig.DEFAULT_SERVER_URL) }

    Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
        Column(modifier = Modifier.padding(24.dp)) {
            Text("OpenIDX Agent", style = MaterialTheme.typography.headlineMedium)
            Spacer(Modifier.height(16.dp))
            if (identity != null) {
                Text("Status: ${identity.status}")
                Text("Agent ID: ${identity.agentId}")
                Text("Server: ${identity.serverUrl}")
                Text("Method: ${identity.enrollmentMethod}")
            } else {
                Text("Sign in with your work email to enroll this device.")
                Spacer(Modifier.height(12.dp))
                OutlinedTextField(
                    value = serverUrl,
                    onValueChange = { serverUrl = it },
                    label = { Text("OpenIDX server URL") },
                    singleLine = true,
                )
                Spacer(Modifier.height(12.dp))
                Button(onClick = { onSignIn(serverUrl) }) {
                    Text("Sign in with OpenIDX")
                }
            }
        }
    }
}
