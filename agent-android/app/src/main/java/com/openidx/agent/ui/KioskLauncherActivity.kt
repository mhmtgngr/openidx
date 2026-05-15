package com.openidx.agent.ui

import android.app.ActivityManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.LauncherApps
import android.content.pm.PackageManager
import android.graphics.Color
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color as ComposeColor
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.openidx.agent.core.KioskState

/**
 * Multi-app kiosk launcher. Shown as the home replacement when policy.mode
 * is "multi_app". Lists the allowed apps as large icons; tapping launches
 * the app while remaining inside lock-task (the DPM whitelist permits it).
 *
 * Hides the status bar / nav bar via WindowManager flags so users can't
 * pull down the shade. The lock-task feature mask on the server side
 * decides whether those bars are accessible at all.
 *
 * Single-app mode bypasses this activity — the KioskController launches the
 * configured activity directly and the lock-task whitelist prevents the
 * user from leaving it.
 */
class KioskLauncherActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.decorView.systemUiVisibility = (
            android.view.View.SYSTEM_UI_FLAG_HIDE_NAVIGATION
                or android.view.View.SYSTEM_UI_FLAG_IMMERSIVE_STICKY
                or android.view.View.SYSTEM_UI_FLAG_FULLSCREEN
            )
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)

        setContent { KioskLauncherScreen() }
    }

    override fun onResume() {
        super.onResume()
        // Re-enter lock-task on resume in case Android dropped us out
        // (happens after some OEM-specific event flows).
        runCatching {
            val am = getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
            @Suppress("DEPRECATION")
            val mode = am.lockTaskModeState
            if (mode == ActivityManager.LOCK_TASK_MODE_NONE) {
                startLockTask()
            }
        }
    }

    override fun onBackPressed() {
        // Suppress back inside the launcher; lock-task lets back leave the
        // activity stack but we always want to land back here.
    }
}

@Composable
private fun KioskLauncherScreen() {
    val ctx = LocalContext.current
    val policy = remember { KioskState(ctx).load() }
    var apps by remember { mutableStateOf<List<KioskAppEntry>>(emptyList()) }

    LaunchedEffect(policy) {
        apps = (policy?.allowed_packages ?: emptyList()).mapNotNull { pkg ->
            runCatching { resolveAppEntry(ctx, pkg) }.getOrNull()
        }
    }

    Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
        Column(
            modifier = Modifier.fillMaxSize().padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text(
                text = policy?.name?.takeIf { it.isNotBlank() } ?: "OpenIDX Kiosk",
                style = MaterialTheme.typography.headlineSmall,
            )
            LazyVerticalGrid(
                columns = GridCells.Adaptive(120.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                items(apps) { app -> KioskTile(app) { launchApp(ctx, app) } }
            }
        }
    }
}

@Composable
private fun KioskTile(app: KioskAppEntry, onClick: () -> Unit) {
    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(16.dp))
            .background(ComposeColor(0xFFE3E8EF))
            .clickable(onClick = onClick)
            .padding(20.dp),
        contentAlignment = Alignment.Center,
    ) {
        Text(app.label, textAlign = TextAlign.Center)
    }
}

private data class KioskAppEntry(
    val packageName: String,
    val label: String,
    val activityComponent: ComponentName,
)

private fun resolveAppEntry(ctx: Context, packageName: String): KioskAppEntry {
    val pm = ctx.packageManager
    val launch = pm.getLaunchIntentForPackage(packageName)
        ?: error("no launch intent for $packageName")
    val component = launch.component ?: error("no component for $packageName")
    val info = pm.getApplicationInfo(packageName, 0)
    val label = pm.getApplicationLabel(info).toString()
    return KioskAppEntry(packageName, label, component)
}

private fun launchApp(ctx: Context, app: KioskAppEntry) {
    val intent = Intent().apply {
        component = app.activityComponent
        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    }
    runCatching { ctx.startActivity(intent) }
}
