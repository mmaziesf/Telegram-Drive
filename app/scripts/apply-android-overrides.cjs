#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

const appRoot = path.resolve(__dirname, '..');
const source = path.join(appRoot, 'android-overrides');
const destination = path.join(appRoot, 'src-tauri', 'gen', 'android');

if (!fs.existsSync(destination)) {
  throw new Error('Android project is missing. Run `npm run tauri android init` first.');
}
if (!fs.existsSync(source)) {
  throw new Error('Committed Android overrides are missing.');
}

for (const entry of fs.readdirSync(source)) {
  fs.cpSync(path.join(source, entry), path.join(destination, entry), {
    recursive: true,
    force: true,
  });
}

const required = [
  'app/build.gradle.kts',
  'app/proguard-rules.pro',
  'app/src/main/AndroidManifest.xml',
  'app/src/main/baseline-prof.txt',
  'app/src/main/startup-prof.txt',
  'app/src/androidTest/java/io/github/mmaziesf/unofficialtelegramdrive/AndroidPlatformContractTest.kt',
  'app/src/main/java/io/github/mmaziesf/unofficialtelegramdrive/MainActivity.kt',
  'app/src/main/java/io/github/mmaziesf/unofficialtelegramdrive/TelegramDriveApplication.kt',
  'app/src/main/java/io/github/mmaziesf/unofficialtelegramdrive/UploadForegroundService.kt',
  'app/src/main/java/io/github/mmaziesf/unofficialtelegramdrive/MediaPlayerActivity.kt',
  'app/src/main/java/io/github/mmaziesf/unofficialtelegramdrive/PlaybackService.kt',
  'app/src/main/java/io/github/mmaziesf/unofficialtelegramdrive/TransferRecoveryWorker.kt',
  'app/src/main/java/io/github/mmaziesf/unofficialtelegramdrive/TransferJobService.kt',
  'app/src/main/res/drawable-xhdpi/tv_banner.png',
  'app/src/main/res/values/strings.xml',
  'app/src/main/res/xml/backup_rules.xml',
  'app/src/main/res/xml/data_extraction_rules.xml',
  'app/src/main/res/xml/file_paths.xml',
  'app/src/main/res/xml/network_security_config.xml',
];

for (const relative of required) {
  if (!fs.existsSync(path.join(destination, relative))) {
    throw new Error(`Required Android input was not reproduced: ${relative}`);
  }
}

console.log('Applied committed Android Gradle, manifest, Kotlin, and resource overrides.');
