# Builds and signs the MDM-Lite Android agent APK without Gradle.
# Requires: JDK 17+, Android SDK (build-tools 34 + platform android-34).
#   $env:ANDROID_HOME = "C:\Android\Sdk"     (or it auto-detects common paths)
#
# Run:  powershell -ExecutionPolicy Bypass -File build.ps1
param(
    [string]$OutFile = "..\..\release\android\MDM-Lite-Agent.apk",
    [string]$StorePass = "mdmlite2026"
)

$ErrorActionPreference = "Stop"

if ($env:ANDROID_HOME) { $sdk = $env:ANDROID_HOME }
elseif ($env:ANDROID_SDK_ROOT) { $sdk = $env:ANDROID_SDK_ROOT }
elseif (Test-Path "$env:LOCALAPPDATA\Android\Sdk") { $sdk = "$env:LOCALAPPDATA\Android\Sdk" }
else { throw "Android SDK not found. Set ANDROID_HOME." }

$bt = "$sdk\build-tools\34.0.0"
$platform = "$sdk\platforms\android-34"
$androidJar = "$platform\android.jar"

foreach ($p in @($bt, $platform)) {
    if (-not (Test-Path $p)) { throw "Missing SDK component: $p (run sdkmanager: `"$bt\sdkmanager.bat`" `"platforms;android-34`" `"build-tools;34.0.0`" `"platform-tools`")" }
}

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$buildDir = Join-Path $root "build"
$resZip   = Join-Path $buildDir "gen\res.zip"
$baseApk  = Join-Path $buildDir "base-unsigned.apk"
$aligned  = Join-Path $buildDir "aligned.apk"
$finalApk = Join-Path $buildDir "MDM-Lite-Agent.apk"
$classes  = Join-Path $buildDir "classes"
$dexOut   = Join-Path $buildDir "dex"
$keystore = Join-Path $buildDir "mdmlite-release.keystore"
$signing  = Join-Path (Split-Path -Parent $root) "..\release\android\signing\mdmlite-release.keystore"

New-Item -ItemType Directory -Force -Path "$buildDir\gen","$classes","$dexOut" | Out-Null

Write-Host "[1/6] Compile resources"
& "$bt\aapt2.exe" compile --dir "$root\res" -o $resZip
if ($LASTEXITCODE) { throw "aapt2 compile failed ($LASTEXITCODE)" }

Write-Host "[2/6] Link resources + manifest"
& "$bt\aapt2.exe" link -o $baseApk -I $androidJar --manifest "$root\AndroidManifest.xml" -R $resZip --auto-add-overlay
if ($LASTEXITCODE) { throw "aapt2 link failed ($LASTEXITCODE)" }

Write-Host "[3/6] Compile Java sources"
$srcs = Get-ChildItem "$root\java" -Recurse -Filter *.java | ForEach-Object { $_.FullName }
& javac --release 11 -classpath $androidJar -d $classes $srcs
if ($LASTEXITCODE) { throw "javac failed ($LASTEXITCODE)" }

Write-Host "[4/6] Dex (d8)"
$classFiles = Get-ChildItem $classes -Recurse -Filter *.class | ForEach-Object { $_.FullName }
& java -cp "$bt\lib\d8.jar" com.android.tools.r8.D8 --release --lib $androidJar --min-api 26 --output $dexOut $classFiles
if ($LASTEXITCODE) { throw "d8 failed ($LASTEXITCODE)" }

Write-Host "[5/6] Package + align"
& jar uf $baseApk -C $dexOut classes.dex
if ($LASTEXITCODE) { throw "jar failed ($LASTEXITCODE)" }
& "$bt\zipalign.exe" -f 4 $baseApk $aligned

Write-Host "[6/6] Sign"
if (-not (Test-Path $keystore)) {
    & keytool -genkeypair -keystore $keystore -alias mdmlite -keyalg RSA -keysize 2048 `
        -validity 10000 -storepass $StorePass -keypass $StorePass `
        -dname "CN=MDM-Lite Agent, OU=MDM-Lite, O=MDM-Lite, L=Local, ST=NA, C=US"
}
& "$bt\apksigner.bat" sign --ks $keystore --ks-key-alias mdmlite `
    --ks-pass "pass:$StorePass" --key-pass "pass:$StorePass" --out $finalApk $aligned
if ($LASTEXITCODE) { throw "apksigner failed ($LASTEXITCODE)" }
& "$bt\apksigner.bat" verify --verbose $finalApk | Out-Null

New-Item -ItemType Directory -Force -Path (Split-Path -Parent $OutFile) | Out-Null
Copy-Item $finalApk $OutFile -Force
if (-not (Test-Path $signing)) {
    Copy-Item $keystore $signing -Force
}
Write-Host "OK -> $OutFile ($([math]::Round((Get-Item $OutFile).Length/1KB,1)) KB, signed v1+v2)"