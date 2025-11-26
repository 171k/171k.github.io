---
title: "Apktool"
date: 2024-05-01
---

# APKTool Cheatsheet

Quick references I learnt throughout my journey using apktool in CTF

---

## 📦 Install APKTool

```bash
sudo apt install apktool
```

Or.. just download the latest JAR + wrapper script from the official site.

---

## 🔧 Decode / Decompile APK

### Full decode

```bash
apktool d app.apk
```

Creates a folder `app/` with smali, resources, manifest.

I use this one the most and use find + grep to get hardcoded flag lol

### Decode with original resources

```bash
apktool d app.apk -r
```

Skips decoding resources like XML → keeps them in binary form.

### Specify output directory

```bash
apktool d app.apk -o output_folder
```

---

## 🛠 Rebuild / Recompile APK

```bash
apktool b app_folder
```

Outputs to: `app_folder/dist/app_folder.apk`

### Rebuild with custom output

```bash
apktool b app_folder -o newapp.apk
```

Do this after patching apk file, dont forget to sign! (sign instruction below)

---

## 🔑 Signing the Rebuilt APK (Required!)

Android requires signing before installation.

### Generate keystore (first time only)

```bash
keytool -genkey -v -keystore mykey.keystore -alias myalias -keyalg RSA -keysize 2048 -validity 10000
```

### Sign APK

```bash
jarsigner -keystore mykey.keystore newapp.apk myalias
```

### Verify signature

```bash
jarsigner -verify newapp.apk
```

### Using apksigner (recommended because easier)

```bash
apksigner sign --ks mykey.keystore --out signed.apk newapp.apk
```

---

## 🔍 Common Edits

### 1. Modify resources (res/)

Change layouts, strings, images, etc.

### 2. Edit AndroidManifest.xml

Example: allow debug

```xml
android:debuggable="true"
```

### 3. Edit smali code

Smali is inside `smali/` folder.  
Example smali search:

```bash
grep -R "key" -n smali/
```

Challenge creators looooveeeeeeeeees hiding flags in smali and res. So go check there first!

---

## 🧹 Clean Build Directory

If a build cache causes errors i usually just delete everything:

```bash
rm -rf app_folder/build
```

---

## 🧪 Useful Tools (Optional)

- **jadx** → decompile Java/Kotlin (has gui so its very very niceeeeee)
  
- **aapt2** → inspect resources
  
- **zipalign** → optimize APK
  

### Zipalign example

```bash
zipalign -v 4 signed.apk aligned.apk
```

---

## ✔ Quick Reference

| Action | Command |
| --- | --- |
| Decode | `apktool d app.apk` |
| Decode (raw resources) | `apktool d app.apk -r` |
| Build | `apktool b folder` |
| Install framework | `apktool if framework.apk` |
| Sign APK | `apksigner sign --ks key.keystore` |
| Zipalign | `zipalign -v 4 in.apk out.apk` |

---

Feel free to contact me if I made a mistake here and there hehe
