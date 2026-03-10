---

title: "TNG Madani QR Phishing"
date: 2026-03-10
categories: [Blue Team, Analysis]
tags: [Phishing, Web]
featured: true

---

# Touch 'n Go / Malaysia Madani Scam QR Phishing analysis!
![](/assets/images/posts/madaniikan/tngtipu.png)
**Date:** 2026-03-10

**Target URL:** `https://bantuan-tng-inst.aply-gov.online/ap/`

**Threat Type:** Phishing / Telegram Account Takeover

**Severity:** HIGH (Active credential-harvesting campaign targeting Malaysian citizen)

**By:** 171k

Click [here](#my-advice-to-dear-malaysian) to skip to summary and my advice :3

---

## Executive Summary

This is an **active phishing campaign** impersonating the **Malaysia Madani government assistance program** and **Touch 'n Go eWallet**. The site was registered **less than 24 hours** before analysis (9/3/2026) and lures victims with a fake eWallet credit claim. The source code contains an untranslated Azerbaijani sentence referencing "₼3,399 AZN" (Azerbaijani manat) which indicates that the kit was recycled from a prior Azerbaijani campaign without proper localization.

Rather than stealing banking credentials directly, this kit executes a **full Telegram account takeover** by harvesting the victim's phone number, OTP and 2FA password in that particular order.

The backend uses a phishing kit self-identifying as **Truelogin V5**, with its **admin panel left exposed** and a Telegram bot used to receive stolen credentials in real time. No public threat intelligence on "Truelogin V5" was found.. it appears to be a reusable phishing kit rather than a widely-documented PhaaS product.

---

## i. Infrastructure & Domain Intelligence

### WHOIS

| Property                    | Value                                                                                                                   |
| --------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| **Domain**                  | `aply-gov.online`                                                                                                       |
| **Subdomain**               | `bantuan-tng-inst.aply-gov.online`                                                                                      |
| **Registry Domain ID**      | `D627894236-CNIC`                                                                                                       |
| **Registrar**               | Web Commerce Communications Ltd (WebNIC) — Malaysian registrar                                                          |
| **Registrar IANA ID**       | 460                                                                                                                     |
| **Creation Date**           | **2026-03-09 07:24:48 UTC** (< 24 hours before discovery)                                                               |
| **Updated Date**            | 2026-03-09 19:33:56 UTC                                                                                                 |
| **Expiry Date**             | 2027-03-09 23:59:59 UTC                                                                                                 |
| **DNSSEC**                  | Unsigned                                                                                                                |
| **Domain Status**           | `addPeriod`, `serverTransferProhibited`, `clientTransferProhibited`, `clientUpdateProhibited`, `clientDeleteProhibited` |
| **Registrar Abuse Contact** | support@webnic.cc / +60.389966788                                                                                       |

> The domain was created at 07:24 UTC and updated once at 19:33 UTC on the same day, suggesting rapid deployment and reconfiguration of the kit on launch day. The `addPeriod` EPP status confirms the domain is within its initial registration grace period which is a useful signal for automated domain-age detection rules!

### DNS Records

| Record Type     | Value                                                    |
| --------------- | -------------------------------------------------------- |
| **Nameservers** | `dana.ns.cloudflare.com`, `kevin.ns.cloudflare.com`      |
| **A (IPv4)**    | `104.21.90.163`, `172.67.202.116`                        |
| **AAAA (IPv6)** | `2606:4700:3034::6815:5aa3`, `2606:4700:3034::ac43:ca74` |

Both IPs belong to **Cloudflare anycast** (AS13335). The real origin server IP is hidden behind Cloudflare's reverse proxy.

### Domain Name Deception

The domain name `aply-gov.online` is crafted to **visually impersonate** a government domain:

```
Fake:    bantuan-tng-inst[.]aply-gov[.]online/ap/
Real:   *.gov.my  (actual Malaysian government TLD)
```

The attacker chose the `.online` TLD and structured the domain so `gov` appears as part of the second-level domain then hoping a casual user reads it as government-affiliated. 

---

## ii. The Phishing Page

![](/assets/images/posts/madaniikan/phishingsite.png)

### Impersonation

The page impersonates the following legitimate entities:

| Entity Spoofed                           | Evidence                                                              |
| ---------------------------------------- | --------------------------------------------------------------------- |
| **Malaysia Madani** (government program) | Branding, Malay-language text, government lure theme                  |
| **Touch 'n Go eWallet**                  | `images/touch.png`, `images/touch4.jpg` logo images, product UI clone |
| **Jata Negara (national crest)**         | `images/JataNegara.gif` — Malaysian coat of arms                      |

Additional assets on the page: `images/processing.gif`, `images/footer.webp`, `images/banner.webp` (CSS background).
These makes the website looks more legit to trick users.

### Lure Image & QR Code Delivery Vector

![](/assets/images/posts/madaniikan/tngphishh.png)

The lure image shows a fake **Touch 'n Go eWallet "Money Packet"** with a QR code and instructions in Malay:

letak gambar sini.

> "1. Lancarkan aplikasi eWallet → 2. Imbas Kod QR → 3. Sahkan Transaksi"
> "Imbas QR untuk teruskan" 

The QR code in the lure image encodes the phishing URL. This is the likely **primary delivery vector** where the image is shared via WhatsApp groups, Telegram or social media thenvictims scan the QR code to land on the phishing page. The QR code itself should be treated as an IOC.

### Attack Flow (Multi-Step Credential Harvest)

```
[Victim scans QR code / clicks link]
      │
      ▼
┌─────────────────────────────────────────────────────┐
│ STEP 1 — Identity Collection                        │
│  • Full Name  (input: full_name)                    │
│  • Telegram Phone Number  (input: phone_number)     │
│  • Normalize to +60XXXXXXXXX format                 │
│  POST → gateway.php?path=/generate-session          │
│  (Triggers Telegram to send OTP to victim's phone)  │
└─────────────────────────────────────────────────────┘
      │ Success
      ▼
┌─────────────────────────────────────────────────────┐
│ STEP 2 — OTP Harvest                                │
│  • 5-digit OTP (5 individual .otp-cell inputs)      │
│  POST → gateway.php?path=/validate-otp              │
│  (Authenticates attacker's Telegram session)        │
└─────────────────────────────────────────────────────┘
      │ If 2FA enabled
      ▼
┌─────────────────────────────────────────────────────┐
│ STEP 3 — 2FA Password Harvest                       │
│  • Telegram 2FA password  (input: password)         │
│  POST → gateway.php?path=/validate-password         │
└─────────────────────────────────────────────────────┘
      │ All steps complete
      ▼
[window.location.href = "https://malaysiamadani.gov.my/"]
    (Redirect to real gov site to avoid suspicion)
```

The victim is seamlessly redirected to the **legitimate Malaysia Madani website** after all credentials are captured which is a classic social engineering finish that prevents the victim from realising they were just compromised.

### 

### Error Handling in JavaScript

![](/assets/images/posts/madaniikan/jserror.png)

The client-side JavaScript handles specific Telegram API error codes, revealing the kit's awareness of Telegram's authentication flow:

| Error Code              | Meaning                                     |
| ----------------------- | ------------------------------------------- |
| `phone_number_invalid`  | Entered number not a valid Telegram account |
| `phone_code_expired`    | OTP timed out before submission             |
| `phone_code_invalid`    | Wrong OTP entered                           |
| `password_hash_invalid` | Wrong 2FA password                          |
| HTTP 429                | Rate limiting hit — too many auth attempts  |

### 

### What is Actually Being Stolen

This is **NOT** a traditional banking credential phish. The attacker is performing a **Telegram Account Takeover (ATO)**:

| Data Collected            | Purpose                                      |
| ------------------------- | -------------------------------------------- |
| Full Name                 | Victim profiling                             |
| Phone Number (+60 format) | Trigger real Telegram OTP to victim's device |
| Telegram OTP Code         | Complete Telegram login on attacker's device |
| Telegram 2FA Password     | Bypass Telegram's two-step verification      |

Once all three are submitted, the attacker has **full access to the victim's Telegram account** which may contain contacts, messages, groups, crypto wallets linked to Telegram and the ability to impersonate the victim to scam their contacts.

---

## iii. Backend — Truelogin V5

### Admin Panel Exposure

![](/assets/images/posts/madaniikan/adminpanel.png)

Navigating to `gateway.php?path=/generate-session` via GET request (instead of POST) **reveals the full Truelogin V5 admin dashboard** in a browser. This is a significant OPSEC failure by the operator.

The exposed admin panel shows:

| Property         | Value                                                                                                            |
| ---------------- | ---------------------------------------------------------------------------------------------------------------- |
| **Kit Name**     | Truelogin V5                                                                                                     |
| **Status**       | API ONLINE (animated green pulse indicator)                                                                      |
| **Backend**      | Node.js HTTP server on ports 80/443                                                                              |
| **Database**     | MongoDB (status: connected)                                                                                      |
| **Notification** | Telegram Bot                                                                                                     |
| **UI Note**      | "Update konfigurasi tanpa harus SSH ke server" (Indonesian: "Update configuration without SSHing to the server") |

![](/assets/images/posts/madaniikan/bottoken.png)

The panel allows an authenticated operator to **load and edit the `.env` configuration**, which contains:

```
BOT_TOKEN     ← Telegram bot token for receiving stolen credentials
USER_ID       ← Attacker's Telegram user ID (notifications destination)
API_ID        ← Telegram API application ID
API_HASH      ← Telegram API application hash
DATABASE_URL  ← MongoDB connection string
COLLECTION    ← MongoDB collection name
SOCKS5        ← SOCKS5 proxy (for evading Telegram API geolocation checks)
```

> The admin panel UI is accessible **without authentication** — only the "Load Settings" and "Save & Restart" actions require a password. The dashboard itself, including server status and connection info, is fully public.

### Setting Configuration (`setting.php`)

```json
{
  "apiBase": "",
  "requestCodePath": "gateway.php?path=/generate-session",
  "verifyCodePath": "gateway.php?path=/validate-otp",
  "verifyPasswordPath": "gateway.php?path=/validate-password",
  "notifyEndpoint": "",
  "defaultCountry": "ID"
}
```

> Note `"defaultCountry": "ID"` is for Indonesia. The kit was configured for Indonesian targets and redeployed for Malaysia with Malay-language content but without updating this default.

### API Endpoints

| Endpoint                              | Method | Purpose                                                    |
| ------------------------------------- | ------ | ---------------------------------------------------------- |
| `gateway.php?path=/generate-session`  | POST   | Initiates Telegram auth session with victim's phone number |
| `gateway.php?path=/generate-session`  | GET    | **Exposes Truelogin V5 admin panel** (OPSEC failure)       |
| `gateway.php?path=/validate-otp`      | POST   | Submits OTP to complete Telegram login                     |
| `gateway.php?path=/validate-password` | POST   | Submits 2FA password                                       |
| `gateway.php?path=/status`            | GET    | Returns HTTP 403                                           |
| `gateway.php` (no path)               | GET    | Returns `{"status":"error","message":"missing path"}`      |

---

## iv. Indicators of Compromise (IOCs)

### Network IOCs

| Type             | Value                                          |
| ---------------- | ---------------------------------------------- |
| **Phishing URL** | `https://bantuan-tng-inst.aply-gov.online/ap/` |
| **Domain**       | `aply-gov.online`                              |
| **Subdomain**    | `bantuan-tng-inst.aply-gov.online`             |
| **IP Address 1** | `104.21.90.163` (Cloudflare)                   |
| **IP Address 2** | `172.67.202.116` (Cloudflare)                  |
| **IPv6 1**       | `2606:4700:3034::6815:5aa3`                    |
| **IPv6 2**       | `2606:4700:3034::ac43:ca74`                    |

### 

### Infrastructure IOCs

| Type                     | Value                                                                                  |
| ------------------------ | -------------------------------------------------------------------------------------- |
| **Admin Panel**          | `https://bantuan-tng-inst.aply-gov.online/ap/gateway.php?path=/generate-session` (GET) |
| **Config File**          | `https://bantuan-tng-inst.aply-gov.online/ap/setting.php`                              |
| **Kit Name**             | Truelogin V5                                                                           |
| **Kit Language**         | Indonesian (admin UI text, code comments)                                              |
| **Redirect Destination** | `https://malaysiamadani.gov.my/`                                                       |

### 

### Content IOCs

| Type                           | Value                                                                   |
| ------------------------------ | ----------------------------------------------------------------------- |
| **Azerbaijani remnant string** | `₼3.399 AZN məbləğində sosial yardım paketi üçün müraciətiniz aktivdir` |
| **Azerbaijani UI string**      | `Bildirişlər` (Notifications), `Təbrik edirik!` (Congratulations!)      |
| **QR code lure image**         | `tngphish.jpeg` — Touch 'n Go Money Packet with embedded phishing URL   |

### 

### Behavioral IOCs

| Behaviour                                                     | Detail                                        |
| ------------------------------------------------------------- | --------------------------------------------- |
| POST to `/generate-session` with `phone_number`               | Phone harvesting + Telegram OTP trigger       |
| POST to `/validate-otp` with `phone_number` + `code`          | OTP harvesting                                |
| POST to `/validate-password` with `phone_number` + `password` | 2FA harvesting                                |
| Redirect to `malaysiamadani.gov.my` on success                | Covers tracks post-compromise                 |
| OTP input with 5 auto-advancing `.otp-cell` fields            | Distinctive UI pattern for kit fingerprinting |

---

## v. Mistakes & OPSEC Failures

The operator made several notable errors that aid attribution and detection:

| #   | Mistake                           | Detail                                                                                                                                                                                                                                                                                                                       |
| --- | --------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | **Untranslated Azerbaijani text** | An entire sentence in Azerbaijani was left in the source: `"₼3.399 AZN məbləğində sosial yardım paketi üçün müraciətiniz aktivdir"` ("Your application for a social assistance package of ₼3,399 AZN is active"). This is not just a currency typo — it's a full untranslated paragraph from a prior Azerbaijani deployment. |
| 2   | **Azerbaijani UI strings**        | `"Bildirişlər"` (Notifications) and `"Təbrik edirik!"` (Congratulations!) left in the notification panel — Azerbaijani, not Malay.                                                                                                                                                                                           |
| 3   | **Wrong country default**         | `defaultCountry: "ID"` (Indonesia) in `setting.php` — kit was configured for Indonesian targets, never updated for Malaysia.                                                                                                                                                                                                 |
| 4   | **Mixed languages in code**       | JavaScript error messages use Indonesian phrasing (e.g., `"Silakan isi formulir terlebih dahulu"`) while the user-facing page is in Malay.                                                                                                                                                                                   |
| 5   | **Admin panel exposed**           | `gateway.php?path=/generate-session` renders the full Truelogin V5 admin dashboard publicly via GET, leaking backend stack info (Node.js, MongoDB, Telegram bot).                                                                                                                                                            |
| 6   | **1-day-old domain**              | Registered 2026-03-09, deployed same day — trivially detected by domain age heuristics. `addPeriod` EPP status further confirms brand-new registration.                                                                                                                                                                      |
| 7   | **No SSL certificate diversity**  | Uses Cloudflare's shared certificate — no custom cert for the fake domain.                                                                                                                                                                                                                                                   |
| 8   | **DNSSEC unsigned**               | Legitimate Malaysian government domains use DNSSEC.                                                                                                                                                                                                                                                                          |

---

## vi. Threat Actor Assessment

Based on the evidence:

- **Kit deployment chain: Azerbaijan → Indonesia → Malaysia**. The Azerbaijani full-sentence remnants and UI strings indicate the kit was **originally deployed for an Azerbaijani campaign**. The `defaultCountry: "ID"` and Indonesian code comments show it was subsequently adapted for Indonesia and finally redeployed for Malaysia with Malay-language content. The operator did not clean up artifacts from either prior deployment.
- **Kit is likely commercial or shared** - The Truelogin V5 admin panel's polished UI, modular `.env` configuration, and "update without SSH" feature suggest a reusable kit designed for non-technical operators. While it self-identifies as "Truelogin V5," no public threat intel reports document this kit by name, so it may be distributed within closed communities rather than being a widely-known PhaaS product.
- **Low-sophistication operator** - Multiple OPSEC failures (untranslated Azerbaijani text, exposed admin panel, wrong country code, unmodified Indonesian error messages) suggest a **script kiddie or low-tier fraudster** deploying a kit they did not develop and do not fully understand.
- **Target demographic** - Malay-speaking Malaysian citizens seeking government financial assistance. The "bantuan" (aid/assistance) lure is extremely common in Malaysian social media scam campaigns.
- **Delivery method** - Likely shared via WhatsApp/Telegram groups, social media (Facebook/TikTok) or SMS blasting using the QR code lure image as the primary social engineering hook. Typical for this category of Malaysian financial scam.

---

## vii. Summary Table

| Category          | Finding                                                             |
| ----------------- | ------------------------------------------------------------------- |
| **Threat Type**   | Telegram Account Takeover via Phishing                              |
| **Kit**           | Truelogin V5 (reusable phishing kit)                                |
| **Domain Age**    | < 24 hours (registered 2026-03-09, `addPeriod` status)              |
| **Hosting**       | Cloudflare CDN (AS13335), origin server hidden                      |
| **Target**        | Malaysian citizens (Malay-speaking)                                 |
| **Lure**          | Fake Touch 'n Go / Malaysia Madani government aid via QR code       |
| **Data Stolen**   | Telegram phone, OTP, 2FA password → Full account takeover           |
| **Exfiltration**  | Telegram bot (BOT_TOKEN in backend .env)                            |
| **Admin Panel**   | Exposed publicly at `gateway.php?path=/generate-session`            |
| **Kit History**   | Azerbaijan → Indonesia → Malaysia (untranslated remnants from each) |
| **Actor Profile** | Low-sophistication kit operator                                     |
| **Status**        | ACTIVE at time of analysis                                          |

Disclaimer: *Analysis were conducted in a sandboxed environment. No credentials were submitted to the phishing kit.*

--- 

# My Advice to Dear Malaysian

i will mix english and malay in this section so the audience could fully capture my advice.

---

## 1. If its too good to be true. Create doubt.

Always doubt something when it comes to giving you full benefit without returns to the sender. For example, we can see that the phisher in this campaign claims that they are sending money to us which is a very good deeds (too good to be true) so doubt it.

Sentiasa wujudkan rasa was-was apabila melihat sesuatu yang sepertinya memberikan kita kebaikan tanpa balasan kepada pihak pemberi. Sebagai contoh, kita dapat lihat yang scammer tng ewallet ini cuba menghantar duit kepada kita. Memang benar bahawa ada sahaja orang yang ingin berbuat baik akan tetapi lebih baik kita berwaspada dan semak dahulu!

## 2. Ask around. People around you cares.

Dont be shy to ask people around you especially those who are close to you. You might think that telling or asking other people on free money may make cause you to lose money if its legit but lets throw away our greediness and create cautions instead.

Jangan malu bertanya kepada orang sekitar kita terutamanya yang rapat. Kita mungkin terfikir bahawa berkongsi maklumat mengenai duit percuma seperti boleh menyebabkan kita tak dapat duit atas dasar berebut akan tetapi ianya lebih baik jika kita buangkan sifat tamak dan wujudkan sifat berjaga-jaga di dalam diri.

## 3. Watch over your elders.

Sometimes for youngsters and IT people, we can identify that its a scam in one look. This is because we are NOT their target victim. Usually the targeted victims are among those who are financially stucked or elders who is not really good in digital and believes everything they see. So watch over your elders, remind them to consult you before clicking or sending anything sensitive online!

Kadangkala bagi orang-orang muda dan orang IT, kita dapat kenalpasti perkara sebegini adalah scam dalam sekelip mata. Ini kerana kita BUKAN mangsa yang mereka inginkan. Selalunya mangsa adalah di kalangan orang-orang yang kesempitan wang ataupun warga emas yang tidak celik digital dan percaya semua yang mereka lihat. Jadi perhatikanlah orang tersayang kalian, ingatkan mereka untuk sentiasa bertanya kepada kalian dahulu sebelum menekan atau menghantar perkara yang sensitif di dunia digital!

That is all from me, stay safe everyone! <3 🦆

---
