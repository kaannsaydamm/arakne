# 🕷️ ARAKNE (Project SystemPurge)
### Advanced Forensic & Remediation Framework
**Versiyon:** v1.0.0

---

## 🇹🇷 TURKISH (TÜRKÇE)

**Arakne**, gelişmiş siber güvenlik ve temizlik operasyonları için tasarlanmış, işletim sistemi API'lerinin manipüle edilebileceği durumlarda doğrudan sistem kaynaklarını analiz eden bir araçtır. Standart güvenlik çözümlerinin (EDR/AV) yetersiz kaldığı; Rootkit, Bootkit, Ransomware ve Dosyasız (Fileless) tehditlere karşı, sistem bütünlüğünü sağlamak ve zararlıları temizlemek için kullanılır.

Felsefemiz: **"Varsayım Yapma. Doğrula."**

### 🚀 Özellikler

#### 🪟 Windows Modülü
- **Yüksek Yetkili Süreç Yönetimi:** `SeDebugPrivilege` haklarını kullanarak, erişimi engellenmiş inatçı süreçleri (Ransomware vb.) sonlandırma yeteneği.
- **MFT & Disk Raw Analizi:** Dosya sistemi API'lerini bypass ederek, diski sektör seviyesinde okur. Gizli dosyaları ve NTFS $MFT kayıtlarını analiz eder.
- **Offline Registry Analizi:** Gizlenen kayıt defteri anahtarlarını, hive dosyalarını (SYSTEM, SOFTWARE) diskten doğrudan okuyarak tespit eder.
- **Sürücü Güvenliği:** Bilinen zafiyetli sürücüleri (BYOVD) tespit eder.
- **ShimCache Analizi:** Silinmiş dosyaların geçmiş çalıştırma izlerini raporlar.

#### 🐧 Linux Modülü
- **Kernel İzleme (eBPF):** Çekirdek seviyesinde `sys_execve` gibi çağrıları izleyerek gizli süreçleri (Hidden Processes) tespit eder.
- **Bellek/Dosyasız Tehdit Analizi:** `memfd_create` kullanan ve diskte iz bırakmayan zararlıları `/proc` ve bellek haritalarını tarayarak bulur.
- **Bellek Yapı Analizi:** Kernel bellek yapılarını tarayarak listeden silinmiş süreçleri ifşa eder.

#### 🍎 macOS Modülü
- **Gizlilik (TCC) Analizi:** TCC veritabanını analiz ederek kamera, mikrofon ve disk erişimi olan yetkisiz uygulamaları raporlar.
- **Kalıcılık Analizi:** LaunchAgents, LaunchDaemons ve plist dosyalarını tarar.

#### 🛡️ Remediation & Karantina
- **Güvenli Müdahale:** Tehdit tespit edildiğinde ağ bağlantısı kesilir ve süreç askıya alınır.
- **Karantina:** Zararlı dosya karantina dizinine taşınır ve şifrelenerek (XOR) etkisiz hale getirilir.
- **Kanıt Toplama (Evidence Bag):** Dosya silinmeden önce hash'i alınır ve kanıt olarak saklanır.
- **Otomatik Temizlik (Nuke):** Kullanıcı onayı beklemeden tehditleri etkisiz hale getirme modu.

### 💻 Kullanım

**1. İnteraktif Mod (Önerilen):**
```bash
./arakne.exe
```
Menüden işletim sistemini ve tarama türünü seçin.

**2. Otomatik Temizlik (Agresif):**
```bash
./arakne.exe --nuke
```
Tespit edilen tehditleri otomatik olarak karantinaya alır ve temizler.

⚠️ **YASAL UYARI:** Bu araç sistem üzerinde derinlemesine analiz ve değişiklik yapma yeteneğine sahiptir. Yanlış kullanım sistem kararlılığını etkileyebilir. Kritik sistemlerde kullanmadan önce yedek almanız önerilir.

---

## 🇺🇸 ENGLISH

**Arakne** is an advanced forensic and remediation tool designed for scenarios where OS APIs may be compromised. It accesses raw system resources to validate system integrity. It serves as a specialized solution against Rootkits, Bootkits, Ransomware, and Fileless malware when standard defenses are bypassed.

Our Philosophy: **"Trust Nothing. Verify Everything."**

### 🚀 Features

#### 🪟 Windows Module
- **Elevated Process Management:** Uses `SeDebugPrivilege` to terminate stubborn processes (e.g., Ransomware) that deny standard access.
- **Raw Disk & MFT Parsing:** Bypasses OS APIs to read the disk at the sector level. Parses NTFS Master File Table ($MFT) to find hidden/locked files.
- **Offline Registry Analysis:** Reads Registry Hives (SYSTEM, SOFTWARE) directly from disk to uncover hidden persistence keys.
- **Vulnerable Driver Detection:** Identifies drivers known to be vulnerable (BYOVD).
- **ShimCache Analysis:** Reconstructs execution history of deleted binaries.

#### 🐧 Linux Module
- **Kernel Monitoring (eBPF):** Hooks kernel syscalls (`sys_execve`) to trace execution paths invisible to userspace.
- **Memory/Fileless Analysis:** Scans `/proc` and memory maps to detect malware running solely in RAM via `memfd_create`.
- **Kernel Structure Analysis:** Analyzes Kernel memory to find unlinked processes.

#### 🍎 macOS Module
- **Privacy (TCC) Analysis:** Parses the TCC database to detect unauthorized entitlements (Camera, Mic, Full Disk Access).
- **Persistence Analysis:** Scans for malicious LaunchAgents and LaunchDaemons.

#### 🛡️ Remediation & Quarantine
- **Secure Response:** Threats are immobilized (suspended/network cut) immediately upon detection.
- **Quarantine:** Artifacts are moved to a secure vault and encrypted (XOR) to neutralize them.
- **Evidence Collection:** Proof is hashed and secured before remediation.
- **Auto-Cleanup (Nuke):** Automated neutralization mode without user interaction.

### 💻 Usage

**1. Interactive Mode (Recommended):**
```bash
./arakne.exe
```
Select your OS and scan options from the menu.

**2. Auto-Cleanup (Aggressive):**
```bash
./arakne.exe --nuke
```
Automatically detects, quarantines, and removes threats.

⚠️ **DISCLAIMER:** This tool operates at a low level on the system. Improper use may cause system instability. Backup is recommended before use.

---

### Made By Kaan Saydam, 2026.
