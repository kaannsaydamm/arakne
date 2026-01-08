# 🕷️ ARAKNE
### Advanced Forensic & Remediation Framework
**Version:** v2.0.0  |  **Author:** Kaan Saydam  |  **License:** MIT

---

## 📖 Genel Bakış / Overview

**Arakne**, işletim sistemi seviyesinde derinlemesine tehdit analizi ve temizleme operasyonları için tasarlanmış kapsamlı bir güvenlik aracıdır. Standart güvenlik çözümlerinin (EDR/AV) yetersiz kaldığı durumlarda, sistem kaynaklarına doğrudan erişerek Rootkit, Bootkit, Ransomware ve Fileless tehditleri tespit eder ve temizler.

**Arakne** is a comprehensive security tool designed for deep threat analysis and remediation at the operating system level. It directly accesses system resources to detect and clean Rootkits, Bootkits, Ransomware, and Fileless threats when standard security solutions fail.

---

## 📋 İçindekiler / Table of Contents

- [Özellikler / Features](#-özellikler--features)
- [Kurulum / Installation](#-kurulum--installation)
  - [Windows](#windows-kurulumu)
  - [Linux](#linux-kurulumu)
  - [macOS](#macos-kurulumu)
- [Kullanım / Usage](#-kullanım--usage)
- [Modüller / Modules](#-modüller--modules)
- [Sürücü Derleme / Driver Compilation](#-sürücü-derleme--driver-compilation)
- [Katkıda Bulunma / Contributing](#-katkıda-bulunma)

---

## 🚀 Özellikler / Features

### Windows Modülü
| Özellik | Açıklama |
|---------|----------|
| **YARA Tarayıcı** | 6 dahili kural ile zararlı yazılım tespiti (Mimikatz, CobaltStrike, Meterpreter, PowerShell, WebShell, Ransomware) |
| **MFT Parser** | NTFS $MFT kayıtlarını ayrıştırır, timestomping ve ADS tespit eder |
| **Registry Analizi** | Run keys, Services, IFEO, AppInit_DLLs kalıcılık mekanizmalarını tarar |
| **Memory Scanner** | RWX bellekte çalışan shellcode/beacon tespiti |
| **ETW Sniffer** | PowerShell ScriptBlock, .NET Assembly, AMSI log analizi |
| **UEFI Scanner** | Secure Boot, Test Signing, DEP durumu kontrolü |
| **Shimcache Parser** | AppCompatCache'den çalıştırma geçmişi çıkarır |
| **LOLDriver Scanner** | Bilinen zafiyetli sürücüleri hash ile tespit eder |
| **Browser Forensics** | Chrome/Edge uzantı analizi |
| **WFP Network Killswitch** | Kernel seviyesinde ağ izolasyonu |

### Linux Modülü
| Özellik | Açıklama |
|---------|----------|
| **Hidden Process Detection** | /proc taraması ile gizli süreç tespiti |
| **LD_PRELOAD Check** | Library injection tespiti |
| **Crontab Scanner** | Kalıcılık için cron analizi |
| **Kernel Module Check** | Bilinen rootkit modüllerini tespit eder |
| **Memfd Hunter** | /proc/maps ile fileless malware tespiti |
| **Deleted Binary Detection** | Silinen ama çalışan binary'leri bulur |

### macOS Modülü
| Özellik | Açıklama |
|---------|----------|
| **LaunchAgent/Daemon Analizi** | Plist dosyalarını tarar |
| **Shell Profile Check** | .bashrc/.zshrc kalıcılık kontrolü |
| **Kext Scanner** | Yüklü kernel uzantılarını listeler |
| **SIP Status Check** | System Integrity Protection durumu |

---

## 📦 Kurulum / Installation

### Hızlı Başlangıç (Prebuilt Binary)

Eğer derlemek istemiyorsanız, hazır binary kullanabilirsiniz:

```bash
# Windows
git clone https://github.com/kaannsaydamm/arakne.git
cd arakne
.\arakne.exe

# Linux/macOS
git clone https://github.com/kaannsaydamm/arakne.git
cd arakne
chmod +x arakne
./arakne
```

---

### Windows Kurulumu

#### Gereksinimler
- Windows 10/11 (64-bit)
- Administrator yetkisi
- (Opsiyonel) Go 1.21+ (kaynak koddan derlemek için)
- (Opsiyonel) Windows Driver Kit (WDK) (kernel sürücüsü için)

#### Adım 1: Kurulum Yöntemleri (Önerilen)

**Seçenek A: MSI Installer (Son Kullanıcı)**
1. `installer/ArakneSetup.msi` dosyasını çalıştırın.
2. Yükleme tamamlandığında **"Launch Driver Installer"** kutucuğunu işaretleyin.
3. Açılan pencerede sürücü kurulumunu onaylayın.

**Seçenek B: Geliştirici Kurulumu (One-Click Setup)**
```powershell
# Projeyi klonlayın ve kök dizinde:
.\setup.ps1
```
*Bu script sürücüyü derler, ikonu gömer ve uygulamayı oluşturur.*

#### Adım 2: Manuel Derleme (Opsiyonel)
```powershell
# Sadece uygulamayı derlemek için:
go build -o arakne.exe ./cmd/arakne
```

#### Adım 3: Manuel Sürücü Kurulumu (Gelişmiş)
Eğer `setup.ps1` kullanmadıysanız:
```powershell
# 1. Test Signing modunu aç
bcdedit /set testsigning on

# 2. Sürücüyü derle (VS2022 + WDK Gerekir)
cd driver\windows
msbuild ArakneDriver.sln /p:Configuration=Release /p:Platform=x64

# 3. Sürücüyü yükle
sc create Arakne type= kernel binPath= "C:\path\to\arakne_wfp.sys"
sc start Arakne
```

---

### Linux Kurulumu

#### Gereksinimler
- Linux Kernel 4.x+ (64-bit)
- Root yetkisi
- Go 1.21+
- (Opsiyonel) Kernel headers (kernel modülü için)
- (Opsiyonel) build-essential, make

#### Adım 1: Binary Kullanımı
```bash
# Projeyi klonla
git clone https://github.com/kaannsaydamm/arakne.git
cd arakne

# Çalıştır
sudo ./arakne
```

#### Adım 2: Kaynak Koddan Derleme
```bash
# Go kur
sudo apt install golang-go   # Debian/Ubuntu
# veya
sudo dnf install golang      # Fedora

# Projeyi klonla
git clone https://github.com/kaannsaydamm/arakne.git
cd arakne

# Bağımlılıkları indir
go mod tidy

# Derle
go build -o arakne ./cmd/arakne

# Çalıştır
sudo ./arakne
```

#### Adım 3: Linux Kernel Modülü Kurulumu (Opsiyonel)
```bash
# 1. Kernel headers kur
sudo apt install linux-headers-$(uname -r)   # Debian/Ubuntu
sudo dnf install kernel-devel                 # Fedora

# 2. Modülü derle
cd driver/linux
make

# 3. Modülü yükle
sudo insmod arakne_probe.ko

# 4. Doğrula
lsmod | grep arakne
dmesg | tail -10

# 5. Cihazı kontrol et
ls -la /dev/arakne

# 6. Modülü kaldır (opsiyonel)
sudo rmmod arakne_probe
```

---

### macOS Kurulumu

#### Gereksinimler
- macOS 11+ (Big Sur veya üzeri)
- Root yetkisi
- Go 1.21+
- Xcode Command Line Tools

#### Adım 1: Derleme
```bash
# Xcode tools kur
xcode-select --install

# Go kur (Homebrew ile)
brew install go

# Projeyi klonla
git clone https://github.com/kaannsaydamm/arakne.git
cd arakne

# Bağımlılıkları indir (macOS için özel)
GOOS=darwin go mod tidy

# Derle
GOOS=darwin GOARCH=amd64 go build -o arakne ./cmd/arakne
# veya Apple Silicon için:
GOOS=darwin GOARCH=arm64 go build -o arakne ./cmd/arakne

# Çalıştır
sudo ./arakne
```

---

## 🎮 Kullanım / Usage

### İnteraktif Mod (Önerilen)
```bash
# Windows
.\arakne.exe

# Linux/macOS
sudo ./arakne
```

Menüden seçenekleri kullanarak:
1. **Quick Scan** - Hızlı tarama (Browser, Logs, Drivers)
2. **Deep Dive** - Derinlemesine analiz (MFT, Memory, UEFI)
3. **YARA Scan** - Zararlı yazılım imza taraması
4. **Kill Process** - Kernel seviyesinde süreç sonlandırma
5. **Quarantine** - Dosya karantinaya alma
6. **Whitelist** - Korumalı süreçleri görüntüle
7. **Network Killswitch** - Ağ trafiğini engelle
8. **Evidence Bag** - Kanıt toplama
9. **Reporting** - JSON/HTML rapor oluştur

### Otomatik Temizlik Modu
```bash
# Tehdit tespitinde otomatik temizlik
.\arakne.exe --nuke
```

### Yardım
```bash
.\arakne.exe --help
```

---

## 📊 Modüller / Modules

### Tarama Modülleri
| Modül | Dosya | Açıklama |
|-------|-------|----------|
| YARA | `yara.go` | Dahili imza tabanlı tarama |
| Memory | `memory.go` | RWX bellek bölgesi tespiti |
| MFT | `mft.go` | NTFS kayıt ayrıştırma |
| ETW | `etw.go` | Event log analizi |
| Registry | `registry.go` | Kalıcılık taraması |
| Shimcache | `shimcache.go` | Çalıştırma geçmişi |
| UEFI | `uefi.go` | Boot güvenliği |
| LOLDrivers | `loldrivers.go` | Zafiyetli sürücüler |
| Browser | `browser.go` | Uzantı analizi |
| Forensics | `forensics.go` | Olay günlüğü analizi |

### Remediation Modülleri
| Modül | Dosya | Açıklama |
|-------|-------|----------|
| Surgical Mode | `stages.go` | Otomatik ComboFix benzeri temizlik |
| Process Killer | `process_killer.go` | Kernel destekli süreç sonlandırma |
| Quarantine | `quarantine.go` | XOR şifrelemeli karantina |
| Evidence | `evidence.go` | Kanıt ZIP'leme |
| Reporting | `reporting.go` | JSON/HTML rapor |

---

## 🔧 Sürücü Derleme / Driver Compilation

### Windows Driver (WDK Gerekli)
Otomatik derleme için kök dizindeki `setup.ps1` scriptini kullanmanız önerilir.

Manuel derleme:
```powershell
# Visual Studio 2022 + WDK 10 kur
cd driver\windows

# Derle
msbuild ArakneDriver.sln /p:Configuration=Release /p:Platform=x64

# Çıktı: x64\Release\arakne_wfp.sys
```

### Linux Kernel Module
```bash
cd driver/linux

# Derle
make

# Çıktı: arakne_probe.ko

# Test
sudo insmod arakne_probe.ko
sudo dmesg | tail
```

---

## 📁 Proje Yapısı

```
arakne/
├── cmd/
│   └── arakne/
│       ├── main.go           # Ana giriş noktası
│       └── menu_helpers.go   # Menü fonksiyonları
├── installer/
│   ├── Product.wxs       # WiX MSI Tanımı
│   └── build_msi.bat     # MSI Derleme scripti
├── driver/
│   ├── linux/
│   │   ├── main.c            # Linux kernel modülü
│   │   └── Makefile
│   └── windows/
│       ├── main.c            # Windows KMDF sürücüsü
│       ├── arakne_wfp.sys    # Derlenmiş sürücü
│       ├── install.ps1       # Sürücü yükleme scripti
│       ├── setup_driver.bat  # MSI için wrapper
│       └── ...
├── internal/
│   ├── core/
│   │   ├── interfaces.go     # Temel arayüzler
│   │   ├── whitelist.go      # Korumalı süreçler
│   │   ├── quarantine.go     # Karantina sistemi
│   │   ├── evidence.go       # Kanıt toplama
│   │   ├── reporting.go      # Raporlama
│   │   └── remediation.go    # Tehdit müdahale
│   ├── platform/
│   │   ├── windows/          # 16 Windows modülü
│   │   ├── linux/            # 2 Linux modülü
│   │   └── darwin/           # 1 macOS modülü
│   └── utils/
│       └── admin.go          # Yetki kontrolü
├── winres/                # İkon kaynakları
├── setup.ps1              # Unified Build Script
├── evidence/                  # Kanıt dizini
├── go.mod
├── go.sum
├── Makefile
├── LICENSE
└── README.md
```

---

## ⚠️ Yasal Uyarı / Disclaimer

Bu araç sistem üzerinde derinlemesine analiz ve değişiklik yapma yeteneğine sahiptir. 

**KULLANIM UYARILARI:**
- Sadece yetkili olduğunuz sistemlerde kullanın
- Kritik sistemlerde kullanmadan önce yedek alın
- Test ortamında deneyin
- Kernel sürücüleri sistem kararlılığını etkileyebilir

**Bu yazılım "OLDUĞU GİBİ" sağlanmaktadır, herhangi bir garanti verilmemektedir.**

---

## 🤝 Katkıda Bulunma

1. Fork yapın
2. Feature branch oluşturun (`git checkout -b feature/yeni-ozellik`)
3. Değişikliklerinizi commit edin (`git commit -m 'Yeni özellik eklendi'`)
4. Branch'e push yapın (`git push origin feature/yeni-ozellik`)
5. Pull Request açın

---

## 📜 Lisans

MIT License - Detaylar için [LICENSE](LICENSE) dosyasına bakın.

---

## 📞 İletişim

**Kaan Saydam**  
GitHub: [@kaannsaydamm](https://github.com/kaannsaydamm)

---

*Made with ☕ in Turkey, 2026*
