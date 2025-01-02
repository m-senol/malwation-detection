# LibVMI ile Windows 7 VM Üzerinde Hafıza Taraması

## Proje Amacı
Bu proje, bir Windows 7 sanal makinesi (VM) üzerinde çalışan süreçlerin hafıza içeriklerini analiz etmek için geliştirilmiştir.

---

## Proje Adımları

### 1. Xen Hypervisor ve Windows 7 Kurulumu
- **Xen Hypervisor Kurulumu:**
  - Xen Hypervisor kurulumu sırasında "[Xen Project Beginner's Guide](https://wiki.xenproject.org/wiki/Xen_Project_Beginners_Guide)" kullanıldı.
  - Sanal makineler (VM) başarıyla oluşturuldu ve kaynaklar paylaştırıldı.

- **Windows 7 Guest VM Kurulumu:**
  - Yapılandırma dosyasını oluşturmak için Vergilius Project'ten `_EPROCESS` bilgileri kullanıldı ([Kaynak](https://www.vergiliusproject.com/kernels/x64/windows-7/sp1/_EPROCESS)).
  - VM kurulumu başarıyla tamamlandı.

---

### 2. LibVMI ve YARA Kurulumu
- **LibVMI Kurulumu:**
  - Resmi [LibVMI dokümantasyonu](https://libvmi.com/docs/gcode-install.html) rehberliğinde tamamlandı.

- **YARA Kurulumu:**
  - Resmi [YARA dokümantasyonu](https://yara.readthedocs.io/en/latest/) takip edilerek YARA kuruldu ve küçük bir test kuralı ile doğrulandı.

---

### 3. Proje Yol Haritası
1. Tüm süreçleri listeleme.
2. Süreçlerin hafıza içeriklerini okuma.
3. Bu içerikleri YARA kullanarak tarama.

---

### 4. Süreçlerin Hafıza Analizi
- **Süreçlerin Listelenmesi:**
  - LibVMI'nin `process-list.c` örneği temel alınarak süreç listesi çıkarıldı.

- **Hafıza İçeriklerine Erişim:**
  - Süreçlerin hafıza içeriklerine erişmek için derinlemesine araştırma yapıldı.
  - Kullanılan kaynaklar:
    - [_EPROCESS](https://www.vergiliusproject.com/kernels/x64/windows-7/sp1/_EPROCESS)
    - [_MM_AVL_TABLE](https://www.vergiliusproject.com/kernels/x64/windows-7/sp1/_MM_AVL_TABLE)
    - [_MMADDRESS_NODE](https://www.vergiliusproject.com/kernels/x64/windows-7/sp1/_MMADDRESS_NODE)
    - [Virtualization Techniques](https://www.sciencedirect.com/science/article/pii/S1742287607000503?ref=pdf_download&fr=RR-2&rr=8fb3d765bf1cd348)
    - [Virtual Page Number](https://www.sciencedirect.com/topics/computer-science/virtual-page-number)

---

### 5. YARA ile Hafıza Taraması
- Hafıza içeriklerinin YARA ile taranması aşamasına geçildi.
- [YARA Documentation](https://yara.readthedocs.io/en/latest/) kullanılarak hafıza içerikleri tarandı.

---

## Sonuç ve İlerleyen Adımlar
- Süreçlerin listelenmesi ve hafıza içeriklerine erişim büyük ölçüde tamamlandı.
- Hafıza içeriklerinin YARA ile taranması üzerinde çalışılıyor ve test süreci devam ediyor.

### İlerleyen Adımlar:
- Testlerin detaylandırılması.
- Tüm süreçler için otomatik bir tarama sistemi geliştirilmesi.

---
