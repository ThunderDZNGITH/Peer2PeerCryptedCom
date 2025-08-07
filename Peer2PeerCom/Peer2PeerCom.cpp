#include <iostream>
#include <thread>
#include <vector>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wincrypt.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Advapi32.lib")

// --- Affichage HEX pour debug ---
void print_hex(const std::string& label, const std::vector<BYTE>& blob) {
    std::cout << label << " (" << blob.size() << " bytes):" << std::endl;
    for (size_t i = 0; i < blob.size(); ++i) {
        printf("%02X", blob[i]);
        if ((i + 1) % 16 == 0) std::cout << std::endl;
    }
    if (blob.size() % 16) std::cout << std::endl;
    std::cout << std::endl;
}

// --- Affichage clé AES brute (PLAINTEXTKEYBLOB, Windows >=8) ---
void print_aes_plain(HCRYPTKEY hKey) {
    DWORD len = 0;
    if (!CryptExportKey(hKey, 0, PLAINTEXTKEYBLOB, 0, NULL, &len)) {
        std::cerr << "[!] Impossible d'exporter la clé AES en PLAINTEXTKEYBLOB" << std::endl;
        return;
    }
    std::vector<BYTE> blob(len);
    if (CryptExportKey(hKey, 0, PLAINTEXTKEYBLOB, 0, blob.data(), &len)) {
        std::cout << "Clé AES 256 bits (brute):" << std::endl;
        // L'entête fait 16 octets, la clé brute commence à l'offset 16
        for (size_t i = 16; i < blob.size(); ++i) {
            printf("%02X", blob[i]);
        }
        std::cout << std::endl << std::endl;
    }
}

// --- Partie cryptographie (CryptoAPI) ---
struct CryptoCtx {
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hRSA = 0;
    HCRYPTKEY hPeerRSA = 0;
    HCRYPTKEY hSession = 0;
};

// Génère un contexte avec une clé RSA 2048 bits
bool crypto_init(CryptoCtx& ctx) {
    if (!CryptAcquireContext(&ctx.hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        return false;
    if (!CryptGenKey(ctx.hProv, AT_KEYEXCHANGE, 2048 << 16 | CRYPT_EXPORTABLE, &ctx.hRSA))
        return false;
    return true;
}

// Export de la clé publique RSA (en blob binaire)
bool export_rsa_pubkey(CryptoCtx& ctx, std::vector<BYTE>& blob) {
    DWORD len = 0;
    if (!CryptExportKey(ctx.hRSA, 0, PUBLICKEYBLOB, 0, NULL, &len)) return false;
    blob.resize(len);
    return CryptExportKey(ctx.hRSA, 0, PUBLICKEYBLOB, 0, blob.data(), &len);
}

// Import la clé publique du peer
bool import_rsa_pubkey(CryptoCtx& ctx, const BYTE* blob, DWORD len) {
    return CryptImportKey(ctx.hProv, blob, len, 0, 0, &ctx.hPeerRSA);
}

// Génère une clé AES 256 bits pour la session
bool generate_aes_key(CryptoCtx& ctx) {
    return CryptGenKey(ctx.hProv, CALG_AES_256, CRYPT_EXPORTABLE, &ctx.hSession);
}

// Exporte la clé AES en la chiffrant avec la clé publique du peer (SIMPLEBLOB)
bool export_aes_for_peer(CryptoCtx& ctx, std::vector<BYTE>& blob) {
    DWORD len = 0;
    if (!CryptExportKey(ctx.hSession, ctx.hPeerRSA, SIMPLEBLOB, 0, NULL, &len)) return false;
    blob.resize(len);
    return CryptExportKey(ctx.hSession, ctx.hPeerRSA, SIMPLEBLOB, 0, blob.data(), &len);
}

// Importe la clé AES reçue (chiffrée avec ta clé RSA privée)
bool import_aes_from_peer(CryptoCtx& ctx, const BYTE* blob, DWORD len) {
    return CryptImportKey(ctx.hProv, blob, len, ctx.hRSA, 0, &ctx.hSession);
}

// Envoie un "blob" binaire (taille sur 2 octets, puis données)
bool send_blob(SOCKET sock, const std::vector<BYTE>& blob) {
    uint16_t len = htons((uint16_t)blob.size());
    if (send(sock, (char*)&len, 2, 0) != 2) return false;
    int sent = 0;
    while (sent < (int)blob.size()) {
        int r = send(sock, (char*)blob.data() + sent, (int)blob.size() - sent, 0);
        if (r <= 0) return false;
        sent += r;
    }
    return true;
}
bool recv_blob(SOCKET sock, std::vector<BYTE>& blob) {
    uint16_t len = 0;
    int r = recv(sock, (char*)&len, 2, MSG_WAITALL);
    if (r != 2) return false;
    len = ntohs(len);
    blob.resize(len);
    int recvd = 0;
    while (recvd < len) {
        int rr = recv(sock, (char*)blob.data() + recvd, len - recvd, 0);
        if (rr <= 0) return false;
        recvd += rr;
    }
    return true;
}

// Chiffre un message avec AES
bool aes_encrypt(HCRYPTKEY hKey, const std::string& plaintext, std::vector<BYTE>& ciphertext) {
    DWORD len = (DWORD)plaintext.size();
    DWORD buflen = len + 32; // Marge
    ciphertext.resize(buflen);
    memcpy(ciphertext.data(), plaintext.data(), len);
    if (!CryptEncrypt(hKey, 0, TRUE, 0, ciphertext.data(), &len, buflen)) return false;
    ciphertext.resize(len);
    return true;
}

// Déchiffre un message AES
bool aes_decrypt(HCRYPTKEY hKey, const BYTE* data, DWORD datalen, std::string& plain) {
    std::vector<BYTE> buf(data, data + datalen);
    DWORD len = datalen;
    if (!CryptDecrypt(hKey, 0, TRUE, 0, buf.data(), &len)) return false;
    plain.assign((char*)buf.data(), len);
    return true;
}

// --- Affichage propre UTF-8 sur console Windows
void set_utf8_console() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    std::ios_base::sync_with_stdio(false);
}

// --- Thread de réception ---
void receive_loop(SOCKET sock, HCRYPTKEY hAES) {
    while (true) {
        std::vector<BYTE> buf;
        if (!recv_blob(sock, buf)) {
            std::cout << "\n[Connexion perdue]\n";
            exit(0);
        }
        std::string plain;
        if (aes_decrypt(hAES, buf.data(), (DWORD)buf.size(), plain)) {
            std::cout << "\nAutre: " << plain << std::endl << "Vous: ";
        }
    }
}

int main() {
    set_utf8_console();

    // -- Initialisation Winsock --
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "Echec WSAStartup\n";
        return 1;
    }

    // -- Récupération IP locale --
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == SOCKET_ERROR) {
        std::cerr << "Erreur gethostname\n";
        WSACleanup();
        return 1;
    }
    addrinfo hints{}, * res = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(hostname, nullptr, &hints, &res) != 0) {
        std::cerr << "Erreur getaddrinfo\n";
        WSACleanup();
        return 1;
    }
    char ipstr[INET_ADDRSTRLEN] = { 0 };
    sockaddr_in* sockaddr_ipv4 = (sockaddr_in*)res->ai_addr;
    inet_ntop(AF_INET, &(sockaddr_ipv4->sin_addr), ipstr, sizeof(ipstr));
    freeaddrinfo(res);
    std::cout << "Ton IP locale (pour le peer sur le même réseau) : " << ipstr << std::endl;

    // -- Saisie des paramètres peer --
    int my_port = 0;
    std::cout << "Port d'écoute local ? ";
    std::cin >> my_port;
    std::cin.ignore();

    std::string peer_ip;
    int peer_port = 0;
    std::cout << "IP du peer à contacter ? ";
    std::getline(std::cin, peer_ip);
    std::cout << "Port du peer à contacter ? ";
    std::cin >> peer_port; std::cin.ignore();

    // -- Préparation serveur local --
    SOCKET server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == INVALID_SOCKET) { std::cerr << "Erreur socket\n"; return 1; }
    sockaddr_in local_addr{};
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = INADDR_ANY;
    local_addr.sin_port = htons(my_port);

    if (bind(server_fd, (sockaddr*)&local_addr, sizeof(local_addr)) == SOCKET_ERROR) {
        std::cerr << "Erreur bind\n"; closesocket(server_fd); WSACleanup(); return 1;
    }
    if (listen(server_fd, 1) == SOCKET_ERROR) {
        std::cerr << "Erreur listen\n"; closesocket(server_fd); WSACleanup(); return 1;
    }

    // -- Connexion peer (mode client ou serveur) --
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        std::cerr << "Erreur socket client\n";
        closesocket(server_fd); WSACleanup(); return 1;
    }
    sockaddr_in peer_addr{};
    peer_addr.sin_family = AF_INET;
    peer_addr.sin_port = htons(peer_port);
    inet_pton(AF_INET, peer_ip.c_str(), &peer_addr.sin_addr);

    bool is_client = (connect(sock, (sockaddr*)&peer_addr, sizeof(peer_addr)) != SOCKET_ERROR);
    if (!is_client) {
        std::cerr << "Connect échoué, attente connexion entrante..." << std::endl;
        closesocket(sock);
        sockaddr_in from_addr;
        int from_len = sizeof(from_addr);
        sock = accept(server_fd, (sockaddr*)&from_addr, &from_len);
        if (sock == INVALID_SOCKET) {
            std::cerr << "Erreur accept\n";
            closesocket(server_fd); WSACleanup(); return 1;
        }
        std::cout << "Connexion entrante acceptée !" << std::endl;
    }
    else {
        std::cout << "Connecté en tant que client !" << std::endl;
    }

    // --- Echange des clés et AES session ---
    CryptoCtx ctx;
    if (!crypto_init(ctx)) { std::cerr << "Crypto init failed!\n"; return 1; }
    std::vector<BYTE> my_pubkey, peer_pubkey;
    if (!export_rsa_pubkey(ctx, my_pubkey)) { std::cerr << "Erreur export clé publique\n"; return 1; }
    print_hex("Ma clé publique RSA", my_pubkey);

    // Echange des clés publiques
    if (!send_blob(sock, my_pubkey)) { std::cerr << "Erreur envoi pubkey\n"; return 1; }
    if (!recv_blob(sock, peer_pubkey)) { std::cerr << "Erreur recv pubkey\n"; return 1; }
    print_hex("Clé publique RSA du peer", peer_pubkey);

    if (!import_rsa_pubkey(ctx, peer_pubkey.data(), (DWORD)peer_pubkey.size())) {
        std::cerr << "Erreur import peer pubkey\n"; return 1;
    }

    // Echange de la clé de session AES
    std::vector<BYTE> session_blob;
    if (is_client) {
        if (!generate_aes_key(ctx)) { std::cerr << "Erreur génération clé AES\n"; return 1; }
        print_aes_plain(ctx.hSession); // Affiche la clé AES brute (debug)
        if (!export_aes_for_peer(ctx, session_blob)) { std::cerr << "Erreur export AES\n"; return 1; }
        print_hex("Ma clé AES session (SIMPLEBLOB)", session_blob);
        if (!send_blob(sock, session_blob)) { std::cerr << "Erreur envoi clé session\n"; return 1; }
    }
    else {
        if (!recv_blob(sock, session_blob)) { std::cerr << "Erreur recv session key\n"; return 1; }
        print_hex("Clé AES session reçue (SIMPLEBLOB)", session_blob);
        if (!import_aes_from_peer(ctx, session_blob.data(), (DWORD)session_blob.size())) {
            std::cerr << "Erreur import clé session\n"; return 1;
        }
        print_aes_plain(ctx.hSession); // Affiche la clé AES brute après import (debug)
    }

    std::cout << "[Canal chiffré prêt]\n" << std::endl;

    // --- Lancement du thread de réception ---
    std::thread recv_thread(receive_loop, sock, ctx.hSession);

    // --- Boucle d'envoi chiffré ---
    std::string msg;
    while (true) {
        std::cout << "Vous: ";
        std::getline(std::cin, msg);
        if (msg.empty()) continue;
        std::vector<BYTE> crypted;
        if (!aes_encrypt(ctx.hSession, msg, crypted)) {
            std::cerr << "Erreur chiffrement!\n";
            break;
        }
        if (!send_blob(sock, crypted)) {
            std::cerr << "Erreur send!\n";
            break;
        }
        if (msg == "exit") break;
    }

    // --- Cleanup ---
    closesocket(sock);
    closesocket(server_fd);
    recv_thread.detach();

    if (ctx.hSession) CryptDestroyKey(ctx.hSession);
    if (ctx.hPeerRSA) CryptDestroyKey(ctx.hPeerRSA);
    if (ctx.hRSA) CryptDestroyKey(ctx.hRSA);
    if (ctx.hProv) CryptReleaseContext(ctx.hProv, 0);

    WSACleanup();
    return 0;
}
