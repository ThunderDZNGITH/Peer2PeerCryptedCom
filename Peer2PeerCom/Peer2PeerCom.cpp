#include <iostream>
#include <thread>
#include <vector>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wincrypt.h>
#include <fstream>

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

bool crypto_init(CryptoCtx& ctx) {
    if (!CryptAcquireContext(&ctx.hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        return false;
    if (!CryptGenKey(ctx.hProv, AT_KEYEXCHANGE, 2048 << 16 | CRYPT_EXPORTABLE, &ctx.hRSA))
        return false;
    return true;
}

bool export_rsa_pubkey(CryptoCtx& ctx, std::vector<BYTE>& blob) {
    DWORD len = 0;
    if (!CryptExportKey(ctx.hRSA, 0, PUBLICKEYBLOB, 0, NULL, &len)) return false;
    blob.resize(len);
    return CryptExportKey(ctx.hRSA, 0, PUBLICKEYBLOB, 0, blob.data(), &len);
}

bool import_rsa_pubkey(CryptoCtx& ctx, const BYTE* blob, DWORD len) {
    return CryptImportKey(ctx.hProv, blob, len, 0, 0, &ctx.hPeerRSA);
}

bool generate_aes_key(CryptoCtx& ctx) {
    return CryptGenKey(ctx.hProv, CALG_AES_256, CRYPT_EXPORTABLE, &ctx.hSession);
}

bool export_aes_for_peer(CryptoCtx& ctx, std::vector<BYTE>& blob) {
    DWORD len = 0;
    if (!CryptExportKey(ctx.hSession, ctx.hPeerRSA, SIMPLEBLOB, 0, NULL, &len)) return false;
    blob.resize(len);
    return CryptExportKey(ctx.hSession, ctx.hPeerRSA, SIMPLEBLOB, 0, blob.data(), &len);
}

bool import_aes_from_peer(CryptoCtx& ctx, const BYTE* blob, DWORD len) {
    return CryptImportKey(ctx.hProv, blob, len, ctx.hRSA, 0, &ctx.hSession);
}

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

bool aes_encrypt(HCRYPTKEY hKey, const std::string& plaintext, std::vector<BYTE>& ciphertext) {
    DWORD len = (DWORD)plaintext.size();
    DWORD buflen = len + 32;
    ciphertext.resize(buflen);
    memcpy(ciphertext.data(), plaintext.data(), len);
    if (!CryptEncrypt(hKey, 0, TRUE, 0, ciphertext.data(), &len, buflen)) return false;
    ciphertext.resize(len);
    return true;
}

bool aes_decrypt(HCRYPTKEY hKey, const BYTE* data, DWORD datalen, std::string& plain) {
    std::vector<BYTE> buf(data, data + datalen);
    DWORD len = datalen;
    if (!CryptDecrypt(hKey, 0, TRUE, 0, buf.data(), &len)) return false;
    plain.assign((char*)buf.data(), len);
    return true;
}

void set_utf8_console() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    std::ios_base::sync_with_stdio(false);
}

// ---- Envoi fichier ----
bool send_file(SOCKET sock, HCRYPTKEY hKey, const std::string& filepath) {
    std::ifstream f(filepath, std::ios::binary);
    if (!f) {
        std::cerr << "[Erreur] Impossible d'ouvrir " << filepath << std::endl;
        return false;
    }
    std::vector<BYTE> data((std::istreambuf_iterator<char>(f)), {});
    if (data.empty()) {
        std::cerr << "[Erreur] Fichier vide ou erreur lecture" << std::endl;
        return false;
    }

    std::string fname = filepath;
    size_t pos = fname.find_last_of("/\\");
    if (pos != std::string::npos)
        fname = fname.substr(pos + 1);

    std::string header = "FILE:" + fname + ":" + std::to_string(data.size()) + "\n";

    std::vector<BYTE> crypted;
    std::vector<BYTE> to_encrypt(header.begin(), header.end());
    to_encrypt.insert(to_encrypt.end(), data.begin(), data.end());

    if (!aes_encrypt(hKey, std::string(to_encrypt.begin(), to_encrypt.end()), crypted)) {
        std::cerr << "Erreur chiffrement fichier" << std::endl;
        return false;
    }
    if (!send_blob(sock, crypted)) {
        std::cerr << "Erreur envoi fichier" << std::endl;
        return false;
    }
    std::cout << "[Fichier envoyé: " << fname << " (" << data.size() << " octets)]\n";
    return true;
}

// -- Ajoute un suffixe si fichier existe déjà --
std::string get_unique_filename(const std::string& base) {
    std::ifstream test(base.c_str(), std::ios::binary);
    if (!test) return base; // Pas de collision

    std::string name = base;
    std::string ext;
    size_t dot = base.find_last_of('.');
    if (dot != std::string::npos) {
        name = base.substr(0, dot);
        ext = base.substr(dot); // includes the dot
    }
    int idx = 1;
    std::string candidate;
    do {
        candidate = name + "_" + std::to_string(idx) + ext;
        std::ifstream test2(candidate.c_str(), std::ios::binary);
        if (!test2) break;
        idx++;
    } while (true);
    return candidate;
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
            // Détection fichier (pas de starts_with en C++14)
            if (plain.compare(0, 5, "FILE:") == 0) {
                size_t p1 = plain.find(':', 5);
                size_t p2 = plain.find(':', p1 + 1);
                size_t p3 = plain.find('\n', p2 + 1);
                if (p1 != std::string::npos && p2 != std::string::npos && p3 != std::string::npos) {
                    std::string fname = plain.substr(5, p1 - 5);
                    size_t filesize = std::stoul(plain.substr(p1 + 1, p2 - p1 - 1));
                    std::string dest_name = get_unique_filename(fname);
                    std::ofstream out(dest_name.c_str(), std::ios::binary);
                    if (out) {
                        out.write(plain.data() + p3 + 1, plain.size() - p3 - 1);
                        std::cout << "\n[Fichier reçu: " << fname << " (" << filesize << " octets) => enregistré sous: " << dest_name << "]\nVous: ";
                    }
                    else {
                        std::cerr << "[Erreur ouverture fichier pour écriture: " << dest_name << "]\nVous: ";
                    }
                    continue;
                }
            }
            std::cout << "\nAutre: " << plain << std::endl << "Vous: ";
        }
    }
}

int main() {
    set_utf8_console();

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "Echec WSAStartup\n";
        return 1;
    }

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

    CryptoCtx ctx;
    if (!crypto_init(ctx)) { std::cerr << "Crypto init failed!\n"; return 1; }
    std::vector<BYTE> my_pubkey, peer_pubkey;
    if (!export_rsa_pubkey(ctx, my_pubkey)) { std::cerr << "Erreur export clé publique\n"; return 1; }
    print_hex("Ma clé publique RSA", my_pubkey);

    if (!send_blob(sock, my_pubkey)) { std::cerr << "Erreur envoi pubkey\n"; return 1; }
    if (!recv_blob(sock, peer_pubkey)) { std::cerr << "Erreur recv pubkey\n"; return 1; }
    print_hex("Clé publique RSA du peer", peer_pubkey);

    if (!import_rsa_pubkey(ctx, peer_pubkey.data(), (DWORD)peer_pubkey.size())) {
        std::cerr << "Erreur import peer pubkey\n"; return 1;
    }

    std::vector<BYTE> session_blob;
    if (is_client) {
        if (!generate_aes_key(ctx)) { std::cerr << "Erreur génération clé AES\n"; return 1; }
        print_aes_plain(ctx.hSession);
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
        print_aes_plain(ctx.hSession);
    }

    std::cout << "[Canal chiffré prêt]\n" << std::endl;

    std::thread recv_thread(receive_loop, sock, ctx.hSession);

    std::string msg;
    while (true) {
        std::cout << "Vous: ";
        std::getline(std::cin, msg);
        if (msg.empty()) continue;
        if (msg[0] == '/') {
            if (msg == "/exit") break;
            else if (msg == "/clear") { system("cls"); continue; }
            else if (msg == "/whoami") {
                std::cout << "[IP locale: " << ipstr << " | Port: " << my_port << "]\n";
                continue;
            }
            else if (msg == "/help") {
                std::cout << "/exit   : Quitter\n"
                    "/clear  : Nettoyer l'écran\n"
                    "/whoami : Affiche infos locales\n"
                    "/sendfile <chemin> : Envoie un fichier chiffré\n";
                continue;
            }
            else if (msg.size() >= 10 && msg.substr(0, 10) == "/sendfile ") {
                std::string filepath = msg.substr(10);
                send_file(sock, ctx.hSession, filepath);
                continue;
            }
            else {
                std::cout << "[Commande inconnue, tapez /help]\n";
                continue;
            }
        }

        std::vector<BYTE> crypted;
        if (!aes_encrypt(ctx.hSession, msg, crypted)) {
            std::cerr << "Erreur chiffrement!\n";
            break;
        }
        if (!send_blob(sock, crypted)) {
            std::cerr << "Erreur send!\n";
            break;
        }
    }

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
