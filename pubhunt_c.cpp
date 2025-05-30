#include <iostream>
#include <iomanip>
#include <vector>
#include <fstream>
#include <sstream>
#include <gmpxx.h>
#include <secp256k1.h>
#include <omp.h>

// g++ -o pubhunt_c pubhunt_c.cpp -lgmpxx -lgmp -lsecp256k1 -fopenmp

using namespace std;

// Curve parameters
const mpz_class P("115792089237316195423570985008687907853269984665640564039457584007908834671663");
const mpz_class N("115792089237316195423570985008687907852837564279074904382605163141518161494337");
const mpz_class G_x("55066263022277343669578718895168534326250603453777594175500187360389116729240");
const mpz_class A(0), B(7);

// Calculate potential private key for a given multiplier k
mpz_class calculate_private_key(const mpz_class& pub_x, const mpz_class& k) {
    mpz_class private_key = (pub_x + k * G_x) % N;
    private_key = pub_x - private_key;
    if (private_key < 0) {
        private_key += N;
    }
    return private_key;
}

// Convert hex string to byte vector
vector<unsigned char> hexToBytes(const string& hex) {
    vector<unsigned char> bytes;
    try {
        for (size_t i = 0; i < hex.length(); i += 2) {
            bytes.push_back(stoul(hex.substr(i, 2), nullptr, 16));
        }
    } catch (...) {
        return {};
    }
    return bytes;
}

// Check if a private key generates the given public key
bool check(const mpz_class& private_key, const vector<unsigned char>& original_public_key) {
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    if (!ctx) return false;

    unsigned char privkey_bytes[32] = {0};
    string priv_hex = private_key.get_str(16);
    size_t byte_len = (priv_hex.length() + 1) / 2;
    size_t offset = 32 - min(byte_len, size_t(32));
    mpz_export(privkey_bytes + offset, nullptr, 1, 1, 0, 0, private_key.get_mpz_t());

    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, privkey_bytes)) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    unsigned char pubkey_serialized[65];
    size_t len = 65;
    secp256k1_ec_pubkey_serialize(ctx, pubkey_serialized, &len, &pubkey, SECP256K1_EC_UNCOMPRESSED);

    secp256k1_context_destroy(ctx);
    return len == 65 && vector<unsigned char>(pubkey_serialized, pubkey_serialized + 65) == original_public_key;
}

// Validate point on secp256k1 curve
bool is_on_curve(const mpz_class& x, const mpz_class& y) {
    mpz_class y2 = (y * y) % P;
    mpz_class x3 = (x * x * x) % P;
    mpz_class ax = (A * x) % P;
    mpz_class right = (x3 + ax + B) % P;
    return y2 == right;
}

int main() {
    ifstream file("allpubs.txt");
    if (!file.is_open()) {
        return 1;
    }

    // Read all points into a vector
    vector<pair<mpz_class, mpz_class>> points;
    string line;
    while (getline(file, line)) {
        line.erase(remove_if(line.begin(), line.end(), ::isspace), line.end());
        if (line.empty()) continue;

        stringstream ss(line);
        string x_str, y_str;
        if (!getline(ss, x_str, ',') || !getline(ss, y_str, ',')) {
            continue;
        }

        mpz_class x_coord, y_coord;
        try {
            x_coord.set_str(x_str, 10);
            y_coord.set_str(y_str, 10);
        } catch (...) {
            continue;
        }

        if (!is_on_curve(x_coord, y_coord)) {
            continue;
        }

        points.emplace_back(x_coord, y_coord);
    }
    file.close();

    if (points.empty()) {
        return 1;
    }

    #pragma omp parallel for schedule(dynamic)
    for (size_t i = 0; i < points.size(); ++i) {
        auto [x_coord, y_coord] = points[i];

        // Convert to uncompressed public key
        string x_hex = x_coord.get_str(16);
        string y_hex = y_coord.get_str(16);
        x_hex = string(64 - x_hex.length(), '0') + x_hex;
        y_hex = string(64 - y_hex.length(), '0') + y_hex;
        string pubkey_hex = "04" + x_hex + y_hex;
        if (pubkey_hex.length() != 130) {
            continue;
        }

        vector<unsigned char> pubkey_bytes = hexToBytes(pubkey_hex);
        if (pubkey_bytes.empty()) {
            continue;
        }

        bool found = false;

        // Initial attempts with k=1 and k=2
        for (mpz_class k = 1; k <= 2 && !found; k++) {
            mpz_class private_key = calculate_private_key(x_coord, k);
            if (check(private_key, pubkey_bytes)) {
                #pragma omp critical
                cout << "Found Matching Private Key for x=" << x_coord.get_str(10) << ": 0x" << private_key.get_str(16) << " (k=" << k << ")" << endl;
                found = true;
            }
        }

        // If no match, iterate with k=3, 4, ...
        if (!found) {
            const mpz_class max_k = 100000000000;
            for (mpz_class k = 3; k <= max_k && !found; k++) {
                mpz_class private_key = calculate_private_key(x_coord, k);
                if (check(private_key, pubkey_bytes)) {
                    #pragma omp critical
                    cout << "Found Matching Private Key for x=" << x_coord.get_str(10) << ": 0x" << private_key.get_str(16) << " (k=" << k << ")" << endl;
                    found = true;
                }
            }
        }
    }

    return 0;
}