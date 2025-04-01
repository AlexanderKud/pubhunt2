// Developed from George Toloraia 
// Description: This code attempts to find a private key for a given uncompressed public key using the secp256k1 curve.
// Compile with: g++ -o pubhunt pubhunt.cpp -lgmpxx -lgmp -lsecp256k1
// Run with: ./pubhunt
// Note: Ensure you have the GMP and secp256k1 libraries installed.
// Disclaimer: This code is for educational purposes only. Use responsibly and ethically.
// The author is not responsible for any misuse or illegal activities.

#include <iostream>
#include <iomanip>
#include <vector>
#include <gmpxx.h>
#include <secp256k1.h>

using namespace std;

// Define large numbers using GMP
const mpz_class P("115792089237316195423570985008687907852837564279074904382605163141518161494337");
const mpz_class G_x("55066263022277343669578718895168534326250603453777594175500187360389116729240");

// Calculate a potential private key
mpz_class calculate(const mpz_class& public_key, const mpz_class& div) {
    if (div <= 1) return 0; // Prevent division by zero
    mpz_class minus = public_key / div;
    mpz_class plus = (G_x * minus) % P;
    return plus;
}

// Convert hex string to byte vector
vector<unsigned char> hexToBytes(const string& hex) {
    vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        bytes.push_back(stoul(hex.substr(i, 2), nullptr, 16));
    }
    return bytes;
}

// Check if a private key candidate generates the given public key
bool check(const mpz_class& private_key_candidate, const vector<unsigned char>& original_public_key) {
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

    unsigned char privkey_bytes[32] = {0};  // Ensure 32-byte array
    size_t count = 0;
    mpz_export(privkey_bytes, &count, 1, 1, 0, 0, private_key_candidate.get_mpz_t()); // Convert to bytes

    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, privkey_bytes)) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    unsigned char pubkey_serialized[65];
    size_t len = 65;
    secp256k1_ec_pubkey_serialize(ctx, pubkey_serialized, &len, &pubkey, SECP256K1_EC_UNCOMPRESSED);

    secp256k1_context_destroy(ctx);

    // // Debug output
    // cout << "--------------------------------------------------" << endl;
    // cout << "Checking Private Key Candidate: " << private_key_candidate.get_str(16) << endl;
    
    // cout << "Generated Public Key: ";
    // for (int i = 0; i < 65; i++) {
    //     printf("%02x", pubkey_serialized[i]);
    // }
    // cout << endl;

    // cout << "Expected Public Key: ";
    // for (int i = 0; i < 65; i++) {
    //     printf("%02x", original_public_key[i]);
    // }
    // cout << endl;

    // Compare full 65-byte uncompressed key
    bool match = (vector<unsigned char>(pubkey_serialized, pubkey_serialized + 65) == original_public_key);
    
    // cout << "Match Status: " << (match ? "✅ MATCHED!" : "❌ NOT MATCHED!") << endl;
    // cout << "--------------------------------------------------" << endl;
    
    return match;
}

int main() {
    string input_hex;
    cout << "Enter an Uncompressed Public Key (Hex): ";
    cin >> input_hex;

    // Ensure it's an uncompressed key
    if (input_hex.length() != 130 || input_hex.substr(0, 2) != "04") {
        cout << "Invalid uncompressed public key!" << endl;
        return 1;
    }

    // Extract X-coordinate (characters 2-66)
    string x_coord = input_hex.substr(2, 64);
    vector<unsigned char> pubkey_bytes = hexToBytes(input_hex); // Convert full public key to bytes

    mpz_class original_public_key(x_coord, 16);
    mpz_class div = 2;

    while (true) {
        mpz_class find_key = calculate(original_public_key, div);
        if (find_key == 0) {
            cout << "Division by zero error. Stopping.\n";
            break;
        }

        if (check(find_key, pubkey_bytes)) {
            cout << "✅ Found Matching Private Key: " << find_key.get_str(16) << endl; // Print in HEX
            break;
        }

        div++;
    }

    return 0;
}
