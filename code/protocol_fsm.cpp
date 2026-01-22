#include "protocol_fsm.h"
#include "crypto_utils.h"
#include <openssl/sha.h>
#include <stdexcept>

using namespace std;

void terminate(Session& session) {
    session.phase = TERMINATED; 
    session.c2s_enc.clear();
    session.c2s_mac.clear();
    session.s2c_enc.clear();
    session.s2c_mac.clear(); 
}

bool opcode_allowed(Phase phase, Opcode opcode) {
    if (phase == INIT) return (opcode == CLIENT_HELLO || opcode == SERVER_CHALLENGE); 
    if (phase == ACTIVE) return (opcode == CLIENT_DATA || opcode == SERVER_AGGR_RESPONSE || opcode == TERMINATE); 
    return false;
}

bool direction_allowed(Opcode opcode, Direction dir) {
    switch (opcode) {
        case CLIENT_HELLO: case CLIENT_DATA: return dir == C2S; 
        case SERVER_CHALLENGE: case SERVER_AGGR_RESPONSE: return dir == S2C; 
        case TERMINATE: return true;
        default: return false;
    }
}

vector<unsigned char> hash_evolve(const vector<unsigned char>& key, const vector<unsigned char>& data) {
    vector<unsigned char> combined = key;
    combined.insert(combined.end(), data.begin(), data.end());
    vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
    SHA256(combined.data(), combined.size(), hash.data()); 
    return hash;
}

vector<unsigned char> serialize_for_hmac(const RawMessage& msg) {
    vector<unsigned char> buffer;
    buffer.push_back(static_cast<unsigned char>(msg.opcode));
    buffer.push_back(msg.client_id);
    for (int i = 0; i < 4; i++) buffer.push_back((msg.round >> (i * 8)) & 0xFF); 
    buffer.push_back(static_cast<unsigned char>(msg.direction));
    buffer.insert(buffer.end(), msg.iv.begin(), msg.iv.end());
    buffer.insert(buffer.end(), msg.ciphertext.begin(), msg.ciphertext.end()); 
    return buffer;
}

Session init_session(unsigned char client_id, const vector<unsigned char>& master_key) {
    Session s{};
    s.phase = INIT;
    s.expected_round = 0; 

    s.c2s_enc = hash_evolve(master_key, {'C','2','S','-','E','N','C'});
    s.c2s_mac = hash_evolve(master_key, {'C','2','S','-','M','A','C'});
    s.s2c_enc = hash_evolve(master_key, {'S','2','C','-','E','N','C'});
    s.s2c_mac = hash_evolve(master_key, {'S','2','C','-','M','A','C'});
    
    return s;
}

ProcessResult process_incoming(Session& session, RawMessage& msg) {
    if (session.phase == TERMINATED) return REJECTED;

    if (!opcode_allowed(session.phase, msg.opcode) || 
        !direction_allowed(msg.opcode, msg.direction) || 
        msg.round != session.expected_round) {
        terminate(session);
        return REJECTED;
    }

    vector<unsigned char>& mac_key = (msg.direction == C2S) ? session.c2s_mac : session.s2c_mac;
    vector<unsigned char> auth_data = serialize_for_hmac(msg);
    if (!verify_hmac(auth_data, mac_key, msg.hmac)) {
        terminate(session);
        return REJECTED;
    }

    vector<unsigned char>& enc_key = (msg.direction == C2S) ? session.c2s_enc : session.s2c_enc;
    vector<unsigned char> plaintext;
    try {
        plaintext = aes_cbc_decrypt(msg.ciphertext, enc_key, msg.iv);
        if (!pkcs7_unpad(plaintext)) throw runtime_error("Padding Failure");
    } catch (...) {
        terminate(session);
        return REJECTED;
    }

    if (msg.direction == C2S) {
        session.c2s_enc = hash_evolve(session.c2s_enc, msg.ciphertext);
        session.c2s_mac = hash_evolve(session.c2s_mac, plaintext); 
    } else {
        session.s2c_enc = hash_evolve(session.s2c_enc, plaintext); 
        session.s2c_mac = hash_evolve(session.s2c_mac, plaintext);
    }

    session.expected_round++; 
    if (session.phase == INIT) session.phase = ACTIVE; 
    if (msg.opcode == TERMINATE) terminate(session); 

    return ACCEPTED;
}