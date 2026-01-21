#include "protocol_fsm.h"
#include "crypto_utils.h"
#include <vector>
#include <stdexcept>

using namespace std;

// Verifies HMAC over (header || ciphertext)
bool verify_hmac(const RawMessage& msg, const vector<unsigned char>& mac_key);

// Decrypts ciphertext using AES-CBC and performs PKCS#7 unpadding.
// Throws on ANY failure.
vector<unsigned char> decrypt_and_unpad(const RawMessage& msg, const vector<unsigned char>& enc_key);

// Evolves session keys after successful message processing
void ratchet_keys(Session& session, RawMessage& msg, const vector<unsigned char>& plaintext);

static bool opcode_allowed(Phase phase, Opcode opcode) {
    switch (phase) {
        case Phase::INIT:
            return opcode == Opcode::CLIENT_HELLO || opcode == Opcode::SERVER_CHALLENGE;

        case Phase::ACTIVE:
            return opcode == Opcode::CLIENT_DATA || opcode == Opcode::SERVER_AGGR_RESPONSE || opcode == Opcode::TERMINATE;

        case Phase::TERMINATED:
            return false;
    }
    return false;
}

static bool direction_allowed(Opcode opcode, Direction dir) {
    switch (opcode) {
        case Opcode::CLIENT_HELLO:
            return dir == Direction::C2S;

        case Opcode::CLIENT_DATA:
            return dir == Direction::C2S;

        case Opcode::SERVER_CHALLENGE:
            return dir == Direction::S2C;

        case Opcode::SERVER_AGGR_RESPONSE:
            return dir == Direction::S2C;

        case Opcode::TERMINATE:
            return true;
    }
    return false;
}

static void terminate(Session& session) {
    session.phase = Phase::TERMINATED;

    session.c2s_enc.clear();
    session.c2s_mac.clear();
    session.s2c_enc.clear();
    session.s2c_mac.clear();
}

Session init_session(unsigned char client_id, vector<unsigned char>& master_key) {
    Session s{};

    s.phase = Phase::INIT;
    s.expected_round = 0;

    // Placeholder: real derivation done in crypto_utils
    s.c2s_enc = master_key;
    s.c2s_mac = master_key;
    s.s2c_enc = master_key;
    s.s2c_mac = master_key;

    return s;
}

ProcessResult process_incoming(Session& session, RawMessage& msg) {
    if (session.phase == Phase::TERMINATED) {
        return ProcessResult::TERMINATED;
    }

    if (!opcode_allowed(session.phase, msg.opcode)) {
        terminate(session);
        return ProcessResult::TERMINATED;
    }

    if (!direction_allowed(msg.opcode, msg.direction)) {
        terminate(session);
        return ProcessResult::TERMINATED;
    }

    if (msg.round != session.expected_round) {
        terminate(session);
        return ProcessResult::TERMINATED;
    }

    vector<unsigned char>& mac_key = (msg.direction == Direction::C2S) ? session.c2s_mac : session.s2c_mac;

    if (!verify_hmac(msg, mac_key)) {
        terminate(session);
        return ProcessResult::TERMINATED;
    }

    vector<unsigned char>& enc_key = (msg.direction == Direction::C2S) ? session.c2s_enc : session.s2c_enc;
    vector<unsigned char> plaintext;

    try {
        plaintext = decrypt_and_unpad(msg, enc_key);
    } catch (...) {
        terminate(session);
        return ProcessResult::TERMINATED;
    }

    if (plaintext.empty()) {
        terminate(session);
        return ProcessResult::TERMINATED;
    }

    ratchet_keys(session, msg, plaintext);
    session.expected_round++;

    if (session.phase == Phase::INIT) {
        session.phase = Phase::ACTIVE;
    }

    if (msg.opcode == Opcode::TERMINATE) {
        terminate(session);
        return ProcessResult::TERMINATED;
    }

    return ProcessResult::ACCEPTED;
}
