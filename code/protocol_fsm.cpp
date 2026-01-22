#include "protocol_fsm.h"
#include "crypto_utils.h"
#include <vector>
#include <stdexcept>

using namespace std;

bool verify_hmac(const RawMessage& msg, const vector<unsigned char>& mac_key);
vector<unsigned char> decrypt_and_unpad(const RawMessage& msg, const vector<unsigned char>& enc_key);
void ratchet_keys(Session& session, RawMessage& msg, const vector<unsigned char>& plaintext);

static bool opcode_allowed(Phase phase, Opcode opcode) {
    switch (phase) {
        case INIT:
            return opcode == CLIENT_HELLO || opcode == SERVER_CHALLENGE;

        case ACTIVE:
            return opcode == CLIENT_DATA || opcode == SERVER_AGGR_RESPONSE || opcode == TERMINATE;

        case TERMINATED:
            return false;
    }
    return false;
}

static bool direction_allowed(Opcode opcode, Direction dir) {
    switch (opcode) {
        case CLIENT_HELLO:
            return dir == C2S;

        case CLIENT_DATA:
            return dir == C2S;

        case SERVER_CHALLENGE:
            return dir == S2C;

        case SERVER_AGGR_RESPONSE:
            return dir == S2C;

        case TERMINATE:
            return true;
    }
    return false;
}

static void terminate(Session& session) {
    session.phase = TERMINATED;

    session.c2s_enc.clear();
    session.c2s_mac.clear();
    session.s2c_enc.clear();
    session.s2c_mac.clear();
}

Session init_session(unsigned char client_id, vector<unsigned char>& master_key) {
    Session s{};

    s.phase = INIT;
    s.expected_round = 0;

    // Placeholder: real derivation done in crypto_utils
    s.c2s_enc = master_key;
    s.c2s_mac = master_key;
    s.s2c_enc = master_key;
    s.s2c_mac = master_key;

    return s;
}

ProcessResult process_incoming(Session& session, RawMessage& msg) {
    if (session.phase == TERMINATED) {
        return REJECTED;
    }

    if (!opcode_allowed(session.phase, msg.opcode)) {
        terminate(session);
        return REJECTED;
    }

    if (!direction_allowed(msg.opcode, msg.direction)) {
        terminate(session);
        return REJECTED;
    }

    if (msg.round != session.expected_round) {
        terminate(session);
        return REJECTED;
    }

    vector<unsigned char>& mac_key = (msg.direction == C2S) ? session.c2s_mac : session.s2c_mac;

    if (!verify_hmac(msg, mac_key)) {
        terminate(session);
        return REJECTED;
    }

    vector<unsigned char>& enc_key = (msg.direction == C2S) ? session.c2s_enc : session.s2c_enc;
    vector<unsigned char> plaintext;

    try {
        plaintext = decrypt_and_unpad(msg, enc_key);
    } catch (...) {
        terminate(session);
        return REJECTED;
    }

    if (plaintext.empty()) {
        terminate(session);
        return REJECTED;
    }

    ratchet_keys(session, msg, plaintext);
    session.expected_round++;

    if (session.phase == INIT) {
        session.phase = ACTIVE;
    }

    if (msg.opcode == TERMINATE) {
        terminate(session);
        return REJECTED;
    }

    return ACCEPTED;
}
