#ifndef PROTOCOL_FSM_H
#define PROTOCOL_FSM_H

#include <cstdint>
#include <vector>
#include <stdexcept>

using namespace std;

enum class Phase {
    INIT,
    ACTIVE,
    TERMINATED
};

enum class Direction : unsigned char {
    C2S = 0,
    S2C = 1
};

enum class Opcode : unsigned char {
    CLIENT_HELLO = 10,
    SERVER_CHALLENGE = 20,
    CLIENT_DATA = 30,
    SERVER_AGGR_RESPONSE = 40,
    TERMINATE = 50
};

struct RawMessage {
    Opcode opcode;
    unsigned char client_id;
    unsigned int round;
    Direction direction;

    vector<unsigned char> iv;
    vector<unsigned char> ciphertext;
    vector<unsigned char> hmac;
};

struct Session {
    Phase phase;
    unsigned int expected_round;

    vector<unsigned char> c2s_enc;
    vector<unsigned char> c2s_mac;
    vector<unsigned char> s2c_enc;
    vector<unsigned char> s2c_mac;
};

Session init_session(unsigned char client_id, const vector<unsigned char>& master_key);

enum class ProcessResult {
    ACCEPTED,
    TERMINATED
};

ProcessResult process_incoming(
    Session& session,
    RawMessage& msg
);

#endif
