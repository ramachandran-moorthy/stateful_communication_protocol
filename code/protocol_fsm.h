#ifndef PROTOCOL_FSM_H
#define PROTOCOL_FSM_H

#include <vector>
#include <cstdint>
#include <string>

using namespace std;

enum Phase {
    INIT,
    ACTIVE,
    TERMINATED
};

enum Direction {
    C2S = 0,
    S2C = 1
};

enum Opcode {
    CLIENT_HELLO = 10,
    SERVER_CHALLENGE = 20,
    CLIENT_DATA = 30,
    SERVER_AGGR_RESPONSE = 40,
    KEY_DESYNC_ERROR = 50,
    TERMINATE = 60
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

enum ProcessResult {
    ACCEPTED,
    REJECTED
};

void terminate(Session& session);
bool opcode_allowed(Phase phase, Opcode opcode);
bool direction_allowed(Opcode opcode, Direction dir);
Session init_session(unsigned char client_id, const vector<unsigned char>& master_key);
ProcessResult process_incoming(Session& session, RawMessage& msg);
vector<unsigned char> serialize_for_hmac(const RawMessage& msg);
vector<unsigned char> hash_evolve(const vector<unsigned char>& key, const vector<unsigned char>& data);

#endif