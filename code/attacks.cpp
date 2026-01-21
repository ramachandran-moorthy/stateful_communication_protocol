#include "protocol_fsm.h"

#include <cassert>
#include <iostream>
#include <vector>

using namespace std;

//for testing 
bool verify_hmac(const RawMessage&, const vector<unsigned char>&) {
    return true; //always accepted unless testing for false MAC
}

vector<unsigned char> decrypt_and_unpad(const RawMessage&,const vector<unsigned char>&) {
    return {0xDE, 0xAD, 0xBE, 0xEF};  // dummy plaintext
}

void ratchet_keys(Session&, const RawMessage&, const vector<unsigned char>&) {
    // no-op for FSM tests
}

RawMessage make_valid_client_data(unsigned int round) {
    RawMessage msg{};
    msg.opcode = Opcode::CLIENT_DATA;
    msg.client_id = 1;
    msg.round = round;
    msg.direction = Direction::C2S;
    msg.iv = {0x01};
    msg.ciphertext = {0x02};
    msg.hmac = {0x03};
    return msg;
}

void attack_replay() {
    cout << "[*] Replay attack" << endl;

    Session s = init_session(1, {0xAA});
    s.phase = Phase::ACTIVE;

    RawMessage msg = make_valid_client_data(0);

    assert(process_incoming(s, msg) == ProcessResult::ACCEPTED);
    assert(s.expected_round == 1);

    assert(process_incoming(s, msg) == ProcessResult::TERMINATED);
    assert(s.phase == Phase::TERMINATED);
}

void attack_reflection() {
    cout << "[*] Reflection attack" << endl;

    Session s = init_session(1, {0xAA});
    s.phase = Phase::ACTIVE;

    RawMessage msg = make_valid_client_data(0);
    msg.direction = Direction::S2C;

    assert(process_incoming(s, msg) == ProcessResult::TERMINATED);
}

void attack_wrong_phase() {
    cout << "[*] Wrong phase attack" << endl;

    Session s = init_session(1, {0xAA});
    // phase == INIT

    RawMessage msg = make_valid_client_data(0);

    assert(process_incoming(s, msg) == ProcessResult::TERMINATED);
}

void attack_round_skip() {
    cout << "[*] Round skip attack" << endl;

    Session s = init_session(1, {0xAA});
    s.phase = Phase::ACTIVE;

    RawMessage msg = make_valid_client_data(5); // jump ahead

    assert(process_incoming(s, msg) == ProcessResult::TERMINATED);
}

void attack_opcode_misuse() {
    cout << "[*] Opcode misuse attack" << endl;

    Session s = init_session(1, {0xAA});
    s.phase = Phase::ACTIVE;

    RawMessage msg = make_valid_client_data(0);
    msg.opcode = Opcode::CLIENT_HELLO; // invalid in ACTIVE

    assert(process_incoming(s, msg) == ProcessResult::TERMINATED);
}

void attack_terminate() {
    cout << "[*] Terminate opcode attack" << endl;

    Session s = init_session(1, {0xAA});
    s.phase = Phase::ACTIVE;

    RawMessage msg = make_valid_client_data(0);
    msg.opcode = Opcode::TERMINATE;

    assert(process_incoming(s, msg) == ProcessResult::TERMINATED);
    assert(s.phase == Phase::TERMINATED);
}

int main() {
    attack_replay();
    attack_reflection();
    attack_wrong_phase();
    attack_round_skip();
    attack_opcode_misuse();
    attack_terminate();

    cout << "[+] All attack tests passed" << endl;
    return 0;
}
