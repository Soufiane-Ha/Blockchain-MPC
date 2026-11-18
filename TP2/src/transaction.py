
import json
import time


def create_transaction(sender, receiver, amount, nonce):

    if sender not in ["alice", "bob", "carol", "dave"]:
        raise ValueError("Unknown sender")

    if receiver not in ["alice", "bob", "carol", "dave"]:
        raise ValueError("Unknown receiver")

    if sender == receiver:
        raise ValueError("Sender and receiver must be different")

    if not isinstance(amount, int) or amount <= 0:
        raise ValueError("Amount must be a positive integer")

    if not isinstance(nonce, int) or nonce < 1:
        raise ValueError("Invalid nonce")

    return {
        "sender": sender,
        "receiver": receiver,
        "amount": amount,
        "nonce": nonce,
        "timestamp": int(time.time())
    }


def serialize_transaction(transaction):

    # Canonical JSON: same data always produces same bytes
    return json.dumps(
        transaction,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True
    ).encode("utf-8")
