"""Verify basic SealPIR round-trip."""

from pysealpir import (
    PIRClient,
    PIRServer,
    gen_encryption_params,
    gen_pir_params,
)


def test_round_trip() -> None:
    number_of_items = 8
    size_per_item = 4
    N = 2048
    logt = 20
    d = 1

    enc_params = gen_encryption_params(N, logt)
    pir_params = gen_pir_params(number_of_items, size_per_item, d, enc_params)

    client = PIRClient(enc_params, pir_params)
    server = PIRServer(enc_params, pir_params)

    key = client.generate_galois_keys()
    server.set_galois_key(0, key, enc_params)

    database = bytes(range(number_of_items * size_per_item))
    server.set_database(database, number_of_items, size_per_item)
    server.preprocess_database()

    element_index = 3
    index = client.get_fv_index(element_index)
    offset = client.get_fv_offset(element_index)

    query = client.generate_query(index)
    reply = server.generate_reply(query, 0)
    result = client.decode_reply(reply, offset)

    expected = database[element_index * size_per_item : (element_index + 1) * size_per_item]
    assert result == expected
