"""Minimal round-trip example using SealPIR bindings."""

from sealpir import (
    PIRClient,
    PIRServer,
    gen_encryption_params,
    gen_pir_params,
)


def main() -> None:
    number_of_items = 16
    size_per_item = 4
    poly_modulus_degree = 2048
    logt = 20
    d = 1

    enc_params = gen_encryption_params(poly_modulus_degree, logt)
    pir_params = gen_pir_params(number_of_items, size_per_item, d, enc_params)

    client = PIRClient(enc_params, pir_params)
    server = PIRServer(enc_params, pir_params)

    galois_key = client.generate_galois_keys()
    server.set_galois_key(0, galois_key, enc_params)

    # Build a tiny database of sequential bytes
    database = bytes(range(number_of_items * size_per_item))
    server.set_database(database, number_of_items, size_per_item)
    server.preprocess_database()

    element_index = 5
    index = client.get_fv_index(element_index)
    offset = client.get_fv_offset(element_index)

    query = client.generate_query(index)
    reply = server.generate_reply(query, 0)
    result = client.decode_reply(reply, offset)

    print("Retrieved:", list(result))
    expected = database[element_index * size_per_item : (element_index + 1) * size_per_item]
    assert result == expected


if __name__ == "__main__":
    main()
