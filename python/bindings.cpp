#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <sstream>

#include "pir.hpp"
#include "pir_client.hpp"
#include "pir_server.hpp"

namespace py = pybind11;

// Helper: create EncryptionParameters and return
static seal::EncryptionParameters
gen_enc_params_wrapper(std::uint32_t N, std::uint32_t logt) {
    seal::EncryptionParameters params(seal::scheme_type::bfv);
    gen_encryption_params(N, logt, params);
    return params;
}

// Helper: generate PIR parameters and return
static PirParams gen_pir_params_wrapper(std::uint64_t ele_num,
                                       std::uint64_t ele_size,
                                       std::uint32_t d,
                                       const seal::EncryptionParameters &enc,
                                       bool enable_symmetric = false,
                                       bool enable_batching = true,
                                       bool enable_mswitching = true) {
    PirParams p;
    gen_pir_params(ele_num, ele_size, d, enc, p,
                   enable_symmetric, enable_batching, enable_mswitching);
    return p;
}

// Wrap set_database taking Python bytes
static void set_database_from_bytes(PIRServer &server, py::bytes db,
                                    std::uint64_t ele_num,
                                    std::uint64_t ele_size) {
    std::string buffer = db;
    auto data = std::make_unique<uint8_t[]>(buffer.size());
    std::memcpy(data.get(), buffer.data(), buffer.size());
    server.set_database(std::move(data), ele_num, ele_size);
}

// Wrap generate_serialized_query
static py::bytes generate_query_serialized(PIRClient &client,
                                           std::uint64_t index) {
    std::stringstream stream;
    client.generate_serialized_query(index, stream);
    return py::bytes(stream.str());
}

// Wrap server side generation of serialized reply
static py::bytes generate_reply_serialized(PIRServer &server,
                                           const std::string &query,
                                           std::uint32_t client_id) {
    std::stringstream qs(query);
    PirQuery q = server.deserialize_query(qs);
    PirReply r = server.generate_reply(q, client_id);
    std::stringstream rs;
    server.serialize_reply(r, rs);
    return py::bytes(rs.str());
}

// Wrap client decode from serialized reply
static py::bytes decode_reply_serialized(PIRClient &client,
                                         const std::string &reply,
                                         std::uint64_t offset) {
    std::stringstream rs(reply);
    PirReply r;
    while (rs.rdbuf()->in_avail() > 0) {
        seal::Ciphertext ct;
        ct.load(*client.get_context(), rs);
        r.push_back(ct);
    }
    std::vector<uint8_t> result = client.decode_reply(r, offset);
    return py::bytes(reinterpret_cast<const char *>(result.data()),
                     result.size());
}

// Wrap generation of galois keys
static py::bytes generate_galois_keys_serialized(PIRClient &client) {
    auto g = client.generate_galois_keys();
    std::string s = serialize_galoiskeys(g);
    return py::bytes(s);
}

// Wrap server set_galois_key from serialized bytes
static void set_galois_key_serialized(PIRServer &server, std::uint32_t client_id,
                                      const std::string &key,
                                      const seal::EncryptionParameters &enc) {
    auto context = std::make_shared<seal::SEALContext>(enc, true);
    auto g = deserialize_galoiskeys(key, context);
    server.set_galois_key(client_id, *g);
    delete g;
}

PYBIND11_MODULE(sealpir, m) {
    m.doc() = "Python bindings for SealPIR";

    py::class_<seal::EncryptionParameters>(m, "EncryptionParameters")
        .def(py::init<seal::scheme_type>());

    py::class_<PirParams>(m, "PirParams")
        .def(py::init<>())
        .def_readwrite("enable_symmetric", &PirParams::enable_symmetric)
        .def_readwrite("enable_batching", &PirParams::enable_batching)
        .def_readwrite("enable_mswitching", &PirParams::enable_mswitching)
        .def_readwrite("ele_num", &PirParams::ele_num)
        .def_readwrite("ele_size", &PirParams::ele_size)
        .def_readwrite("elements_per_plaintext", &PirParams::elements_per_plaintext)
        .def_readwrite("num_of_plaintexts", &PirParams::num_of_plaintexts)
        .def_readwrite("d", &PirParams::d)
        .def_readwrite("expansion_ratio", &PirParams::expansion_ratio)
        .def_readwrite("nvec", &PirParams::nvec)
        .def_readwrite("slot_count", &PirParams::slot_count);

    m.def("gen_encryption_params", &gen_enc_params_wrapper,
          py::arg("poly_modulus_degree"), py::arg("logt"),
          "Generate SEAL encryption parameters");
    m.def("gen_pir_params", &gen_pir_params_wrapper,
          py::arg("ele_num"), py::arg("ele_size"), py::arg("d"),
          py::arg("enc_params"), py::arg("enable_symmetric") = false,
          py::arg("enable_batching") = true,
          py::arg("enable_mswitching") = true,
          "Generate PIR parameters");

    py::class_<PIRClient>(m, "PIRClient")
        .def(py::init<const seal::EncryptionParameters &, const PirParams &>(),
             "Create a PIR client")
        .def("generate_galois_keys", &generate_galois_keys_serialized,
             "Return serialized Galois keys")
        .def("generate_query", &generate_query_serialized,
             py::arg("index"), "Generate serialized query")
        .def("decode_reply", &decode_reply_serialized,
             py::arg("reply"), py::arg("offset"),
             "Decode serialized reply and return bytes")
        .def("get_fv_index", &PIRClient::get_fv_index)
        .def("get_fv_offset", &PIRClient::get_fv_offset);

    py::class_<PIRServer>(m, "PIRServer")
        .def(py::init<const seal::EncryptionParameters &, const PirParams &>(),
             "Create a PIR server")
        .def("set_database", &set_database_from_bytes,
             py::arg("db"), py::arg("ele_num"), py::arg("ele_size"),
             "Load raw database bytes")
        .def("preprocess_database", &PIRServer::preprocess_database,
             "Preprocess database for queries")
        .def("set_galois_key", &set_galois_key_serialized,
             py::arg("client_id"), py::arg("key"), py::arg("enc_params"),
             "Set serialized Galois key for client")
        .def("generate_reply", &generate_reply_serialized,
             py::arg("query"), py::arg("client_id"),
             "Generate serialized reply");
}

