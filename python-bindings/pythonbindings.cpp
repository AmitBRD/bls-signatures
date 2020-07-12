// Copyright 2018 Chia Network Inc

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//    http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/operators.h>

#include "../src/privatekey.hpp"
#include "../src/bls.hpp"

namespace py = pybind11;
using namespace bls;

PYBIND11_MODULE(blspy, m) {
    py::class_<bn_t*>(m, "bn_ptr");

    py::class_<AggregationInfo>(m, "AggregationInfo")
        .def("from_msg_hash", [](const PublicKey &pk, const py::bytes &b) {
            std::string str(b);
            const uint8_t* input = reinterpret_cast<const uint8_t*>(str.data());
            return AggregationInfo::FromMsgHash(pk, input);
        })
        .def("from_msg", [](const PublicKey &pk, const py::bytes &b) {
            std::string str(b);
            const uint8_t* input = reinterpret_cast<const uint8_t*>(str.data());
            return AggregationInfo::FromMsg(pk, input, len(b));
        })
        .def("merge_infos", &AggregationInfo::MergeInfos)
        .def("get_pubkeys", &AggregationInfo::GetPubKeys)
        .def("get_msg_hashes", [](const AggregationInfo &self) {
            std::vector<uint8_t*> msgHashes = self.GetMessageHashes();
            std::vector<py::bytes> ret;
            for (const uint8_t* msgHash : msgHashes) {
                ret.push_back(py::bytes(reinterpret_cast<const char*>(msgHash), BLS::MESSAGE_HASH_LEN));
            }
            return ret;
        })
        .def(py::self == py::self)
        .def(py::self != py::self)
        .def(py::self < py::self)
        .def("__repr__", [](const AggregationInfo &a) {
            std::stringstream s;
            s << a;
            return "<AggregationInfo " + s.str() + ">";
        });

    py::class_<PrivateKey>(m, "PrivateKey")
        .def_property_readonly_static("PRIVATE_KEY_SIZE", [](py::object self) {
            return PrivateKey::PRIVATE_KEY_SIZE;
        })
        .def("from_seed", [](const py::bytes &b) {
            std::string str(b);
            const uint8_t* input = reinterpret_cast<const uint8_t*>(str.data());
            return PrivateKey::FromSeed(input, len(b));
        })
        .def("from_bytes", [](const py::bytes &b) {
            std::string str(b);
            const uint8_t* input = reinterpret_cast<const uint8_t*>(str.data());
            return PrivateKey::FromBytes(input);
        })
        .def("__bytes__", [](const PrivateKey &k) {
            uint8_t* output = Util::SecAlloc<uint8_t>(PrivateKey::PRIVATE_KEY_SIZE);
            k.Serialize(output);
            py::bytes ret = py::bytes(reinterpret_cast<char*>(output), PrivateKey::PRIVATE_KEY_SIZE);
            Util::SecFree(output);
            return ret;
        })
        .def("serialize", [](const PrivateKey &k) {
            uint8_t* output = Util::SecAlloc<uint8_t>(PrivateKey::PRIVATE_KEY_SIZE);
            k.Serialize(output);
            py::bytes ret = py::bytes(reinterpret_cast<char*>(output), PrivateKey::PRIVATE_KEY_SIZE);
            Util::SecFree(output);
            return ret;
        })
        .def("__deepcopy__", [](const PrivateKey &k, const py::object& memo) {
            return PrivateKey(k);
        })
        .def("get_public_key", [](const PrivateKey &k) {
            return k.GetPublicKey();
        })
        .def("aggregate", &PrivateKey::Aggregate)
        .def("aggregate_insecure", &PrivateKey::AggregateInsecure)
        .def("sign_insecure", [](const PrivateKey &k, const py::bytes &msg) {
            std::string str(msg);
            const uint8_t* input = reinterpret_cast<const uint8_t*>(str.data());
            return k.SignInsecure(input, len(msg));
        })
        .def("sign_insecure_prehashed", [](const PrivateKey &k, const py::bytes &msg) {
            std::string str(msg);
            const uint8_t* input = reinterpret_cast<const uint8_t*>(str.data());
            return k.SignInsecurePrehashed(input);
        })
        .def("sign", [](const PrivateKey &k, const py::bytes &msg) {
            std::string str(msg);
            const uint8_t* input = reinterpret_cast<const uint8_t*>(str.data());
            return k.Sign(input, len(msg));
        })
        .def("sign_prehashed", [](const PrivateKey &k, const py::bytes &msg) {
            std::string str(msg);
            const uint8_t* input = reinterpret_cast<const uint8_t*>(str.data());
            return k.SignPrehashed(input);
        })
        .def("sign_prepend", [](const PrivateKey &k, const py::bytes &msg) {
            std::string str(msg);
            const uint8_t* input = reinterpret_cast<const uint8_t*>(str.data());
            return k.SignPrepend(input, len(msg));
        })
        .def("sign_prepend_prehashed", [](const PrivateKey &k, const py::bytes &msg) {
            std::string str(msg);
            const uint8_t* input = reinterpret_cast<const uint8_t*>(str.data());
            return k.SignPrependPrehashed(input);
        })
        .def("private_child", &PrivateKey::PrivateChild)
        .def("public_child", &PrivateKey::PublicChild)
        .def(py::self == py::self)
        .def(py::self != py::self)
        .def("__repr__", [](const PrivateKey &k) {
            uint8_t* output = Util::SecAlloc<uint8_t>(PrivateKey::PRIVATE_KEY_SIZE);
            k.Serialize(output);
            std::string ret = "<PrivateKey " + Util::HexStr(output, PrivateKey::PRIVATE_KEY_SIZE) + ">";
            Util::SecFree(output);
            return ret;
        });

    py::class_<PublicKey>(m, "PublicKey")
        .def_property_readonly_static("PUBLIC_KEY_SIZE", [](py::object self) {
            return PublicKey::PUBLIC_KEY_SIZE;
        })
        .def("from_bytes", [](const py::bytes &b) {
            std::string str(b);
            return PublicKey::FromBytes(reinterpret_cast<const uint8_t*>(str.data()));
        })
        .def("aggregate", &PublicKey::Aggregate)
        .def("aggregate_insecure", &PublicKey::AggregateInsecure)
        .def("get_fingerprint", &PublicKey::GetFingerprint)
        .def("serialize", [](const PublicKey &pk) {
            uint8_t* output = new uint8_t[PublicKey::PUBLIC_KEY_SIZE];
            pk.Serialize(output);
            py::bytes ret = py::bytes(reinterpret_cast<char*>(output), PublicKey::PUBLIC_KEY_SIZE);
            delete[] output;
            return ret;
        })
        .def("__bytes__", [](const PublicKey &pk) {
            uint8_t* output = new uint8_t[PublicKey::PUBLIC_KEY_SIZE];
            pk.Serialize(output);
            py::bytes ret = py::bytes(reinterpret_cast<char*>(output), PublicKey::PUBLIC_KEY_SIZE);
            delete[] output;
            return ret;
        })
        .def("__deepcopy__", [](const PublicKey &k, py::object memo) {
            return PublicKey(k);
        })
        .def(py::self == py::self)
        .def(py::self != py::self)
        .def("__repr__", [](const PublicKey &pk) {
            std::stringstream s;
            s << pk;
            return "<PublicKey " + s.str() + ">";
        });

    py::class_<InsecureSignature>(m, "InsecureSignature")
        .def_property_readonly_static("SIGNATURE_SIZE", [](py::object self) {
            return InsecureSignature::SIGNATURE_SIZE;
        })
        .def("from_bytes", [](const py::bytes &b) {
            std::string str(b);
            return InsecureSignature::FromBytes(reinterpret_cast<const uint8_t*>(str.data()));
        })
        .def("serialize", [](const InsecureSignature &sig) {
            uint8_t* output = new uint8_t[InsecureSignature::SIGNATURE_SIZE];
            sig.Serialize(output);
            py::bytes ret = py::bytes(reinterpret_cast<char*>(output), InsecureSignature::SIGNATURE_SIZE);
            delete[] output;
            return ret;
        })
        .def("__bytes__", [](const InsecureSignature &sig) {
            uint8_t* output = new uint8_t[InsecureSignature::SIGNATURE_SIZE];
            sig.Serialize(output);
            py::bytes ret = py::bytes(reinterpret_cast<char*>(output), InsecureSignature::SIGNATURE_SIZE);
            delete[] output;
            return ret;
        })
        .def("__deepcopy__", [](const InsecureSignature &sig, py::object memo) {
            return InsecureSignature(sig);
        })
        .def("verify", [](const InsecureSignature &sig,
                          const std::vector<py::bytes> hashes,
                          const std::vector<PublicKey>& pubKeys) {
            std::vector<const uint8_t*> hashes_pointers;
            std::vector<std::string> str_hashes;
            for (const py::bytes b : hashes) {
                std::string str(b);
                str_hashes.push_back(str);
            }
            for (std::string& str : str_hashes) {
                hashes_pointers.push_back(reinterpret_cast<const uint8_t*>(str.data()));
            }
            return sig.Verify(hashes_pointers, pubKeys);
        })
        .def("aggregate", &InsecureSignature::Aggregate)
        .def("divide_by", &InsecureSignature::DivideBy)
        .def(py::self == py::self)
        .def(py::self != py::self)
        .def("__repr__", [](const InsecureSignature &sig) {
            std::stringstream s;
            s << sig;
            return "<InsecureSignature " + s.str() + ">";
        });

    py::class_<Signature>(m, "Signature")
        .def_property_readonly_static("SIGNATURE_SIZE", [](py::object self) {
            return Signature::SIGNATURE_SIZE;
        })
        .def("from_bytes", [](const py::bytes &b) {
            std::string str(b);
            return Signature::FromBytes(reinterpret_cast<const uint8_t*>(str.data()));
        })
        .def("serialize", [](const Signature &sig) {
            uint8_t* output = new uint8_t[Signature::SIGNATURE_SIZE];
            sig.Serialize(output);
            py::bytes ret = py::bytes(reinterpret_cast<char*>(output), Signature::SIGNATURE_SIZE);
            delete[] output;
            return ret;
        })
        .def("__bytes__", [](const Signature &sig) {
            uint8_t* output = new uint8_t[Signature::SIGNATURE_SIZE];
            sig.Serialize(output);
            py::bytes ret = py::bytes(reinterpret_cast<char*>(output), Signature::SIGNATURE_SIZE);
            delete[] output;
            return ret;
        })
        .def("__deepcopy__", [](const Signature &sig, py::object memo) {
            return Signature(sig);
        })
        .def("verify", &Signature::Verify)
        .def("aggregate", &Signature::Aggregate)
        .def("divide_by", &Signature::DivideBy)
        .def("set_aggregation_info", &Signature::SetAggregationInfo)
        .def("get_aggregation_info", [](const Signature &sig) {
            return *sig.GetAggregationInfo();
        })
        .def("from_insecure_sig", [](const InsecureSignature &s) {
            return Signature::FromInsecureSig(s);
        })
        .def("get_insecure_sig", &Signature::GetInsecureSig)
        .def(py::self == py::self)
        .def(py::self != py::self)
        .def("__repr__", [](const Signature &sig) {
            std::stringstream s;
            s << sig;
            return "<Signature " + s.str() + ">";
        });

    py::class_<PrependSignature>(m, "PrependSignature")
        .def_property_readonly_static("SIGNATURE_SIZE", [](py::object self) {
            return PrependSignature::SIGNATURE_SIZE;
        })
        .def("from_bytes", [](const py::bytes &b) {
            std::string str(b);
            const uint8_t* input = reinterpret_cast<const uint8_t*>(str.data());
            return PrependSignature::FromBytes(input);
        })
        .def("serialize", [](const PrependSignature &sig) {
            uint8_t* output = new uint8_t[PrependSignature::SIGNATURE_SIZE];
            sig.Serialize(output);
            py::bytes ret = py::bytes(reinterpret_cast<char*>(output), PrependSignature::SIGNATURE_SIZE);
            delete[] output;
            return ret;
        })
        .def("__bytes__", [](const PrependSignature &sig) {
            uint8_t* output = new uint8_t[PrependSignature::SIGNATURE_SIZE];
            sig.Serialize(output);
            py::bytes ret = py::bytes(reinterpret_cast<char*>(output), PrependSignature::SIGNATURE_SIZE);
            delete[] output;
            return ret;
        })
        .def("__deepcopy__", [](const PrependSignature &sig, py::object memo) {
            return PrependSignature(sig);
        })
        .def("verify", [](const PrependSignature &sig, const std::vector<py::bytes> &hashes,
                           std::vector<PublicKey> &pks) {
            std::vector<const uint8_t*> converted_hashes;
            std::vector<std::string> strings;
            for (const py::bytes &h : hashes) {
               std::string str(h);
               strings.push_back(str);
            }
            for (uint32_t i = 0; i < strings.size(); i++) {
               converted_hashes.push_back(reinterpret_cast<const uint8_t*>(strings[i].data()));
            }
            return sig.Verify(converted_hashes, pks);
        })
        .def("from_insecure_sig", [](const InsecureSignature &s) {
            return PrependSignature::FromInsecureSig(s);
        })
        .def("get_insecure_sig", &PrependSignature::GetInsecureSig)
        .def("aggregate", &PrependSignature::Aggregate)
        .def("divide_by", &PrependSignature::DivideBy)
        .def(py::self == py::self)
        .def(py::self != py::self)
        .def("__repr__", [](const PrependSignature &sig) {
            std::stringstream s;
            s << sig;
            return "<PrependSignature " + s.str() + ">";
        });

    py::class_<Threshold>(m, "Threshold")
        .def("create", [](size_t T, size_t N) {
            std::vector<PublicKey> commitments;
            std::vector<PrivateKey> secret_fragments;
            g1_t g;
            bn_t b;
            bn_new(b);
            for (size_t i = 0; i < N; i++) {
                commitments.emplace_back(PublicKey::FromG1(&g));
                secret_fragments.emplace_back(PrivateKey::FromBN(b));
            }
            PrivateKey fragment = Threshold::Create(commitments, secret_fragments, T, N);
            return py::make_tuple(fragment, commitments, secret_fragments);
        })
        .def("sign_with_coefficient", [](const PrivateKey sk, const py::bytes &msg, size_t player_index,
                                         const std::vector<size_t> players) {
            std::string str(msg);
            const uint8_t* input = reinterpret_cast<const uint8_t*>(str.data());
            size_t* players_pointer = new size_t[players.size()];
            for (int i=0; i < players.size(); i++) {
                players_pointer[i] = players[i];
            }
            auto ret = Threshold::SignWithCoefficient(sk, input, len(msg), player_index, players_pointer, players.size());
            delete[] players_pointer;
            return ret;
        })
        .def("aggregate_unit_sigs", [](const std::vector<InsecureSignature> sigs,
                                       const std::vector<size_t> players) {
            size_t* players_pointer = new size_t[players.size()];
            for (int i=0; i < players.size(); i++) {
                players_pointer[i] = players[i];
            }
            uint8_t msg[1];
            auto ret = Threshold::AggregateUnitSigs(sigs, msg, 1, players_pointer, players.size());
            delete[] players_pointer;
            return ret;
        })
        .def("verify_secret_fragment", &Threshold::VerifySecretFragment);

    py::class_<BLS>(m, "BLS")
        .def_property_readonly_static("MESSAGE_HASH_LEN", [](py::object self) {
            return BLS::MESSAGE_HASH_LEN;
        });

    py::class_<Util>(m, "Util")
        .def("hash256", [](const py::bytes &message) {
            std::string str(message);
            const uint8_t* input = reinterpret_cast<const uint8_t*>(str.data());
            uint8_t output[BLS::MESSAGE_HASH_LEN];
            Util::Hash256(output, (const uint8_t*)str.data(), str.size());
            return py::bytes(reinterpret_cast<char*>(output), BLS::MESSAGE_HASH_LEN);
        });

#ifdef VERSION_INFO
    m.attr("__version__") = VERSION_INFO;
#else
    m.attr("__version__") = "dev";
#endif
}
