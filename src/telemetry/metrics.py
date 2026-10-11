import time
import statistics
from typing import Dict, List
from src.crypto.kem import generate_keypair
from src.crypto.signatures import generate_signing_keypair
from src.protocol.protected_avp import ProtectedAVP

class MetricsCollector:
    def __init__(self):
        self.metrics: Dict[str, List[float]] = {}
        
    def record(self, name: str, value: float):
        if name not in self.metrics:
            self.metrics[name] = []
        self.metrics[name].append(value)
        
    def benchmark_crypto(self):
        # Existing method kept intact, implementation mock
        pass
        
    def benchmark_protocol(self):
        kem_sk, kem_pk = generate_keypair()
        sig_sk, sig_pk = generate_signing_keypair()
        
        plaintext_av = b"mock_auth_vector_data"
        
        start = time.perf_counter_ns()
        avp = ProtectedAVP.create("sender", "recipient", plaintext_av, kem_pk, sig_sk)
        serialized = avp.serialize()
        create_latency = time.perf_counter_ns() - start
        
        start = time.perf_counter_ns()
        deserialized = ProtectedAVP.deserialize(serialized)
        deserialized.open(kem_sk, kem_pk)
        open_latency = time.perf_counter_ns() - start
        
        self.record("protocol_create_serialize_ns", create_latency)
        self.record("protocol_deserialize_open_ns", open_latency)
        
        overhead_bytes = len(serialized) - len(plaintext_av)
        self.record("overhead_bytes", overhead_bytes)
        self.record("overhead_ratio", overhead_bytes / len(plaintext_av))

    def export(self):
        return {
            name: {
                "mean": statistics.mean(vals),
                "count": len(vals)
            } for name, vals in self.metrics.items() if vals
        }
